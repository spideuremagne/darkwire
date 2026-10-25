using Darkwire.Core;
using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;

[assembly: InternalsVisibleTo("Darkwire.Checks")]
[assembly: InternalsVisibleTo("Darkwire.Service")]

namespace Darkwire.Engine;

/// <summary>
/// The process behind a flow: its Win32 image path for display and the identity WFP classifies it with. In a process running
/// several services, TaggedService is the one whose thread opened the flow's socket, as Windows tags it; null when unknown.
/// </summary>
public sealed record FlowProcess(int ProcessId, long StartedAt, string ImagePath, FlowOwner Owner)
{
    public string? TaggedService { get; init; }
}

/// <summary>
/// One socket from the TCP/UDP owner-module tables. Created is a FILETIME, or zero when Windows does not report it. Entry is
/// the raw table row, from which Windows names the service that opened the socket; it is empty for rows made elsewhere.
/// </summary>
public readonly record struct SocketRow(IPAddress LocalAddress, int LocalPort, IPAddress? RemoteAddress, int RemotePort, int State, int ProcessId, long Created)
{
    public ReadOnlyMemory<byte> Entry { get; init; }
}

/// <summary>
/// Attributes routed flows to processes from the socket owner tables, then reads each process token. Tables are read
/// fresh for every snapshot, so a recycled port is never answered from an older table. A socket whose owner cannot be
/// told apart from another, or whose PID now names a newer process, stays unattributed: the matcher then admits only
/// application-independent allows. In a process running several services, the socket's service tag names the one that
/// opened it.
/// </summary>
public sealed class FlowAttribution
{
    public const int SystemProcessId = 4;
    private const int MaximumCachedProcesses = 4096;
    private readonly object gate = new();
    private readonly Dictionary<(int Pid, long Started), FlowProcess> processes = [];
    private readonly Func<bool, bool, IReadOnlyList<SocketRow>> readTable;
    private readonly Func<int, long, FlowProcess?> readProcess;
    private readonly Func<SocketRow, string?> readModule;

    public FlowAttribution() : this((udp, v6) => udp ? ReadUdp(v6) : ReadTcp(v6), ReadProcess, OwnerModule) { }
    internal FlowAttribution(Func<bool, bool, IReadOnlyList<SocketRow>> readTable, Func<int, long, FlowProcess?> readProcess, Func<SocketRow, string?>? readModule = null)
    { this.readTable = readTable; this.readProcess = readProcess; this.readModule = readModule ?? (_ => null); }

    /// <summary>Starts a batch: each socket table is read at most once, on first use.</summary>
    public Snapshot Begin() => new(this);

    /// <summary>
    /// The processes with established TCP connections they opened to hosts beyond loopback, once for each service that opened
    /// one where Windows tagged it. A connection on a port its process listens on came in, and is left out.
    /// </summary>
    public IReadOnlyList<FlowProcess> Connected()
    {
        List<FlowProcess> result = [];
        var seen = new HashSet<(int, long, string?)>();
        foreach (var v6 in new[] { false, true })
        {
            var rows = readTable(false, v6);
            var listening = rows.Where(r => r.State == 2).Select(r => (r.ProcessId, r.LocalPort)).ToHashSet();
            foreach (var row in rows)
            {
                // MIB_TCP_STATE_ESTAB.
                if (row.State != 5 || row.ProcessId == 0 || row.RemoteAddress is not { } remote || listening.Contains((row.ProcessId, row.LocalPort))) continue;
                if (IPAddress.IsLoopback(remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote)) continue;
                if (Resolve([row]) is { } process && seen.Add((process.ProcessId, process.StartedAt, process.TaggedService))) result.Add(process);
            }
        }
        return result;
    }

    public sealed class Snapshot
    {
        private readonly FlowAttribution owner;
        private readonly IReadOnlyList<SocketRow>?[] tables = new IReadOnlyList<SocketRow>?[4];
        internal Snapshot(FlowAttribution owner) => this.owner = owner;

        /// <summary>The owner of the connecting TCP socket local→remote; a dual-mode socket appears with IPv4-mapped addresses.</summary>
        public FlowProcess? Tcp(IPEndPoint local, IPEndPoint remote) => owner.Resolve(Candidates(false, local, remote));

        /// <summary>The owner of the UDP socket sending from local, bound to that address or to the wildcard.</summary>
        public FlowProcess? Udp(IPEndPoint local) => owner.Resolve(Candidates(true, local, null));

        /// <summary>The owner of the TCP socket listening on local, bound to that address or to the wildcard: where an inbound attempt was headed.</summary>
        public FlowProcess? Listener(IPEndPoint local) => owner.Resolve(Candidates(false, local, null));

        private List<SocketRow> Candidates(bool udp, IPEndPoint local, IPEndPoint? remote)
        {
            List<SocketRow> rows = [];
            var v6 = local.AddressFamily == AddressFamily.InterNetworkV6;
            Collect(Table(udp, v6), local.Address, remote?.Address);
            // A dual-mode IPv6 socket carries IPv4 traffic under IPv4-mapped addresses or the IPv6 wildcard.
            if (rows.Count == 0 && !v6) Collect(Table(udp, true), local.Address.MapToIPv6(), remote?.Address.MapToIPv6());
            return rows;

            void Collect(IReadOnlyList<SocketRow> table, IPAddress address, IPAddress? peer)
            {
                var exact = false;
                foreach (var row in table)
                {
                    if (row.LocalPort != local.Port || row.ProcessId == 0) continue;
                    if (!udp && remote is not null)
                    {
                        // CLOSED, LISTEN, TIME_WAIT and DELETE_TCB rows cannot be the socket sending this SYN.
                        if (row.State is not (1 or 2 or 11 or 12) && row.LocalAddress.Equals(address) && row.RemotePort == remote.Port && peer!.Equals(row.RemoteAddress)) rows.Add(row);
                        continue;
                    }
                    // Without a peer, a TCP row counts only while it listens (MIB_TCP_STATE_LISTEN), like a bound UDP socket.
                    if (!udp && row.State != 2) continue;
                    var specific = row.LocalAddress.Equals(address);
                    if (!specific && !row.LocalAddress.Equals(IPAddress.Any) && !row.LocalAddress.Equals(IPAddress.IPv6Any)) continue;
                    // A socket bound to the exact address receives instead of wildcard sockets sharing the port.
                    if (specific && !exact) { rows.Clear(); exact = true; }
                    if (specific || !exact) rows.Add(row);
                }
            }
        }

        private IReadOnlyList<SocketRow> Table(bool udp, bool v6)
        {
            var index = (udp ? 2 : 0) + (v6 ? 1 : 0);
            return tables[index] ??= owner.readTable(udp, v6);
        }
    }

    private FlowProcess? Resolve(List<SocketRow> rows)
    {
        if (rows.Count == 0 || rows.Any(r => r.ProcessId != rows[0].ProcessId)) return null;
        var created = rows.Where(r => r.Created > 0).Select(r => r.Created).DefaultIfEmpty(0).Min();
        var process = readProcess(rows[0].ProcessId, created);
        if (process is null) return null;
        lock (gate)
        {
            if (processes.TryGetValue((process.ProcessId, process.StartedAt), out var known)) process = known;
            else
            {
                if (processes.Count >= MaximumCachedProcesses) processes.Clear();
                processes[(process.ProcessId, process.StartedAt)] = process;
            }
        }
        // Several sockets of one process can share a UDP port; they name a service only if each carries the same tag.
        var services = ServiceNames.Of(process.Owner.Sids ?? (IEnumerable<string>)[]);
        string? service = null;
        foreach (var row in rows)
        {
            if (Tagged(row, services, readModule) is not { } name || service is not null && service != name) return process;
            service = name;
        }
        return process with { TaggedService = service };
    }

    /// <summary>
    /// The service whose thread opened the socket, as Windows tags it (what netstat -b shows), when the process runs several
    /// and the tag names one of them; null otherwise. The services are the process's own, from its token or the SCM.
    /// </summary>
    public static string? TaggedService(SocketRow row, IReadOnlyList<string> services) => Tagged(row, services, OwnerModule);

    private static string? Tagged(SocketRow row, IReadOnlyList<string> services, Func<SocketRow, string?> readModule) =>
        services.Count > 1 && readModule(row) is { } module ? services.FirstOrDefault(s => s.Equals(module, StringComparison.OrdinalIgnoreCase)) : null;

    /// <summary>
    /// The module Windows names as a socket's owner from its raw owner-module row: for a socket a service's thread opened,
    /// that service. Null when the row carries no owner information, where Windows could only name the process image, or
    /// when Windows cannot say.
    /// </summary>
    public static string? OwnerModule(SocketRow row)
    {
        var udp = row.RemoteAddress is null; var v6 = row.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6;
        // OwningModuleInfo, sixteen opaque 64-bit values, ends every owner-module row.
        if (row.Entry.Length != Stride(udp, v6) || !row.Entry.Span[^128..].ContainsAnyExcept((byte)0)) return null;
        using var entry = new NativeBuffer(row.Entry.Length);
        Marshal.Copy(row.Entry.ToArray(), 0, entry.Pointer, row.Entry.Length);
        var size = 1024;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var buffer = new NativeBuffer(size);
            var result = (udp, v6) switch
            {
                (false, false) => GetOwnerModuleFromTcpEntry(entry.Pointer, 0, buffer.Pointer, ref size),
                (false, true) => GetOwnerModuleFromTcp6Entry(entry.Pointer, 0, buffer.Pointer, ref size),
                (true, false) => GetOwnerModuleFromUdpEntry(entry.Pointer, 0, buffer.Pointer, ref size),
                _ => GetOwnerModuleFromUdp6Entry(entry.Pointer, 0, buffer.Pointer, ref size)
            };
            // TCPIP_OWNER_MODULE_BASIC_INFO: pointers to the module's name and path, which follow in the same buffer.
            if (result == 0) { var name = Marshal.ReadIntPtr(buffer.Pointer); return name == IntPtr.Zero ? null : Marshal.PtrToStringUni(name); }
            if (result != 122 || size is <= 0 or > 65_536) return null;
        }
        return null;
    }

    /// <summary>Opens the process and reads its identity; null when it exited or started after the socket did (PID reuse).</summary>
    public static FlowProcess? ReadProcess(int processId, long socketCreated)
    {
        if (processId == SystemProcessId)
            return new(processId, 0, IdentitySelectors.SystemApplication, new(IdentitySelectors.SystemApplication, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-18" }, null));
        if (processId <= 0) return null;
        using var process = OpenProcess(0x1000, false, (uint)processId);
        if (process.IsInvalid || !GetProcessTimes(process, out var started, out _, out _, out _)) return null;
        // Both are FILETIMEs from the system clock; a process cannot own a socket created before it started.
        if (socketCreated > 0 && started > socketCreated) return null;
        if (ImageName(process, 0) is not { } image || ImageName(process, 1) is not { } native) return null;
        HashSet<string>? sids = null; string? package = null;
        if (OpenProcessToken(process, 0x8, out var token))
        {
            using (token)
            {
                try { (sids, package) = TokenIdentity(token); }
                catch (Win32Exception) { sids = null; package = null; }
            }
        }
        return new(processId, started, image, new(native.ToLowerInvariant(), sids, package));
    }

    /// <summary>
    /// The user and enabled, grant-capable groups. A restricted token passes WFP's access check only when its restricting
    /// SIDs grant as well, so only SIDs present in both lists count.
    /// </summary>
    private static (HashSet<string> Sids, string? Package) TokenIdentity(SafeAccessTokenHandle token)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var user = Information(token, 1)) sids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(user.Pointer)).Value);
        using (var groups = Information(token, 2)) sids.UnionWith(Groups(groups.Pointer));
        if (IsTokenRestricted(token))
        {
            using var restricted = Information(token, 11);
            sids.IntersectWith(Groups(restricted.Pointer));
        }
        using var container = Information(token, 31);
        var sid = Marshal.ReadIntPtr(container.Pointer);
        return (sids, sid == IntPtr.Zero ? null : new SecurityIdentifier(sid).Value);
    }

    private static List<string> Groups(IntPtr buffer)
    {
        // TOKEN_GROUPS on x64: a DWORD count, padding, then 16-byte SID_AND_ATTRIBUTES entries.
        var count = Marshal.ReadInt32(buffer);
        List<string> sids = [];
        for (var i = 0; i < count; i++)
        {
            var entry = buffer + 8 + i * 16;
            var attributes = (uint)Marshal.ReadInt32(entry, 8);
            // SE_GROUP_ENABLED without SE_GROUP_USE_FOR_DENY_ONLY: deny-only groups never grant.
            if ((attributes & 0x4) != 0 && (attributes & 0x10) == 0) sids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(entry)).Value);
        }
        return sids;
    }

    private static NativeBuffer Information(SafeAccessTokenHandle token, int informationClass)
    {
        GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out var length);
        if (length <= 0 || length > 1024 * 1024) throw new Win32Exception(Marshal.GetLastWin32Error());
        var buffer = new NativeBuffer(length);
        if (!GetTokenInformation(token, informationClass, buffer.Pointer, length, out _)) { var error = Marshal.GetLastWin32Error(); buffer.Dispose(); throw new Win32Exception(error); }
        return buffer;
    }

    private static string? ImageName(SafeProcessHandle process, uint flags)
    {
        var buffer = new char[32_768]; var size = (uint)buffer.Length;
        return QueryFullProcessImageName(process, flags, buffer, ref size) && size > 0 ? new string(buffer, 0, (int)size) : null;
    }

    public static IReadOnlyList<SocketRow> ReadTcp(bool v6) => Parse(Read(true, v6), Stride(false, v6), row => v6
        ? new SocketRow(new(row[..16], BinaryPrimitives.ReadUInt32LittleEndian(row[16..])), Port(row[20..]),
            new(row.Slice(24, 16), BinaryPrimitives.ReadUInt32LittleEndian(row[40..])), Port(row[44..]),
            BinaryPrimitives.ReadInt32LittleEndian(row[48..]), BinaryPrimitives.ReadInt32LittleEndian(row[52..]), BinaryPrimitives.ReadInt64LittleEndian(row[56..]))
        : new SocketRow(new(row.Slice(4, 4)), Port(row[8..]), new(row.Slice(12, 4)), Port(row[16..]),
            BinaryPrimitives.ReadInt32LittleEndian(row), BinaryPrimitives.ReadInt32LittleEndian(row[20..]), BinaryPrimitives.ReadInt64LittleEndian(row[24..])));

    public static IReadOnlyList<SocketRow> ReadUdp(bool v6) => Parse(Read(false, v6), Stride(true, v6), row => v6
        ? new SocketRow(new(row[..16], BinaryPrimitives.ReadUInt32LittleEndian(row[16..])), Port(row[20..]), null, 0, 0,
            BinaryPrimitives.ReadInt32LittleEndian(row[24..]), BinaryPrimitives.ReadInt64LittleEndian(row[32..]))
        : new SocketRow(new(row[..4]), Port(row[4..]), null, 0, 0, BinaryPrimitives.ReadInt32LittleEndian(row[8..]), BinaryPrimitives.ReadInt64LittleEndian(row[16..])));

    // MIB_TCPROW_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE and MIB_UDP6ROW_OWNER_MODULE on x64.
    private static int Stride(bool udp, bool v6) => udp ? v6 ? 176 : 160 : v6 ? 192 : 160;

    private delegate SocketRow RowReader(ReadOnlySpan<byte> row);

    /// <summary>MIB_*TABLE_OWNER_MODULE: a DWORD count, padding to 8 bytes, then fixed-size rows, each kept for its owner information.</summary>
    private static List<SocketRow> Parse(byte[] table, int stride, RowReader read)
    {
        if (table.Length < 8) throw new InvalidDataException("Truncated socket table.");
        var count = BinaryPrimitives.ReadInt32LittleEndian(table);
        if (count < 0 || 8 + (long)count * stride > table.Length) throw new InvalidDataException("Socket table rows exceed the buffer.");
        List<SocketRow> rows = new(count);
        for (var i = 0; i < count; i++)
        {
            var entry = table.AsMemory(8 + i * stride, stride);
            rows.Add(read(entry.Span) with { Entry = entry });
        }
        return rows;
    }

    // dwLocalPort and dwRemotePort hold the port in network order in their first two bytes.
    private static int Port(ReadOnlySpan<byte> value) => value[0] << 8 | value[1];

    private static byte[] Read(bool tcp, bool v6)
    {
        var family = v6 ? 23 : 2; var size = 0;
        // TCP_TABLE_OWNER_MODULE_ALL and UDP_TABLE_OWNER_MODULE carry creation timestamps, unlike the PID tables.
        uint Call(IntPtr buffer) => tcp ? GetExtendedTcpTable(buffer, ref size, false, family, 8, 0) : GetExtendedUdpTable(buffer, ref size, false, family, 2, 0);
        var result = Call(IntPtr.Zero);
        for (var attempt = 0; attempt < 8 && result == 122; attempt++)
        {
            size += 4096;
            using var buffer = new NativeBuffer(size);
            result = Call(buffer.Pointer);
            if (result != 0) continue;
            var bytes = new byte[size]; Marshal.Copy(buffer.Pointer, bytes, 0, size);
            return bytes;
        }
        if (result == 0) return new byte[8];
        throw new Win32Exception(unchecked((int)result));
    }

    private sealed class NativeBuffer(int size) : IDisposable
    {
        public IntPtr Pointer { get; private set; } = Marshal.AllocHGlobal(size);
        public void Dispose() { if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; } }
    }

    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetOwnerModuleFromTcpEntry(IntPtr entry, int infoClass, IntPtr buffer, ref int size);
    [DllImport("iphlpapi.dll")] private static extern uint GetOwnerModuleFromTcp6Entry(IntPtr entry, int infoClass, IntPtr buffer, ref int size);
    [DllImport("iphlpapi.dll")] private static extern uint GetOwnerModuleFromUdpEntry(IntPtr entry, int infoClass, IntPtr buffer, ref int size);
    [DllImport("iphlpapi.dll")] private static extern uint GetOwnerModuleFromUdp6Entry(IntPtr entry, int infoClass, IntPtr buffer, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint id);
    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char[] path, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr buffer, int length, out int returned);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsTokenRestricted(SafeAccessTokenHandle token);
}
