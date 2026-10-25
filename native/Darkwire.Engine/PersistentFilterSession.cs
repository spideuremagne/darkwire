using Darkwire.Core;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Darkwire.Engine;

/// <summary>
/// LocalSystem-owned persistent WFP rules. Closing or crashing the service never removes filters.
/// Windows Firewall takeover and recovery are coordinated separately by the service journal.
/// </summary>
public sealed class PersistentFilterSession : IDisposable
{
    public static readonly Guid ProviderKey = new("d2fe8416-72d2-4bd4-b7a8-4e27c77d0e21");
    public static readonly Guid SublayerKey = new("d4fa85fd-50ca-487a-97be-3329495b192d");
    /// <summary>
    /// The startup lock's sublayer, evaluated before every other: a block there is final, so until the service releases it
    /// nothing passes but the lock's own exceptions, which the policy's sublayer still decides.
    /// </summary>
    public static readonly Guid LockSublayerKey = new("7b1f6c2e-4d0a-4f3e-9a51-2c8d6e9f4b13");
    private IntPtr engine, security, subscription;
    // A dynamic session holding the startup lock's release: Windows deletes it, and the lock holds again, when the service stops.
    private IntPtr releaseEngine;
    private readonly object gate = new();
    private readonly ConcurrentQueue<Connection> drops = new();
    private IReadOnlySet<ulong> defaultDenyIds = new HashSet<ulong>();
    // Explicit denies outside the rules, such as a blocklist's or a country's, by filter ID, and the drops reported for each name.
    private IReadOnlyDictionary<ulong, string> namedDenies = new Dictionary<ulong, string>();
    private readonly ConcurrentDictionary<string, long> namedDrops = new(StringComparer.Ordinal);
    // Each named deny's drops as they came, with their addresses, for the record of what Darkwire refused.
    private readonly ConcurrentQueue<(Connection Connection, string Filter)> namedDropDetails = new();
    private ulong probeFilterId;
    private readonly ManualResetEventSlim probeObserved = new();
    private HashSet<(ulong Id, bool BootTime, bool Disabled, bool Lock)> expectedFilters = [];
    // Whether an apply has installed the filters this session expects; until then none is trusted to stay.
    private bool applied;
    // Part of every filter key this session derives (FilterDelta.Keys).
    private readonly byte[] keySecret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    private readonly WfpNative.NetEventCallback callback;
    private readonly Dictionary<string, string> devices = new(StringComparer.OrdinalIgnoreCase);
    public int FilterCount { get; private set; }
    public int BootFilterCount { get; private set; }
    public int LockFilterCount { get; private set; }
    /// <summary>The startup lock is released for as long as this session lives.</summary>
    public bool StartupLockReleased => releaseEngine != IntPtr.Zero;
    /// <summary>The policy and startup lock filters the last integrity check found in WFP; null before the first.</summary>
    public (int Filters, int Lock)? Audited { get; private set; }
    public bool LearningEventsReady => subscription != IntPtr.Zero;
    public string? LearningEventError { get; private set; }

    public PersistentFilterSession()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) throw new PlatformNotSupportedException("64-bit Windows is required.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem) throw new UnauthorizedAccessException("Persistent filtering is owned by the Darkwire LocalSystem service.");
        callback = OnEvent;
        var session = new WfpNative.Session { Key = Guid.NewGuid(), Timeout = 5000, Display = new() { Name = "Darkwire service" } };
        Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine));
        try
        {
            // Other applications and unprivileged users cannot edit these objects. Administrators can still take ownership.
            if (!WfpNative.ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GR;;;BA)", 1, out security, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            Check(WfpNative.FwpmTransactionBegin0(engine, 0));
            try
            {
                var provider = new WfpNative.Provider { Key = ProviderKey, Flags = 1, Display = new() { Name = "Darkwire", Description = "Persistent endpoint network policy" }, ServiceName = "Darkwire" };
                CheckAdd(WfpNative.FwpmProviderAdd0(engine, ref provider, security));
                using var arena = new WfpArena();
                var sublayer = new WfpNative.Sublayer { Key = SublayerKey, Flags = 1, Provider = arena.Allocate(ProviderKey), Weight = 0xF000, Display = new() { Name = "Darkwire policy" } };
                CheckAdd(WfpNative.FwpmSubLayerAdd0(engine, ref sublayer, security));
                var startupLock = new WfpNative.Sublayer { Key = LockSublayerKey, Flags = 1, Provider = arena.Allocate(ProviderKey), Weight = 0xFFFF, Display = new() { Name = "Darkwire startup lock" } };
                CheckAdd(WfpNative.FwpmSubLayerAdd0(engine, ref startupLock, security));
                Check(WfpNative.FwpmTransactionCommit0(engine));
            }
            catch { WfpNative.FwpmTransactionAbort0(engine); throw; }
            foreach (var drive in DriveInfo.GetDrives())
            {
                var name = drive.Name.TrimEnd('\\'); var path = new StringBuilder(32768);
                if (WfpNative.QueryDosDevice(name, path, path.Capacity) != 0) devices[path.ToString()] = name;
            }
            try
            {
                var enabled = new WfpNative.Value { Type = 3, UInt = 1 }; // FWP_UINT32
                Check(WfpNative.FwpmEngineSetOption0(engine, 0, ref enabled)); // collect network events
                var spec = new WfpNative.EventSubscription();
                Check(WfpNative.FwpmNetEventSubscribe1(engine, ref spec, callback, IntPtr.Zero, out subscription));
            }
            catch (Win32Exception error)
            {
                // Learning admission checks readiness separately. Event collection failure
                // must not prevent restoring Windows Firewall and removing our filters.
                subscription = IntPtr.Zero;
                LearningEventError = error.Message;
            }
            var installed = OwnedFilters();
            expectedFilters = installed.Select(f => (f.Id, f.BootTime, f.Disabled, f.Lock)).ToHashSet();
            FilterCount = installed.Count(f => !f.BootTime && !f.Lock); BootFilterCount = installed.Count(f => f.BootTime); LockFilterCount = installed.Count(f => f.Lock);
        }
        catch { Dispose(); throw; }
    }

    /// <summary>Drops Windows reported for each named deny outside the rules, such as a blocklist's, since this session opened.</summary>
    public IReadOnlyDictionary<string, long> DropsByName => namedDrops.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);

    public IReadOnlyList<Connection> DrainBlockedConnections()
    {
        List<Connection> result = [];
        while (result.Count < 1024 && drops.TryDequeue(out var connection)) result.Add(connection);
        return result;
    }

    /// <summary>Drops by named denies since the last drain, each with the deny's name; the program is empty when Windows named none.</summary>
    public IReadOnlyList<(Connection Connection, string Filter)> DrainNamedDrops()
    {
        List<(Connection, string)> result = [];
        while (result.Count < 1024 && namedDropDetails.TryDequeue(out var drop)) result.Add(drop);
        return result;
    }

    /// <summary>The filters the last apply added and deleted; null before the first.</summary>
    public (int Added, int Removed)? LastChanges { get; private set; }

    /// <summary>
    /// Installs the plan in one transaction, changing only the filters that differ from those installed (<see cref="FilterDelta"/>).
    /// Conditions are resolved first, application IDs included, as WFP will hold them, so a filter whose resolution changed is
    /// replaced too. The first apply after the service opens WFP replaces every filter, under new keys, as WFP may have changed
    /// meanwhile; later ones keep only filters this session installed or kept.
    /// </summary>
    public void Apply(FilterPlan plan)
    {
        var registrations = WfpInstallationPlan.Build(plan);
        Dictionary<string, byte[]> resolved = [];
        var conditions = registrations.Select(r => WfpConditions.Resolve(r.Filter, resolved)).ToArray();
        var keys = FilterDelta.Keys([.. registrations.Select((r, i) => (r, conditions[i]))], keySecret);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(engine == IntPtr.Zero, this);
            Check(WfpNative.FwpmTransactionBegin0(engine, 0));
            try
            {
                // Snapshot and mutations share the transaction, including disabled/boot-time filters.
                HashSet<ulong> trusted = applied ? [.. expectedFilters.Select(f => f.Id)] : [];
                var (delete, add, kept) = FilterDelta.Between(OwnedFilters(), [.. registrations.Select((r, i) => (keys[i], r.BootTime, r.Lock))], trusted.Contains);
                foreach (var id in delete) Check(WfpNative.FwpmFilterDeleteById0(engine, id));
                var ids = new ulong[registrations.Count];
                foreach (var (index, id) in kept) ids[index] = id;
                foreach (var index in add) ids[index] = AddRegistration(engine, security, registrations[index], ProviderKey, key: keys[index], conditions: conditions[index]);
                var defaults = new HashSet<ulong>();
                var named = new Dictionary<ulong, string>();
                var expected = new HashSet<(ulong, bool, bool, bool)>();
                for (var index = 0; index < registrations.Count; index++)
                {
                    var registration = registrations[index]; var filter = registration.Filter; var id = ids[index];
                    expected.Add((id, registration.BootTime, false, registration.Lock));
                    // Default denies and, in router mode, the leak guard both mean "no rule allowed this yet": both feed learning.
                    // What the startup lock holds back is not a question for the user.
                    if (registration.BootTime || registration.Lock || filter.RuleId is not null || filter.Action != RuleAction.Deny) continue;
                    if (filter.Weight is FilterCompiler.DefaultWeight or FilterCompiler.LeakGuardWeight) defaults.Add(id);
                    else if (filter.Weight == FilterCompiler.DenyWeight) named[id] = filter.Name;
                }
                Check(WfpNative.FwpmTransactionCommit0(engine));
                expectedFilters = expected; LastChanges = (add.Count, delete.Count); applied = true;
                Volatile.Write(ref defaultDenyIds, defaults); Volatile.Write(ref namedDenies, named); FilterCount = plan.Filters.Count;
                BootFilterCount = registrations.Count(r => r.BootTime); LockFilterCount = registrations.Count(r => r.Lock);
            }
            catch { WfpNative.FwpmTransactionAbort0(engine); throw; }
        }
    }

    public static void ValidatePlan(FilterPlan plan)
    {
        if (!plan.CanApply) throw new InvalidOperationException(string.Join(Environment.NewLine, plan.Errors));
        if (plan.Filters.Count > FilterCompiler.MaximumFilters) throw new InvalidDataException("Too many filters.");
        if (plan.StartupLock.Count > 256) throw new InvalidDataException("Too many startup lock filters.");
        foreach (var f in plan.Filters.Concat(plan.StartupLock))
        {
            if (f.Direction is not (TrafficDirection.Inbound or TrafficDirection.Outbound) || !Enum.IsDefined(f.Action)) throw new InvalidDataException("Invalid native filter action or direction.");
            if (f.LocalPort is { } local && local.Low > local.High || f.RemotePort is { } remote && remote.Low > remote.High) throw new InvalidDataException("Invalid native port range.");
            if ((f.LocalPort is not null || f.RemotePort is not null) && f.Protocol is not (6 or 17)) throw new InvalidDataException("Native port selectors require TCP or UDP.");
            if (f.RemoteNetwork is not null && (!IpNetwork.TryParse(f.RemoteNetwork, out var net) || (net.Address.GetAddressBytes().Length == 16) != f.Ipv6)) throw new InvalidDataException("Invalid native filter network.");
            if (f.LocalNetwork is not null && (!IpNetwork.TryParse(f.LocalNetwork, out var localNet) || (localNet.Address.GetAddressBytes().Length == 16) != f.Ipv6)) throw new InvalidDataException("Invalid native local network.");
            if (f.Protocol == 1 && f.Ipv6 || f.Protocol == 58 && !f.Ipv6) throw new InvalidDataException("ICMP protocol and address family disagree.");
            if (f.IcmpType.HasValue || f.IcmpCode.HasValue)
                if (f.Protocol is not (1 or 58) || !f.IcmpType.HasValue || f.LocalPort is not null || f.RemotePort is not null)
                    throw new InvalidDataException("Invalid native ICMP scope.");
            if (f.LocalInterfaceLuid == 0) throw new InvalidDataException("An interface scope requires a nonzero LUID.");
            if (f.CurrentProfileId is 0 or > 3) throw new InvalidDataException("Invalid native network profile.");
            if (f.Service is { } service && (RuleValidator.IsAny(service) || !IdentitySelectors.ValidService(service)) ||
                f.Users is { } users && (RuleValidator.IsAny(users) || !IdentitySelectors.ValidUsers(users)) ||
                f.Package is { } package && (RuleValidator.IsAny(package) || !IdentitySelectors.ValidPackage(package)))
                throw new InvalidDataException("Invalid native identity scope.");
            if (f.RequiredFlags == 0) throw new InvalidDataException("A flag condition requires at least one flag.");
        }
    }

    /// <summary>Only call after Windows Firewall profile restoration has succeeded.</summary>
    public void RemoveOwnedFilters() => Apply(new([], []));

    /// <summary>
    /// Lifts the startup lock: a dynamic session permits everything in the lock's sublayer above its block, leaving every
    /// decision to the policy beneath. Windows deletes the permits with the session, when this object is disposed or the
    /// service exits however it does, and the lock holds again until the next release.
    /// </summary>
    public void ReleaseStartupLock()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(engine == IntPtr.Zero, this);
            if (releaseEngine != IntPtr.Zero) return;
            var session = new WfpNative.Session { Key = Guid.NewGuid(), Flags = 1, Timeout = 5000, Display = new() { Name = "Darkwire startup release" } };
            Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out var handle));
            try
            {
                Check(WfpNative.FwpmTransactionBegin0(handle, 0));
                try
                {
                    // No provider: these are not Darkwire's persistent filters, which every apply reconciles with its plan.
                    foreach (var ipv6 in new[] { false, true })
                    foreach (var direction in new[] { TrafficDirection.Inbound, TrafficDirection.Outbound })
                        AddRegistration(handle, security, new(new("Darkwire startup release", null, ipv6, direction, RuleAction.Allow, FilterCompiler.LockReleaseWeight),
                            WfpInstallationPlan.AuthorizationLayer(ipv6, direction), 0, Lock: true), null);
                    Check(WfpNative.FwpmTransactionCommit0(handle));
                }
                catch { WfpNative.FwpmTransactionAbort0(handle); throw; }
            }
            catch { WfpNative.FwpmEngineClose0(handle); throw; }
            releaseEngine = handle;
        }
    }

    /// <summary>
    /// Proves that blocked-connection events reach this subscription: a dynamic filter blocks one UDP datagram from this
    /// process to TEST-NET-1 (192.0.2.1:9), and its drop event must arrive within the timeout. The filter vanishes with its session.
    /// </summary>
    public bool ProbeLearningEvents(TimeSpan timeout)
    {
        if (subscription == IntPtr.Zero || Environment.ProcessPath is not { } self) return false;
        var session = new WfpNative.Session { Key = Guid.NewGuid(), Flags = 1, Timeout = 5000, Display = new() { Name = "Darkwire learning probe" } };
        Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out var probeEngine));
        try
        {
            var filter = new NativeFilter("Darkwire learning probe", null, false, TrafficDirection.Outbound, RuleAction.Deny, FilterCompiler.DenyWeight + 50, self, 17,
                RemotePort: new(9, 9), RemoteNetwork: "192.0.2.1/32");
            probeObserved.Reset();
            Volatile.Write(ref probeFilterId, AddRegistration(probeEngine, security, new(filter, WfpNative.ConnectV4, 0), ProviderKey));
            using (var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp))
            {
                try { socket.SendTo(new byte[1], new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9)); }
                catch (System.Net.Sockets.SocketException) { /* The block itself may surface as an access error. */ }
            }
            return probeObserved.Wait(timeout);
        }
        finally { Volatile.Write(ref probeFilterId, 0UL); WfpNative.FwpmEngineClose0(probeEngine); }
    }

    public void VerifyIntegrity()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(engine == IntPtr.Zero, this);
            var owned = OwnedFilters();
            Audited = (owned.Count(f => !f.BootTime && !f.Lock), owned.Count(f => f.Lock));
            if (!expectedFilters.SetEquals(owned.Select(f => (f.Id, f.BootTime, f.Disabled, f.Lock))))
                throw new InvalidDataException("The installed Darkwire filter set changed outside the service.");
        }
    }

    private List<(ulong Id, Guid Key, bool BootTime, bool Disabled, bool Lock)> OwnedFilters()
    {
        List<(ulong Id, Guid Key, bool BootTime, bool Disabled, bool Lock)> result = [];
        // NULL means all filters, including startup and disabled filters (FwpmFilterCreateEnumHandle0).
        Check(WfpNative.FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out var enumeration));
        try
        {
            while (true)
            {
                Check(WfpNative.FwpmFilterEnum0(engine, enumeration, 512, out var entries, out var count));
                try
                {
                    for (var i = 0; i < count; i++)
                    {
                        var filter = Marshal.PtrToStructure<WfpNative.Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                        if (filter.Provider != IntPtr.Zero && Marshal.PtrToStructure<Guid>(filter.Provider) == ProviderKey && (filter.Sublayer == SublayerKey || filter.Sublayer == LockSublayerKey))
                            result.Add((filter.Id, filter.Key, (filter.Flags & 2) != 0, (filter.Flags & 0x20) != 0, filter.Sublayer == LockSublayerKey));
                    }
                }
                finally { WfpNative.FwpmFreeMemory0(ref entries); }
                if (count < 512) break;
            }
        }
        finally { WfpNative.FwpmFilterDestroyEnumHandle0(engine, enumeration); }
        return result;
    }

    /// <param name="key">The filter's key; a random one when null, as for filters that live only as long as their session.</param>
    /// <param name="conditions">The registration's conditions already resolved; resolved here when null.</param>
    internal static ulong AddRegistration(IntPtr engine, IntPtr security, WfpRegistration registration, Guid? providerKey, Dictionary<string, byte[]>? resolved = null,
        Guid? key = null, IReadOnlyList<ConditionSpec>? conditions = null)
    {
        var spec = registration.Filter;
        using var arena = new WfpArena();
        var (native, count) = WfpConditions.ToNative(conditions ?? WfpConditions.Resolve(spec, resolved), arena);
        var filter = new WfpNative.Filter
        {
            Key = key ?? Guid.NewGuid(), Flags = registration.Flags, Provider = providerKey is { } provider ? arena.Allocate(provider) : IntPtr.Zero,
            Sublayer = registration.Lock ? LockSublayerKey : SublayerKey,
            Display = new() { Name = spec.Name },
            Layer = registration.Layer,
            Weight = new() { Type = 4, Pointer = arena.Allocate(spec.Weight) },
            ConditionCount = count, Conditions = native,
            Action = new() { Type = spec.Action == RuleAction.Deny ? 0x1001u : 0x1002u }
        };
        Check(WfpNative.FwpmFilterAdd0(engine, ref filter, security, out var id)); return id;
    }

    private void OnEvent(IntPtr context, IntPtr value)
    {
        try
        {
            // FWPM_NET_EVENT2 / FWPM_NET_EVENT_HEADER2, Windows SDK 10.0.26100.0 x64 layouts.
            if (value == IntPtr.Zero || Marshal.ReadInt32(value, 104) != 3) return; // CLASSIFY_DROP
            var drop = Marshal.ReadIntPtr(value, 112); if (drop == IntPtr.Zero) return;
            var filterId = unchecked((ulong)Marshal.ReadInt64(drop));
            if (filterId != 0 && filterId == Volatile.Read(ref probeFilterId)) { probeObserved.Set(); return; }
            if (Volatile.Read(ref namedDenies).TryGetValue(filterId, out var name))
            {
                namedDrops.AddOrUpdate(name, 1, (_, count) => count + 1);
                if (namedDropDetails.Count < 1024 && Dropped(value, drop, application: false) is { } refused) namedDropDetails.Enqueue((refused, name));
                return;
            }
            if (!Volatile.Read(ref defaultDenyIds).Contains(filterId)) return;
            if (Dropped(value, drop, application: true) is { } connection && drops.Count < 1024) drops.Enqueue(connection);
        }
        catch { /* A native callback must never unwind into BFE. Missing metadata stays blocked. */ }
    }

    /// <summary>
    /// The attempt a drop event describes: its program, addresses, ports, protocol and direction; null when the event lacks
    /// them. Without <paramref name="application"/> a drop Windows named no program for, such as a scan of a closed port, has an empty one.
    /// </summary>
    private Connection? Dropped(IntPtr value, IntPtr drop, bool application)
    {
        var flags = (uint)Marshal.ReadInt32(value, 8);
        var required = 0x01u | 0x04 | 0x08 | 0x10 | 0x20 | (application ? 0x100u : 0);
        if ((flags & required) != required) return null;
        var version = Marshal.ReadInt32(value, 12); if (version is not (0 or 1)) return null;
        var path = "";
        if ((flags & 0x100) != 0)
        {
            var appBlob = Marshal.PtrToStructure<WfpNative.Blob>(value + 64);
            if (appBlob.Data != IntPtr.Zero && appBlob.Size is >= 2 and <= 65536 && appBlob.Size % 2 == 0)
            {
                path = Marshal.PtrToStringUni(appBlob.Data, (int)appBlob.Size / 2)?.TrimEnd('\0') ?? "";
                foreach (var device in devices.OrderByDescending(p => p.Key.Length))
                    if (path.StartsWith(device.Key + "\\", StringComparison.OrdinalIgnoreCase)) { path = device.Value + path[device.Key.Length..]; break; }
            }
        }
        if (application && (!Path.IsPathFullyQualified(path) || !File.Exists(path))) return null;
        var direction = Marshal.ReadInt32(drop, 24) switch { 0x3901 => TrafficDirection.Outbound, 0x3900 => TrafficDirection.Inbound, _ => TrafficDirection.Unknown };
        if (direction == TrafficDirection.Unknown) return null;
        var protocol = Marshal.ReadByte(value, 16) switch { 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", _ => "" };
        if (protocol.Length == 0) return null;
        return new Connection(path.Length > 0 ? Path.GetFileNameWithoutExtension(path) : "", path, 0, Address(value + 36, version),
            unchecked((ushort)Marshal.ReadInt16(value, 54)), unchecked((ushort)Marshal.ReadInt16(value, 52)), protocol, direction,
            LocalAddress: Address(value + 20, version), State: application ? "Blocked pending decision" : "Blocked");
    }
    private static string Address(IntPtr address, int version)
    {
        var bytes = new byte[version == 0 ? 4 : 16]; Marshal.Copy(address, bytes, 0, bytes.Length);
        if (version == 0) System.Array.Reverse(bytes); return new IPAddress(bytes).ToString();
    }
    private static void CheckAdd(uint error) { if (error != 0x80320009) Check(error); } // FWP_E_ALREADY_EXISTS
    private static void Check(uint error) { if (error != 0) throw new Win32Exception(unchecked((int)error), $"WFP error 0x{error:X8}"); }
    public void Dispose()
    {
        lock (gate)
        {
            if (subscription != IntPtr.Zero) { WfpNative.FwpmNetEventUnsubscribe0(engine, subscription); subscription = IntPtr.Zero; }
            if (releaseEngine != IntPtr.Zero) { WfpNative.FwpmEngineClose0(releaseEngine); releaseEngine = IntPtr.Zero; }
            if (engine != IntPtr.Zero) { WfpNative.FwpmEngineClose0(engine); engine = IntPtr.Zero; }
            if (security != IntPtr.Zero) { WfpNative.LocalFree(security); security = IntPtr.Zero; }
        }
        GC.KeepAlive(callback); GC.SuppressFinalize(this);
    }
}
