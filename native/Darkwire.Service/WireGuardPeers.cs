using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Service;

/// <summary>
/// What WireGuard counts for a tunnel's servers: the bytes it sent them and received from them, handshakes included, and when
/// a handshake last completed; null before the first.
/// </summary>
internal readonly record struct PeerTraffic(long Sent, long Received, DateTimeOffset? LastHandshake);

/// <summary>
/// Reads a tunnel's peers from the WireGuardNT driver as wg.exe does: the adapter's device, found by the name WireGuard gives
/// it, answers WG_IOCTL_GET with an interface record, then each peer followed by its allowed IPs. A device is opened for one
/// read and closed at once, since an open handle would keep a stopped tunnel's interface from going away.
/// </summary>
internal static class WireGuardPeers
{
    // WG_IOCTL_INTERFACE, WG_IOCTL_PEER and WG_IOCTL_ALLOWED_IP, each aligned to eight bytes, and the fields read from them.
    internal const int InterfaceSize = 80, PeerSize = 136, AllowedIpSize = 24;
    internal const int PeersCountAt = 72, SentAt = 104, ReceivedAt = 112, HandshakeAt = 120, AllowedIpsAt = 128;
    // CTL_CODE(45208, 321, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
    private const uint Get = 0xB098C506;
    private const int FirstSize = 4096, MaximumSize = 1 << 20, MaximumPeers = 1_000, MaximumAllowedIps = 100_000;
    private static readonly Guid NetClass = new("4d36e972-e325-11ce-bfc1-08002be10318"), NetInterface = new("cac88484-7515-4c03-82e6-71a87abac361");
    // DEVPKEY_WG_NAME: the name WireGuard gives its adapter, the tunnel's.
    private static readonly PropertyKey NameKey = new() { Format = new("65726957-7547-7261-644e-616d654b6579"), Id = 3 };
    private static readonly ulong Earliest = (ulong)new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc(), Latest = (ulong)DateTime.MaxValue.ToFileTimeUtc();

    /// <summary>The device path of the present WireGuard adapter by this name; null when there is none.</summary>
    public static string? Device(string name)
    {
        var netClass = NetClass;
        var devices = SetupDiGetClassDevsEx(ref netClass, @"SWD\WireGuard", IntPtr.Zero, 2, IntPtr.Zero, null, IntPtr.Zero);
        if (devices == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var property = new byte[512];
            for (uint index = 0; index < 4096; index++)
            {
                var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
                if (!SetupDiEnumDeviceInfo(devices, index, ref device))
                {
                    if (Marshal.GetLastWin32Error() == 259) return null;
                    continue;
                }
                var key = NameKey;
                if (!SetupDiGetDeviceProperty(devices, ref device, ref key, out var type, property, (uint)property.Length, out var length, 0) || type != 0x12) continue;
                var adapter = Encoding.Unicode.GetString(property, 0, (int)Math.Min(length, (uint)property.Length)).TrimEnd('\0');
                if (!adapter.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                if (SetupDiGetDeviceInstanceId(devices, ref device, null, 0, out var characters) || Marshal.GetLastWin32Error() != 122 || characters is 0 or > 1024) continue;
                var instance = new char[characters];
                if (!SetupDiGetDeviceInstanceId(devices, ref device, instance, characters, out _)) continue;
                var id = new string(instance).TrimEnd('\0');
                var netInterface = NetInterface;
                if (CM_Get_Device_Interface_List_Size(out var size, ref netInterface, id, 0) != 0 || size is < 2 or > 32_768) continue;
                var paths = new char[size];
                if (CM_Get_Device_Interface_List(ref netInterface, id, paths, size, 0) != 0) continue;
                var end = Array.IndexOf(paths, '\0');
                if (end > 0) return new string(paths, 0, end);
            }
            return null;
        }
        finally { SetupDiDestroyDeviceInfoList(devices); }
    }

    /// <summary>What the adapter at this device path counts for its peers; null when it has none.</summary>
    /// <exception cref="Win32Exception">The device could not be opened or read, as once it is gone.</exception>
    /// <exception cref="InvalidDataException">The driver answered in a layout this build does not know.</exception>
    public static PeerTraffic? Read(string device)
    {
        using var handle = CreateFile(device, 0xC0000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var size = FirstSize;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            // The answer holds the tunnel's private key: read into a buffer the collector never moves, so no copy stays behind,
            // and wiped once read.
            var answer = GC.AllocateArray<byte>(size, pinned: true);
            try
            {
                if (DeviceIoControl(handle, Get, IntPtr.Zero, 0, answer, (uint)size, out var returned, IntPtr.Zero))
                    return returned <= size ? Parse(answer.AsSpan(0, (int)returned)) : throw Unknown();
                var error = Marshal.GetLastWin32Error();
                if (error != 234 || returned <= size || returned > MaximumSize) throw new Win32Exception(error);
                size = (int)returned;
            }
            finally { CryptographicOperations.ZeroMemory(answer); }
        }
        throw new InvalidDataException("WireGuard's peers kept growing while they were read.");
    }

    /// <summary>
    /// The peers in an answer to WG_IOCTL_GET: their bytes summed, and the latest handshake. Null without peers. An answer whose
    /// records do not add up to its exact length, or that holds an impossible count or time, is in a layout this build does not know.
    /// </summary>
    internal static PeerTraffic? Parse(ReadOnlySpan<byte> answer)
    {
        if (answer.Length < InterfaceSize) throw Unknown();
        var peers = BinaryPrimitives.ReadUInt32LittleEndian(answer[PeersCountAt..]);
        if (peers > MaximumPeers) throw Unknown();
        long sent = 0, received = 0; ulong latest = 0;
        var offset = InterfaceSize;
        for (var i = 0u; i < peers; i++)
        {
            if (answer.Length - offset < PeerSize) throw Unknown();
            var peer = answer.Slice(offset, PeerSize);
            var tx = BinaryPrimitives.ReadUInt64LittleEndian(peer[SentAt..]); var rx = BinaryPrimitives.ReadUInt64LittleEndian(peer[ReceivedAt..]);
            var handshake = BinaryPrimitives.ReadUInt64LittleEndian(peer[HandshakeAt..]); var allowed = BinaryPrimitives.ReadUInt32LittleEndian(peer[AllowedIpsAt..]);
            if (tx > long.MaxValue / 4 || rx > long.MaxValue / 4 || allowed > MaximumAllowedIps || handshake != 0 && (handshake < Earliest || handshake > Latest)) throw Unknown();
            sent += (long)tx; received += (long)rx; latest = Math.Max(latest, handshake);
            offset += PeerSize + (int)allowed * AllowedIpSize;
            if (offset > answer.Length) throw Unknown();
        }
        if (offset != answer.Length) throw Unknown();
        return peers == 0 ? null : new(sent, received, latest == 0 ? null : new DateTimeOffset(DateTime.FromFileTimeUtc((long)latest)));
    }

    private static InvalidDataException Unknown() => new("WireGuard answered in a layout this build does not know.");

    [StructLayout(LayoutKind.Sequential)] private struct DeviceInfo { public uint Size; public Guid ClassGuid; public uint Instance; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct PropertyKey { public Guid Format; public uint Id; }
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiGetClassDevsExW")] private static extern IntPtr SetupDiGetClassDevsEx(ref Guid classGuid, string enumerator, IntPtr parent, uint flags, IntPtr set, string? machine, IntPtr reserved);
    [DllImport("setupapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref DeviceInfo device);
    [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetDevicePropertyW")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDeviceProperty(IntPtr set, ref DeviceInfo device, ref PropertyKey key, out uint type, byte[] buffer, uint size, out uint required, uint flags);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiGetDeviceInstanceIdW")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref DeviceInfo device, [Out] char[]? id, uint size, out uint required);
    [DllImport("setupapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, EntryPoint = "CM_Get_Device_Interface_List_SizeW")] private static extern uint CM_Get_Device_Interface_List_Size(out uint length, ref Guid interfaceClass, string device, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, EntryPoint = "CM_Get_Device_Interface_ListW")] private static extern uint CM_Get_Device_Interface_List(ref Guid interfaceClass, string device, [Out] char[] paths, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
}
