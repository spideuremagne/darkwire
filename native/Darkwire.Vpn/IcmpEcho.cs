using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Darkwire.Vpn;

/// <summary>
/// ICMP echo from user mode through the IP Helper API. Requests carry an explicit source address, so with the strong
/// host model they leave through that address's interface instead of the tunnel routes.
/// </summary>
public static class IcmpEcho
{
    private const int EchoReplySize = 40, Echo6ReplySize = 36;

    /// <summary>The echoed data, or null on timeout, error or an ICMP error reply.</summary>
    public static byte[]? Send(IPAddress source, IPAddress destination, byte[] data, TimeSpan timeout)
    {
        if (source.AddressFamily != destination.AddressFamily || data.Length > 65_500) throw new ArgumentException("Echo endpoints must share a family.");
        var v6 = destination.AddressFamily == AddressFamily.InterNetworkV6;
        var handle = v6 ? Icmp6CreateFile() : IcmpCreateFile();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return null;
        var size = (v6 ? Echo6ReplySize : EchoReplySize) + data.Length + 8 + 576;
        var reply = Marshal.AllocHGlobal(size);
        try
        {
            var milliseconds = (uint)Math.Clamp(timeout.TotalMilliseconds, 1, 10_000);
            if (!v6)
            {
                var count = IcmpSendEcho2Ex(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, Address(source), Address(destination), data, (ushort)data.Length, IntPtr.Zero, reply, (uint)size, milliseconds);
                // ICMP_ECHO_REPLY on x64: Address, Status, RoundTripTime, DataSize at 12, Data pointer at 16.
                if (count == 0 || Marshal.ReadInt32(reply, 4) != 0) return null;
                var length = (ushort)Marshal.ReadInt16(reply, 12); var pointer = Marshal.ReadIntPtr(reply, 16);
                if (length > data.Length || pointer == IntPtr.Zero) return null;
                var echoed = new byte[length]; Marshal.Copy(pointer, echoed, 0, length);
                return echoed;
            }
            var from = SocketAddress6(source); var to = SocketAddress6(destination);
            var replies = Icmp6SendEcho2(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, from, to, data, (ushort)data.Length, IntPtr.Zero, reply, (uint)size, milliseconds);
            // ICMPV6_ECHO_REPLY: a packed 26-byte address, then Status at 28; the echoed data follows the 36-byte structure.
            if (replies == 0 || Marshal.ReadInt32(reply, 28) != 0) return null;
            var copy = new byte[data.Length]; Marshal.Copy(reply + Echo6ReplySize, copy, 0, copy.Length);
            return copy;
        }
        finally { Marshal.FreeHGlobal(reply); IcmpCloseHandle(handle); }
    }

    // IPAddr is the address in network byte order, as in_addr stores it.
    private static uint Address(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes());

    private static byte[] SocketAddress6(IPAddress address)
    {
        // sockaddr_in6: family, port, flow info, address, scope ID.
        var bytes = new byte[28];
        BitConverter.GetBytes((ushort)23).CopyTo(bytes, 0);
        address.GetAddressBytes().CopyTo(bytes, 8);
        BitConverter.GetBytes((uint)address.ScopeId).CopyTo(bytes, 24);
        return bytes;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr IcmpCreateFile();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr Icmp6CreateFile();
    [DllImport("iphlpapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IcmpCloseHandle(IntPtr handle);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2Ex(IntPtr handle, IntPtr eventHandle, IntPtr apcRoutine, IntPtr apcContext, uint source, uint destination,
        byte[] data, ushort size, IntPtr options, IntPtr reply, uint replySize, uint timeout);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint Icmp6SendEcho2(IntPtr handle, IntPtr eventHandle, IntPtr apcRoutine, IntPtr apcContext, byte[] source, byte[] destination,
        byte[] data, ushort size, IntPtr options, IntPtr reply, uint replySize, uint timeout);
}
