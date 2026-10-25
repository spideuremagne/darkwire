using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Darkwire.Vpn;

internal static class LoopbackPeerIdentity
{
    // The accepted socket is service-owned. Match its reverse tuple to the exact pinned child PID.
    public static bool Matches(Socket socket, int processId)
    {
        if (socket.LocalEndPoint is not IPEndPoint local || socket.RemoteEndPoint is not IPEndPoint remote || processId <= 0 ||
            local.AddressFamily != AddressFamily.InterNetwork || remote.AddressFamily != AddressFamily.InterNetwork ||
            !IPAddress.IsLoopback(local.Address) || !IPAddress.IsLoopback(remote.Address)) return false;
        var size = 0; GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (size is < 4 or > 16 * 1024 * 1024) throw new InvalidDataException("Invalid TCP ownership table size.");
            var capacity = size; var data = Marshal.AllocHGlobal(capacity);
            try
            {
                var result = GetExtendedTcpTable(data, ref size, false, 2, 5, 0);
                if (result == 122) continue;
                if (result != 0) throw new Win32Exception((int)result);
                var count = Marshal.ReadInt32(data);
                if (count < 0 || (long)count * 24 + 4 > capacity) throw new InvalidDataException("Invalid TCP ownership table.");
                var source = BinaryPrimitives.ReadInt32LittleEndian(remote.Address.GetAddressBytes());
                var destination = BinaryPrimitives.ReadInt32LittleEndian(local.Address.GetAddressBytes());
                for (var i = 0; i < count; i++)
                {
                    var row = data + 4 + i * 24;
                    if (Marshal.ReadInt32(row) == 5 && Marshal.ReadInt32(row, 20) == processId &&
                        Marshal.ReadInt32(row, 4) == source && Marshal.ReadInt32(row, 12) == destination &&
                        Port(row + 8) == remote.Port && Port(row + 16) == local.Port) return true;
                }
                return false;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        throw new IOException("The TCP ownership table changed during validation.");
    }
    private static int Port(IntPtr value) => Marshal.ReadByte(value) << 8 | Marshal.ReadByte(value, 1);
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, uint family, uint kind, uint reserved);
}
