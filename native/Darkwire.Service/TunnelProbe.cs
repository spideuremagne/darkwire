using Darkwire.Vpn;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Service;

/// <summary>Checks a tunnel by asking a DNS server through it, from a socket pinned to the tunnel as the relay pins its own.</summary>
internal static class TunnelProbe
{
    /// <summary>
    /// Asks the server for the root zone's name servers, which tells it nothing about this PC, and returns the round trip once
    /// an answer to that question comes back in time, or once the server's host refuses it, which shows the tunnel carries
    /// traffic both ways; null when nothing comes back.
    /// </summary>
    public static TimeSpan? Ask(Egress route, IPEndPoint server, TimeSpan timeout)
    {
        var v4 = route.Source.AddressFamily == AddressFamily.InterNetwork;
        using var socket = new Socket(route.Source.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        // IP_UNICAST_IF: IPv4 takes the interface index in network byte order, IPv6 in host order.
        socket.SetSocketOption(v4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, (SocketOptionName)31, v4 ? IPAddress.HostToNetworkOrder((int)route.Index) : (int)route.Index);
        socket.Bind(new IPEndPoint(route.Source, 0));
        var id = (ushort)Random.Shared.Next(1, 65_536);
        // Header with recursion desired and one question: the root, NS, IN.
        byte[] query = [(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
        var started = Stopwatch.GetTimestamp();
        socket.SendTo(query, server);
        var buffer = new byte[4096];
        while (true)
        {
            var left = timeout - Stopwatch.GetElapsedTime(started);
            if (left <= TimeSpan.Zero) return null;
            socket.ReceiveTimeout = Math.Max(1, (int)Math.Ceiling(left.TotalMilliseconds));
            EndPoint from = new IPEndPoint(v4 ? IPAddress.Any : IPAddress.IPv6Any, 0);
            int received;
            try { received = socket.ReceiveFrom(buffer, ref from); }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.TimedOut) { return null; }
            // An ICMP port unreachable from the server's host came back through the tunnel.
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionReset) { return Stopwatch.GetElapsedTime(started); }
            if (received >= 12 && buffer[0] == (byte)(id >> 8) && buffer[1] == (byte)id && (buffer[2] & 0x80) != 0 && from is IPEndPoint answering && answering.Address.Equals(server.Address))
                return Stopwatch.GetElapsedTime(started);
        }
    }
}
