using System.Net;
using System.Net.Sockets;

namespace Darkwire.Core;

public static class ConnectionDisplay
{
    // PTR names are display metadata. They must never populate Connection.Hostname,
    // which is reserved for names observed in the application's DNS/connection data.
    public static string Destination(string address, string? hostname = "", string? reverseHostname = "")
    {
        if (!string.IsNullOrWhiteSpace(hostname) && !hostname.Equals(address, StringComparison.OrdinalIgnoreCase))
            return $"{hostname} ({address})";
        if (!string.IsNullOrWhiteSpace(reverseHostname) && !reverseHostname.Equals(address, StringComparison.OrdinalIgnoreCase))
            return $"{address} ({reverseHostname})";
        return address;
    }

    public static string Endpoint(string address, int port) =>
        IPAddress.TryParse(address, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}" : $"{address}:{port}";

    public static string Key(Connection c) =>
        $"{c.ProcessId}|{c.Path}|{c.Protocol}|{c.LocalAddress}|{c.LocalPort}|{c.RemoteAddress}|{c.RemotePort}";
}

/// <summary>Preserves direction observed during a TCP handshake while its tuple remains in successive snapshots.</summary>
public sealed class ConnectionDirectionTracker
{
    private Dictionary<string, TrafficDirection> previous = new(StringComparer.Ordinal);
    public List<Connection> Apply(IEnumerable<Connection> snapshot)
    {
        Dictionary<string, TrafficDirection> current = new(StringComparer.Ordinal);
        List<Connection> result = [];
        foreach (var connection in snapshot)
        {
            var key = ConnectionDisplay.Key(connection);
            var direction = connection.Direction;
            if (direction == TrafficDirection.Unknown && previous.TryGetValue(key, out var known)) direction = known;
            if (direction is TrafficDirection.Inbound or TrafficDirection.Outbound) current[key] = direction;
            result.Add(connection with { Direction = direction });
        }
        previous = current;
        return result;
    }
}
