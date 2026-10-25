using System.Net;

namespace Darkwire.Core;

/// <summary>
/// Darkwire's own programs, and the connection router's sockets, in the TCP table. The router carries each routed
/// connection on three sockets: the application's, from Darkwire's adapter to the destination; the service's, from the
/// egress to the same destination; and the service's accepted end of the translated connection, whose peer is one of the
/// router's own addresses. Only the application's is the connection; the service's two are how it travels.
/// </summary>
/// <param name="serviceDirectory">The service's folder, which holds the service and the backends it runs.</param>
public sealed class OwnConnections(string serviceDirectory)
{
    /// <summary>Darkwire's adapter networks, which hold the router's own addresses.</summary>
    public static IReadOnlyList<string> TunnelNetworks { get; } = ["198.18.0.0/15", "fd5a:9c33:21e7::/64"];

    /// <summary>The installed service's folder, which only administrators can change.</summary>
    public static string InstalledServiceDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire", "Service");

    private readonly string service = Path.Combine(serviceDirectory, "Darkwire.Service.exe");
    private readonly string[] programs =
    [
        Path.Combine(serviceDirectory, "Darkwire.Service.exe"), Path.Combine(serviceDirectory, "Backends", "DnsCrypt", "dnscrypt-proxy.exe"),
        Path.Combine(serviceDirectory, "Backends", "WireGuard", "wireguard.exe")
    ];
    private static readonly IpNetwork[] tunnel = [.. TunnelNetworks.Select(n => { IpNetwork.TryParse(n, out var network); return network; })];

    /// <summary>Whether one of Darkwire's own programs made the connection: its service, its DNS proxy or a VPN backend.</summary>
    public bool Own(Connection connection) => programs.Contains(connection.Path, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The connections programs made, without the relay's sockets: a service socket to a destination a program connects to
    /// from Darkwire's adapter is taken for that connection's relay. A routed connection, one from the adapter that the relay
    /// carries or that reaches the router itself, is outbound, as are Darkwire's own, which only dial out, loopback aside.
    /// </summary>
    public List<Connection> Made(IEnumerable<Connection> snapshot)
    {
        var all = snapshot.ToArray();
        bool Relays(Connection c) => c.Path.Equals(service, StringComparison.OrdinalIgnoreCase);
        static (string, int) Remote(Connection c) => (c.RemoteAddress, c.RemotePort);
        var fromAdapter = all.Where(c => !Relays(c) && OnAdapter(c.LocalAddress)).Select(Remote).ToHashSet();
        var relayed = all.Where(c => Relays(c) && !OnAdapter(c.LocalAddress) && !OnAdapter(c.RemoteAddress)).Select(Remote).ToHashSet();
        List<Connection> made = [];
        foreach (var c in all)
        {
            if (Relays(c) && (OnAdapter(c.LocalAddress) || OnAdapter(c.RemoteAddress) || fromAdapter.Contains(Remote(c)))) continue;
            var routed = !Relays(c) && OnAdapter(c.LocalAddress) && (relayed.Contains(Remote(c)) || OnAdapter(c.RemoteAddress));
            var outbound = routed || Own(c) && !(IPAddress.TryParse(c.RemoteAddress, out var remote) && IPAddress.IsLoopback(remote));
            made.Add(c.Direction == TrafficDirection.Unknown && outbound ? c with { Direction = TrafficDirection.Outbound } : c);
        }
        return made;
    }

    /// <summary>Whether an address is in Darkwire's adapter networks: the application's end of a routed connection, or the router's own.</summary>
    public static bool OnAdapter(string address) =>
        IPAddress.TryParse(address, out var parsed) && tunnel.Any(n => n.Contains(parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed));
}
