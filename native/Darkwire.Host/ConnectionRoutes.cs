using System.Net;
using Darkwire.Engine;

namespace Darkwire.Host;

/// <summary>
/// The route each connection in the TCP table takes. Darkwire's router reports the connections it carries by the
/// application's socket on its adapter, each with the VPN profile whose tunnel it takes or none; a socket on a running
/// tunnel's own address, such as one of Darkwire's downloads through it, goes through that tunnel; loopback goes nowhere;
/// everything else takes the Windows route, which includes a system VPN.
/// </summary>
public sealed class ConnectionRoutes
{
    public const string WindowsRoute = "Windows route", Loopback = "Loopback", Unknown = "—";
    public static readonly ConnectionRoutes None = new([], [], _ => "");
    private readonly Dictionary<(string, int, string, int), Guid?> routed = [];
    private readonly Dictionary<string, Guid> tunnels = new(StringComparer.Ordinal);
    private readonly Func<Guid, string> name;

    /// <param name="routed">What the router reports; empty while Darkwire routes nothing.</param>
    /// <param name="tunnels">The VPN tunnels the router runs, with their addresses.</param>
    /// <param name="name">A profile's name.</param>
    public ConnectionRoutes(IEnumerable<RoutedConnection> routed, IEnumerable<TunnelStatus> tunnels, Func<Guid, string> name)
    {
        this.name = name;
        foreach (var c in routed) this.routed[(Address(c.LocalAddress), c.LocalPort, Address(c.RemoteAddress), c.RemotePort)] = c.ProfileId;
        foreach (var tunnel in tunnels.Where(t => t.State == "Up"))
        foreach (var address in tunnel.Addresses ?? [])
            this.tunnels[Address(address.Split('/')[0])] = tunnel.ProfileId;
    }

    /// <summary>The VPN profile whose tunnel carries the connection, the Windows route, loopback, or unknown for one from Darkwire's adapter the router does not report.</summary>
    public string Of(Connection connection)
    {
        if (routed.TryGetValue((Address(connection.LocalAddress), connection.LocalPort, Address(connection.RemoteAddress), connection.RemotePort), out var profile))
            return profile is { } through ? name(through) : WindowsRoute;
        if (IPAddress.TryParse(connection.RemoteAddress, out var remote) && IPAddress.IsLoopback(remote)) return Loopback;
        if (tunnels.TryGetValue(Address(connection.LocalAddress), out var tunnel)) return name(tunnel);
        // Opened or closed between the router's report and the snapshot.
        return OwnConnections.OnAdapter(connection.LocalAddress) ? Unknown : WindowsRoute;
    }

    private static string Address(string text) =>
        IPAddress.TryParse(text, out var parsed) ? (parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed).ToString() : text;
}
