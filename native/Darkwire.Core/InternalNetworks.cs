using System.Net;

namespace Darkwire.Core;

/// <summary>
/// Addresses of the PC's own networks rather than the internet: private (RFC 1918), link-local and unique local unicast, and
/// multicast and broadcast, which never leave the local network. Loopback keeps its own core filters.
/// </summary>
public static class InternalNetworks
{
    /// <summary>Internal hosts: what a peer on the local network connects from, and what VPN tunnels leave alone by default.</summary>
    public static IReadOnlyList<string> Unicast { get; } = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"];
    /// <summary>Multicast and broadcast destinations.</summary>
    public static IReadOnlyList<string> Groups { get; } = ["224.0.0.0/4", "255.255.255.255/32", "ff00::/8"];

    private static readonly IpNetwork[] unicast = [.. Unicast.Select(Parse)], groups = [.. Groups.Select(Parse)];

    public static bool IsUnicast(IPAddress address) => unicast.Any(n => n.Contains(Unmapped(address)));
    public static bool IsGroup(IPAddress address) => groups.Any(n => n.Contains(Unmapped(address)));

    /// <summary>
    /// What internal access decides for a connection: null when it isn't internal traffic or rules decide it. Inbound is
    /// allowed only on networks Windows calls private or domain, since on a public network strangers share its private
    /// addresses; outbound includes multicast and broadcast.
    /// </summary>
    public static DecisionKind? Decide(AppState state, Connection connection)
    {
        if (state.InternalNetworks == InternalAccess.Rules || !IPAddress.TryParse(connection.RemoteAddress, out var remote)) return null;
        var inbound = connection.Direction == TrafficDirection.Inbound;
        if (!IsUnicast(remote) && (inbound || !IsGroup(remote))) return null;
        if (state.InternalNetworks == InternalAccess.Block) return DecisionKind.Deny;
        return !inbound || connection.Location is "Private" or "Domain" ? DecisionKind.Allow : null;
    }

    private static IPAddress Unmapped(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    private static IpNetwork Parse(string network) => IpNetwork.TryParse(network, out var parsed) ? parsed : throw new InvalidDataException("Invalid internal network.");
}
