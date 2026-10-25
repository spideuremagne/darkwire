using Darkwire.Vpn;
using System.ComponentModel;
using System.Net;

namespace Darkwire.Service;

/// <summary>Where the physical network reaches an address, and the table that holds host routes to it.</summary>
internal interface IPeerRouteTable
{
    /// <summary>The physical interface and next hop toward the address; null when no physical route reaches it.</summary>
    (ulong Luid, IPAddress NextHop)? Find(IPAddress peer);
    void Add(ulong luid, IPAddress peer, IPAddress nextHop);
    void Delete(ulong luid, IPAddress peer, IPAddress nextHop);
}

internal sealed class NativePeerRouteTable(EgressSelector physical) : IPeerRouteTable
{
    public (ulong Luid, IPAddress NextHop)? Find(IPAddress peer) => physical.Hop(peer) is { } hop ? (hop.Egress.Luid, hop.NextHop) : null;
    public void Add(ulong luid, IPAddress peer, IPAddress nextHop) => TunnelNetwork.AddHostRoute(luid, peer, nextHop);
    public void Delete(ulong luid, IPAddress peer, IPAddress nextHop) => TunnelNetwork.DeleteHostRoute(luid, peer, nextHop);
}

/// <summary>
/// Host routes that carry each VPN backend's own traffic to its servers over the physical network. WireGuard's driver
/// chooses routes from the system table, skipping only its own interface, so Darkwire's capture routes would take its
/// transport into the router, and under a default profile into the very tunnel it carries. A host route outranks the
/// capture routes on prefix length. A server several tunnels share keeps its route until the last of them stops.
/// </summary>
internal sealed class PeerRoutes(IPeerRouteTable table)
{
    private readonly object gate = new();
    private readonly Dictionary<IPAddress, Pin> pins = [];

    /// <summary>Routes the addresses physically until the handle is disposed.</summary>
    public IDisposable Hold(IEnumerable<IPAddress> peers)
    {
        var held = peers.Distinct().ToArray();
        lock (gate)
            foreach (var peer in held)
            {
                if (!pins.TryGetValue(peer, out var pin)) { pins[peer] = pin = new(); Place(peer, pin); }
                pin.Count++;
            }
        return new Release(this, held);
    }

    /// <summary>After an interface change: each address takes the physical route that reaches it now, or keeps trying.</summary>
    public void Refresh()
    {
        lock (gate)
            foreach (var (peer, pin) in pins) { Remove(peer, pin); Place(peer, pin); }
    }

    /// <summary>Removes every route, as the router stops.</summary>
    public void Clear()
    {
        lock (gate)
        {
            foreach (var (peer, pin) in pins) Remove(peer, pin);
            pins.Clear();
        }
    }

    /// <summary>The addresses routed now, and through which interface and next hop.</summary>
    public IReadOnlyList<(IPAddress Peer, ulong Luid, IPAddress NextHop)> Routed()
    {
        lock (gate) return [.. pins.Where(p => p.Value.Route is not null).Select(p => (p.Key, p.Value.Route!.Value.Luid, p.Value.Route.Value.NextHop))];
    }

    private void Drop(IPAddress[] peers)
    {
        lock (gate)
            foreach (var peer in peers)
                if (pins.TryGetValue(peer, out var pin) && --pin.Count <= 0) { Remove(peer, pin); pins.Remove(peer); }
    }

    // Callers hold the gate. An address no physical route reaches now gets its route at the next refresh.
    private void Place(IPAddress peer, Pin pin)
    {
        try
        {
            if (table.Find(peer) is not { } route) return;
            table.Add(route.Luid, peer, route.NextHop);
            pin.Route = route;
        }
        catch (Win32Exception error) { ServiceHost.Log($"The route to VPN server {peer} could not be added: {error.Message}"); }
    }

    private void Remove(IPAddress peer, Pin pin)
    {
        if (pin.Route is not { } route) return;
        pin.Route = null;
        try { table.Delete(route.Luid, peer, route.NextHop); }
        catch (Win32Exception error) { ServiceHost.Log($"The route to VPN server {peer} could not be removed: {error.Message}"); }
    }

    private sealed class Pin
    {
        public int Count;
        public (ulong Luid, IPAddress NextHop)? Route;
    }

    private sealed class Release(PeerRoutes owner, IPAddress[] peers) : IDisposable
    {
        private int released;
        public void Dispose() { if (Interlocked.Exchange(ref released, 1) == 0) owner.Drop(peers); }
    }
}
