using Darkwire.Vpn;
using System.Net;
using System.Net.NetworkInformation;

namespace Darkwire.Service;

/// <summary>A backend's tunnel addresses: those its interface holds, and those it shares with the interface that holds them.</summary>
internal static class TunnelAddresses
{
    /// <summary>Whether each address is on the interface or, when shared, still on whichever interface holds it.</summary>
    public static bool Held(NetworkInterface network, IEnumerable<IPAddress> addresses, IReadOnlySet<IPAddress> shared)
    {
        var held = network.GetIPProperties().UnicastAddresses.Select(a => a.Address).ToArray();
        return addresses.All(a => held.Contains(a) || shared.Contains(a) && TunnelNetwork.Holder(a) is not null);
    }

    /// <summary>
    /// Keeps shared addresses usable: the weak host model on their families, which a backend's own interface setup could
    /// undo as it starts, and on this interface any address no interface holds any more, its holder having gone.
    /// </summary>
    public static void Keep(Guid interfaceId, IEnumerable<(IPAddress Address, int Prefix)> shared)
    {
        var addresses = shared.ToArray();
        if (addresses.Length == 0) return;
        var (luid, _) = TunnelNetwork.Interface(interfaceId);
        foreach (var family in addresses.Select(a => a.Address.AddressFamily).Distinct()) TunnelNetwork.ShareAddresses(luid, family);
        foreach (var (address, prefix) in addresses)
            if (TunnelNetwork.Holder(address) is null) TunnelNetwork.AddAddress(luid, address, prefix);
    }
}
