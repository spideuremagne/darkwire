using System.Net;

namespace Darkwire.Vpn;

/// <summary>
/// The interface and source address the tunnel supervisor routes a tunnel's flows through. The supervisor must
/// separately verify that this exact interface belongs to the expected tunnel; an interface name is not proof of a VPN.
/// </summary>
public sealed class TunnelRoute
{
    public TunnelRoute(Guid interfaceId, IPAddress sourceAddress)
    {
        if (interfaceId == Guid.Empty || !VpnConfiguration.IsUnicast(sourceAddress) || sourceAddress.IsIPv6LinkLocal)
            throw new ArgumentException("A tunnel interface ID and unicast source address are required.");
        InterfaceId = interfaceId; SourceAddress = sourceAddress;
    }
    public Guid InterfaceId { get; }
    public IPAddress SourceAddress { get; }
}
