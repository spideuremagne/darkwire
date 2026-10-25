using Darkwire.Core;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Darkwire.Engine;

public interface INetworkEnvironment { NetworkSnapshot Capture(); }

/// <summary>
/// Reads the interface data that Windows uses for LocalSubnet, DNS, DHCP, WINS and DefaultGateway rule keywords.
/// Excluded interfaces (Darkwire's own tunnel) are neither keyword sources nor egress candidates.
/// </summary>
public sealed class NetworkEnvironment(IReadOnlyCollection<Guid>? excluded = null) : INetworkEnvironment
{
    public NetworkSnapshot Capture()
    {
        List<NetworkInterfaceSnapshot> interfaces = [];
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.OperationalStatus != OperationalStatus.Up || !Guid.TryParse(nic.Id, out var id)) continue;
            if (excluded?.Contains(id) == true) continue;
            if (ConvertInterfaceGuidToLuid(ref id, out var luid) != 0 || luid == 0) continue;
            IPInterfaceProperties properties;
            try { properties = nic.GetIPProperties(); }
            catch (NetworkInformationException) { continue; }
            // A zero-length prefix would make "local subnet" mean every address.
            var subnets = properties.UnicastAddresses.Where(a => a.PrefixLength > 0)
                .Select(a => AddressKeywords.Canonical(new IpNetwork(Unscoped(a.Address), a.PrefixLength))).Distinct().ToArray();
            interfaces.Add(new(luid, subnets, Hosts(properties.DnsAddresses), Hosts(properties.GatewayAddresses.Select(g => g.Address)),
                Hosts(properties.DhcpServerAddresses), Hosts(properties.WinsServersAddresses)) { DnsSuffix = Suffix(properties.DnsSuffix) });
        }
        string domain;
        try { domain = Suffix(IPGlobalProperties.GetIPGlobalProperties().DomainName); }
        catch (NetworkInformationException) { domain = ""; }
        return new(interfaces) { Domain = domain };
    }

    /// <summary>A DNS suffix as Windows reports it, when it is a DNS name; empty otherwise.</summary>
    private static string Suffix(string? value) => BlocklistNames.Normalize(value ?? "") ?? (value is { Length: > 0 } single && Uri.CheckHostName(single) == UriHostNameType.Dns && !single.Contains('.') ? single.ToLowerInvariant() : "");

    private static IPAddress Unscoped(IPAddress address) => new(address.GetAddressBytes());
    private static string[] Hosts(IEnumerable<IPAddress> addresses) => addresses
        .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
        .Select(a => Unscoped(a) + (a.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128")).Distinct().ToArray();
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceGuidToLuid(ref Guid id, out ulong luid);
}
