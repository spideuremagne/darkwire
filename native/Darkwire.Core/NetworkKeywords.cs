namespace Darkwire.Core;

public sealed record NetworkInterfaceSnapshot(ulong Luid, IReadOnlyList<string> Subnets, IReadOnlyList<string> DnsServers,
    IReadOnlyList<string> Gateways, IReadOnlyList<string> DhcpServers, IReadOnlyList<string> WinsServers)
{
    /// <summary>The DNS suffix the network hands out with the interface's address, such as home or corp.example.com; empty for none.</summary>
    public string DnsSuffix { get; init; } = "";
}

/// <summary>Interface addresses used to resolve Windows dynamic address keywords when policy is compiled.</summary>
public sealed record NetworkSnapshot(IReadOnlyList<NetworkInterfaceSnapshot> Interfaces)
{
    public static readonly NetworkSnapshot Empty = new([]);
    /// <summary>The domain this PC belongs to; empty for none.</summary>
    public string Domain { get; init; } = "";
    public string Fingerprint => Domain + "/" + string.Join(';', Interfaces.OrderBy(i => i.Luid).Select(i => i.Luid + ":" + i.DnsSuffix + ":" + string.Join('|',
        new[] { i.Subnets, i.DnsServers, i.Gateways, i.DhcpServers, i.WinsServers }.Select(list => string.Join(',', list.Order(StringComparer.Ordinal))))));

    /// <summary>The domains this PC's networks and its own domain name, whose names the local networks answer.</summary>
    public IReadOnlyList<string> LocalDomains => [.. Interfaces.Select(i => i.DnsSuffix).Append(Domain).Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)];

    /// <summary>
    /// The local networks: each remaining interface's on-link subnets, as CIDRs. Host-sized subnets, such as a VPN tunnel's
    /// own address, link-local space and Darkwire's tunnel networks are none.
    /// </summary>
    /// <param name="excluded">Interfaces that are not local networks, such as VPN tunnels.</param>
    public IReadOnlyList<string> LocalNetworks(Func<ulong, bool> excluded)
    {
        var local = new List<string>();
        foreach (var nic in Interfaces.Where(i => !excluded(i.Luid)))
        foreach (var subnet in nic.Subnets)
        {
            if (!IpNetwork.TryParse(subnet, out var network)) continue;
            var bits = network.Address.GetAddressBytes().Length * 8;
            if (network.Prefix < 1 || network.Prefix > bits - 2 || AddressRanges.Within(network, NotLocal)) continue;
            var canonical = AddressKeywords.Canonical(network);
            if (!local.Contains(canonical)) local.Add(canonical);
        }
        return local;
    }

    // Unspecified, loopback, link-local, multicast and reserved space, and Darkwire's own tunnel networks.
    private static readonly string[] NotLocal = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "198.18.0.0/15", "::/127", "fe80::/10", "ff00::/8", "fd5a:9c33:21e7::/64"];
}

/// <summary>LocalSubnet, DNS, DHCP, WINS and DefaultGateway, optionally limited to one family with a 4 or 6 suffix.</summary>
public static class AddressKeywords
{
    public static readonly IReadOnlyList<string> Names = ["LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway"];

    public static bool TryParse(string token, out string keyword, out bool? ipv6)
    {
        keyword = ""; ipv6 = null;
        foreach (var name in Names)
        {
            if (token.Equals(name, StringComparison.OrdinalIgnoreCase)) { keyword = name; return true; }
            if (token.Length == name.Length + 1 && token.StartsWith(name, StringComparison.OrdinalIgnoreCase) && token[^1] is '4' or '6')
            { keyword = name; ipv6 = token[^1] == '6'; return true; }
        }
        return false;
    }

    /// <summary>Resolves a keyword to networks paired with the interface that owns them.</summary>
    public static IEnumerable<(ulong Luid, string Network)> Expand(string keyword, bool? ipv6, NetworkSnapshot snapshot)
    {
        foreach (var nic in snapshot.Interfaces)
        {
            IReadOnlyList<string> values = keyword switch
            {
                "LocalSubnet" => nic.Subnets, "DNS" => nic.DnsServers, "DHCP" => nic.DhcpServers,
                "WINS" => nic.WinsServers, "DefaultGateway" => nic.Gateways, _ => []
            };
            foreach (var value in values.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!IpNetwork.TryParse(value, out var network)) continue;
                var bytes = network.Address.GetAddressBytes();
                if (ipv6 is { } family && (bytes.Length == 16) != family) continue;
                yield return (nic.Luid, Canonical(network));
            }
        }
    }

    public static string Canonical(IpNetwork network)
    {
        var bytes = network.Address.GetAddressBytes();
        for (var bit = network.Prefix; bit < bytes.Length * 8; bit++) bytes[bit / 8] &= (byte)~(1 << (7 - bit % 8));
        return new System.Net.IPAddress(bytes) + "/" + network.Prefix;
    }
}
