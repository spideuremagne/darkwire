using System.Text;
using System.Text.RegularExpressions;

namespace Darkwire.Core;

/// <summary>
/// A server on the public resolver list as the DNS picker shows it: its name and provider, its description, what its first
/// stamp says of it, and every stamp it has.
/// </summary>
public sealed record DnsCatalogEntry(string Name, string Provider, string Description, DnsProtocol Protocol, bool Dnssec, bool NoLog, bool NoFilter, bool Ipv6,
    IReadOnlyList<string> Stamps);

/// <summary>
/// The DNSCrypt project's public resolver list (v3 markdown): a "## name" heading for each server, then its description and
/// one or more stamps. The service downloads it from the project's mirrors and checks its minisign signature; only DNSCrypt
/// and DNS over HTTPS servers are kept.
/// </summary>
public static partial class ResolverList
{
    public const string FileName = "public-resolvers.md";
    /// <summary>The key the DNSCrypt project signs its resolver lists with, as dnscrypt-proxy's own configuration names it.</summary>
    public const string PublicKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    public static readonly IReadOnlyList<string> Urls =
    [
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
        "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md",
        "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md"
    ];
    public const int MaximumEntries = 5000, MaximumStamps = 8;

    [GeneratedRegex("^[a-z0-9._-]{1,64}$")] private static partial Regex NamePattern();

    /// <summary>Whether a name can name a DNS server: lower-case letters, digits, dots, hyphens and underscores, as the list's do.</summary>
    public static bool ValidName(string? name) => name is not null && NamePattern().IsMatch(name);

    /// <summary>The list's servers in its order; entries without a supported stamp, or with a name already taken, are left out.</summary>
    public static IReadOnlyList<DnsCatalogEntry> Parse(string markdown)
    {
        List<DnsCatalogEntry> entries = [];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var sections = markdown.Replace("\r\n", "\n").Split("\n## ");
        // The preamble before the first heading describes the list itself.
        foreach (var section in sections.Skip(1))
        {
            var lines = section.Split('\n');
            var name = lines[0].Trim();
            if (!ValidName(name) || !seen.Add(name)) continue;
            List<string> stamps = []; var description = new StringBuilder();
            DnsStamp? first = null;
            foreach (var raw in lines.Skip(1))
            {
                var line = raw.Trim();
                if (line.StartsWith(DnsStamp.Scheme, StringComparison.Ordinal))
                {
                    if (stamps.Count >= MaximumStamps || !DnsStamp.TryParse(line, out var stamp)) continue;
                    first ??= stamp; stamps.Add(line);
                }
                else if (line.Length > 0 && description.Length < 1000) description.Append(description.Length > 0 ? " " : "").Append(line);
            }
            if (first is null) continue;
            entries.Add(new(name, DnsProviders.Of(name), description.Length > 1000 ? description.ToString(0, 1000) : description.ToString(),
                first.Protocol, first.Dnssec, first.NoLog, first.NoFilter, first.Ipv6, stamps));
            if (entries.Count >= MaximumEntries) break;
        }
        return entries;
    }

    /// <summary>
    /// When a signed list was signed, from its trusted comment ("timestamp:…", a tab, "file:public-resolvers.md"); null when the
    /// comment names another file or no time, so a signature over another of the project's lists never passes for this one.
    /// </summary>
    public static long? SignedAt(string trustedComment)
    {
        var fields = trustedComment.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Select(f => f.Split(':', 2)).Where(f => f.Length == 2)
            .GroupBy(f => f[0], StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First()[1], StringComparer.Ordinal);
        return fields.GetValueOrDefault("file") == FileName && long.TryParse(fields.GetValueOrDefault("timestamp"), out var time) && time > 0 ? time : null;
    }
}

/// <summary>The providers the DNS picker groups the resolver list by: well-known ones by name, every other server under Other.</summary>
public static class DnsProviders
{
    public const string Other = "Other providers";
    private static readonly (string Prefix, string Name)[] Known =
    [
        ("adfilter", "AdFilter"), ("adguard", "AdGuard DNS"), ("cira", "CIRA Canadian Shield"), ("cisco", "Cisco OpenDNS"), ("cleanbrowsing", "CleanBrowsing"),
        ("cloudflare", "Cloudflare"), ("comodo", "Comodo Secure DNS"), ("cs", "cryptostorm"), ("dnscry.pt", "dnscry.pt"), ("libredns", "LibreDNS"),
        ("mullvad", "Mullvad"), ("nextdns", "NextDNS"), ("plan9dns", "Plan 9 DNS"), ("quad9", "Quad9"), ("uncensoreddns", "UncensoredDNS")
    ];
    public static IReadOnlyList<string> Names { get; } = [.. Known.Select(k => k.Name).Order(StringComparer.OrdinalIgnoreCase)];

    public static string Of(string server)
    {
        foreach (var (prefix, name) in Known)
            if (server == prefix || server.StartsWith(prefix + "-", StringComparison.Ordinal)) return name;
        return Other;
    }
}

/// <summary>
/// Names a local network answers rather than the internet: single labels, the zones set aside for private networks, reverse
/// lookups for private and link-local addresses, the NAT64 probe, Windows' connectivity checks, and the domains the networks
/// and the PC's own domain hand out. Darkwire asks the network's servers, or a tunnel's, for these, never an internet resolver.
/// </summary>
public static class LocalNames
{
    private static readonly string[] Zones =
    [
        "local", "lan", "home", "home.arpa", "internal", "localdomain", "localhost", "corp", "intranet", "private", "ipv4only.arpa",
        "10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa", "127.in-addr.arpa",
        .. Enumerable.Range(16, 16).Select(octet => $"{octet}.172.in-addr.arpa"),
        .. Enumerable.Range(64, 64).Select(octet => $"{octet}.100.in-addr.arpa"),
        "c.f.ip6.arpa", "d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
        "msftconnecttest.com", "msftncsi.com"
    ];

    /// <param name="domains">The DNS suffixes the networks hand out and the PC's domain, any case, with or without a final dot.</param>
    public static bool Contains(string name, IEnumerable<string> domains)
    {
        if (!name.Contains('.')) return true;
        return Zones.Any(zone => Within(name, zone)) || domains.Select(d => d.Trim().TrimEnd('.').ToLowerInvariant()).Any(d => d.Length > 0 && Within(name, d));
    }

    private static bool Within(string name, string zone) => name == zone || name.Length > zone.Length && name.EndsWith(zone, StringComparison.Ordinal) && name[^(zone.Length + 1)] == '.';
}
