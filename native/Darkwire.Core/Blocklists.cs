using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Core;

/// <summary>
/// How a list's lines read. Hosts files name exact hosts; wildcard domain lists and adblock rules name a domain with every
/// subdomain, and adblock exceptions keep one resolvable; network lists hold addresses, CIDRs and ranges.
/// </summary>
public enum BlocklistFormat { Hosts, Wildcards, Adblock, Networks }

/// <summary>A well-known list the service downloads itself. The policy names it by Id and never carries its contents.</summary>
public sealed record BlocklistCatalogEntry(string Id, string Name, string Publisher, string Description, string Url, BlocklistFormat Format,
    int Estimate, string Homepage, string? License = null)
{
    /// <summary>Domain lists are enforced by DNS filtering in the connection router; network lists by kernel filters.</summary>
    public bool Domains => Format != BlocklistFormat.Networks;
}

public static class BlocklistCatalog
{
    private const string HaGeZi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/", HaGeZiHome = "https://github.com/hagezi/dns-blocklists";

    public static IReadOnlyList<BlocklistCatalogEntry> Entries { get; } =
    [
        new("hagezi-light", "HaGeZi Multi Light", "HaGeZi", "Ads, tracking, metrics and some badware, chosen not to break sites.",
            HaGeZi + "light-onlydomains.txt", BlocklistFormat.Wildcards, 59_614, HaGeZiHome, "GPL-3.0"),
        new("hagezi-normal", "HaGeZi Multi Normal", "HaGeZi", "All-round protection: ads, tracking, phishing, malware, scams and cryptojacking.",
            HaGeZi + "multi-onlydomains.txt", BlocklistFormat.Wildcards, 161_902, HaGeZiHome, "GPL-3.0"),
        new("hagezi-pro", "HaGeZi Multi Pro", "HaGeZi", "Extended protection and the publisher's recommendation; now and then blocks a site you want.",
            HaGeZi + "pro-onlydomains.txt", BlocklistFormat.Wildcards, 198_026, HaGeZiHome, "GPL-3.0"),
        new("hagezi-tif", "HaGeZi Threat Intelligence (mini)", "HaGeZi", "Malware, phishing, scam and command-and-control domains from threat intelligence feeds.",
            HaGeZi + "tif.mini-onlydomains.txt", BlocklistFormat.Wildcards, 223_998, HaGeZiHome, "GPL-3.0"),
        new("hagezi-doh", "HaGeZi Encrypted DNS Bypass", "HaGeZi", "Encrypted DNS servers, so browsers fall back to DNS that Darkwire filters.",
            HaGeZi + "doh-onlydomains.txt", BlocklistFormat.Wildcards, 3_272, HaGeZiHome, "GPL-3.0"),
        // abuse.ch no longer serves URLhaus's public downloads (410 Gone); malware-filter builds this list from its API.
        new("urlhaus", "URLhaus Malware Hosts", "malware-filter", "Hosts currently distributing malware, from abuse.ch's URLhaus.",
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt", BlocklistFormat.Hosts, 558, "https://gitlab.com/malware-filter/urlhaus-filter", "CC0 1.0"),
        new("adaway", "AdAway", "AdAway", "Mobile ad and analytics servers.",
            "https://adaway.org/hosts.txt", BlocklistFormat.Hosts, 6_540, "https://adaway.org", "CC BY 3.0"),
        new("firehol-level1", "FireHOL Level 1", "FireHOL", "Attack sources, botnet controllers and hijacked networks (DShield, Feodo, Spamhaus DROP).",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", BlocklistFormat.Networks, 3_919, "https://iplists.firehol.org"),
        new("anudeep", "Anudeep's Ad Servers", "Anudeep", "Ad and tracking servers.",
            "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", BlocklistFormat.Hosts, 42_531, "https://github.com/anudeepND/blacklist"),
        new("1hosts-lite", "1Hosts Lite", "badmojr", "Ads, tracking and malware, tuned to avoid breakage.",
            "https://badmojr.github.io/1Hosts/Lite/domains.wildcards", BlocklistFormat.Wildcards, 102_259, "https://github.com/badmojr/1Hosts", "MPL-2.0"),
        new("oisd-small", "OISD Small", "OISD", "Ads, tracking and malware with very few false positives.",
            "https://small.oisd.nl/domainswild2", BlocklistFormat.Wildcards, 56_079, "https://oisd.nl"),
        new("oisd-big", "OISD Big", "OISD", "Broader ads, tracking, malware and phishing coverage.",
            "https://big.oisd.nl/domainswild2", BlocklistFormat.Wildcards, 236_318, "https://oisd.nl"),
        new("kadhosts", "KADhosts", "Filters Heroes", "Scams, fake shops, SMS subscription traps and malware, focused on Poland.",
            "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt", BlocklistFormat.Hosts, 40_354, "https://github.com/FiltersHeroes/KADhosts", "CC BY-SA 4.0"),
    ];

    /// <summary>Firefox turns its automatic encrypted DNS off when this name does not resolve.</summary>
    public const string Canary = "use-application-dns.net";

    /// <summary>Hosts Darkwire downloads lists and GeoIP data from. They stay resolvable, so no list can stop its own updates.</summary>
    public static IReadOnlyList<string> SourceHosts { get; } = Entries.Select(e => new Uri(e.Url).Host).Append("download.db-ip.com").Distinct().ToArray();

    public static BlocklistCatalogEntry? Find(string? id) => id is null ? null : Entries.FirstOrDefault(e => e.Id == id);
}

/// <summary>Downloaded catalog lists, which the policy names but does not carry.</summary>
public interface IBlocklistContents
{
    /// <summary>A network list's CIDRs, or null while it has not been downloaded.</summary>
    IReadOnlyList<string>? Networks(string catalogId);
}

public static class BlocklistNames
{
    /// <summary>
    /// A host name as DNS filtering compares it: lowercase ASCII without a trailing dot, two or more labels of letters, digits,
    /// hyphens and underscores, and a top-level label that is not numeric. Null for anything else, address literals included.
    /// </summary>
    public static string? Normalize(ReadOnlySpan<char> text)
    {
        if (text.EndsWith(".")) text = text[..^1];
        if (text.Length is 0 or > 253) return null;
        Span<char> lower = stackalloc char[text.Length];
        int labels = 1, length = 0; var numeric = true;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '.')
            {
                if (length == 0) return null;
                labels++; length = 0; numeric = true; lower[i] = c; continue;
            }
            if (c is >= 'A' and <= 'Z') c = (char)(c + 32);
            else if (c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) return null;
            if (++length > 63) return null;
            numeric &= c is >= '0' and <= '9';
            lower[i] = c;
        }
        return length == 0 || labels < 2 || numeric ? null : new string(lower);
    }
}

/// <summary>A downloaded list in normalized form: exact hosts, domains with their subdomains, exceptions and networks.</summary>
public sealed class BlocklistContent
{
    public const int MaximumEntries = 2_000_000;
    private const string Header = "# Darkwire blocklist 1";

    private BlocklistContent(string[] hosts, string[] domains, string[] exceptions, IReadOnlyList<string> networks)
    { Hosts = hosts; Domains = domains; Exceptions = exceptions; Networks = networks; }

    public IReadOnlyList<string> Hosts { get; }
    public IReadOnlyList<string> Domains { get; }
    public IReadOnlyList<string> Exceptions { get; }
    /// <summary>Merged CIDRs without protected space (<see cref="AddressRanges.Protected"/>).</summary>
    public IReadOnlyList<string> Networks { get; }
    /// <summary>What the list blocks: names for a domain list, networks for an address list.</summary>
    public int Count => Hosts.Count + Domains.Count + Networks.Count;

    /// <summary>Reads a list as its publisher wrote it. Lines this format cannot express a block with are skipped.</summary>
    public static BlocklistContent Parse(TextReader reader, BlocklistFormat format)
    {
        HashSet<string> hosts = new(StringComparer.Ordinal), domains = new(StringComparer.Ordinal), exceptions = new(StringComparer.Ordinal);
        List<IpNetwork> networks = [];
        Span<Range> tokens = stackalloc Range[3];
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var text = line.AsSpan().Trim();
            if (text.IsEmpty || text[0] is '#' or '!' or '[') continue;
            if (format != BlocklistFormat.Adblock && text.IndexOf('#') is var comment and >= 0) text = text[..comment].TrimEnd();
            var count = text.SplitAny(tokens, " \t", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (count == 0) continue;
            switch (format)
            {
                case BlocklistFormat.Hosts:
                    // "0.0.0.0 host [host...]", or a bare host. The address only says where the host was sent.
                    if (!IPAddress.TryParse(text[tokens[0]], out _)) { Add(hosts, text[tokens[0]]); break; }
                    foreach (var name in text[tokens[0].End.Value..].ToString().Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
                        if (!Local(name)) Add(hosts, name);
                    break;
                case BlocklistFormat.Wildcards:
                    var domain = text[tokens[0]];
                    Add(domains, domain.StartsWith("*.") ? domain[2..] : domain);
                    break;
                case BlocklistFormat.Adblock:
                    if (Adblock(text[tokens[0]], out var rule, out var exception)) Add(exception ? exceptions : domains, rule);
                    break;
                case BlocklistFormat.Networks:
                    var value = text[tokens[0]].ToString();
                    if (IpNetwork.TryParse(value, out var network)) networks.Add(network);
                    else if (IpAddressRange.TryParse(value, out var range)) networks.AddRange(range.ToNetworks());
                    break;
            }
            if (hosts.Count + domains.Count + exceptions.Count + networks.Count > MaximumEntries) throw new InvalidDataException("The list has more than two million entries.");
        }
        return new(Sorted(hosts), Sorted(domains), Sorted(exceptions), AddressRanges.Normalize(networks));
    }

    private static bool Local(string name) => name.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase);
    private static void Add(HashSet<string> set, ReadOnlySpan<char> name) { if (BlocklistNames.Normalize(name) is { } normalized) set.Add(normalized); }
    private static string[] Sorted(HashSet<string> set) { var array = set.ToArray(); Array.Sort(array, StringComparer.Ordinal); return array; }

    /// <summary>
    /// "||example.com^" blocks a domain with its subdomains and "@@||example.com^" keeps one resolvable. Rules with paths,
    /// wildcards or options other than $important are browser rules and say nothing about DNS.
    /// </summary>
    private static bool Adblock(ReadOnlySpan<char> text, out ReadOnlySpan<char> name, out bool exception)
    {
        name = default;
        exception = text.StartsWith("@@");
        if (exception) text = text[2..];
        if (!text.StartsWith("||")) return false;
        text = text[2..];
        if (text.IndexOf('$') is var options and >= 0)
        {
            if (!text[(options + 1)..].Equals("important", StringComparison.OrdinalIgnoreCase)) return false;
            text = text[..options];
        }
        if (!text.EndsWith("^")) return false;
        name = text[..^1];
        return true;
    }

    /// <summary>The normalized form the service stores: one entry a line, marked = host, * domain, ! exception, @ network.</summary>
    public void Write(TextWriter writer)
    {
        writer.WriteLine(Header);
        foreach (var host in Hosts) { writer.Write('='); writer.WriteLine(host); }
        foreach (var domain in Domains) { writer.Write('*'); writer.WriteLine(domain); }
        foreach (var exception in Exceptions) { writer.Write('!'); writer.WriteLine(exception); }
        foreach (var network in Networks) { writer.Write('@'); writer.WriteLine(network); }
    }

    /// <summary>Reads what <see cref="Write"/> stored, validating every entry again.</summary>
    public static BlocklistContent Read(TextReader reader)
    {
        if (reader.ReadLine() != Header) throw new InvalidDataException("Not a Darkwire blocklist.");
        List<string> hosts = [], domains = [], exceptions = [], networks = [];
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length < 2) throw new InvalidDataException("A stored blocklist entry is empty.");
            var value = line[1..];
            var valid = line[0] switch
            {
                '=' => Keep(hosts, value), '*' => Keep(domains, value), '!' => Keep(exceptions, value),
                '@' => IpNetwork.TryParse(value, out _) && value.Contains('/') && Keep(networks, value, normalized: false),
                _ => false
            };
            if (!valid) throw new InvalidDataException("A stored blocklist entry is invalid.");
            if (hosts.Count + domains.Count + exceptions.Count + networks.Count > MaximumEntries) throw new InvalidDataException("The stored list has more than two million entries.");
        }
        return new([.. hosts], [.. domains], [.. exceptions], networks);
    }

    private static bool Keep(List<string> list, string value, bool normalized = true)
    {
        if (normalized && BlocklistNames.Normalize(value) != value) return false;
        list.Add(value); return true;
    }
}

/// <summary>
/// Names DNS filtering answers itself. Each name is held as a 64-bit digest in a sorted array, about eight bytes a name, so
/// millions fit; a lookup hashes the queried name and each parent domain once. Exceptions win over blocks.
/// </summary>
public sealed class DomainFilter
{
    public static readonly DomainFilter Empty = new(Array.Empty<ulong>(), Array.Empty<ulong>(), Array.Empty<ulong>());
    private readonly ulong[] hosts, domains, exceptions;

    private DomainFilter(ulong[] hosts, ulong[] domains, ulong[] exceptions) { this.hosts = hosts; this.domains = domains; this.exceptions = exceptions; }

    /// <param name="hosts">Names blocked exactly.</param>
    /// <param name="domains">Names blocked with every subdomain.</param>
    /// <param name="exceptions">Names that stay resolvable, with every subdomain, whatever else lists them.</param>
    public DomainFilter(IEnumerable<string> hosts, IEnumerable<string> domains, IEnumerable<string> exceptions)
        : this(Digests(hosts), Digests(domains), Digests(exceptions)) { }

    public static DomainFilter From(BlocklistContent content) => new(content.Hosts, content.Domains, content.Exceptions);

    /// <summary>Blocked names, counting a name listed by several lists once.</summary>
    public int Count => hosts.Length + domains.Length;

    /// <summary>One filter blocking what any of the given filters block, keeping every exception.</summary>
    public static DomainFilter Combine(IReadOnlyCollection<DomainFilter> filters) => filters.Count == 1 ? filters.First() :
        new(Union(filters.Select(f => f.hosts)), Union(filters.Select(f => f.domains)), Union(filters.Select(f => f.exceptions)));

    /// <summary>Whether a query for the name is answered as nonexistent: a listed host, or inside a listed domain, and no exception covers it.</summary>
    public bool Blocks(string name)
    {
        if (Count == 0 || BlocklistNames.Normalize(name) is not { } normalized) return false;
        Span<ulong> parents = stackalloc ulong[128];
        var count = 0;
        for (var start = 0; ; )
        {
            parents[count++] = Digest(normalized.AsSpan(start));
            var dot = normalized.IndexOf('.', start);
            if (dot < 0) break;
            start = dot + 1;
        }
        parents = parents[..count];
        foreach (var digest in parents) if (Array.BinarySearch(exceptions, digest) >= 0) return false;
        if (Array.BinarySearch(hosts, parents[0]) >= 0) return true;
        foreach (var digest in parents) if (Array.BinarySearch(domains, digest) >= 0) return true;
        return false;
    }

    /// <summary>Whether both filters hold the same names, so swapping one for the other changes no answer.</summary>
    public bool SameAs(DomainFilter other) => hosts.AsSpan().SequenceEqual(other.hosts) && domains.AsSpan().SequenceEqual(other.domains) && exceptions.AsSpan().SequenceEqual(other.exceptions);

    private static ulong[] Digests(IEnumerable<string> names)
    {
        List<ulong> digests = [];
        foreach (var name in names) if (BlocklistNames.Normalize(name) is { } normalized) digests.Add(Digest(normalized));
        return Unique([.. digests]);
    }

    private static ulong[] Union(IEnumerable<ulong[]> arrays) => Unique(arrays.SelectMany(a => a).ToArray());

    private static ulong[] Unique(ulong[] values)
    {
        Array.Sort(values);
        var length = 0;
        for (var i = 0; i < values.Length; i++) if (length == 0 || values[length - 1] != values[i]) values[length++] = values[i];
        return length == values.Length ? values : values[..length];
    }

    // The first eight bytes of a SHA-256: two different names share a digest with odds around one in 2^64 per pair.
    private static ulong Digest(ReadOnlySpan<char> name)
    {
        Span<byte> bytes = stackalloc byte[256]; Span<byte> hash = stackalloc byte[32];
        var length = Encoding.ASCII.GetBytes(name, bytes);
        SHA256.HashData(bytes[..length], hash);
        return BinaryPrimitives.ReadUInt64LittleEndian(hash);
    }
}
