using Darkwire.Core;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Darkwire.Engine;

/// <summary>Display-text and package resolvers used during translation. Tests supply deterministic ones.</summary>
public sealed record WindowsRuleContext(Func<string, string?> ResolveText, Func<string, string?> PackageSid, Version OsVersion);

/// <summary>
/// Translates Windows rules without widening what Windows allows. Untranslatable alternatives shrink allow rules and
/// broaden block rules. Untranslatable restrictions leave allow rules unenforced and are dropped from block rules.
/// </summary>
public static partial class WindowsRuleTranslator
{
    private enum Issue { Malformed, Restriction, Alternative, Extension }
    private sealed class Field { public readonly List<string> Tokens = []; public bool Present, Any, Alternatives; }

    private static readonly HashSet<string> KnownKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Action", "Active", "Dir", "Protocol", "Profile", "LPort", "LPort2_10", "LPort2_20", "RPort", "RPort2_10", "LA4", "LA6", "RA4", "RA6", "RA42", "RA62",
        "App", "Svc", "Name", "Desc", "EmbedCtxt", "Edge", "Defer", "LSM", "LOM", "ICMP4", "ICMP6", "Platform", "Platform2", "SkipVer", "PCross",
        "LUAuth", "LUAuth2_24", "LUOwn", "AppPkgId", "PFN", "TTK", "TTK2_22", "TTK2_27", "TTK2_28", "IF", "IFType", "Security", "Security2", "Security2_9",
        "RMauth", "RUAuth", "AuthByPassOut", "NNm", "SecurityRealmId"
    };
    // SDDL aliases seen in local-user authorization lists.
    private static readonly Dictionary<string, string> SidAliases = new(StringComparer.OrdinalIgnoreCase)
    { ["SY"] = "S-1-5-18", ["LS"] = "S-1-5-19", ["NS"] = "S-1-5-20", ["BA"] = "S-1-5-32-544", ["BU"] = "S-1-5-32-545", ["AU"] = "S-1-5-11", ["WD"] = "S-1-1-0", ["IU"] = "S-1-5-4", ["SU"] = "S-1-5-6" };
    [GeneratedRegex(@"^(O:[A-Za-z0-9-]+)?(G:[A-Za-z0-9-]+)?D:[A-Z]*((\(A;;CC;;;[A-Za-z0-9-]+\))+)$", RegexOptions.CultureInvariant)] private static partial Regex SimpleAllowList();
    [GeneratedRegex(@"\(A;;CC;;;([A-Za-z0-9-]+)\)", RegexOptions.CultureInvariant)] private static partial Regex AllowEntry();
    [GeneratedRegex(@"^[A-Za-z0-9.\-]{1,64}_[a-z0-9]{13}$", RegexOptions.CultureInvariant)] private static partial Regex PackageFamilyName();

    public static FirewallRule Translate(WindowsRuleRecord record, WindowsRuleContext context)
    {
        List<(Issue Kind, string Reason)> issues = [];
        void Note(Issue kind, string reason) => issues.Add((kind, reason));
        string? One(string key)
        {
            var values = record.All(key).ToArray();
            if (values.Length > 1) Note(Issue.Malformed, "duplicate " + key);
            return values.FirstOrDefault();
        }
        bool True(string key) => One(key)?.Equals("TRUE", StringComparison.OrdinalIgnoreCase) == true;
        foreach (var key in record.Fields.Select(f => f.Key).Distinct(StringComparer.OrdinalIgnoreCase).Where(k => !KnownKeys.Contains(k)))
            Note(Issue.Malformed, "unknown field " + key);

        var actionText = One("Action") ?? "";
        var block = actionText.Equals("Block", StringComparison.OrdinalIgnoreCase);
        if (actionText.Equals("ByPass", StringComparison.OrdinalIgnoreCase)) Note(Issue.Restriction, "authenticated bypass");
        else if (!block && !actionText.Equals("Allow", StringComparison.OrdinalIgnoreCase)) Note(Issue.Malformed, "unknown action");
        var enabled = True("Active");
        var direction = One("Dir")?.ToLowerInvariant() switch { "in" => TrafficDirection.Inbound, "out" => TrafficDirection.Outbound, _ => TrafficDirection.Unknown };
        if (direction == TrafficDirection.Unknown) Note(Issue.Malformed, "unknown direction");
        var protocol = 256;
        if (One("Protocol") is { } protocolText && (!int.TryParse(protocolText, NumberStyles.None, CultureInfo.InvariantCulture, out protocol) || protocol > 255))
        { Note(Issue.Malformed, "invalid protocol"); protocol = 256; }

        HashSet<string> profiles = [];
        foreach (var value in record.All("Profile"))
        {
            var name = value.ToLowerInvariant() switch { "domain" => "Domain", "private" => "Private", "public" => "Public", _ => null };
            if (name is null) Note(Issue.Malformed, "unknown network profile"); else profiles.Add(name);
        }

        var transport = protocol is 6 or 17;
        Field Ports(params string[] keys)
        {
            var field = new Field();
            foreach (var token in keys.SelectMany(record.All).SelectMany(Split))
            {
                field.Present = true;
                if (RuleValidator.IsAny(token)) field.Any = true;
                else if (RuleValidator.ValidPorts(token)) field.Tokens.Add(token);
                else { field.Alternatives = true; Note(Issue.Alternative, PortKeyword(token)); }
            }
            if (field.Present && !transport) Note(Issue.Malformed, "ports without TCP or UDP");
            return field;
        }
        var localPorts = Ports("LPort", "LPort2_10", "LPort2_20");
        var remotePorts = Ports("RPort", "RPort2_10");

        Field Addresses(bool remote, params (string Key, bool Ipv6, bool KeywordsOnly)[] keys)
        {
            var field = new Field();
            foreach (var (key, ipv6, keywordsOnly) in keys)
            foreach (var token in record.All(key).SelectMany(Split))
            {
                field.Present = true;
                if (token == "*") field.Any = true;
                else if (!keywordsOnly && TryAddress(token, ipv6, out var normalized)) field.Tokens.Add(normalized);
                else if (remote && !keywordsOnly && AddressKeywords.TryParse(token, out var keyword, out var family) && family is null) field.Tokens.Add(keyword + (ipv6 ? "6" : "4"));
                else if (remote && token.All(char.IsAsciiLetterOrDigit)) { field.Alternatives = true; Note(Issue.Alternative, AddressKeyword(token)); }
                else Note(Issue.Malformed, "invalid address " + token);
            }
            foreach (var keyword in AddressKeywords.Names)
                if (field.Tokens.Contains(keyword + "4") && field.Tokens.Contains(keyword + "6"))
                { field.Tokens.RemoveAll(t => t == keyword + "4" || t == keyword + "6"); field.Tokens.Add(keyword); }
            return field;
        }
        var localAddresses = Addresses(false, ("LA4", false, false), ("LA6", true, false));
        var remoteAddresses = Addresses(true, ("RA4", false, false), ("RA6", true, false), ("RA42", false, true), ("RA62", true, true));

        List<string> icmp = [];
        foreach (var (key, icmpProtocol) in new[] { ("ICMP4", 1), ("ICMP6", 58) })
        foreach (var token in record.All(key).SelectMany(Split))
        {
            if (protocol != icmpProtocol) { Note(Issue.Malformed, key + " without its protocol"); continue; }
            if (IcmpSelectors.TryParse(token, out _)) icmp.Add(token); else Note(Issue.Malformed, "invalid ICMP entry");
        }

        var application = One("App");
        var service = One("Svc") switch { null or "" => "*", "*" => IdentitySelectors.AllServices, var name => name };
        if (!IdentitySelectors.ValidService(service)) { Note(Issue.Malformed, "invalid service name"); service = "*"; }

        List<string> users = [];
        if (One("LUAuth") is { } authorized)
        {
            if (TryAllowList(authorized, out var sids)) users.AddRange(sids);
            else Note(Issue.Restriction, "complex local user scope");
        }
        if (One("LUAuth2_24") is not null) Note(Issue.Restriction, "conditional local user scope");
        // Package rules carry the installing user as owner. Allow rules keep that restriction; block rules drop it so they never shrink.
        if (One("LUOwn") is { } owner)
        {
            if (!IdentitySelectors.IsSid(owner)) Note(Issue.Malformed, "invalid rule owner");
            else if (owner != "S-1-5-18" && !block)
            {
                if (users.Count == 0) users.Add(owner);
                else if (!users.SequenceEqual([owner])) Note(Issue.Restriction, "owner combined with user scope");
            }
        }

        var package = "*";
        if (One("AppPkgId") is { } packageId)
        {
            if (packageId == "*") package = IdentitySelectors.AllPackages;
            else if (IdentitySelectors.ValidPackage(packageId)) package = packageId;
            else Note(Issue.Restriction, "package ID " + packageId);
        }
        if (One("PFN") is { } familyName)
        {
            var sid = PackageFamilyName().IsMatch(familyName) ? context.PackageSid(familyName) : null;
            if (sid is null || !IdentitySelectors.ValidPackage(sid)) Note(Issue.Restriction, "package " + familyName);
            else if (package == "*") package = sid;
            else if (package != sid) Note(Issue.Restriction, "package ID and family name disagree");
        }

        foreach (var key in new[] { "TTK", "TTK2_22", "TTK2_27", "TTK2_28" })
            foreach (var token in record.All(key).SelectMany(Split)) Note(Issue.Restriction, TrustedPeers(token));
        var edge = True("Edge");
        if (One("Defer") is { } deferral) { Note(Issue.Extension, "edge traversal deferred to the " + (deferral.Equals("App", StringComparison.OrdinalIgnoreCase) ? "app" : "user")); edge = false; }
        if (record.All("IF").Any()) Note(Issue.Restriction, "specific interfaces");
        if (One("IFType") is { } interfaceType && !interfaceType.Equals("All", StringComparison.OrdinalIgnoreCase)) Note(Issue.Restriction, "interface type " + interfaceType);
        if (!block && new[] { "Security", "Security2", "Security2_9" }.Any(k => One(k) is not null)) Note(Issue.Restriction, "IPsec authentication requirement");
        if (One("RMauth") is not null || One("RUAuth") is not null) Note(Issue.Restriction, "remote computer or user authorization");
        if (True("AuthByPassOut")) Note(Issue.Extension, "outbound authenticated bypass");
        if (True("LSM")) Note(Issue.Extension, "loose source mapping");
        if (True("LOM")) Note(Issue.Restriction, "local-only mapping");
        if (One("NNm") is not null) Note(Issue.Restriction, "named networks");
        if (One("SecurityRealmId") is not null) Note(Issue.Restriction, "IPsec security realm");
        var notApplicable = false;
        if (record.All("Platform").ToArray() is { Length: > 0 } platforms)
        {
            switch (PlatformApplies(platforms, One("Platform2"), context.OsVersion))
            {
                case null: Note(Issue.Restriction, "Windows version condition"); break;
                case false: notApplicable = true; break;
            }
        }

        var malformed = issues.Any(i => i.Kind == Issue.Malformed);
        var restricted = issues.Any(i => i.Kind == Issue.Restriction);
        var emptied = false;
        string Final(Field field)
        {
            if (!field.Present || field.Any || block && field.Alternatives) return "*";
            if (field.Tokens.Count > 0) return string.Join(',', field.Tokens.Distinct(StringComparer.OrdinalIgnoreCase));
            emptied = true; return "*";
        }
        var rawName = One("Name") ?? record.Id;
        var rawGroup = One("EmbedCtxt");
        var rule = new FirewallRule
        {
            ApplicationName = DisplayName(rawName, context, record.All("PFN").FirstOrDefault()) is { Length: > 0 } displayName ? displayName : record.Id,
            Group = rawGroup is null ? "Windows Firewall" : context.ResolveText(rawGroup) ?? rawGroup,
            Path = string.IsNullOrEmpty(application) ? "*" : application,
            Enabled = enabled && !notApplicable,
            Action = block ? RuleAction.Deny : RuleAction.Allow,
            Direction = direction == TrafficDirection.Unknown ? TrafficDirection.Any : direction,
            Protocol = IpProtocol.Name(protocol),
            Location = profiles.Count is 0 or 3 ? "Any" : string.Join(',', new[] { "Domain", "Private", "Public" }.Where(profiles.Contains)),
            LocalPorts = Final(localPorts), RemotePorts = Final(remotePorts),
            LocalAddresses = Final(localAddresses), RemoteAddresses = Final(remoteAddresses),
            IcmpTypesAndCodes = icmp.Count == 0 ? "*" : string.Join(',', icmp.Distinct()),
            Service = service, User = users.Count == 0 ? "*" : string.Join(',', users.Distinct(StringComparer.OrdinalIgnoreCase)), Package = package,
            EdgeTraversal = edge && direction == TrafficDirection.Inbound,
            Source = "Windows Firewall", WindowsRuleId = record.Id, OriginalDefinition = record.Raw
        };
        rule.Import = notApplicable ? ImportOutcome.Inert
            : issues.Count == 0 ? ImportOutcome.Exact
            : !rule.Enabled ? ImportOutcome.Inert
            : block ? malformed ? ImportOutcome.Refused : ImportOutcome.Narrowed
            : malformed || restricted || emptied ? ImportOutcome.Unenforced : ImportOutcome.Narrowed;
        var reasons = issues.Select(i => i.Reason).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        rule.ImportWarning = notApplicable ? "Applies to other Windows versions."
            : reasons.Length == 0 ? null : "Not translatable: " + string.Join("; ", reasons) + ".";
        return rule;
    }

    /// <summary>Accepts only "(A;;CC;;;SID)" entries: allow match-filter access, no conditions or denies.</summary>
    private static bool TryAllowList(string sddl, out List<string> sids)
    {
        sids = [];
        if (!SimpleAllowList().IsMatch(sddl)) return false;
        foreach (Match entry in AllowEntry().Matches(sddl[sddl.IndexOf("D:", StringComparison.Ordinal)..]))
        {
            var value = entry.Groups[1].Value;
            if (SidAliases.TryGetValue(value, out var aliased)) value = aliased;
            if (!IdentitySelectors.IsSid(value)) return false;
            sids.Add(value);
        }
        return sids.Count > 0;
    }

    private static bool TryAddress(string token, bool ipv6, out string normalized)
    {
        normalized = token;
        static bool Family(IPAddress address, bool ipv6) => address.AddressFamily == (ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        if (token.Contains('%')) return false;
        if (token.Contains('-')) return IpAddressRange.TryParse(token, out _) && IPAddress.TryParse(token.Split('-')[0].Trim(), out var start) && Family(start, ipv6);
        var slash = token.IndexOf('/');
        if (slash < 0) return IPAddress.TryParse(token, out var single) && Family(single, ipv6);
        if (!IPAddress.TryParse(token[..slash], out var address) || !Family(address, ipv6)) return false;
        var suffix = token[(slash + 1)..];
        int prefix;
        if (!ipv6 && IPAddress.TryParse(suffix, out var mask) && mask.AddressFamily == AddressFamily.InterNetwork)
        {
            // Windows stores IPv4 subnets with dotted masks. Only contiguous masks are CIDR networks.
            var bits = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
            prefix = System.Numerics.BitOperations.PopCount(bits);
            if (bits != (prefix == 0 ? 0u : uint.MaxValue << (32 - prefix))) return false;
        }
        else if (!int.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)) return false;
        if (!IpNetwork.TryParse(address + "/" + prefix, out var network)) return false;
        normalized = AddressKeywords.Canonical(network); return true;
    }

    private static bool? PlatformApplies(string[] entries, string? lastOperator, Version os)
    {
        var any = false;
        for (var i = 0; i < entries.Length; i++)
        {
            var parts = entries[i].Split(':');
            if (parts.Length != 3 || parts[0] != "2" || !int.TryParse(parts[1], out var major) || !int.TryParse(parts[2], out var minor)) return null;
            var comparison = os.Major != major ? os.Major.CompareTo(major) : os.Minor.CompareTo(minor);
            bool? match = (i == entries.Length - 1 ? lastOperator?.ToUpperInvariant() : null) switch { null or "EQ" => comparison == 0, "GTEQ" => comparison >= 0, _ => null };
            if (match is null) return null;
            any |= match.Value;
        }
        return any;
    }

    private static string? DisplayName(string raw, WindowsRuleContext context, string? familyName)
    {
        if (!raw.StartsWith('@')) return raw;
        if (context.ResolveText(raw) is { Length: > 0 } resolved) return resolved;
        // Package display resources may be unavailable to SYSTEM. Fall back to the package name.
        var separator = familyName?.LastIndexOf('_') ?? -1;
        return separator > 0 ? familyName![..separator] : raw;
    }
    private static IEnumerable<string> Split(string value) => value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    private static string PortKeyword(string token) => token.ToLowerInvariant() switch
    {
        "rpc" => "dynamic RPC ports", "rpc-epmap" => "RPC endpoint mapper port", "teredo" => "Teredo port",
        "iphttpsin" or "iphttpsout" => "IP-HTTPS port", "iptlsin" or "iptlsout" => "IP-TLS port", "ply2disc" => "Play To discovery port",
        "mdns" => "mDNS port", "dhcp" => "DHCP port", _ => "port keyword " + token
    };
    private static string AddressKeyword(string token) => token.ToLowerInvariant() switch
    {
        "intranet" => "intranet addresses", "rmtintranet" => "remote intranet addresses", "internet" => "Internet addresses",
        "ply2renders" => "Play To renderers", "captiveportal" => "captive portal addresses", _ => "address keyword " + token
    };
    private static string TrustedPeers(string token) => token.ToLowerInvariant() switch
    {
        "proxsharing" => "proximity sharing peers", "wfddisplay" => "Wi-Fi Direct display peers", "wfdprint" => "Wi-Fi Direct print peers",
        "upnp" => "UPnP peers", "wfdkmdriver" => "Wi-Fi Direct driver peers", "wfdcdpsvc" => "Wi-Fi Direct device peers", _ => "trusted peer group " + token
    };
}
