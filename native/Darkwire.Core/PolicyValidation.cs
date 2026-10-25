namespace Darkwire.Core;

/// <summary>Validates untrusted deserialized policy before service admission or compilation.</summary>
public static class PolicyValidation
{
    public static IReadOnlyList<string> Validate(AppState? state)
    {
        if (state is null) return ["Policy is required."];
        List<string> errors = [];
        if (state.SchemaVersion != 1) errors.Add("Unsupported policy schema.");
        if (!Enum.IsDefined(state.Mode)) errors.Add("Unknown firewall mode.");
        if (!Enum.IsDefined(state.InternalNetworks)) errors.Add("Unknown internal network access.");
        if (!Enum.IsDefined(state.OwnTraffic)) errors.Add("Unknown route for Darkwire's own connections.");
        if (state.Rules is null || state.Blocklists is null || state.VpnProfiles is null || state.BlockedCountries is null || state.AllowedCountries is null || state.BlockedAsns is null ||
            state.DnsServers is null || state.BlockedNames is null)
            return ["Policy collections must not be null."];
        if (state.DnsServers.Count > MaximumDnsServers || state.BlockedNames.Count > MaximumBlockedNames) return ["Policy exceeds the supported collection limits."];
        foreach (var server in state.DnsServers)
            if (DnsServerError(server) is { } error) errors.Add(error);
        if (state.DnsServers.Where(s => s?.Name is not null).GroupBy(s => s.Name, StringComparer.Ordinal).Any(g => g.Count() > 1))
            errors.Add("Each DNS server can be chosen once.");
        if (state.BlockedNames.Any(name => name is null || BlocklistNames.Normalize(name) != name))
            errors.Add("A blocked name must be a DNS name in lower case, such as tracker.example.com.");
        if (state.Rules.Count > 20_000 || state.Blocklists.Count > 256 || state.VpnProfiles.Count > VpnAssignments.MaximumProfiles)
            return ["Policy exceeds the supported collection limits."];
        foreach (var rule in state.Rules)
        {
            if (rule is null) { errors.Add("Policy contains an empty rule."); continue; }
            var fields = new[] { rule.ApplicationName, rule.Group, rule.Path, rule.Location, rule.LocalPorts, rule.RemoteAddresses, rule.RemotePorts, rule.Protocol, rule.Service, rule.User, rule.LocalAddresses, rule.IcmpTypesAndCodes, rule.Package };
            if (fields.Any(s => s is null || s.Length > 32_768 || s.Contains('\0')) || rule.WindowsRuleId is { Length: 0 or > 1024 } ||
                rule.OriginalDefinition is { Length: > 65_536 } || rule.ImportWarning is { Length: > 65_536 })
                errors.Add("Rule fields contain an invalid or oversized value.");
            else errors.AddRange(RuleValidator.Validate(rule).Select(e => rule.ApplicationName + ": " + e));
        }
        if (state.Rules.Where(r => r is not null).Select(r => r.Id).Distinct().Count() != state.Rules.Count)
            errors.Add("Rule identifiers must be unique.");
        var windowsIds = state.Rules.Where(r => r?.WindowsRuleId is not null).Select(r => r.WindowsRuleId!).ToArray();
        if (windowsIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != windowsIds.Length)
            errors.Add("Each Windows rule can be imported only once.");
        foreach (var list in state.Blocklists)
        {
            if (list is null || list.Entries is null || list.Entries.Count > 1_000_000 || list.Name is null || list.Name.Length > 1024 ||
                list.Entries.Any(e => string.IsNullOrWhiteSpace(e) || e.Length > 2048 || e.Contains('\0')))
                errors.Add("Blocklist data is invalid or exceeds its size limit.");
            // The service downloads catalog lists from its own catalog; a policy can only name one.
            else if (list.CatalogId is not null && (BlocklistCatalog.Find(list.CatalogId) is null || list.Entries.Count > 0))
                errors.Add("A catalog blocklist must name a known list and carry no entries.");
        }
        if (state.Blocklists.Where(l => l?.CatalogId is not null).GroupBy(l => l.CatalogId).Any(g => g.Count() > 1))
            errors.Add("Each catalog blocklist can be added once.");
        // Darkwire runs WireGuard only; an OpenVPN profile from an earlier build stays valid, so its policy still loads, but never connects.
        foreach (var profile in state.VpnProfiles)
            if (profile is null || profile.Id == Guid.Empty || profile.Kind is not ("WireGuard" or "OpenVPN") ||
                string.IsNullOrWhiteSpace(profile.Name) || profile.Name.Length > 256 || profile.Name.Any(char.IsControl) ||
                profile.Applications is null || profile.Applications.Count > 20_000 ||
                profile.Applications.Any(p => string.IsNullOrWhiteSpace(p) || p.Length > 32_768 || p.Contains('\0') || !Path.IsPathFullyQualified(p)))
                errors.Add("VPN assignments contain an invalid application path.");
        if (state.VpnProfiles.Any(p => p?.Applications is not null && p.Applications.Any(a => a is not null && !VpnAssignments.Carriable(a))))
            errors.Add(VpnAssignments.ServiceHostRefusal);
        if (state.VpnProfiles.Where(p => p is not null).Select(p => p.Id).Distinct().Count() != state.VpnProfiles.Count)
            errors.Add("VPN profile identifiers must be unique.");
        if (state.DefaultOutboundVpnProfileId is { } defaultId && !state.VpnProfiles.Any(p => p is not null && p.Id == defaultId))
            errors.Add("The default outbound VPN profile does not exist.");
        if (state.OwnTraffic == OwnRoute.Profile && !state.VpnProfiles.Any(p => p is not null && p.Id == state.OwnTrafficProfileId))
            errors.Add("The VPN profile for Darkwire's own connections does not exist.");
        var assignments = state.VpnProfiles.Where(p => p?.Applications is not null).SelectMany(p => p.Applications).ToArray();
        var validAssignments = assignments.Where(p => !string.IsNullOrWhiteSpace(p) && !p.Contains('\0') && Path.IsPathFullyQualified(p)).Select(Path.GetFullPath).ToArray();
        if (validAssignments.Distinct(StringComparer.OrdinalIgnoreCase).Count() != validAssignments.Length)
            errors.Add("An application can be assigned to only one VPN configuration.");
        if (state.BlockedCountries.Concat(state.AllowedCountries).Any(c => c is null || c.Length != 2 || c.Any(ch => !char.IsAsciiLetter(ch)))) errors.Add("Country codes must contain two letters.");
        // An empty allow list would refuse every country.
        if (state.CountryAllowList && state.AllowedCountries.Count == 0) errors.Add("Choose at least one country to allow, or block countries instead.");
        if (state.BlockedAsns.Any(a => a == 0)) errors.Add("ASN zero is not a valid restriction.");
        return errors.Distinct().Take(100).ToArray();
    }

    public const int MaximumDnsServers = 64, MaximumBlockedNames = 10_000;

    /// <summary>
    /// What is wrong with an encrypted DNS server, or null: a name as the public resolver list writes them, and one to eight
    /// DNSCrypt or DNS over HTTPS stamps.
    /// </summary>
    public static string? DnsServerError(DnsServer? server)
    {
        if (server is null || server.Name is null || server.Stamps is null || server.Stamps.Any(s => s is null)) return "A DNS server is incomplete.";
        if (!ResolverList.ValidName(server.Name)) return "A DNS server's name must be up to 64 lower-case letters, digits, dots, hyphens and underscores.";
        if (server.Stamps.Count is 0 or > ResolverList.MaximumStamps || server.Stamps.Any(s => !DnsStamp.TryParse(s, out _)))
            return $"{server.Name}: a DNS server needs one to {ResolverList.MaximumStamps} DNSCrypt or DNS over HTTPS stamps.";
        return null;
    }
}
