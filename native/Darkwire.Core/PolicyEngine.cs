using System.Net;
using System.Net.Sockets;

namespace Darkwire.Core;

public readonly record struct IpNetwork(IPAddress Address, int Prefix)
{
    public static bool TryParse(string? text, out IpNetwork network)
    {
        network = default;
        // WFP address masks carry no zone/interface ID. Accepting one would silently discard that scope.
        if (string.IsNullOrWhiteSpace(text) || text.Contains('%')) return false;
        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address)) return false;
        var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = bits;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits)) return false;
        network = new(address, prefix); return true;
    }
    public bool Contains(IPAddress candidate)
    {
        var a = Address.GetAddressBytes(); var b = candidate.GetAddressBytes();
        if (a.Length != b.Length) return false;
        var whole = Prefix / 8; var remainder = Prefix % 8;
        for (var i = 0; i < whole; i++) if (a[i] != b[i]) return false;
        return remainder == 0 || (a[whole] >> (8 - remainder)) == (b[whole] >> (8 - remainder));
    }
}

public static class RuleValidator
{
    public static string[] Tokens(string? value) => value?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];
    public static bool IsAny(string? value) => value is "*" or "Any" or "any";
    public static bool ValidPorts(string value) => IsAny(value) || (Tokens(value).Length > 0 && Tokens(value).All(p =>
    {
        var range = p.Split('-');
        return range.Length <= 2 && int.TryParse(range[0], out var low) && low is >= 0 and <= 65535 &&
            (range.Length == 1 || (int.TryParse(range[1], out var high) && high >= low && high <= 65535));
    }));
    public static bool PortMatches(string value, int port) => IsAny(value) || Tokens(value).Any(p =>
    {
        var r = p.Split('-'); return int.TryParse(r[0], out var low) && (r.Length == 1 ? low == port :
            r.Length == 2 && int.TryParse(r[1], out var high) && port >= low && port <= high);
    });
    public static bool ValidAddresses(string? value, bool allowKeywords = false) => IsAny(value) || Tokens(value).Length > 0 &&
        Tokens(value).All(p => IpNetwork.TryParse(p, out _) || IpAddressRange.TryParse(p, out _) || allowKeywords && AddressKeywords.TryParse(p, out _, out _));
    // Dynamic keywords resolve only in the service compiler; the desktop preview never assumes they match.
    public static bool AddressMatches(string selector, string address) => IsAny(selector) || IPAddress.TryParse(address, out var ip) &&
        Tokens(selector).Any(n => IpNetwork.TryParse(n, out var network) && network.Contains(ip) || IpAddressRange.TryParse(n, out var range) && range.Contains(ip));
    public static List<string> Validate(FirewallRule rule)
    {
        List<string> errors = [];
        if (!Enum.IsDefined(rule.Action)) errors.Add("Select Allow or Deny.");
        if (!Enum.IsDefined(rule.Direction) || rule.Direction == TrafficDirection.Unknown) errors.Add("Select Any, Inbound, or Outbound.");
        if (string.IsNullOrWhiteSpace(rule.ApplicationName)) errors.Add("Application name is required.");
        if (string.IsNullOrWhiteSpace(rule.Path)) errors.Add("Path is required. Use * for all applications.");
        if (!ValidPorts(rule.LocalPorts)) errors.Add("Local ports must be *, a port, or comma-separated ports and ranges.");
        if (!ValidPorts(rule.RemotePorts)) errors.Add("Remote ports must be *, a port, or comma-separated ports and ranges.");
        if (!ValidAddresses(rule.RemoteAddresses, allowKeywords: true))
            errors.Add("Remote addresses must be IP addresses, CIDRs, inclusive same-family ranges, or LocalSubnet, DNS, DHCP, WINS or DefaultGateway.");
        if (!ValidAddresses(rule.LocalAddresses)) errors.Add("Local addresses must be *, IP addresses, CIDRs, or inclusive address ranges.");
        if (!IpProtocol.TryParse(rule.Protocol, out var protocol)) errors.Add("Protocol must be Any, TCP, UDP, ICMPv4, ICMPv6, or IP 0–255.");
        if (!IcmpSelectors.TryParse(rule.IcmpTypesAndCodes, out _) || !IsAny(rule.IcmpTypesAndCodes) && protocol is not (1 or 58))
            errors.Add("ICMP selectors require ICMP and type:code pairs such as 8:* or 128:0.");
        if (Tokens(rule.Location).Length == 0 || Tokens(rule.Location).Any(p => !new[] { "Any", "Domain", "Private", "Public" }.Contains(p))) errors.Add("Location must be Any, Domain, Private, or Public.");
        if (Tokens(rule.Location).Length > 1 && Tokens(rule.Location).Contains("Any")) errors.Add("Any cannot be combined with a specific network profile.");
        if (rule.Service is null || !IdentitySelectors.ValidService(rule.Service)) errors.Add("Service must be *, AllServices, or one service name.");
        if (rule.User is null || !IdentitySelectors.ValidUsers(rule.User)) errors.Add("User must be *, or comma-separated account names or SIDs.");
        if (rule.Package is null || !IdentitySelectors.ValidPackage(rule.Package)) errors.Add("Package must be *, AllPackages, or an AppContainer SID (S-1-15-2-…).");
        if (rule.Import is { } outcome && !Enum.IsDefined(outcome)) errors.Add("Unknown import outcome.");
        if (rule.Enabled && rule.Import is ImportOutcome.Inert or ImportOutcome.Refused)
            errors.Add("This imported rule stays disabled: " + (rule.ImportWarning ?? "its Windows scope cannot be enforced."));
        return errors;
    }
}

/// <summary>Shared install semantics for the native compiler and the desktop preview.</summary>
public static class RuleEnforcement
{
    /// <summary>
    /// Whether an enabled rule installs filters. A reduced allow installs the part Darkwire can express, which Windows allowed
    /// too; a broader block waits for consent because it can block traffic Windows allowed. Unenforced, Inert and Refused never
    /// install, so traffic only they allowed stays blocked, or asks in Learning.
    /// </summary>
    public static bool Installs(FirewallRule rule) => rule.Import switch
    {
        null or ImportOutcome.Exact => true,
        ImportOutcome.Narrowed => rule.Action != RuleAction.Deny || rule.NarrowingAccepted,
        _ => false
    };
    /// <summary>Only a broader block needs consent: a rule left unenforced or reduced never allows more than Windows did.</summary>
    public static bool NeedsConsent(FirewallRule rule) =>
        rule.Enabled && rule.Import == ImportOutcome.Narrowed && rule.Action == RuleAction.Deny && !rule.NarrowingAccepted;
}

public sealed class PolicyEngine
{
    public PolicyDecision Evaluate(AppState state, Connection connection)
    {
        if (!Enum.IsDefined(state.Mode)) return new(DecisionKind.Deny, "Invalid policy mode");
        if (state.Mode == FirewallMode.Lockdown) return new(DecisionKind.Deny, "Lockdown");
        if (state.Mode == FirewallMode.Open) return new(DecisionKind.Allow, "Open mode");
        return Decide(state, connection, own: false) ??
            (state.Mode == FirewallMode.Learning ? new(DecisionKind.Prompt, "No matching rule") : new(DecisionKind.Deny, "Block new"));
    }

    /// <summary>
    /// A connection of one of Darkwire's own programs (<see cref="OwnConnections"/>), which needs no rule while connections are
    /// routed: the relay's permit lets the service out, in Lockdown too, the router lets the DNS proxy out, and the VPN
    /// backends have permits to their peers. Explicit denies still refuse them, a country allow list does not. Without
    /// routing they are decided like any program's.
    /// </summary>
    public PolicyDecision EvaluateOwn(AppState state, Connection connection)
    {
        if (!state.RouteConnections || !Enum.IsDefined(state.Mode) || state.Mode == FirewallMode.Open) return Evaluate(state, connection);
        PolicyDecision own = new(DecisionKind.Allow, "Darkwire's own connection");
        return state.Mode == FirewallMode.Lockdown ? own : Decide(state, connection, own: true) ?? own;
    }

    /// <summary>What the rules, geographic policy, lists and internal networks decide; null when none of them does.</summary>
    private static PolicyDecision? Decide(AppState state, Connection connection, bool own)
    {
        var rules = state.Rules.Where(r => r.Enabled && RuleEnforcement.Installs(r) && RuleValidator.Validate(r).Count == 0 && Matches(r, connection)).ToArray();
        var deny = rules.FirstOrDefault(r => r.Action == RuleAction.Deny);
        if (deny is not null) return new(DecisionKind.Deny, deny.ApplicationName, deny.Id);
        // An allow list refuses every country it leaves out, except to Darkwire's own connections; an address no country
        // claims, such as an internal one, passes.
        if (state.CountryAllowList ? !own && connection.Country.Length > 0 && !state.AllowedCountries.Contains(connection.Country, StringComparer.OrdinalIgnoreCase)
            : state.BlockedCountries.Contains(connection.Country, StringComparer.OrdinalIgnoreCase)) return new(DecisionKind.Deny, "Country policy");
        if (connection.Asn != 0 && state.BlockedAsns.Contains(connection.Asn)) return new(DecisionKind.Deny, "ASN policy");
        foreach (var list in state.Blocklists.Where(l => l.Enabled))
            if (list.Entries.Any(e => BlocklistParser.Matches(e, connection))) return new(DecisionKind.Deny, list.Name);
        var allow = rules.FirstOrDefault(r => r.Action == RuleAction.Allow);
        if (allow is not null) return new(DecisionKind.Allow, allow.ApplicationName, allow.Id);
        return InternalNetworks.Decide(state, connection) is { } internalAccess ? new(internalAccess, "Internal networks") : null;
    }
    private static bool Matches(FirewallRule r, Connection c) =>
        (RuleValidator.IsAny(r.Path) || string.Equals(Environment.ExpandEnvironmentVariables(r.Path), c.Path, StringComparison.OrdinalIgnoreCase) ||
            IdentitySelectors.IsSystemApplication(r.Path) && c.ProcessId == 4) &&
        RuleValidator.IsAny(r.Package) &&
        (r.Direction == TrafficDirection.Any || r.Direction == c.Direction) &&
        (RuleValidator.IsAny(r.Location) || RuleValidator.Tokens(r.Location).Contains(c.Location, StringComparer.OrdinalIgnoreCase)) &&
        (RuleValidator.IsAny(r.Protocol) || IpProtocol.TryParse(r.Protocol, out var rp) && IpProtocol.TryParse(c.Protocol, out var cp) && rp == cp) &&
        RuleValidator.PortMatches(r.LocalPorts, c.LocalPort) && RuleValidator.PortMatches(r.RemotePorts, c.RemotePort) &&
        RuleValidator.AddressMatches(r.RemoteAddresses, c.RemoteAddress) && RuleValidator.AddressMatches(r.LocalAddresses, c.LocalAddress) &&
        IcmpSelectors.Matches(r.IcmpTypesAndCodes, c.IcmpType, c.IcmpCode) &&
        (RuleValidator.IsAny(r.Service) || r.Service == IdentitySelectors.AllServices && c.Service.Length > 0 || r.Service.Equals(c.Service, StringComparison.OrdinalIgnoreCase)) &&
        (RuleValidator.IsAny(r.User) || RuleValidator.Tokens(r.User).Contains(c.User, StringComparer.OrdinalIgnoreCase));
}
