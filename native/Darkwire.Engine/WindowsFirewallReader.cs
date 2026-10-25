using Darkwire.Core;
using Microsoft.Win32;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Darkwire.Engine;

/// <summary>Profiles use NET_FW_PROFILE_TYPE2 bits: 1 Domain, 2 Private, 4 Public.</summary>
public sealed record WindowsFirewallReadResult(List<FirewallRule> Rules, Dictionary<int, bool> Profiles, List<string> Errors)
{
    public Dictionary<int, bool> InboundAllowed { get; init; } = [];
    public Dictionary<int, bool> OutboundAllowed { get; init; } = [];
}

/// <summary>
/// Reads the local Windows Firewall rule store losslessly. The COM view only cross-checks counts and states:
/// it omits trust-tuple, Play To and package-family scope, so translating from it can widen rules.
/// </summary>
public static class WindowsFirewallReader
{
    public const string RuleStore = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    private const string GroupPolicyRules = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
    public const int MaximumRules = 20_000;

    public static WindowsRuleContext CurrentContext()
    {
        ConcurrentDictionary<string, string?> text = new(), packages = new();
        return new(s => text.GetOrAdd(s, ResolveIndirectString), s => packages.GetOrAdd(s, AppContainerSid), Environment.OSVersion.Version);
    }

    public static WindowsFirewallReadResult Read()
    {
        List<string> errors = []; Dictionary<int, bool> profiles = [], inbound = [], outbound = [];
        List<(bool Enabled, int Action, int Direction)> active = [];
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new PlatformNotSupportedException("Windows Firewall is unavailable."))!;
        try
        {
            if ((int)policy.LocalPolicyModifyState != 0) errors.Add("Windows Firewall is managed by policy or local changes are not effective.");
            foreach (var profile in new[] { 1, 2, 4 })
            {
                profiles[profile] = policy.FirewallEnabled[profile];
                inbound[profile] = (int)policy.DefaultInboundAction[profile] == 1;
                outbound[profile] = (int)policy.DefaultOutboundAction[profile] == 1;
            }
            dynamic collection = policy.Rules;
            try
            {
                foreach (dynamic source in collection)
                    try { active.Add(((bool)source.Enabled, (int)source.Action, (int)source.Direction)); }
                    finally { Marshal.FinalReleaseComObject(source); }
            }
            finally { Marshal.FinalReleaseComObject(collection); }
        }
        finally { Marshal.FinalReleaseComObject(policy); }
        using (var groupPolicy = Registry.LocalMachine.OpenSubKey(GroupPolicyRules))
            if (groupPolicy is { ValueCount: > 0 }) errors.Add("Group Policy firewall rules are present. Darkwire inherits only the local rule store.");
        List<(bool Enabled, int Action, int Direction)> stored = [];
        var rules = ReadStore(CurrentContext(), errors, stored);
        if (!Counts(stored).OrderBy(p => p.Key).SequenceEqual(Counts(active).OrderBy(p => p.Key)))
            errors.Add("The Windows Firewall rule store changed while it was read, or the active policy includes rules outside the local store. Read it again.");
        return new(rules, profiles, errors) { InboundAllowed = inbound, OutboundAllowed = outbound };
    }

    private static List<FirewallRule> ReadStore(WindowsRuleContext context, List<string> errors, List<(bool, int, int)> stored)
    {
        using var key = Registry.LocalMachine.OpenSubKey(RuleStore) ?? throw new InvalidDataException("The Windows Firewall rule store is unavailable.");
        var names = key.GetValueNames();
        if (names.Length > MaximumRules) throw new InvalidDataException("The Windows Firewall rule store exceeds the supported size.");
        List<FirewallRule> rules = [];
        foreach (var id in names.Order(StringComparer.Ordinal))
        {
            if (key.GetValueKind(id) != RegistryValueKind.String || key.GetValue(id) is not string raw)
            { errors.Add("Windows Firewall rule " + id + " is not stored as text."); continue; }
            stored.Add(RawState(raw));
            try { rules.Add(WindowsRuleTranslator.Translate(WindowsRuleGrammar.Parse(id, raw), context)); }
            catch (InvalidDataException error) { rules.Add(Unreadable(id, raw, error.Message)); }
        }
        return rules;
    }

    /// <summary>A rule the grammar cannot parse. Allow rules stay unenforced; enabled block rules refuse takeover.</summary>
    public static FirewallRule Unreadable(string id, string raw, string reason)
    {
        var (enabled, action, _) = RawState(raw);
        return new()
        {
            ApplicationName = id.Length is > 0 and <= 256 ? id : "Unreadable Windows rule", Group = "Windows Firewall", Enabled = enabled,
            Action = action == 0 ? RuleAction.Deny : RuleAction.Allow, Source = "Windows Firewall",
            WindowsRuleId = id.Length is > 0 and <= 1024 ? id : null, OriginalDefinition = raw.Length <= 65_536 ? raw : null,
            Import = !enabled ? ImportOutcome.Inert : action == 0 ? ImportOutcome.Refused : ImportOutcome.Unenforced,
            ImportWarning = "Not translatable: " + reason
        };
    }

    // COM encodings: NET_FW_ACTION 0 block, 1 allow; NET_FW_RULE_DIRECTION 1 in, 2 out. Authenticated bypass reads as allow.
    private static (bool Enabled, int Action, int Direction) RawState(string raw)
    {
        string Value(string key) => raw.Split('|').FirstOrDefault(p => p.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))?[(key.Length + 1)..] ?? "";
        return (Value("Active").Equals("TRUE", StringComparison.OrdinalIgnoreCase), Value("Action").Equals("Block", StringComparison.OrdinalIgnoreCase) ? 0 : 1,
            Value("Dir").Equals("In", StringComparison.OrdinalIgnoreCase) ? 1 : 2);
    }
    private static Dictionary<(bool, int, int), int> Counts(IEnumerable<(bool, int, int)> states) => states.GroupBy(s => s).ToDictionary(g => g.Key, g => g.Count());

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)] private static extern int SHLoadIndirectString(string source, StringBuilder output, int capacity, IntPtr reserved);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
    private static string? ResolveIndirectString(string text)
    {
        if (!text.StartsWith('@')) return text;
        var output = new StringBuilder(1024);
        return SHLoadIndirectString(text, output, output.Capacity, IntPtr.Zero) == 0 && output.Length > 0 ? output.ToString() : null;
    }
    /// <summary>Packaged apps run in the AppContainer derived from their package family name.</summary>
    public static string? AppContainerSid(string familyName)
    {
        if (DeriveAppContainerSidFromAppContainerName(familyName, out var sid) != 0 || sid == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(sid).Value; }
        finally { FreeSid(sid); }
    }
}
