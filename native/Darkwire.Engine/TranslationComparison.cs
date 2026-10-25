using Darkwire.Core;

namespace Darkwire.Engine;

public sealed record RuleComparison(string Rule, IReadOnlyList<string> WindowsRuleIds, IReadOnlyList<string> Outcomes, string Verdict,
    IReadOnlyList<string> Windows, IReadOnlyList<string> Darkwire);

/// <summary>
/// Diffs the filters Windows Firewall installed for each enabled rule against Darkwire's translation of the same rule.
/// Run elevated while Windows Firewall is still enabled; it reads WFP and changes nothing.
/// </summary>
public static class TranslationComparison
{
    public static IReadOnlyList<RuleComparison> Compare(IReadOnlyList<FirewallRule> rules, NetworkSnapshot network)
    {
        var installed = WfpInventory.Read(p => p == WfpInventory.MpssvcFirewallProvider).Where(f => f.Layer.StartsWith("ALE_AUTH_", StringComparison.Ordinal))
            .GroupBy(f => f.Name, StringComparer.CurrentCultureIgnoreCase).ToDictionary(g => g.Key, g => g.Select(Describe).ToList(), StringComparer.CurrentCultureIgnoreCase);
        List<RuleComparison> result = [];
        foreach (var group in rules.Where(r => r.Enabled && r.WindowsRuleId is not null).GroupBy(r => r.ApplicationName, StringComparer.CurrentCultureIgnoreCase))
        {
            List<string> compiled = [];
            foreach (var rule in group)
            {
                var copy = System.Text.Json.JsonSerializer.Deserialize<FirewallRule>(System.Text.Json.JsonSerializer.Serialize(rule, StateStore.JsonOptions), StateStore.JsonOptions)!;
                copy.NarrowingAccepted = true;
                var plan = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, CoreNetworking = false, Rules = [copy] }, network: network);
                if (!plan.CanApply) { compiled.Add("compile error: " + string.Join("; ", plan.Errors)); continue; }
                foreach (var filter in plan.Filters.Where(f => f.RuleId == copy.Id))
                {
                    try { compiled.Add(Describe(filter)); }
                    catch (Exception error) when (error is InvalidDataException or System.ComponentModel.Win32Exception or IOException) { compiled.Add("native error: " + error.Message); }
                }
            }
            var windows = installed.GetValueOrDefault(group.Key) ?? [];
            compiled.Sort(StringComparer.Ordinal); windows.Sort(StringComparer.Ordinal);
            var verdict = windows.Count == 0 && compiled.Count == 0 ? "None" : windows.SequenceEqual(compiled) ? "Match"
                : windows.Count == 0 ? "DarkwireOnly" : compiled.Count == 0 ? "WindowsOnly" : "Differs";
            result.Add(new(group.Key, group.Select(r => r.WindowsRuleId!).ToArray(), group.Select(r => r.Import?.ToString() ?? "Exact").Distinct().ToArray(), verdict, windows, compiled));
        }
        return result.OrderBy(r => r.Verdict).ThenBy(r => r.Rule, StringComparer.CurrentCultureIgnoreCase).ToArray();
    }

    // Layer, action and the sorted condition set; weights and IDs legitimately differ between the two firewalls.
    private static string Describe(FilterRecord filter) =>
        $"{filter.Layer} {filter.Action} " + string.Join(" & ", filter.Conditions.Select(c => $"{c.Field} {c.Match} {c.Value}").Order(StringComparer.Ordinal));
    private static string Describe(NativeFilter filter)
    {
        var layer = (filter.Direction == TrafficDirection.Inbound ? "ALE_AUTH_RECV_ACCEPT_" : "ALE_AUTH_CONNECT_") + (filter.Ipv6 ? "V6" : "V4");
        var conditions = WfpConditions.Resolve(filter).Select(WfpInventory.Render).Select(c => $"{c.Field} {c.Match} {c.Value}").Order(StringComparer.Ordinal);
        return $"{layer} {(filter.Action == RuleAction.Deny ? "BLOCK" : "PERMIT")} " + string.Join(" & ", conditions);
    }
}
