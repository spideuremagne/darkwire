using Darkwire.Core;
using Microsoft.Win32;

namespace Darkwire.Engine;

/// <summary>Maps the service SIDs in a process token back to service names, for prompts and service-scoped rules.</summary>
public static class ServiceNames
{
    private static readonly object gate = new();
    private static Dictionary<string, string>? names;
    private static DateTimeOffset built;

    /// <summary>Names of the services whose SIDs appear; "NT SERVICE\ALL SERVICES" (S-1-5-80-0) is not a service.</summary>
    public static IReadOnlyList<string> Of(IEnumerable<string> sids)
    {
        var services = sids.Where(s => s.StartsWith("S-1-5-80-", StringComparison.Ordinal) && s != "S-1-5-80-0").ToArray();
        if (services.Length == 0) return [];
        lock (gate)
        {
            // A service installed since the last scan is picked up, at most once a minute.
            if (names is null || services.Any(s => !names.ContainsKey(s)) && DateTimeOffset.UtcNow - built > TimeSpan.FromMinutes(1)) Build();
            return services.Select(s => names!.GetValueOrDefault(s)).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    /// <summary>
    /// The services a flow's process runs, by its token, and the one the flow belongs to: the only one, or in a process running
    /// several, the one Windows tagged the flow's socket with; null when neither says. WFP tells services apart only by the
    /// token, so a rule for one service in a shared process reaches every service the process runs.
    /// </summary>
    public static (IReadOnlyList<string> Hosted, string? Service) Of(FlowProcess process)
    {
        var hosted = Of(process.Owner.Sids ?? (IEnumerable<string>)[]);
        var tagged = process.TaggedService is { } name ? hosted.FirstOrDefault(s => s.Equals(name, StringComparison.OrdinalIgnoreCase)) : null;
        return (hosted, hosted.Count == 1 ? hosted[0] : tagged);
    }

    private static void Build()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            foreach (var name in key?.GetSubKeyNames() ?? []) result[IdentitySelectors.ServiceSid(name)] = name;
        names = result; built = DateTimeOffset.UtcNow;
    }
}
