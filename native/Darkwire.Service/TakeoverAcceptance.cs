using Darkwire.Core;
using Darkwire.Engine;

namespace Darkwire.Service;

/// <summary>
/// Applications Windows Firewall let out when Darkwire takes over keep their access: the takeover adds a rule allowing
/// everything each one sends. Like any application without a VPN profile of its own, each then leaves through the default
/// outbound route, and its connections come back through it without a prompt. A shared service host's rule names the
/// service that opened the connection; one Windows did not tag is left to prompts, since its rule would reach every service
/// the host runs.
/// </summary>
internal static class TakeoverAcceptance
{
    public const string Group = "Takeover";

    /// <param name="connected">Processes with outbound connections open now.</param>
    /// <param name="installation">Darkwire's own folder, whose programs need no rule.</param>
    /// <param name="existing">The policy's rules; an application they already allow everything out gets no second rule.</param>
    public static IReadOnlyList<FirewallRule> Rules(IEnumerable<FlowProcess> connected, string installation, IEnumerable<FirewallRule> existing)
    {
        var own = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installation)) + Path.DirectorySeparatorChar;
        var allowed = existing.Where(r => r is { Enabled: true, Action: RuleAction.Allow, Direction: TrafficDirection.Outbound or TrafficDirection.Any } &&
                RuleValidator.IsAny(r.RemoteAddresses) && RuleValidator.IsAny(r.RemotePorts) && RuleValidator.IsAny(r.Protocol))
            .Select(r => Key(r.Path, r.Service)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        List<FirewallRule> rules = [];
        foreach (var process in connected)
        {
            var path = process.ImagePath;
            var system = path == IdentitySelectors.SystemApplication;
            if (!system && (!Path.IsPathFullyQualified(path) || path.StartsWith(own, StringComparison.OrdinalIgnoreCase))) continue;
            var (hosted, service) = ServiceNames.Of(process);
            if (hosted.Count > 1 && service is null) continue;
            if (!allowed.Add(Key(path, service ?? "*"))) continue;
            rules.Add(new()
            {
                ApplicationName = service ?? (system ? path : Path.GetFileNameWithoutExtension(path)), Path = path, Service = service ?? "*",
                Group = Group, Action = RuleAction.Allow, Direction = TrafficDirection.Outbound, Protocol = "Any", Source = "Darkwire takeover"
            });
        }
        return rules;
    }

    private static string Key(string path, string service) => path + "|" + service;
}
