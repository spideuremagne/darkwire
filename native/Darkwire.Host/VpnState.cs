using Darkwire.Engine;

namespace Darkwire.Host;

public enum VpnTone { Quiet, Busy, Good, Warn, Bad }

/// <summary>What a VPN profile's card says: a short state, what it means or what to do next, and its color.</summary>
public sealed record VpnCardState(string Pill, string Detail, VpnTone Tone);

public enum VpnPageAction { Apply, SetUp, RestartElevated, CheckAgain }

/// <summary>Why the editor's VPN routes don't run yet, and what the VPN page's button does about it.</summary>
public sealed record VpnPageAlert(string Title, string Detail, VpnPageAction Action);

/// <summary>A tunnel's latest rates in and out, and its peaks, as its card shows them.</summary>
public sealed record VpnThroughput(string Received, string Sent, string Peak);

/// <summary>What the window's banner says while VPN tunnels are being established.</summary>
public sealed record VpnEstablishing(string Title, string Detail);

/// <summary>An application the VPN page offers to assign, where it was found, and the profile that carries it now.</summary>
public sealed record VpnAppChoice(string Name, string Path, string Source, string? CurrentProfile);

/// <summary>
/// How the editor's VPN routes compare with the ones the service enforces, and what each profile's tunnel is doing.
/// The service runs a tunnel only while its enforced policy routes something through the profile.
/// </summary>
public static class VpnState
{
    /// <summary>The profiles the editor's policy would run, routed through or kept connected, in the shape the service reports its own.</summary>
    public static IReadOnlyList<VpnRouteStatus> Draft(AppState draft) =>
        [.. VpnAssignments.Running(draft).Select(p => new VpnRouteStatus(p.Id, p.Kind, p.CredentialsRevision, [.. p.Applications], p.Id == draft.DefaultOutboundVpnProfileId, p.KeepConnected, p.Disconnected))];

    /// <summary>
    /// Whether the service enforces exactly the editor's routes, keeps local traffic off them as the editor does, and sends
    /// Darkwire's own connections the same way.
    /// </summary>
    public static bool Applied(AppState draft, ServiceStatus status)
    {
        var mine = Draft(draft); var enforced = status.Routes ?? [];
        if (mine.Count > 0 && status.LocalNetworkBypassesVpn is { } bypass && bypass != draft.LocalNetworkBypassesVpn) return false;
        if (status.OwnTraffic is { } own && (own != draft.OwnTraffic || own == OwnRoute.Profile && status.OwnTrafficProfileId != draft.OwnTrafficProfileId)) return false;
        return mine.Count == enforced.Count && mine.All(route => Same(route, enforced.FirstOrDefault(r => r.ProfileId == route.ProfileId)));
    }

    private static bool Same(VpnRouteStatus? a, VpnRouteStatus? b) =>
        a is null || b is null ? a is null && b is null :
        a.Kind == b.Kind && a.CredentialsRevision == b.CredentialsRevision && a.Default == b.Default && a.Kept == b.Kept && a.Disconnected == b.Disconnected &&
        a.Applications.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(b.Applications);

    /// <summary>
    /// How long a tunnel may send without an answer, at first or after its server answered, before its card says the server is
    /// not replying; once the service has reconnected it for that, the card says so too.
    /// </summary>
    public static readonly TimeSpan UnansweredAfter = TimeSpan.FromSeconds(10);

    /// <summary>The state of one profile's tunnel, or why it has none and what would start it.</summary>
    /// <param name="status">The service's last answer; null before the first, or while it doesn't answer.</param>
    /// <param name="offline">Several reads in a row went unanswered.</param>
    /// <param name="applying">The editor's route changes are on their way to the service.</param>
    public static VpnCardState Describe(VpnProfile profile, AppState draft, ServiceStatus? status, bool offline, DateTimeOffset now, bool applying = false)
    {
        var mine = Draft(draft).FirstOrDefault(r => r.ProfileId == profile.Id);
        var enforced = status?.Routes?.FirstOrDefault(r => r.ProfileId == profile.Id);
        // An OpenVPN profile from an earlier build never connects; what goes through it is refused until it is removed.
        if (profile.Kind != "WireGuard")
            return new("NOT SUPPORTED", $"Darkwire runs WireGuard tunnels only, so this {profile.Kind} profile can't connect{(mine is null && enforced is null ? "" : ", and what goes through it is refused")}. " +
                "Remove it, and import your provider's WireGuard configuration instead.", mine is null && enforced is null ? VpnTone.Warn : VpnTone.Bad);
        if (status?.Tunnels?.FirstOrDefault(t => t.ProfileId == profile.Id) is { } tunnel)
        {
            var pending = Same(mine, enforced) ? "" : applying ? " Applying your changes to its routes." : " Your changes to its routes aren't applied yet.";
            // Up means the backend and its interface run; only an answer through the tunnel shows the server is there.
            var reconnected = tunnel.Reconnects switch { 0 => "", 1 => "once", var times => times + " times" };
            if (tunnel.State == "Up" && tunnel.Checking)
                return new("CHECKING", $"Connected since {Time(tunnel.Since, now)}; Darkwire is checking that it carries traffic, by asking its DNS server through it." + pending, VpnTone.Busy);
            if (tunnel.State == "Up" && tunnel.CheckFailed is { } failed)
                return new("NO REPLY", $"Up since {Time(tunnel.Since, now)}, but its DNS server didn't answer through it when Darkwire checked at {Time(failed, now)}, so nothing may get through" +
                    (tunnel.CheckRestarts > 0 ? $"; Darkwire has restarted it {Times(tunnel.CheckRestarts)} and checks again, less often each time." : "; Darkwire restarts it.") +
                    " Check that the server is still up, and that this network lets the VPN through." + pending, VpnTone.Bad);
            if (tunnel.Unanswered is { } quiet && now - quiet >= UnansweredAfter)
                return tunnel.Reconnects > 0
                    ? new("NO REPLY", $"Up since {Time(tunnel.Since, now)}, but its server isn't answering; Darkwire has reconnected it {reconnected} and keeps trying, less often each time. " +
                        "Check that the server is still up, and that this network lets the VPN through." + pending, VpnTone.Bad)
                    : tunnel.ReceivedBytes > 0
                    ? new("NO REPLY", $"Up since {Time(tunnel.Since, now)}, but its server stopped answering" + (tunnel.LastReceived is { } last ? $" at {Time(last, now)}" : "") +
                        ": nothing sent through it since has had an answer, so nothing gets through. Check that the server is still up, and that this network lets the VPN through." + pending, VpnTone.Bad)
                    : new("NO REPLY", $"Up since {Time(tunnel.Since, now)}, but its server hasn't answered anything sent through it, so nothing gets through. " +
                        "Check the server's address and keys, and that this network lets the VPN through." + pending, VpnTone.Bad);
            var idle = enforced is { Applications.Count: 0, Default: false, Kept: true } ? " Nothing goes through it yet: assign applications, or make it the default route." : "";
            return tunnel.State switch
            {
                "Up" => new("CONNECTED", Connected(tunnel, enforced?.Default == true, now) + idle + pending, VpnTone.Good),
                "Starting" => new("CONNECTING", (tunnel.Reconnects > 0 ? $"Its server stopped answering, so Darkwire is reconnecting the {profile.Kind} tunnel to {profile.Endpoint}; its applications wait meanwhile."
                    : tunnel.CheckRestarts > 0 ? $"It carried nothing back when Darkwire checked it, so Darkwire is starting the {profile.Kind} tunnel to {profile.Endpoint} again; its applications wait meanwhile."
                    : $"Starting the {profile.Kind} tunnel to {profile.Endpoint}.") + pending, VpnTone.Busy),
                "Failed" => new("DOWN", $"Down since {Time(tunnel.Since, now)}: {(tunnel.Error ?? "the tunnel stopped.").TrimEnd('.')}. Darkwire retries, and refuses its applications until it is back." + pending, VpnTone.Bad),
                _ => new(tunnel.State.ToUpperInvariant(), pending.Trim(), VpnTone.Busy)
            };
        }
        if (mine is null && enforced is null) return new("NOT IN USE", "Connect it, assign an application, or make it the default route.", VpnTone.Quiet);
        if (status is null)
            return offline ? new("UNKNOWN", "The Darkwire service isn't answering, so this tunnel's state is unknown.", VpnTone.Bad) : new("CHECKING", "Asking the Darkwire service.", VpnTone.Busy);
        if (status.VpnBackends is { } backends && !backends.Contains(profile.Kind))
            return new("NO BACKEND", $"This Darkwire package has no {profile.Kind} backend, so the service can't start this tunnel.", VpnTone.Bad);
        if (!status.Active) return new("NOT ENFORCING", "Darkwire isn't enforcing yet. Set it up, and this tunnel starts with the takeover.", VpnTone.Warn);
        if (applying && !Same(mine, enforced)) return new("APPLYING", "Applying your changes to its routes.", VpnTone.Busy);
        if (mine is null) return new("NOT APPLIED", "The service still routes through this profile. Apply VPN routes to stop.", VpnTone.Warn);
        if (!Same(mine, enforced)) return new("NOT APPLIED", "Apply VPN routes to connect.", VpnTone.Warn);
        if (enforced is { Disconnected: true })
        {
            List<string> carried = [];
            if (enforced.Applications.Count > 0) carried.Add(enforced.Applications.Count == 1 ? "its application" : $"its {enforced.Applications.Count} applications");
            if (enforced.Default) carried.Add("every application without a profile of its own");
            if (VpnAssignments.OwnProfile(draft) == profile.Id) carried.Add("Darkwire's own connections");
            var what = carried.Count switch { 0 => "what it carries", 1 => carried[0], _ => string.Join(", ", carried[..^1]) + " and " + carried[^1] };
            return new("DISCONNECTED", $"You disconnected it. Refused until you connect it again, and never sent another way: {what}.", VpnTone.Warn);
        }
        if (status.Mode == FirewallMode.Lockdown) return new("LOCKDOWN", "Lockdown refuses routed connections, so no tunnel runs until you leave it.", VpnTone.Quiet);
        // Alerts come newest first.
        var alert = status.Alerts?.FirstOrDefault(a => a.Contains(profile.Name, StringComparison.Ordinal));
        return new("NOT RUNNING", alert ?? "The service routes through this profile but isn't running its tunnel, so its applications are refused. Settings lists the service's alerts.", VpnTone.Bad);
    }

    private static string Connected(TunnelStatus tunnel, bool carriesDefault, DateTimeOffset now)
    {
        var parts = new List<string> { "Connected since " + Time(tunnel.Since, now) };
        if (tunnel.Addresses is { Count: > 0 } addresses) parts.Add(string.Join(", ", addresses));
        if (tunnel.Shared is { Count: > 0 } shared) parts.Add($"{string.Join(", ", shared)} shared with another connected profile, so pings through it go unanswered");
        if (tunnel.Resolvers is { Count: > 0 } resolvers) parts.Add("DNS " + string.Join(", ", resolvers));
        else if (carriesDefault) parts.Add("no DNS server, so Windows name lookups are refused");
        if (tunnel.SentBytes > 0 || tunnel.ReceivedBytes > 0) parts.Add($"{Size(tunnel.ReceivedBytes)} in, {Size(tunnel.SentBytes)} out");
        return string.Join(" · ", parts) + ".";
    }

    /// <summary>A rate in bits per second, as network speeds are read: bps, kbps, Mbps or Gbps.</summary>
    public static string Bits(long bitsPerSecond) => bitsPerSecond switch
    {
        >= 1_000_000_000 => $"{bitsPerSecond / 1e9:0.00} Gbps",
        >= 1_000_000 => $"{bitsPerSecond / 1e6:0.0} Mbps",
        >= 1_000 => $"{bitsPerSecond / 1e3:0} kbps",
        _ => $"{bitsPerSecond} bps"
    };

    /// <summary>
    /// A running tunnel's throughput: its latest rates in and out, and the highest over the samples the service keeps,
    /// about two seconds apart; null while it has none.
    /// </summary>
    public static VpnThroughput? Throughput(TunnelStatus tunnel)
    {
        if (tunnel is not { State: "Up", InRates: { Count: > 0 } received, OutRates: { Count: > 0 } sent }) return null;
        var seconds = received.Count * 2;
        var window = seconds < 120 ? $"{seconds} s" : $"{seconds / 60} min";
        return new($"↓ {Bits(received[^1])}", $"↑ {Bits(sent[^1])}", $"Peak ↓ {Bits(received.Max())}  ↑ {Bits(sent.Max())} in the last {window}");
    }

    /// <summary>
    /// The window's banner while VPN tunnels are being established: each one starting or being checked end to end, by name;
    /// null once every running tunnel has passed its check, failed it, or is down, and whenever Darkwire runs none. Before the
    /// service's first answer, the editor's routed profiles stand for them, unless the service doesn't answer.
    /// </summary>
    public static VpnEstablishing? Establishing(AppState draft, ServiceStatus? status, bool offline)
    {
        const string title = "Establishing your VPN profiles, please wait";
        string Name(Guid id) => draft.VpnProfiles.FirstOrDefault(p => p.Id == id)?.Name ?? "A VPN profile";
        if (status is null)
            return offline || !Draft(draft).Any(r => !r.Disconnected) ? null : new(title, "Asking the Darkwire service how their tunnels are doing.");
        if (!status.Active || status.Tunnels is not { Count: > 0 } tunnels) return null;
        var doing = tunnels.Where(t => t.State == "Starting" || t.State == "Up" && t.Checking)
            .Select(t => $"{Name(t.ProfileId)} is {(t.State == "Starting" ? "starting" : "being checked")}").ToArray();
        if (doing.Length == 0) return null;
        return new(title, (doing.Length == 1 ? doing[0] : string.Join(", ", doing[..^1]) + " and " + doing[^1]) +
            ". Darkwire asks each tunnel's DNS server through it before counting it connected, and restarts one that carries nothing back. Applications routed through a starting tunnel wait for it.");
    }

    private static string Times(int count) => count == 1 ? "once" : count == 2 ? "twice" : count + " times";

    /// <summary>What Settings says of the VPN tunnels: how many of those the service runs are up, or why it runs none.</summary>
    public static string Summary(ServiceStatus? status) => status switch
    {
        null => "Service not connected",
        { VpnBackends: { } backends } when !backends.Contains("WireGuard") => "No WireGuard backend in this package",
        { Tunnels: { Count: > 0 } tunnels } => $"WireGuard tunnels run by the service; {tunnels.Count(t => t.State == "Up")} of {tunnels.Count} up",
        _ => "WireGuard tunnels run by the service; none running"
    };

    private static string Size(long bytes) => bytes switch
    {
        >= 1_000_000_000 => $"{bytes / 1e9:0.0} GB",
        >= 1_000_000 => $"{bytes / 1e6:0.0} MB",
        >= 1_000 => $"{bytes / 1e3:0} KB",
        _ => $"{bytes} B"
    };

    private static string Time(DateTimeOffset at, DateTimeOffset now)
    {
        var local = at.ToLocalTime();
        return local.Date == now.ToLocalTime().Date ? local.ToString("HH:mm") : local.ToString("MMM d, HH:mm");
    }

    /// <summary>
    /// The VPN page's alert while the editor's routes don't run as edited; null when they do, when there are none, or while
    /// the changes are being applied.
    /// </summary>
    public static VpnPageAlert? Alert(AppState draft, ServiceStatus? status, bool offline, bool elevated, bool applying = false)
    {
        var routes = Draft(draft);
        if (status is null)
            return offline && routes.Count > 0 ? new("The Darkwire service isn't answering", "VPN routes can't be applied or checked until it answers.", VpnPageAction.CheckAgain) : null;
        if (routes.Where(r => r.Kind != "WireGuard").Select(r => draft.VpnProfiles.FirstOrDefault(p => p.Id == r.ProfileId)?.Name ?? "a profile").ToList() is { Count: > 0 } retired)
            return new("OpenVPN profiles no longer connect", $"Darkwire runs WireGuard tunnels only, so what goes through {string.Join(", ", retired)} is refused. " +
                "Remove those profiles, and import your provider's WireGuard configuration instead.", VpnPageAction.CheckAgain);
        var missing = routes.Select(r => r.Kind).Distinct().Where(kind => status.VpnBackends is { } backends && !backends.Contains(kind)).ToList();
        if (missing.Count > 0)
            return new($"This package can't run {string.Join(" or ", missing)} tunnels", $"The Darkwire service has no {string.Join(" or ", missing)} backend, so routes through those profiles can't connect. Install a Darkwire package built with VPN backends.",
                VpnPageAction.CheckAgain);
        if (!status.Active)
            return routes.Count == 0 ? null : new("Darkwire isn't enforcing yet", "Your VPN routes start when Darkwire takes over Windows Firewall." + (elevated ? "" : " Setting it up needs administrator rights."),
                elevated ? VpnPageAction.SetUp : VpnPageAction.RestartElevated);
        if (applying || Applied(draft, status)) return null;
        return new("VPN changes aren't applied", (routes.Count == 0 ? "The service still routes through profiles you have since unassigned." : "The service doesn't route these applications the way the editor does yet.") +
            (elevated ? " Applying stores any configuration the service doesn't have yet." : " Applying them needs administrator rights."),
            elevated ? VpnPageAction.Apply : VpnPageAction.RestartElevated);
    }

    /// <summary>
    /// The full path a VPN profile can carry for a rule or connection path: an absolute executable, with environment
    /// variables expanded. Null for anything else, and for svchost.exe, whose every service would go with it.
    /// </summary>
    public static string? Routable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || RuleValidator.IsAny(path)) return null;
        var expanded = Environment.ExpandEnvironmentVariables(path.Trim());
        if (!Path.IsPathFullyQualified(expanded) || !expanded.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            var full = Path.GetFullPath(expanded);
            return VpnAssignments.Carriable(full) ? full : null;
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    /// <summary>
    /// Applications to offer for a profile: those seen connecting, then those the rules name, each once and by name. Shared
    /// service hosts, Darkwire's own programs and the profile's own applications are left out.
    /// </summary>
    /// <param name="own">Darkwire's install directory; nothing under it can travel through a tunnel.</param>
    public static IReadOnlyList<VpnAppChoice> Choices(VpnProfile target, AppState draft, IEnumerable<Connection> seen, IEnumerable<FirewallRule> rules, string own)
    {
        var offered = new HashSet<string>(target.Applications, StringComparer.OrdinalIgnoreCase);
        var ownDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(own)) + Path.DirectorySeparatorChar;
        IEnumerable<VpnAppChoice> Offer(IEnumerable<(string Name, string Path)> found, string source)
        {
            var choices = new List<VpnAppChoice>();
            foreach (var (name, path) in found)
            {
                if (Routable(path) is not { } full || full.StartsWith(ownDirectory, StringComparison.OrdinalIgnoreCase) || !offered.Add(full)) continue;
                var current = draft.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(full, StringComparer.OrdinalIgnoreCase))?.Name;
                choices.Add(new(string.IsNullOrWhiteSpace(name) ? Path.GetFileNameWithoutExtension(full) : name.Trim(), full, source, current));
            }
            return choices.OrderBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase);
        }
        // A service can go only when it runs alone in a program of its own, outside Windows.
        var connected = Offer(seen.Where(c => c.Service.Length == 0 && c.HostedServices.Length == 0 || VpnAssignments.CarriableService(c.Path, c.HostedServices))
            .Select(c => (c.Service.Length > 0 ? c.Service : c.Application, c.Path)), "Seen connecting").ToList();
        return [.. connected, .. Offer(rules.Where(r => RuleValidator.IsAny(r.Service)).Select(r => (r.ApplicationName, r.Path)), "Named in your rules")];
    }
}
