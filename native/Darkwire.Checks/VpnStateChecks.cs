using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Host;

/// <summary>The VPN page says what each tunnel is doing or what would start it, and when the editor's routes aren't the enforced ones.</summary>
internal static class VpnStateChecks
{
    private const string Browser = @"C:\Apps\browser.exe", Editor = @"C:\Apps\editor.exe";

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "VPN page invariant failed.") { if (!value) throw new Exception(reason); }
        // The service enforcing the draft's routes as they are now, running the tunnel given.
        static ServiceStatus Active(AppState draft, TunnelStatus? tunnel = null) => new(true, true, "Active", FirewallMode.BlockNew, 900, true, "Enforcing.",
            Tunnels: tunnel is null ? null : [tunnel], VpnBackends: ["WireGuard"], Routes: VpnState.Draft(draft) is { Count: > 0 } routes ? routes : null);
        var now = DateTimeOffset.Now;

        check("A profile nothing routes through asks for an application or the default route", () =>
        {
            var work = new VpnProfile { Name = "Work", Endpoint = "vpn.example.net:51820" }; var draft = new AppState { VpnProfiles = [work] };
            Expect(VpnState.Describe(work, draft, Active(draft), false, now) is { Pill: "NOT IN USE", Tone: VpnTone.Quiet } && VpnState.Alert(draft, Active(draft), false, true) is null);
        });
        check("Routes the service doesn't enforce yet ask to be applied, after restarting elevated when needed", () =>
        {
            var work = new VpnProfile { Name = "Work", Endpoint = "vpn.example.net:51820", CredentialsRevision = Guid.NewGuid() };
            var draft = new AppState { VpnProfiles = [work] }; var unrouted = Active(draft);
            work.Applications.Add(Browser);
            Expect(VpnState.Describe(work, draft, unrouted, false, now) is { Pill: "NOT APPLIED", Tone: VpnTone.Warn });
            Expect(VpnState.Alert(draft, unrouted, false, true) is { Action: VpnPageAction.Apply } && VpnState.Alert(draft, unrouted, false, false) is { Action: VpnPageAction.RestartElevated });
            // Enforced as edited, nothing is left to apply, whatever the letter case of the path.
            var applied = Active(draft); work.Applications[0] = Browser.ToUpperInvariant();
            Expect(VpnState.Applied(draft, applied) && VpnState.Alert(draft, applied, false, true) is null);
            // A route the editor dropped is a change too.
            work.Applications.Clear();
            Expect(VpnState.Describe(work, draft, applied, false, now) is { Pill: "NOT APPLIED" } && VpnState.Alert(draft, applied, false, true) is { Action: VpnPageAction.Apply });
            // So are credentials stored again.
            work.Applications.Add(Browser); work.CredentialsRevision = Guid.NewGuid();
            Expect(!VpnState.Applied(draft, applied));
        });
        check("Route changes on their way to the service read as applying, with no call to apply them", () =>
        {
            var work = new VpnProfile { Name = "Work", Endpoint = "vpn.example.net:51820", CredentialsRevision = Guid.NewGuid() };
            var draft = new AppState { VpnProfiles = [work] }; var unrouted = Active(draft);
            work.Applications.Add(Browser);
            Expect(VpnState.Describe(work, draft, unrouted, false, now, applying: true) is { Pill: "APPLYING", Tone: VpnTone.Busy } && VpnState.Alert(draft, unrouted, false, true, applying: true) is null);
            // A running tunnel says its route changes are being applied.
            var up = VpnState.Describe(work, draft, Active(new AppState { VpnProfiles = [new() { Id = work.Id, CredentialsRevision = work.CredentialsRevision, KeepConnected = true }] }, new(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"])), false, now, applying: true);
            Expect(up is { Pill: "CONNECTED" } && up.Detail.EndsWith("Applying your changes to its routes.", StringComparison.Ordinal), up.Detail);
            // Whatever else stops the routes still shows: here, Darkwire not enforcing yet.
            Expect(VpnState.Alert(draft, unrouted with { Active = false, Phase = "Inactive" }, false, true, applying: true) is { Action: VpnPageAction.SetUp });
        });
        check("A tunnel shows as connecting, connected with its addresses and resolvers, or down with its error", () =>
        {
            var work = new VpnProfile { Name = "Work", Endpoint = "vpn.example.net:51820", Applications = [Browser] };
            var draft = new AppState { VpnProfiles = [work], DefaultOutboundVpnProfileId = work.Id };
            var starting = VpnState.Describe(work, draft, Active(draft, new(work.Id, "WireGuard", "Starting", now)), false, now);
            Expect(starting is { Pill: "CONNECTING", Tone: VpnTone.Busy } && starting.Detail.Contains("vpn.example.net:51820"), starting.Detail);
            var up = VpnState.Describe(work, draft, Active(draft, new(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], Resolvers: ["10.64.0.1"])), false, now);
            Expect(up is { Pill: "CONNECTED", Tone: VpnTone.Good } && up.Detail.Contains("10.64.0.2") && up.Detail.Contains("DNS 10.64.0.1"), up.Detail);
            // Carrying every other application, a tunnel without a resolver leaves Windows lookups refused.
            var silent = VpnState.Describe(work, draft, Active(draft, new(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], Resolvers: [])), false, now);
            Expect(silent.Detail.Contains("no DNS server"), silent.Detail);
            // Sharing its address with another profile's tunnel, it says so, and that pings through it go unanswered.
            var sharing = VpnState.Describe(work, draft, Active(draft, new(work.Id, "WireGuard", "Up", now, 9, ["10.88.0.2"], Resolvers: ["10.88.0.1"], Shared: ["10.88.0.2"])), false, now);
            Expect(sharing is { Pill: "CONNECTED", Tone: VpnTone.Good } && sharing.Detail.Contains("10.88.0.2 shared with another connected profile") && sharing.Detail.Contains("pings"), sharing.Detail);
            Expect(!up.Detail.Contains("shared"), up.Detail);
            // A running tunnel's throughput: the latest rates in and out, and the peaks over the samples the service keeps.
            Expect(VpnState.Bits(950) == "950 bps" && VpnState.Bits(12_400) == $"{12.4:0} kbps" && VpnState.Bits(12_400_000) == $"{12.4:0.0} Mbps" && VpnState.Bits(2_500_000_000) == $"{2.5:0.00} Gbps");
            var busy = new TunnelStatus(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], InRates: [1_000_000, 24_000_000], OutRates: [500_000, 1_200_000]);
            Expect(VpnState.Throughput(busy) is { } rates && rates.Received == $"↓ {24.0:0.0} Mbps" && rates.Sent == $"↑ {1.2:0.0} Mbps" &&
                rates.Peak == $"Peak ↓ {24.0:0.0} Mbps  ↑ {1.2:0.0} Mbps in the last 4 s", VpnState.Throughput(busy)?.Peak ?? "No throughput.");
            Expect(VpnState.Throughput(busy with { State = "Failed" }) is null && VpnState.Throughput(busy with { InRates = null }) is null);
            var down = VpnState.Describe(work, draft, Active(draft, new(work.Id, "WireGuard", "Failed", now, Error: "The handshake never completed.")), false, now);
            Expect(down is { Pill: "DOWN", Tone: VpnTone.Bad } && down.Detail.Contains("handshake never completed") && !down.Detail.Contains(".."), down.Detail);
            var running = Active(draft, new(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], Resolvers: ["10.64.0.1"]));
            work.Applications.Add(Editor);
            Expect(VpnState.Describe(work, draft, running, false, now).Detail.Contains("aren't applied"), "Edits to a running profile were not pointed out.");
        });
        check("A missing backend, a service not enforcing, Lockdown and a silent service are each named", () =>
        {
            var work = new VpnProfile { Name = "Work", Applications = [Browser] }; var draft = new AppState { VpnProfiles = [work] };
            var bare = Active(draft) with { VpnBackends = [] };
            Expect(VpnState.Describe(work, draft, bare, false, now) is { Pill: "NO BACKEND" });
            Expect(VpnState.Alert(draft, bare, false, true) is { Action: VpnPageAction.CheckAgain } alert && alert.Title.Contains("WireGuard"));
            var idle = new ServiceStatus(true, false, "Inactive", FirewallMode.Learning, 0, true, "Windows Firewall is in control.", VpnBackends: ["WireGuard"]);
            Expect(VpnState.Describe(work, draft, idle, false, now) is { Pill: "NOT ENFORCING" });
            Expect(VpnState.Alert(draft, idle, false, true) is { Action: VpnPageAction.SetUp } && VpnState.Alert(draft, idle, false, false) is { Action: VpnPageAction.RestartElevated });
            Expect(VpnState.Describe(work, draft, Active(draft) with { Mode = FirewallMode.Lockdown }, false, now) is { Pill: "LOCKDOWN" });
            Expect(VpnState.Describe(work, draft, null, true, now) is { Pill: "UNKNOWN" } && VpnState.Alert(draft, null, true, true) is { Action: VpnPageAction.CheckAgain });
            Expect(VpnState.Describe(work, draft, null, false, now) is { Pill: "CHECKING" } && VpnState.Alert(draft, null, false, true) is null);
            // An applied route whose tunnel the service doesn't run quotes the service's alert about it.
            var stuck = Active(draft) with { Alerts = ["VPN profiles that cannot run keep their applications blocked: Work: stored credentials are unreadable."] };
            Expect(VpnState.Describe(work, draft, stuck, false, now) is { Pill: "NOT RUNNING" } view && view.Detail.Contains("unreadable"));
        });
        check("Settings sums up the tunnels: how many the service runs are up, or why it runs none", () =>
        {
            var work = new VpnProfile { Name = "Work", Applications = [Browser] }; var draft = new AppState { VpnProfiles = [work] };
            var running = Active(draft) with { Tunnels = [new(work.Id, "WireGuard", "Up", now), new(Guid.NewGuid(), "WireGuard", "Starting", now)] };
            Expect(VpnState.Summary(running) == "WireGuard tunnels run by the service; 1 of 2 up", VpnState.Summary(running));
            Expect(VpnState.Summary(Active(draft)) == "WireGuard tunnels run by the service; none running", VpnState.Summary(Active(draft)));
            Expect(VpnState.Summary(Active(draft) with { VpnBackends = [] }) == "No WireGuard backend in this package" && VpnState.Summary(null) == "Service not connected");
        });
        check("An OpenVPN profile from an earlier build never connects, and its card and the page say so rather than ask for a backend", () =>
        {
            var old = new VpnProfile { Name = "Old", Kind = "OpenVPN", Endpoint = "vpn.example.net:1194" }; var draft = new AppState { VpnProfiles = [old] };
            var unused = VpnState.Describe(old, draft, Active(draft), false, now);
            Expect(unused is { Pill: "NOT SUPPORTED", Tone: VpnTone.Warn } && unused.Detail.Contains("WireGuard tunnels only") && VpnState.Alert(draft, Active(draft), false, true) is null, unused.Detail);
            old.Applications.Add(Browser);
            var routed = VpnState.Describe(old, draft, Active(draft), false, now);
            Expect(routed is { Pill: "NOT SUPPORTED", Tone: VpnTone.Bad } && routed.Detail.Contains("refused"), routed.Detail);
            var alert = VpnState.Alert(draft, Active(draft), false, true);
            Expect(alert is { Action: VpnPageAction.CheckAgain } && alert.Detail.Contains("Old") && !alert.Detail.Contains("backend"), alert?.Detail ?? "No alert.");
        });
        check("A connected profile runs with nothing routed through it, and a tunnel that sends without answers says its server isn't replying", () =>
        {
            var ready = new VpnProfile { Name = "Ready", Endpoint = "vpn.example.net:51820", KeepConnected = true };
            var draft = new AppState { VpnProfiles = [ready] };
            Expect(VpnState.Draft(draft).Single() is { Kept: true, Default: false, Applications.Count: 0 });
            var idle = VpnState.Describe(ready, draft, Active(draft, new(ready.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], SentBytes: 2_000, ReceivedBytes: 40_000)), false, now);
            Expect(idle is { Pill: "CONNECTED" } && idle.Detail.Contains("Nothing goes through it yet") && idle.Detail.Contains("40 KB in, 2 KB out"), idle.Detail);
            var silent = VpnState.Describe(ready, draft, Active(draft, new(ready.Id, "WireGuard", "Up", now - TimeSpan.FromSeconds(30), 9, ["10.64.0.2"], SentBytes: 2_000)), false, now);
            Expect(silent is { Pill: "NO REPLY", Tone: VpnTone.Bad } && silent.Detail.Contains("hasn't answered"), silent.Detail);
            // WireGuard counts nothing sent before its handshake succeeds; traffic the router sent in is enough.
            var held = new TunnelStatus(ready.Id, "WireGuard", "Up", now - TimeSpan.FromMinutes(1), 9, ["10.64.0.2"], Routed: now - TimeSpan.FromSeconds(12));
            Expect(VpnState.Describe(ready, draft, Active(draft, held), false, now) is { Pill: "NO REPLY" });
            Expect(VpnState.Describe(ready, draft, Active(draft, held with { Routed = now - TimeSpan.FromSeconds(3) }), false, now) is { Pill: "CONNECTED" });
            Expect(VpnState.Describe(ready, draft, Active(draft, held with { ReceivedBytes = 148 }), false, now) is { Pill: "CONNECTED" });
            // A server that answered and then fell silent: no reply too, saying when it last answered.
            var answered = held with { ReceivedBytes = 148, LastReceived = now - TimeSpan.FromSeconds(40) };
            var quiet = VpnState.Describe(ready, draft, Active(draft, answered with { Silent = now - TimeSpan.FromSeconds(30) }), false, now);
            Expect(quiet is { Pill: "NO REPLY", Tone: VpnTone.Bad } && quiet.Detail.Contains("stopped answering at ") && quiet.Detail.Contains("nothing sent through it since"), quiet.Detail);
            Expect(VpnState.Describe(ready, draft, Active(draft, answered with { Silent = now - TimeSpan.FromSeconds(4) }), false, now) is { Pill: "CONNECTED" });
            // Reconnected because its server stopped answering: said while it connects again, and while it still has no answer.
            var reconnecting = VpnState.Describe(ready, draft, Active(draft, new(ready.Id, "WireGuard", "Starting", now, Reconnects: 1)), false, now);
            Expect(reconnecting is { Pill: "CONNECTING", Tone: VpnTone.Busy } && reconnecting.Detail.Contains("Darkwire is reconnecting"), reconnecting.Detail);
            var still = VpnState.Describe(ready, draft, Active(draft, held with { Reconnects = 2 }), false, now);
            Expect(still is { Pill: "NO REPLY", Tone: VpnTone.Bad } && still.Detail.Contains("reconnected it 2 times"), still.Detail);
            // Just up, or with nothing sent yet, is no silence.
            Expect(VpnState.Describe(ready, draft, Active(draft, new(ready.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], SentBytes: 2_000)), false, now) is { Pill: "CONNECTED" });
            Expect(VpnState.Describe(ready, draft, Active(draft, new(ready.Id, "WireGuard", "Up", now - TimeSpan.FromSeconds(30), 9, ["10.64.0.2"])), false, now) is { Pill: "CONNECTED" });
            // Disconnecting it is a change to apply.
            var running = Active(draft); ready.KeepConnected = false;
            Expect(!VpnState.Applied(draft, running) && VpnState.Describe(ready, draft, running, false, now) is { Pill: "NOT APPLIED" });
        });
        check("While tunnels start or are checked end to end, a banner says which, and each card says it is being checked or that its check failed", () =>
        {
            var work = new VpnProfile { Name = "Work", Endpoint = "vpn.example.net:51820", Applications = [Browser] };
            var home = new VpnProfile { Name = "Home", Endpoint = "home.example.net:51820", KeepConnected = true };
            var draft = new AppState { VpnProfiles = [work, home], DefaultOutboundVpnProfileId = work.Id };
            var up = new TunnelStatus(work.Id, "WireGuard", "Up", now, 9, ["10.64.0.2"], Resolvers: ["10.64.0.1"]);
            ServiceStatus Both(TunnelStatus first, TunnelStatus second) => Active(draft) with { Tunnels = [first, second] };
            // Before the service's first answer the routed profiles stand for the tunnels; offline, or with nothing routed, no banner.
            Expect(VpnState.Establishing(draft, null, false) is { Detail: var asking } && asking.Contains("Asking the Darkwire service"));
            Expect(VpnState.Establishing(draft, null, true) is null && VpnState.Establishing(new AppState { VpnProfiles = [new()] }, null, false) is null);
            var banner = VpnState.Establishing(draft, Both(up with { Checking = true }, new(home.Id, "WireGuard", "Starting", now)), false);
            Expect(banner is { Title: var title, Detail: var detail } && title.Contains("please wait") && detail.StartsWith("Work is being checked and Home is starting", StringComparison.Ordinal), banner?.Detail ?? "No banner.");
            // Once each has passed its check, failed it or gone down, and whenever Darkwire doesn't enforce, the banner goes.
            Expect(VpnState.Establishing(draft, Both(up with { Checked = now }, new(home.Id, "WireGuard", "Failed", now, Error: "No answer.")), false) is null);
            Expect(VpnState.Establishing(draft, Both(up with { CheckFailed = now }, up with { ProfileId = home.Id, Checked = now }), false) is null);
            Expect(VpnState.Establishing(draft, Both(up with { Checking = true }, up) with { Active = false, Phase = "Inactive" }, false) is null);
            // Its card: checking while the check goes on; no reply once it failed, saying how often Darkwire restarted it.
            Expect(VpnState.Describe(work, draft, Both(up with { Checking = true }, up), false, now) is { Pill: "CHECKING", Tone: VpnTone.Busy });
            var failed = VpnState.Describe(work, draft, Both(up with { CheckFailed = now, CheckRestarts = 2 }, up), false, now);
            Expect(failed is { Pill: "NO REPLY", Tone: VpnTone.Bad } && failed.Detail.Contains("didn't answer through it") && failed.Detail.Contains("restarted it twice"), failed.Detail);
            var again = VpnState.Describe(work, draft, Both(new(work.Id, "WireGuard", "Starting", now, CheckRestarts: 1), up), false, now);
            Expect(again is { Pill: "CONNECTING" } && again.Detail.Contains("carried nothing back"), again.Detail);
        });
        check("A disconnected profile stays in the routes without a tunnel, its card says what it refuses, and connecting it is a change to apply", () =>
        {
            var work = new VpnProfile { Name = "Work", Applications = [Browser], Disconnected = true };
            var draft = new AppState { VpnProfiles = [work], DefaultOutboundVpnProfileId = work.Id };
            Expect(VpnState.Draft(draft).Single() is { Disconnected: true, Default: true } && !VpnAssignments.Tunneled(draft).Any() && VpnAssignments.Running(draft).Single() == work);
            var card = VpnState.Describe(work, draft, Active(draft), false, now);
            Expect(card is { Pill: "DISCONNECTED", Tone: VpnTone.Warn } && card.Detail.Contains("its application, every application without a profile of its own and Darkwire's own connections"), card.Detail);
            var enforced = Active(draft); work.Disconnected = false;
            Expect(!VpnState.Applied(draft, enforced) && VpnState.Describe(work, draft, enforced, false, now) is { Pill: "NOT APPLIED" });
        });
        check("Whether local traffic stays off the tunnels is part of what gets applied", () =>
        {
            var work = new VpnProfile { Name = "Work", Applications = [Browser] }; var draft = new AppState { VpnProfiles = [work] };
            var enforced = Active(draft) with { LocalNetworkBypassesVpn = true };
            Expect(VpnState.Applied(draft, enforced));
            draft.LocalNetworkBypassesVpn = false;
            Expect(!VpnState.Applied(draft, enforced) && VpnState.Alert(draft, enforced, false, true) is { Action: VpnPageAction.Apply });
            // With nothing routed the setting matters to nothing.
            work.Applications.Clear();
            Expect(VpnState.Applied(draft, Active(draft) with { LocalNetworkBypassesVpn = true }));
        });
        check("Applications offered for a profile are executables seen or named in rules, never svchost.exe or Darkwire's own", () =>
        {
            Expect(VpnState.Routable(@"%SystemRoot%\System32\curl.exe") is { } curl &&
                curl.Equals(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "curl.exe"), StringComparison.OrdinalIgnoreCase));
            Expect(VpnState.Routable("*") is null && VpnState.Routable("System") is null && VpnState.Routable(@"C:\Windows\System32\svchost.exe") is null && VpnState.Routable(@"C:\Apps\notes.txt") is null);
            var work = new VpnProfile { Name = "Work", Applications = [Editor] }; var home = new VpnProfile { Name = "Home", Applications = [@"C:\Apps\chat.exe"] };
            var draft = new AppState { VpnProfiles = [work, home] };
            static Connection Seen(string name, string path, string service = "") =>
                new(name, path, 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound, Service: service, HostedServices: service);
            var seen = new[] { Seen("Browser", Browser), Seen("Browser", Browser), Seen("Chat", @"C:\Apps\chat.exe"), Seen("Editor", Editor),
                Seen("svchost", @"C:\Windows\System32\svchost.exe", "Dnscache"), Seen("Darkwire", @"C:\Program Files\Darkwire\Service\Darkwire.Service.exe") };
            FirewallRule[] named = [new() { ApplicationName = "Zip", Path = @"C:\Apps\zip.exe" }, new() { ApplicationName = "Browser rule", Path = Browser },
                new() { ApplicationName = "Update", Path = @"C:\Apps\update.exe", Service = "wuauserv" }];
            var choices = VpnState.Choices(work, draft, seen, named, @"C:\Program Files\Darkwire\");
            Expect(choices.Select(c => c.Name).SequenceEqual(["Browser", "Chat", "Zip"]), string.Join(", ", choices.Select(c => c.Name)));
            Expect(choices[0].CurrentProfile is null && choices[1] is { CurrentProfile: "Home", Source: "Seen connecting" } && choices[2].Source == "Named in your rules");
        });
    }
}
