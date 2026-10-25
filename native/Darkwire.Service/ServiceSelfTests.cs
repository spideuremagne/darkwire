using Darkwire.Core;
using Darkwire.Engine;

namespace Darkwire.Service;

internal static class ServiceSelfTests
{
    public static int Run()
    {
        var failed = 0; var passed = 0;
        void Check(string name, Action action) { try { action(); Console.WriteLine("PASS " + name); passed++; } catch (Exception error) { Console.WriteLine("FAIL " + name + ": " + error.Message); failed++; } }
        void Assert(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
        // Built-in loopback, core networking, edge guard, default and router filters for a rule-free Block new policy.
        var baseFilters = FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }, network: NetworkSnapshot.Empty), FakeRouter.TestPlan).Filters.Count;
        FirewallRule Imported(string id, string definition, ImportOutcome outcome) => new()
        { ApplicationName = id, WindowsRuleId = id, OriginalDefinition = definition, Import = outcome, Source = "Windows Firewall", Protocol = "TCP", RemotePorts = "443", ImportWarning = outcome == ImportOutcome.Exact ? null : "Not translatable: test scope." };
        Check("Takeover installs filters before disabling profiles", () =>
        {
            using var t = new Rig(); var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(result.Success, result.Message); Assert(t.Events.IndexOf("apply") < t.Events.IndexOf("disable"));
            Assert(t.Journal.Value.Phase == "Active" && t.Backend.FilterCount == baseFilters);
        });
        Check("Routing starts after the kernel plan and before Windows Firewall is disabled", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Events.IndexOf("apply") < t.Events.IndexOf("router-start") && t.Events.IndexOf("router-start") < t.Events.IndexOf("disable"));
            Assert(t.Backend.Installed.Any(f => f.Name == "Router: leak guard") && t.Router.Context!.Plan.Filters.All(f => !f.Name.StartsWith("Router:", StringComparison.Ordinal)));
        });
        Check("A missing routing runtime refuses takeover before any change unless routing is off", () =>
        {
            using var t = new Rig(); t.Router.Available = false;
            var refused = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(!refused.Success && refused.Message.Contains("Wintun") && !t.Events.Contains("backup") && !t.Events.Contains("apply"));
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, RouteConnections = false })).Success);
            Assert(!t.Events.Contains("router-start") && t.Backend.Installed.All(f => !f.Name.StartsWith("Router:", StringComparison.Ordinal)));
        });
        Check("A router that cannot start rolls the takeover back", () =>
        {
            using var t = new Rig(); t.Router.StartFailure = true;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Events.Contains("disable") && t.Events.IndexOf("restore") < t.Events.IndexOf("remove") && t.Journal.Value.Phase == "Inactive");
        });
        Check("Restoration stops the router before removing filters", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Events.Clear(); Assert(t.Service.Handle(new("restore")).Success);
            Assert(string.Join(",", t.Events.Where(e => e is "restore" or "router-stop" or "remove")) == "restore,router-stop,remove");
        });
        Check("A router that stopped by itself is restarted and reported", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Router.Running = false; t.Router.Fault = "The tunnel adapter was removed.";
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "router-start") == 2 && t.Service.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("adapter was removed")));
        });
        Check("The startup lock holds until the restored router's VPN tunnels are up or failed, then is released", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig("Active", clock: clock);
            var profile = t.Vault.Store("Office", "WireGuard", "198.51.100.7:51820", @"C:\Apps\browser.exe");
            t.Journal.Value.Policy = new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] };
            t.Service.Recover();
            Assert(t.Router.Running && t.Backend.Locked.Count > 0 && !t.Backend.Released && t.Service.Handle(new("status")).Status!.StartupLocked);
            // The lock lets Darkwire's service and the backend's peer through; nothing else.
            Assert(t.Backend.Locked.Any(f => f.ApplicationPath == Environment.ProcessPath && f.Action == RuleAction.Allow) &&
                t.Backend.Locked.Any(f => f.ApplicationPath?.EndsWith("wireguard.exe", StringComparison.OrdinalIgnoreCase) == true && f.RemoteNetwork == "198.51.100.7/32"));
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Starting", clock.Now));
            t.Service.Tick();
            Assert(!t.Backend.Released && t.Service.Handle(new("status")).Status!.StartupLocked, "The lock let go while a tunnel was starting.");
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { State = "Up" };
            t.Service.Tick();
            Assert(t.Backend.Released && !t.Service.Handle(new("status")).Status!.StartupLocked && t.Service.Handle(new("status")).Message.Contains("startup lock is released"));
        });
        Check("Released, the startup lock stays installed through an interface change, so the next start is locked again", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig("Active", clock: clock); t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], [], [], [], [])]);
            var profile = t.Vault.Store("Office", "WireGuard", "198.51.100.7:51820", @"C:\Apps\browser.exe");
            var smb = new FirewallRule { ApplicationName = "SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "LocalSubnet" };
            t.Journal.Value.Policy = new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], Rules = [smb] };
            t.Service.Recover();
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", clock.Now));
            t.Service.Tick();
            Assert(t.Backend.Released && t.Backend.Locked.Count > 0);
            var applies = t.Events.Count(e => e == "apply");
            t.Network.Snapshot = new([new(7, ["10.0.0.0/24"], [], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "apply") == applies + 1, "The interface change was not applied.");
            Assert(t.Backend.Locked.Count > 0, "The reinstalled plan left out the startup lock.");
        });
        Check("Each filter install is recorded with what it was for and the startup lock its plan held and WFP registered, and so is the audit", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig("Active", clock: clock); t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], [], [], [], [])]);
            var smb = new FirewallRule { ApplicationName = "SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "LocalSubnet" };
            t.Journal.Value.Policy = new() { Mode = FirewallMode.BlockNew, Rules = [smb] };
            t.Service.Recover();
            var first = t.Service.Handle(new("status")).Status!.Filters!;
            Assert(first is { Released: false, AuditedAt: null, Installs: [{ Cause: "recovery", Restored: false, LockPlanned: > 0 } recovery] } &&
                recovery.LockRegistered == recovery.LockPlanned && first.LockFilters == recovery.LockPlanned && recovery.Revision == t.Journal.Value.Revision, "The recovery install was not recorded.");
            t.Service.Tick();
            t.Network.Snapshot = new([new(7, ["10.0.0.0/24"], [], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            t.Service.Tick(verifyIntegrity: true);
            var later = t.Service.Handle(new("status")).Status!.Filters!;
            Assert(later is { Released: true, AuditedAt: not null, Installs: [{ Cause: "interface change", Restored: true, LockPlanned: > 0 } change, { Cause: "recovery" }] } &&
                change.LockRegistered == change.LockPlanned && later.AuditedLock == change.LockRegistered && later.AuditedFilters == change.Filters, "The interface change or the audit was not recorded.");
        });
        Check("A startup lock missing after an install, or from WFP at an audit, is reported once until it is back", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig("Active", clock: clock); t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], [], [], [], [])]);
            var smb = new FirewallRule { ApplicationName = "SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "LocalSubnet" };
            t.Journal.Value.Policy = new() { Mode = FirewallMode.BlockNew, Rules = [smb] };
            t.Service.Recover(); t.Service.Tick();
            int Count(string text) => t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains(text));
            void Change(string subnet) { t.Network.Snapshot = new([new(7, [subnet], [], [], [], [])]); for (var i = 0; i < 5; i++) t.Service.Tick(); }
            const string AfterChange = "The startup lock is missing after the interface change", Audit = "The filter audit found no startup lock in WFP";
            t.Backend.LoseLock = true;
            Change("10.0.0.0/24");
            Assert(Count(AfterChange) == 1 && t.Service.Handle(new("status")).Status!.Filters!.Installs[0] is { Cause: "interface change", LockPlanned: > 0, LockRegistered: 0 },
                "An install that registered no lock was not reported.");
            Change("10.0.1.0/24");
            Assert(Count(AfterChange) == 1, "A lock still missing was reported again.");
            // Back, it is reported again when it goes missing next, here from WFP as an audit finds it.
            t.Backend.LoseLock = false;
            Change("10.0.2.0/24");
            t.Backend.AuditFinds = (t.Backend.FilterCount, 0);
            t.Service.Tick(verifyIntegrity: true); t.Service.Tick(verifyIntegrity: true);
            Assert(Count(Audit) == 1 && Count(AfterChange) == 1, "A lock an audit found missing was not reported once.");
        });
        Check("Windows Security's firewall warnings are hidden while Darkwire enforces unless the policy shows them, and the value they replaced comes back", () =>
        {
            using var t = new Rig(); t.FirewallArea.Value = 0;
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.FirewallArea.Value == 1 && t.Journal.Value.OriginalFirewallArea == new SavedValue(0) && t.Service.Handle(new("status")).Status!.FirewallWarningsHidden == true,
                "A takeover left Windows Security's firewall warnings shown.");
            var shown = t.Service.Handle(new("apply-settings", Settings: new(ShowFirewallWarnings: true)));
            Assert(shown.Success && t.FirewallArea.Value == 0 && t.Journal.Value.OriginalFirewallArea is null && shown.Status!.FirewallWarningsHidden == false &&
                t.Journal.Value.Policy.ShowFirewallWarnings, shown.Message);
            var hidden = t.Service.Handle(new("apply-settings", Settings: new(ShowFirewallWarnings: false)));
            Assert(hidden.Success && t.FirewallArea.Value == 1 && t.Journal.Value.OriginalFirewallArea == new SavedValue(0) && hidden.Status!.FirewallWarningsHidden == true, hidden.Message);
            // Windows Firewall restored: the administrator's own 0 is back.
            Assert(t.Service.Handle(new("restore")).Success && t.FirewallArea.Value == 0 && t.Journal.Value.OriginalFirewallArea is null && t.Journal.Value.Phase == "Inactive");
            Assert(t.Service.Handle(new("status")).Status!.FirewallWarningsHidden is null);
        });
        Check("A takeover that shows them leaves Windows Security alone, an install from before hides them at its next start, and restoring removes a value that was never set", () =>
        {
            using var t = new Rig();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, ShowFirewallWarnings = true })).Success);
            Assert(t.FirewallArea.Value is null && t.Journal.Value.OriginalFirewallArea is null && !t.Events.Any(e => e.StartsWith("firewall-area")) &&
                t.Service.Handle(new("status")).Status!.FirewallWarningsHidden == false, "Windows Security was changed though the policy shows its warnings.");
            // A takeover journaled before the setting existed, or one whose value was removed behind Darkwire's back: the next start hides them.
            using var upgraded = new Rig("Active");
            upgraded.Service.Recover();
            Assert(upgraded.FirewallArea.Value == 1 && upgraded.Journal.Value.OriginalFirewallArea == new SavedValue(null), "Recovery left the warnings shown.");
            Assert(upgraded.Service.Handle(new("restore")).Success && upgraded.FirewallArea.Value is null && upgraded.Journal.Value.OriginalFirewallArea is null);
            Assert(upgraded.Events.Contains("firewall-area unset"));
        });
        Check("A policy value Windows refuses is reported and leaves the takeover in force, showing the warnings", () =>
        {
            using var t = new Rig(); t.FirewallArea.Failure = true;
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success && t.Journal.Value.Phase == "Active");
            var status = t.Service.Handle(new("status")).Status!;
            Assert(status.FirewallWarningsHidden == false && status.Alerts!.Any(a => a.Contains("Windows Security's firewall warnings could not be hidden: Access is denied.")), string.Join(" | ", status.Alerts!));
        });
        Check("The startup lock lets go after its limit while a tunnel still starts, whose flows the router keeps holding", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig("Active", clock: clock);
            var profile = t.Vault.Store("Office", "WireGuard", "198.51.100.7:51820");
            t.Journal.Value.Policy = new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id };
            t.Service.Recover();
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Starting", clock.Now));
            clock.Now += TakeoverCoordinator.StartupLockLimit - TimeSpan.FromSeconds(1); t.Service.Tick();
            Assert(!t.Backend.Released);
            clock.Now += TimeSpan.FromSeconds(1); t.Service.Tick();
            Assert(t.Backend.Released && t.Router.Context!.Tunnels?.DefaultProfileId == profile.Id);
        });
        Check("Once started, every install releases the startup lock first, so changing policy never holds the network", () =>
        {
            using var t = new Rig(); t.Service.Tick();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success && t.Backend.Locked.Count > 0);
            Assert(t.Events.IndexOf("release") >= 0 && t.Events.IndexOf("release") < t.Events.IndexOf("apply") && !t.Service.Handle(new("status")).Status!.StartupLocked);
        });
        Check("The startup lock follows the policy: off, or Open without VPN profiles, nothing holds the network", () =>
        {
            using var t = new Rig(); t.Service.Tick();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, StartupLock = false })).Success && t.Backend.Locked.Count == 0);
            var on = t.Service.Handle(new("apply-settings", Settings: new(StartupLock: true)));
            Assert(on.Success && t.Backend.Locked.Count > 0 && t.Journal.Value.Policy.StartupLock && on.Message.Contains("internet stays blocked"), on.Message);
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open }, ExpectedRevision: t.Journal.Value.Revision)).Success && t.Backend.Locked.Count == 0);
        });
        Check("A startup lock that cannot be released is left out of the installed filters and reported", () =>
        {
            using var t = new Rig(); t.Service.Tick(); t.Backend.ReleaseFailure = true;
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success && t.Backend.Locked.Count == 0);
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("startup lock could not be released")));
        });
        Check("Takeover keeps what was connected: one rule allowing everything out per application, in the Takeover group", () =>
        {
            var own = Path.Combine(Path.GetTempPath(), "Darkwire");
            static FlowProcess Running(string path, params string[] sids) => new(9, 1, path, new(path.ToLowerInvariant(), new HashSet<string>(sids, StringComparer.OrdinalIgnoreCase), null));
            var svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");
            var host = Running(svchost, IdentitySelectors.ServiceSid("Dnscache"), IdentitySelectors.ServiceSid("Dhcp"));
            FlowProcess[] connected = [Running(@"C:\Apps\browser.exe"), Running(@"C:\Apps\browser.exe"), Running(@"C:\Apps\mail.exe"), Running(Path.Combine(own, "Service", "Darkwire.Service.exe")),
                host, host with { TaggedService = "dnscache" }, Running("relative.exe")];
            // Darkwire's own programs, a relative path, an untagged shared host and an application rules already let out get none.
            var rules = TakeoverAcceptance.Rules(connected, own, [new() { ApplicationName = "mail", Path = @"C:\Apps\mail.exe" }]);
            Assert(rules.Count == 2 && rules.All(r => r is { Group: TakeoverAcceptance.Group, Action: RuleAction.Allow, Direction: TrafficDirection.Outbound, Protocol: "Any" } &&
                RuleValidator.IsAny(r.RemoteAddresses) && RuleValidator.IsAny(r.RemotePorts)));
            Assert(rules.Any(r => r.Path == @"C:\Apps\browser.exe" && r.Service == "*") && rules.Any(r => r.Path == svchost && r.Service.Equals("Dnscache", StringComparison.OrdinalIgnoreCase)));
            // The service passes what is connected at its takeover and keeps the rules in the policy it enforces.
            using var t = new Rig(connected: () => [Running(@"C:\Apps\browser.exe"), host with { TaggedService = "dnscache" }]);
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(result.Success && result.Policy!.Rules.Count(r => r.Group == TakeoverAcceptance.Group) == 2 && result.Message.Contains("2 applications that were connected"), result.Message);
            Assert(t.Backend.Installed.Any(f => f.ApplicationPath == @"C:\Apps\browser.exe" && f.Action == RuleAction.Allow && f.Direction == TrafficDirection.Outbound && f.RemoteNetwork is null));
        });
        Check("Policy settings apply alone at the enforced revision; one that cannot apply leaves the policy as it was", () =>
        {
            using var t = new Rig();
            Assert(!t.Service.Handle(new("apply-settings", Settings: new(InternalNetworks: InternalAccess.Block))).Success, "Settings applied before takeover.");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            var blocked = t.Service.Handle(new("apply-settings", Settings: new(InternalNetworks: InternalAccess.Block)));
            Assert(blocked.Success && t.Journal.Value.Policy.InternalNetworks == InternalAccess.Block && t.Journal.Value.Revision == 2 && blocked.Message.Contains("blocked unless a rule allows"), blocked.Message);
            Assert(t.Backend.Installed.Any(f => f.Name == "Internal networks" && f.Action == RuleAction.Deny));
            var lists = t.Service.Handle(new("apply-settings", Settings: new(Blocklists: [new() { Name = "Mine", Entries = ["198.51.100.0/24"] }])));
            Assert(lists.Success && t.Backend.Installed.Any(f => f.Name == "Mine" && f.RemoteNetwork == "198.51.100.0/24") && t.Journal.Value.Policy.InternalNetworks == InternalAccess.Block);
            // An allow list needs GeoIP data, which this service has none of.
            var refused = t.Service.Handle(new("apply-settings", Settings: new(Geography: new([], true, ["CH"], []))));
            Assert(!refused.Success && !t.Journal.Value.Policy.CountryAllowList && t.Journal.Value.Revision == 3, refused.Message);
        });
        Check("Blocklist hits count once in all and once for each list, with the kernel's drops for each list's filters", () =>
        {
            var counter = new BlocklistHitCounter();
            counter.Hit(["hagezi-pro", BlocklistHits.CustomKey("Mine")]); counter.Hit(["hagezi-pro"]); counter.Hit([]);
            var hits = counter.Snapshot([("firehol-level1", 5), ("hagezi-pro", 1)]);
            Assert(hits.Total == 8 && hits.ByList["hagezi-pro"] == 3 && hits.ByList[BlocklistHits.CustomKey("Mine")] == 1 && hits.ByList["firehol-level1"] == 5);
            using var t = new Rig();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, Blocklists = [new() { Name = "Mine", Entries = ["198.51.100.0/24"] }] })).Success);
            t.Backend.Drops["Mine"] = 4; t.Backend.Drops["Geographic restriction"] = 9;
            var status = t.Service.Handle(new("status")).Status!;
            Assert(status.ListHits is { Total: 4 } listed && listed.ByList[BlocklistHits.CustomKey("Mine")] == 4, "A list's kernel drops were not counted for it alone.");
        });
        Check("Open mode and disabled routing stop the router; enforced modes update it", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Lockdown }, ExpectedRevision: 1)).Success && t.Events.Contains("router-update"));
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open }, ExpectedRevision: 2)).Success && t.Events.Contains("router-stop") && !t.Router.Running);
        });
        Check("Answering a held connection's prompt hands the router a plan with the new rule", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Assert(t.Router.Broker!.Ask(new("Browser", @"C:\Apps\browser.exe", 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound)) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow)).Success);
            var plan = t.Router.Context!.Plan;
            Assert(plan.Filters.Any(f => f.ApplicationPath == @"C:\Apps\browser.exe" && f.Action == RuleAction.Allow && f.RemoteNetwork == "203.0.113.7"));
        });
        Check("A prompt's chosen scope reaches the rule the service installs, for that application only", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Assert(t.Router.Broker!.Ask(new("Browser", @"C:\Apps\browser.exe", 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound)) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, Scope: LearningScope.AnyHost)).Success);
            // A port's answer covers it over TCP and UDP, as HTTPS and QUIC share 443.
            Assert(t.Service.Handle(new("policy")).Policy!.Rules is [{ Path: @"C:\Apps\browser.exe", RemoteAddresses: "*", RemotePorts: "443", Protocol: "TCP" }, { Path: @"C:\Apps\browser.exe", RemoteAddresses: "*", RemotePorts: "443", Protocol: "UDP" }]);
            // The rule's own allows; internal networks have theirs at the same weight.
            var allows = t.Router.Context!.Plan.Filters.Where(f => f.Action == RuleAction.Allow && f.Weight == FilterCompiler.AllowWeight && f.RuleId is not null).ToArray();
            Assert(allows.Length > 0 && allows.All(f => f.ApplicationPath == @"C:\Apps\browser.exe" && f.RemoteNetwork is null && f.RemotePort == new PortRange(443, 443)) &&
                allows.Any(f => f.Protocol == 6) && allows.Any(f => f.Protocol == 17));
        });
        RouterDecisionTests.Run(Check);
        RouterTunnelTests.Run(Check);
        Check("Unaccepted broader blocks refuse even Lockdown takeover", () =>
        {
            using var t = new Rig(); var block = Imported("Share", "v2.33|share|", ImportOutcome.Narrowed); block.Action = RuleAction.Deny; t.Firewall.Rules.Add(block);
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Lockdown })).Success);
            Assert(!t.Events.Contains("apply") && !t.Events.Contains("disable"));
        });
        Check("Out-of-scope imports take over without consent and install nothing", () =>
        {
            using var t = new Rig(); t.Firewall.Rules.Add(Imported("Share", "v2.33|share|", ImportOutcome.Unenforced));
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })); Assert(result.Success, result.Message);
            Assert(t.Backend.Installed.Count > 0 && t.Backend.Installed.All(f => f.Name != "Share"));
        });
        Check("Accepted broader blocks survive re-import while Windows is unchanged", () =>
        {
            using var t = new Rig(); var windows = Imported("Share", "v2.33|share|", ImportOutcome.Narrowed); windows.Action = RuleAction.Deny; t.Firewall.Rules.Add(windows);
            var preflight = t.Service.Handle(new("preflight", new() { Mode = FirewallMode.BlockNew }));
            Assert(!preflight.Success && preflight.Policy!.Rules.Single().Import == ImportOutcome.Narrowed && preflight.Defaults is not null);
            var draft = preflight.Policy!; draft.Rules.Single().NarrowingAccepted = true; draft.Rules.Single().RemotePorts = "8443";
            var result = t.Service.Handle(new("takeover", draft)); Assert(result.Success, result.Message);
            var kept = t.Journal.Value.Policy.Rules.Single(); Assert(kept.NarrowingAccepted && kept.RemotePorts == "8443" && kept.Import == ImportOutcome.Narrowed);
        });
        Check("Changed Windows rules discard stale consent and edits", () =>
        {
            using var t = new Rig(); var current = Imported("Share", "v2.33|new|", ImportOutcome.Narrowed); current.Action = RuleAction.Deny; t.Firewall.Rules.Add(current);
            var stale = Imported("Share", "v2.33|old|", ImportOutcome.Narrowed); stale.Action = RuleAction.Deny; stale.NarrowingAccepted = true;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, Rules = [stale] })).Success);
            Assert(!t.Events.Contains("apply") && !t.Events.Contains("disable"));
        });
        Check("Losing Windows hardening or isolation blocks restores Windows Firewall", () =>
        {
            using var t = new Rig(); t.DisabledProtections = new() { ["PROVIDER_MPSSVC_WSH"] = 120, ["PROVIDER_MPSSVC_APP_ISOLATION"] = 40 };
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(!result.Success && result.Message.Contains("PROVIDER_MPSSVC_WSH 200 → 120"), result.Message);
            Assert(t.Events.IndexOf("disable") < t.Events.LastIndexOf("restore") && t.Events.LastIndexOf("restore") < t.Events.IndexOf("remove") && t.Journal.Value.Phase == "Inactive");
        });
        Check("Native resolution failures refuse takeover before any backup or filter change", () =>
        {
            using var t = new Rig(); t.NativeErrors.Add("App: Volume Z: is unavailable.");
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(!result.Success && result.Message.Contains("Volume Z:")); Assert(!t.Events.Contains("backup") && !t.Events.Contains("apply") && !t.Events.Contains("disable"));
        });
        Check("Interface changes reinstall keyword rules only when the plan changes", () =>
        {
            using var t = new Rig(); t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], ["192.168.1.1/32"], [], [], [])]);
            var smb = new FirewallRule { ApplicationName = "SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "LocalSubnet" };
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, Rules = [smb] })).Success);
            var applies = t.Events.Count(e => e == "apply");
            t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], ["192.168.1.53/32"], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "apply") == applies, "An identical plan was reinstalled.");
            t.Network.Snapshot = new([new(7, ["10.0.0.0/24"], [], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "apply") == applies + 1 && t.Backend.Installed.Any(f => f.RemoteNetwork == "10.0.0.0/24" && f.LocalInterfaceLuid == 7));
        });
        Check("Initial Open cannot silently bypass import admission", () =>
        {
            using var t = new Rig(); Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Open })).Success);
            Assert(!t.Events.Contains("disable"));
        });
        Check("Backup failure leaves firewall and WFP unchanged", () =>
        {
            using var t = new Rig(); t.Firewall.ExportFailure = true;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Events.Contains("apply") && !t.Events.Contains("disable"));
        });
        Check("WFP failure restores profiles before removing filters", () =>
        {
            using var t = new Rig(); t.Backend.ApplyFailure = true;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Events.Contains("disable")); Assert(t.Events.IndexOf("restore") < t.Events.IndexOf("remove"));
        });
        Check("Partial Windows disable failure restores baseline", () =>
        {
            using var t = new Rig(); t.Firewall.DisableFailure = true;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Events.IndexOf("restore") < t.Events.IndexOf("remove") && t.Journal.Value.Phase == "Inactive");
        });
        Check("Restore failure retains persistent filtering", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Events.Clear(); t.Firewall.RestoreFailure = true;
            Assert(!t.Service.Handle(new("restore")).Success); Assert(!t.Events.Contains("remove") && t.Backend.FilterCount == baseFilters);
        });
        Check("Prepared journal recovery restores Windows first", () =>
        {
            using var t = new Rig("Prepared"); t.Service.Recover();
            Assert(t.Events.IndexOf("restore") < t.Events.IndexOf("remove")); Assert(t.Journal.Value.Phase == "Inactive");
        });
        Check("Recovery can restore profiles without learning event subscription", () =>
        {
            using var t = new Rig("Prepared"); t.Backend.EventsReady = false;
            t.Service.Recover();
            Assert(t.Events.IndexOf("restore") >= 0 && t.Events.IndexOf("restore") < t.Events.IndexOf("remove"));
            Assert(t.Journal.Value.Phase == "Inactive" && !t.Service.Handle(new("status")).Status!.LearningEventsReady);
        });
        Check("Active recovery reinstalls durable policy before profile change", () =>
        {
            using var t = new Rig("Active"); t.Service.Recover();
            Assert(t.Events.IndexOf("apply") < t.Events.IndexOf("disable"));
        });
        Check("Apply failure preserves previous policy", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Backend.ApplyFailure = true;
            Assert(!t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open }, ExpectedRevision: 1)).Success);
            Assert(t.Service.Handle(new("policy")).Policy?.Mode == FirewallMode.BlockNew && t.Backend.FilterCount == baseFilters);
        });
        Check("Durable intent failure leaves active policy and filters untouched", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Events.Clear(); t.Journal.FailPhase = "Applying";
            Assert(!t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open }, ExpectedRevision: 1)).Success);
            Assert(!t.Events.Contains("apply"));
            Assert(t.Service.Handle(new("policy")).Policy!.Mode == FirewallMode.BlockNew && t.Service.Handle(new("status")).Status!.Active);
        });
        Check("Takeover durable intent failure cannot change filtering", () =>
        {
            using var t = new Rig(); t.Journal.FailPhase = "Prepared";
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Events.Contains("apply") && !t.Events.Contains("disable"));
            Assert(t.Service.Handle(new("status")).Status!.Phase == "Inactive");
        });
        Check("Stale draft cannot replace a newer enforced policy", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Lockdown }, ExpectedRevision: 1)).Success);
            t.Events.Clear(); Assert(!t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open }, ExpectedRevision: 1)).Success);
            Assert(!t.Events.Contains("apply") && t.Service.Handle(new("status")).Status!.PolicyRevision == 2);
        });
        Check("Unversioned draft cannot replace an enforced policy", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open })).Success);
        });
        Check("Learning refuses inactive event subscription", () =>
        {
            using var t = new Rig(); t.Backend.EventsReady = false;
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Assert(!t.Events.Contains("disable"));
        });
        Check("Learning approval uses service-observed endpoint", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 0, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            var pending = t.Service.Handle(new("pending")).Pending!; Assert(pending.Count == 1);
            var result = t.Service.Handle(new("resolve", RequestId: pending[0].Id, Action: RuleAction.Allow)); Assert(result.Success, result.Message);
            var policy = t.Service.Handle(new("policy")).Policy!;
            Assert(policy.Rules.Single().Path == @"C:\Apps\browser.exe" && policy.Rules.Single().RemoteAddresses == "203.0.113.7");
        });
        Check("A blocked attempt from a service host prompts for the one service its socket's token names, and only that service gets the rule", () =>
        {
            const string svchost = @"C:\Windows\System32\svchost.exe";
            var owner = 640;
            var sockets = new FlowAttribution((udp, v6) => udp && !v6 ? [new SocketRow(System.Net.IPAddress.Parse("192.168.1.20"), 50_123, null, 0, 0, owner, 1000)] : [],
                (pid, created) => pid == 640
                    ? new FlowProcess(pid, 500, svchost, new(svchost.ToLowerInvariant(), new HashSet<string>(["S-1-5-19", IdentitySelectors.ServiceSid("W32Time")], StringComparer.OrdinalIgnoreCase), null))
                    : new FlowProcess(pid, 500, @"C:\Apps\other.exe", new(@"c:\apps\other.exe", new HashSet<string>(["S-1-5-21-1-2-3-1001"]), null)));
            using var t = new Rig(attribution: sockets); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Connection Blocked(int port) => new("svchost", svchost, 0, "203.0.113.9", 123, port, "UDP", TrafficDirection.Outbound, LocalAddress: "192.168.1.20");
            t.Backend.Observed.Add(Blocked(50_123));
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            Assert(request.Connection is { Service: "W32Time", ProcessId: 640 }, "The prompt did not name the service.");
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow)).Success);
            Assert(t.Service.Handle(new("policy")).Policy!.Rules.Single() is { Path: svchost, Service: "W32Time", RemotePorts: "123" });
            // A socket now owned by another executable is a recycled port, and says nothing about this attempt.
            owner = 641;
            t.Backend.Observed.Add(Blocked(50_123) with { RemoteAddress = "203.0.113.10" });
            Assert(t.Service.Handle(new("pending")).Pending!.Single().Connection is { Service: "", ProcessId: 0 });
        });
        Check("A blocked attempt from a shared service host prompts for the service Windows tagged its socket with, listing the services sharing its process", () =>
        {
            const string svchost = @"C:\Windows\System32\svchost.exe";
            var sockets = new FlowAttribution((udp, v6) => !udp && !v6 ? [new SocketRow(System.Net.IPAddress.Parse("192.168.1.20"), 50_124, System.Net.IPAddress.Parse("203.0.113.9"), 443, 3, 650, 1000)] : [],
                (pid, created) => new FlowProcess(pid, 500, svchost, new(svchost.ToLowerInvariant(),
                    new HashSet<string>(["S-1-5-18", IdentitySelectors.ServiceSid("BITS"), IdentitySelectors.ServiceSid("wuauserv")], StringComparer.OrdinalIgnoreCase), null)),
                _ => "wuauserv");
            using var t = new Rig(attribution: sockets); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("svchost", svchost, 0, "203.0.113.9", 443, 50_124, "TCP", TrafficDirection.Outbound, LocalAddress: "192.168.1.20"));
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            Assert(request.Connection is { Service: "wuauserv", ProcessId: 650 } && request.Connection.SharedServices() is ["BITS"], "The prompt did not name the tagged service.");
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow)).Success);
            Assert(t.Service.Handle(new("policy")).Policy!.Rules.Single() is { Path: svchost, Service: "wuauserv", RemotePorts: "443" });
        });
        Check("A status read is answered at once while a takeover holds the coordinator lock, and shows its outcome once it ends", () =>
        {
            using var t = new Rig(); using var hold = new ManualResetEventSlim(false); t.Backend.HoldApply = hold;
            var takeover = Task.Run(() => t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })));
            try
            {
                Assert(t.Backend.ApplyEntered.Wait(TimeSpan.FromSeconds(10)), "The takeover never reached the filter backend.");
                var clock = System.Diagnostics.Stopwatch.StartNew(); var during = t.Service.Handle(new("status"));
                Assert(clock.Elapsed < TimeSpan.FromSeconds(1) && during is { Success: true, Status: { Active: false, Phase: "Inactive" } }, "A status read waited for the takeover.");
            }
            finally { hold.Set(); }
            Assert(takeover.Wait(TimeSpan.FromSeconds(10)) && takeover.Result.Success, "The held takeover did not finish.");
            Assert(t.Service.Handle(new("status")).Status is { Active: true, Phase: "Active" }, "The takeover's outcome was not published.");
        });
        Check("The public pipe answers a second client while a slow request holds another instance", () =>
        {
            using var t = new Rig(); using var hold = new ManualResetEventSlim(false); t.Backend.HoldApply = hold;
            using var stop = new CancellationTokenSource();
            var name = "Darkwire.SelfTest." + Guid.NewGuid().ToString("N");
            var server = ControlPipe.RunPipeAsync(t.Service, name, ControlPipe.PublicInstances, false, stop.Token);
            var takeover = Task.Run(() => t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })));
            try
            {
                Assert(t.Backend.ApplyEntered.Wait(TimeSpan.FromSeconds(10)), "The takeover never reached the filter backend.");
                // A policy read waits for the coordinator lock and holds its pipe instance meanwhile.
                var slow = Task.Run(() => SendOverPipe(name, new("policy")));
                Thread.Sleep(300);
                var clock = System.Diagnostics.Stopwatch.StartNew(); var status = SendOverPipe(name, new("status"));
                Assert(clock.Elapsed < TimeSpan.FromSeconds(2) && status.Status is { Phase: "Inactive" } && !slow.IsCompleted, "The second client waited for the first.");
                hold.Set();
                Assert(slow.Wait(TimeSpan.FromSeconds(10)) && slow.Result.Success, "The slow request was not answered.");
            }
            finally { hold.Set(); stop.Cancel(); }
            Assert(takeover.Wait(TimeSpan.FromSeconds(10)) && server.Wait(TimeSpan.FromSeconds(10)), "The pipe did not stop.");
        });
        Check("A pipe instance keeps serving after clients that hang up early, and a slow reader still gets its whole reply", () =>
        {
            using var t = new Rig(); using var stop = new CancellationTokenSource();
            var name = "Darkwire.SelfTest." + Guid.NewGuid().ToString("N");
            var server = ControlPipe.RunPipeAsync(t.Service, name, 1, false, stop.Token);
            try
            {
                // One client leaves without a word, another without reading its reply; a single instance must serve the next.
                using (OpenPipe(name)) { }
                using (var rude = OpenPipe(name)) ServiceProtocol.WriteAsync(rude, new ServiceRequest("status"), default).GetAwaiter().GetResult();
                Assert(SendOverPipe(name, new("status")).Status is { Phase: "Inactive" }, "The pipe stopped serving after a client hung up.");
                // A reader that pauses between the length and the body, as a busy desktop app can.
                using var slow = OpenPipe(name);
                ServiceProtocol.WriteAsync(slow, new ServiceRequest("status"), default).GetAwaiter().GetResult();
                var header = new byte[4]; slow.ReadExactly(header);
                Thread.Sleep(300);
                var body = new byte[System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header)]; slow.ReadExactly(body);
                Assert(System.Text.Encoding.UTF8.GetString(body).Contains("\"Phase\"", StringComparison.Ordinal), "The reply was cut off before the client read it.");
            }
            finally { stop.Cancel(); }
            Assert(server.Wait(TimeSpan.FromSeconds(10)), "The pipe did not stop.");
        });
        Check("Unknown prompt IDs cannot create rules", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Assert(!t.Service.Handle(new("resolve", RequestId: Guid.NewGuid(), Action: RuleAction.Allow)).Success);
            Assert(t.Service.Handle(new("policy")).Policy!.Rules.Count == 0);
        });
        Check("Null policy data is rejected before Windows changes", () =>
        {
            using var t = new Rig(); Assert(!t.Service.Handle(new("takeover", new() { Rules = null! })).Success); Assert(t.Events.Count == 0);
        });
        Check("Service protocol rejects oversized frames", () =>
        {
            using var memory = new MemoryStream(BitConverter.GetBytes(ServiceProtocol.MaximumMessageBytes + 1));
            try { ServiceProtocol.ReadAsync<ServiceRequest>(memory, default).GetAwaiter().GetResult(); throw new Exception("Frame accepted"); } catch (InvalidDataException) { }
        });
        Check("Service protocol round trip", () =>
        {
            using var memory = new MemoryStream(); ServiceProtocol.WriteAsync(memory, new ServiceRequest("status"), default).GetAwaiter().GetResult();
            memory.Position = 0; Assert(ServiceProtocol.ReadAsync<ServiceRequest>(memory, default).GetAwaiter().GetResult().Command == "status");
        });
        Check("Malformed client frames cannot terminate control handling or change policy", () =>
        {
            using var t = new Rig();
            foreach (var bytes in new[] { BitConverter.GetBytes(-1), BitConverter.GetBytes(0), BitConverter.GetBytes(ServiceProtocol.MaximumMessageBytes + 1),
                new byte[] { 3, 0, 0, 0, (byte)'{' }, new byte[] { 4, 0, 0, 0, (byte)'n', (byte)'u', (byte)'l', (byte)'l' } })
            {
                using var input = new MemoryStream(bytes);
                Assert(!ControlPipe.HandleConnectionAsync(t.Service, input, true, () => true, default).GetAwaiter().GetResult());
                Assert(t.Events.Count == 0);
            }
            using var status = RequestStream(new("status")); var responseAt = status.Length;
            Assert(ControlPipe.HandleConnectionAsync(t.Service, status, false, () => false, default).GetAwaiter().GetResult());
            status.Position = responseAt; Assert(ServiceProtocol.ReadAsync<ServiceResponse>(status, default).GetAwaiter().GetResult().Success);
        });
        Check("Public control lane rejects policy-sized uploads before authentication or allocation", () =>
        {
            using var t = new Rig(); using var input = new MemoryStream(BitConverter.GetBytes(1025)); var authenticated = false;
            Assert(!ControlPipe.HandleConnectionAsync(t.Service, input, false, () => { authenticated = true; return true; }, default).GetAwaiter().GetResult());
            Assert(!authenticated && t.Events.Count == 0);
        });
        Check("Control mutations require both the admin lane and an administrator token", () =>
        {
            foreach (var (lane, token) in new[] { (false, false), (true, false), (false, true), (true, true) })
            {
                using var t = new Rig(); using var input = RequestStream(new("restore")); var responseAt = input.Length;
                Assert(ControlPipe.HandleConnectionAsync(t.Service, input, lane, () => token, default).GetAwaiter().GetResult());
                input.Position = responseAt; var reply = ServiceProtocol.ReadAsync<ServiceResponse>(input, default).GetAwaiter().GetResult();
                Assert(reply.Success == (lane && token));
                if (!lane || !token) Assert(t.Events.Count == 0);
            }
        });
        Check("Service reports boot guards separately and clears them on restoration", () =>
        {
            using var t = new Rig(); var taken = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(taken.Success && taken.Status?.FilterCount == baseFilters && taken.Status.BootFilterCount == 4);
            var restored = t.Service.Handle(new("restore"));
            Assert(restored.Success && restored.Status?.FilterCount == 0 && restored.Status.BootFilterCount == 0);
        });
        ServiceGeoTests.Run(Check);
        Check("Failed learning filter commit preserves the request and permits a later retry", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            t.Service.Tick(); var request = t.Service.Handle(new("pending")).Pending!.Single();
            t.Backend.ApplyFailure = true;
            Assert(!t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new())).Success);
            Assert(t.Service.Handle(new("pending")).Pending!.Single().Id == request.Id);
            Assert(t.Service.Handle(new("policy")).Policy!.Rules.Count == 0);
            t.Backend.ApplyFailure = false;
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new())).Success);
            Assert(t.Service.Handle(new("pending")).Pending!.Count == 0);
        });
        Check("Allowing any host on a port also answers the application's other requests there, over TCP and UDP, and leaves the rest waiting", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            static Connection Attempt(string address, int port, string protocol = "TCP", string path = @"C:\Apps\browser.exe") =>
                new(Path.GetFileNameWithoutExtension(path), path, 1, address, port, 50000, protocol, TrafficDirection.Outbound);
            t.Backend.Observed.AddRange([Attempt("203.0.113.7", 443), Attempt("198.51.100.9", 443), Attempt("203.0.113.7", 443, "UDP"), Attempt("203.0.113.7", 80),
                Attempt("203.0.113.7", 443, path: @"C:\Apps\mail.exe")]);
            var waiting = t.Service.Handle(new("pending")).Pending!;
            Assert(waiting.Count == 5 && waiting[0].Connection is { RemoteAddress: "203.0.113.7", RemotePort: 443, Protocol: "TCP" });
            var answered = t.Service.Handle(new("resolve", RequestId: waiting[0].Id, Action: RuleAction.Allow, Scope: LearningScope.AnyHost));
            Assert(answered.Success && answered.Message.EndsWith("This decision also answered 2 other waiting requests.", StringComparison.Ordinal), answered.Message);
            Assert(answered.Policy!.Rules is [{ Protocol: "TCP", RemoteAddresses: "*", RemotePorts: "443" }, { Protocol: "UDP", RemoteAddresses: "*", RemotePorts: "443" }]);
            var left = t.Service.Handle(new("pending")).Pending!;
            Assert(left.Count == 2 && left.Any(p => p.Connection.RemotePort == 80) && left.Any(p => p.Connection.Application == "mail"), string.Join(", ", left.Select(p => p.Connection.Endpoint)));
            // What is left can still be answered under the policy the first answer made.
            Assert(t.Service.Handle(new("resolve", RequestId: left.Single(p => p.Connection.RemotePort == 80).Id, Action: RuleAction.Deny)).Success);
            Assert(t.Service.Handle(new("pending")).Pending!.Single().Connection.Application == "mail");
        });
        Check("Learning rejects missing VPN profiles without consuming or allowing the request", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            Assert(!t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(Guid.NewGuid()))).Success);
            Assert(t.Service.Handle(new("pending")).Pending!.Single().Id == request.Id);
            Assert(t.Service.Handle(new("policy")).Policy!.Rules.Count == 0);
        });
        Check("A route through a profile without service credentials cannot partially commit a learning allow rule", () =>
        {
            using var t = new Rig(); var profile = new VpnProfile { Name = "Private" };
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning, VpnProfiles = [profile] })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            var refused = t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(!refused.Success && refused.Message.Contains("Store in service"), refused.Message);
            var policy = t.Service.Handle(new("policy")).Policy!;
            Assert(policy.Rules.Count == 0 && policy.VpnProfiles.Single().Applications.Count == 0);
            Assert(t.Service.Handle(new("pending")).Pending!.Count == 1);
        });
        ServiceTunnelTests(Check);
        Check("Failed learning intent write retains the prompt", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            var request = t.Service.Handle(new("pending")).Pending!.Single(); t.Journal.FailPhase = "Applying";
            Assert(!t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow)).Success);
            Assert(t.Service.Handle(new("pending")).Pending!.Single().Id == request.Id && t.Journal.Value.Phase == "Active");
        });
        Check("Uncertain active commit hides stale prompts and recovers durable intent", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            t.Backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            var request = t.Service.Handle(new("pending")).Pending!.Single(); t.Journal.FailPhase = "Active";
            Assert(!t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow)).Success);
            Assert(t.Journal.Value.Phase == "Applying" && t.Service.Handle(new("pending")).Pending!.Count == 0);
            t.Journal.FailPhase = null; t.Service.Tick();
            Assert(t.Journal.Value.Phase == "Active" && t.Service.Handle(new("policy")).Policy!.Rules.Count == 1);
        });
        Check("Service policy responses and journal exclude desktop credential blobs", () =>
        {
            using var t = new Rig(); var policy = new AppState { Mode = FirewallMode.BlockNew, VpnProfiles = [new() { EncryptedConfig = "PRIVATE-CREDENTIAL-BLOB" }] };
            Assert(t.Service.Handle(new("takeover", policy)).Success);
            Assert(t.Service.Handle(new("policy")).Policy!.VpnProfiles.Single().EncryptedConfig == "");
            Assert(t.Journal.Value.Policy.VpnProfiles.Single().EncryptedConfig == "");
            Assert(policy.VpnProfiles.Single().EncryptedConfig == "PRIVATE-CREDENTIAL-BLOB");
        });
        Check("Changed native filters are reinstalled in place; persistent tampering escalates to a restart", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Backend.IntegrityFailure = true; var applies = t.Events.Count(e => e == "apply");
            for (var i = 0; i < 5; i++) t.Service.Tick(true);
            Assert(t.Events.Count(e => e == "apply") == applies + 5 && t.Service.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("reinstalled")));
            try { t.Service.Tick(true); throw new Exception("Repeated tampering was not escalated"); } catch (InvalidDataException) { }
            Assert(!t.Events.Contains("remove") && t.Backend.FilterCount == baseFilters);
        });
        Check("Re-enabled Windows Firewall is disabled again; a repeat within a minute is reported, not fought", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            var disables = t.Events.Count(e => e == "disable");
            t.Firewall.Disabled = false; for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "disable") == disables + 1 && t.Firewall.Disabled);
            t.Firewall.Disabled = false; for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Events.Count(e => e == "disable") == disables + 1 && t.Service.Handle(new("status")).Status!.Alerts!.First().Contains("keeps re-enabling"));
        });
        Check("Missing drop events enable failure auditing, which is restored with Windows Firewall", () =>
        {
            using var t = new Rig(); t.Backend.Probes.Enqueue(false); t.Backend.Probes.Enqueue(true);
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })); Assert(result.Success, result.Message);
            Assert(t.Audit.Values.Values.All(v => (v & 0x2) != 0) && t.Journal.Value.OriginalAudit!.Values.All(v => v == 0x1));
            Assert(t.Service.Handle(new("restore")).Success && t.Audit.Values.Values.All(v => v == 0x1) && t.Journal.Value.OriginalAudit is null);
        });
        Check("Learning stays refused when drop events never arrive, and auditing is reverted", () =>
        {
            using var t = new Rig(); t.Backend.Probes.Enqueue(false); t.Backend.Probes.Enqueue(false);
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning })).Success);
            Assert(t.Audit.Values.Values.All(v => v == 0x1) && t.Journal.Value.Phase == "Inactive" && t.Journal.Value.OriginalAudit is null);
        });
        Check("Conflicting firewall managers refuse takeover before any change", () =>
        {
            using var t = new Rig(); t.Firewall.ConflictList.Add("Windows Firewall Control is installed.");
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew }));
            Assert(!result.Success && result.Message.Contains("Windows Firewall Control") && !t.Events.Contains("backup") && !t.Events.Contains("apply"));
        });
        Check("Foreign hard-permit filters are reported once", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Backend.Permits.Add("Bypass (Vendor, ALE_AUTH_CONNECT_V4)"); t.Service.Tick(true);
            var alerts = t.Service.Handle(new("status")).Status!.Alerts!; Assert(alerts.Count == 1 && alerts[0].Contains("Bypass"));
            t.Service.Tick(true); Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count == 1);
        });
        Check("The hard-permit watch knows the WireGuard tunnels the policy runs and those the router is starting", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Everything", "WireGuard", "198.51.100.7:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id })).Success);
            var starting = Guid.NewGuid();
            t.Router.TunnelStates.Add(new(starting, "WireGuard", "Starting", DateTimeOffset.UtcNow));
            t.Service.Tick(true);
            Assert(t.Backend.WireGuardTunnels.Count == 2 && t.Backend.WireGuardTunnels.Contains(profile.Id) && t.Backend.WireGuardTunnels.Contains(starting));
        });
        Check("WireGuard's permits for its own tunnel service are Darkwire's only for the bundled executable and a tunnel run here", () =>
        {
            var tunnel = Guid.NewGuid(); var sid = IdentitySelectors.ServiceSid(WireGuardBackend.ServiceName(WireGuardBackend.Names(tunnel)[1]));
            var services = new HashSet<string>([sid], StringComparer.OrdinalIgnoreCase);
            const string bundled = @"\device\harddiskvolume3\program files\darkwire\service\backends\wireguard\wireguard.exe";
            // As WfpInventory reads the permit WireGuard's firewall adds for each tunnel service, here its outbound IPv4 one.
            static FilterRecord Permit(string application, string descriptor, params ConditionRecord[] more) =>
                new(7, "Permit unrestricted outbound traffic for WireGuard service (IPv4)", "c24b36ed-fe94-4fbe-9260-9dc45c7bf36a", "WireGuard filters",
                    "ALE_AUTH_CONNECT_V4", "PERMIT", 15, 8, [new("ALE_APP_ID", "EQUAL", application), new("ALE_USER_ID", "EQUAL", descriptor), .. more], null);
            var own = "D:(A;;CC;;;" + sid + ")";
            Assert(WireGuardBackend.OwnPermit(Permit(bundled, own), bundled, services));
            // A separately installed WireGuard, another tunnel's service, a wider grant, another condition or an unreadable
            // descriptor is someone else's, and so is any permit while no WireGuard tunnel runs.
            Assert(!WireGuardBackend.OwnPermit(Permit(@"\device\harddiskvolume3\program files\wireguard\wireguard.exe", own), bundled, services));
            Assert(!WireGuardBackend.OwnPermit(Permit(bundled, "D:(A;;CC;;;" + IdentitySelectors.ServiceSid(WireGuardBackend.ServiceName(WireGuardBackend.Names(Guid.NewGuid())[0])) + ")"), bundled, services));
            Assert(!WireGuardBackend.OwnPermit(Permit(bundled, own + "(A;;CC;;;WD)"), bundled, services));
            Assert(!WireGuardBackend.OwnPermit(Permit(bundled, own, new ConditionRecord("IP_REMOTE_PORT", "EQUAL", "443")), bundled, services));
            Assert(!WireGuardBackend.OwnPermit(Permit(bundled, "unreadable descriptor"), bundled, services));
            Assert(!WireGuardBackend.OwnPermit(Permit(bundled, own), bundled, new HashSet<string>()));
        });
        foreach (var json in new[] { "{\"Command\":\"status\",\"Command\":\"restore\"}", "{\"Command\":\"status\",\"Unexpected\":1}" })
            Check("Control JSON rejects ambiguous or unknown fields: " + json, () =>
            {
                using var stream = new MemoryStream(); var bytes = System.Text.Encoding.UTF8.GetBytes(json); stream.Write(BitConverter.GetBytes(bytes.Length)); stream.Write(bytes); stream.Position = 0;
                try { ServiceProtocol.ReadAsync<ServiceRequest>(stream, default).GetAwaiter().GetResult(); throw new Exception("Ambiguous command accepted"); } catch (System.Text.Json.JsonException) { }
            });
        ServiceVpnTests.Run(Check);
        ServiceSetupTests.Run(Check);
        GeoUpdateTests.Run(Check);
        BlocklistTests.Run(Check);
        EncryptedDnsTests.Run(Check);
        ServiceDnsTests(Check);
        Console.WriteLine($"{passed} service checks passed; {failed} failed. Fake backends only; no Windows filtering or profile changes.");
        return failed == 0 ? 0 : 1;
    }
    /// <summary>Encrypted DNS, blocked names and Darkwire's own route through the coordinator: what applies, what the router and kernel get, and what the status says.</summary>
    private static void ServiceDnsTests(Action<string, Action> check)
    {
        static void Assert(bool value, string reason = "Encrypted DNS service invariant failed.") { if (!value) throw new Exception(reason); }
        static IEnumerable<NativeFilter> Named(IEnumerable<NativeFilter> filters, string name) => filters.Where(f => f.Name == name);
        var listedStamp = DnsStamp.FromUrl("https://dns.quad9.net/dns-query", 3);
        var catalog = new FakeResolvers([new("quad9-doh-ip4-port443-filter-pri", "Quad9", "Quad9.", DnsProtocol.Https, true, true, false, false, [listedStamp])]);
        DnsServer Listed() => new() { Name = "quad9-doh-ip4-port443-filter-pri", Stamps = [DnsStamp.FromUrl("https://old.quad9.example/dns-query")], Listed = true };

        check("Blocked names and encrypted DNS apply by themselves, reach the router and confine the Windows DNS client", () =>
        {
            using var t = new Rig(resolvers: catalog);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(!t.Backend.Installed.Any(f => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal)) && t.Router.Context!.Dns.Count == 0);
            var applied = t.Service.Handle(new("apply-settings", Settings: new(BlockedNames: ["ads.example.com"], DnsServers: [Listed()])));
            Assert(applied.Success && applied.Policy!.BlockedNames.SequenceEqual(["ads.example.com"]) && applied.Policy.DnsServers.Single().Listed, applied.Message);
            var context = t.Router.Context!;
            // A listed server runs the verified list's stamps, not those the policy kept.
            Assert(context.LoopbackNames!.Blocks("cdn.ads.example.com") && context.Names is not null && context.Dns.Single().Stamps.SequenceEqual([listedStamp]) && context.ResolvesSystemDns);
            Assert(Named(t.Backend.Installed, "Router: DNS client guard").Count() == 4 && Named(t.Backend.Installed, "DNS filtering: unrouted server").Count() == 4);
            // Hits for blocked names count under their own key.
            context.NameAnswered!("ads.example.com");
            Assert(t.Service.Handle(new("status")).Status!.ListHits!.ByList[BlocklistHits.NamesKey] == 1);
            // Without the list, the policy's own stamps run.
            using var bare = new Rig();
            Assert(bare.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, DnsServers = [Listed()] })).Success);
            Assert(bare.Router.Context!.Dns.Single().Stamps.Single().Equals(Listed().Stamps[0]));
        });
        check("Encrypted DNS refuses to apply where the package has no dnscrypt-proxy, and needs routing", () =>
        {
            using var t = new Rig();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            t.Router.Backends.Remove(TakeoverCoordinator.DnsBackend);
            var refused = t.Service.Handle(new("apply-settings", Settings: new(DnsServers: [Listed()])));
            Assert(!refused.Success && refused.Message.Contains("dnscrypt-proxy") && t.Router.Context!.Dns.Count == 0, refused.Message);
            var unrouted = t.Service.Handle(new("apply", new() { Mode = FirewallMode.BlockNew, RouteConnections = false, DnsServers = [Listed()] }, ExpectedRevision: t.Service.Handle(new("status")).Status!.PolicyRevision));
            Assert(!unrouted.Success && unrouted.Message.Contains("connection router"), unrouted.Message);
        });
        check("Encrypted DNS keeps the router running in Open, and Lockdown runs no DNS proxy", () =>
        {
            using var t = new Rig();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, DnsServers = [Listed()] })).Success);
            var revision = t.Service.Handle(new("status")).Status!.PolicyRevision;
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open, DnsServers = [Listed()] }, ExpectedRevision: revision)).Success);
            Assert(t.Router.Running && t.Router.Context!.Mode == FirewallMode.Open && t.Router.Context.Dns.Count == 1 && Named(t.Backend.Installed, "Router: DNS client guard").Count() == 4);
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Lockdown, DnsServers = [Listed()] }, ExpectedRevision: revision + 1)).Success);
            Assert(t.Router.Context!.Dns.Count == 0);
        });
        check("Any user may read the connections the router carries with their routes, without waiting, and only while Darkwire enforces", () =>
        {
            using var t = new Rig();
            RoutedConnection[] carried = [new("198.18.0.1", 50_000, "203.0.113.8", 443, Guid.NewGuid()), new("fd5a:9c33:21e7::1", 50_001, "2001:db8::9", 443)];
            t.Router.Connections = carried;
            Assert(ServiceClient.IsPublic("routed-connections") && t.Service.Handle(new("routed-connections")) is { Success: true, Routed.Count: 0 }, "Connections were reported before takeover.");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Service.Handle(new("routed-connections")).Routed!.SequenceEqual(carried));
            // An apply under way holds the coordinator; the read does not wait for it.
            using var hold = new ManualResetEventSlim(false); t.Backend.HoldApply = hold; t.Backend.ApplyEntered.Reset();
            var revision = t.Service.Handle(new("status")).Status!.PolicyRevision;
            var apply = Task.Run(() => t.Service.Handle(new("apply", new() { Mode = FirewallMode.Learning }, ExpectedRevision: revision)));
            try
            {
                Assert(t.Backend.ApplyEntered.Wait(TimeSpan.FromSeconds(10)), "The apply never reached the filter backend.");
                var clock = System.Diagnostics.Stopwatch.StartNew();
                Assert(t.Service.Handle(new("routed-connections")).Routed!.Count == 2 && clock.Elapsed < TimeSpan.FromSeconds(1), "The read waited for the apply.");
            }
            finally { hold.Set(); }
            Assert(apply.Wait(TimeSpan.FromSeconds(10)) && apply.Result.Success, "The held apply did not finish.");
        });
        check("While encrypted DNS runs, the startup lock lets the DNS proxy reach its servers", () =>
        {
            using var t = new Rig();
            static bool Proxy(NativeFilter f) => f.ApplicationPath == DnsCryptProxy.Executable(Path.GetDirectoryName(FakeRouter.TestPlan.ServicePath)!);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success && t.Backend.Locked.Count > 0 && !t.Backend.Locked.Any(Proxy));
            Assert(t.Service.Handle(new("apply-settings", Settings: new(DnsServers: [Listed()]))).Success);
            Assert(t.Backend.Locked.Count(Proxy) == 2 && t.Backend.Locked.Where(Proxy).All(f => f is { Direction: TrafficDirection.Outbound, Action: RuleAction.Allow }), "The DNS proxy cannot pass the startup lock.");
            var revision = t.Service.Handle(new("status")).Status!.PolicyRevision;
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Lockdown, DnsServers = [Listed()] }, ExpectedRevision: revision)).Success);
            Assert(!t.Backend.Locked.Any(Proxy), "Lockdown, which runs no DNS proxy, let one through the startup lock.");
        });
        check("Darkwire's own connections follow the default route, or the route chosen for them, and the status says which", () =>
        {
            using var t = new Rig(); var work = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820"); var home = t.Vault.Store("Home", "WireGuard", "198.51.100.8:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [work, home], DefaultOutboundVpnProfileId = work.Id })).Success);
            Assert(t.Router.Context!.OwnTunnel == work.Id && !t.Router.Context.OwnRefused);
            var routed = t.Service.Handle(new("apply-vpn", Routes: new([work, home], work.Id, OwnTraffic: OwnRoute.Profile, OwnTrafficProfileId: home.Id)));
            Assert(routed.Success && t.Router.Context!.OwnTunnel == home.Id && t.Router.Context.Profiles.Any(p => p.ProfileId == home.Id), routed.Message);
            Assert(routed.Status is { OwnTraffic: OwnRoute.Profile } status && status.OwnTrafficProfileId == home.Id && routed.Policy!.OwnTraffic == OwnRoute.Profile);
            // The profile carrying them can't be removed from under them.
            Assert(!t.Service.Handle(new("remove-vpn", VpnProfileId: home.Id)).Success);
            var windows = t.Service.Handle(new("apply-vpn", Routes: new([work, home], work.Id, OwnTraffic: OwnRoute.Windows, OwnTrafficProfileId: home.Id)));
            Assert(windows.Success && t.Router.Context!.OwnTunnel is null && windows.Policy!.OwnTrafficProfileId is null && t.Router.Context.Profiles.All(p => p.ProfileId != home.Id));
        });
        check("Darkwire's own downloads leave through the own route's tunnel, never another way, or physically", () =>
        {
            using var t = new Rig(); var work = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820");
            var tunnel = new Darkwire.Vpn.Egress(900, 9, System.Net.IPAddress.Parse("10.64.0.2"), 0, 0); var lan = new Darkwire.Vpn.Egress(42, 7, System.Net.IPAddress.Parse("192.168.1.20"), 0, 25);
            t.Router.OwnRoutes = (_, profile) => profile is null ? lan : profile == work.Id && t.Router.TunnelUp ? tunnel : null;
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [work], DefaultOutboundVpnProfileId = work.Id })).Success);
            var destination = System.Net.IPAddress.Parse("203.0.113.9");
            Assert(t.Service.OwnEgress(destination) is null, "A download left while the own route's tunnel was down.");
            t.Router.TunnelUp = true;
            Assert(t.Service.OwnEgress(destination) == tunnel);
            Assert(t.Service.Handle(new("apply-vpn", Routes: new([work], work.Id, OwnTraffic: OwnRoute.Windows))).Success && t.Service.OwnEgress(destination) == lan);
        });
        check("The DNS servers command offers the verified list, and asks for it when the service has none", () =>
        {
            using var t = new Rig(resolvers: catalog);
            var offered = t.Service.Handle(new("dns-servers"));
            Assert(offered.Success && offered.DnsCatalog!.Servers.Single().Name == "quad9-doh-ip4-port443-filter-pri" && !catalog.Requested && ServiceClient.IsPublic("dns-servers"));
            var empty = new FakeResolvers([]);
            using var fresh = new Rig(resolvers: empty);
            Assert(fresh.Service.Handle(new("dns-servers")) is { Success: true, DnsCatalog.Servers.Count: 0 } && empty.Requested);
        });
        check("Refusals reach the status from the router and the kernel, once each, newest first", () =>
        {
            using var t = new Rig();
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            var refusal = new BlockedFlow(DateTimeOffset.UtcNow, @"C:\Apps\game.exe", "203.0.113.8", 443, "TCP", TrafficDirection.Outbound, "No rule allows it");
            t.Router.Context!.Refused!(refusal); t.Router.Context.Refused!(refusal with { Time = DateTimeOffset.UtcNow.AddSeconds(1) });
            t.Backend.NamedDrops.Add((new Connection("", "", 0, "198.51.100.23", 3389, 51000, "TCP", TrafficDirection.Inbound), "Geographic restriction"));
            var blocked = t.Service.Handle(new("status")).Status!.Blocked!;
            Assert(blocked.Count == 2 && blocked.Any(b => b is { Application: @"C:\Apps\game.exe", Count: 2 }) && blocked.Any(b => b is { Application: "Windows", Reason: "Geographic restriction", Direction: TrafficDirection.Inbound, RemotePort: 3389 }));
        });
    }

    private sealed class FakeResolvers(IReadOnlyList<DnsCatalogEntry> servers) : IResolverCatalog
    {
        public bool Requested;
        public IReadOnlyList<DnsCatalogEntry> Servers => servers;
        public DnsCatalog Catalog() => new(servers, null, null, Requested);
        public void Request() => Requested = true;
    }

    /// <summary>Per-application VPN routing through the coordinator: admission, the kernel and router plans, and learning's route choice.</summary>
    private static void ServiceTunnelTests(Action<string, Action> check)
    {
        const string Browser = @"C:\Apps\browser.exe";
        static void Assert(bool value, string reason = "VPN service invariant failed.") { if (!value) throw new Exception(reason); }
        static IEnumerable<NativeFilter> Named(IEnumerable<NativeFilter> filters, string name) => filters.Where(f => f.Name == name);

        check("A policy with VPN assignments activates in router mode once the service holds its credentials", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] }));
            Assert(result.Success, result.Message);
            Assert(t.Events.IndexOf("apply") < t.Events.IndexOf("router-start") && t.Events.IndexOf("router-start") < t.Events.IndexOf("disable"));
            var guards = Named(t.Backend.Installed, "Router: VPN guard").ToArray();
            Assert(guards.Length == 4 && guards.All(f => f.ApplicationPath == Browser && f.Weight == FilterCompiler.VpnGuardWeight && f.Action == RuleAction.Deny));
            // One for each name the profile's tunnel may run under, as the service by that name.
            var endpoints = Named(t.Backend.Installed, "Router: VPN endpoint").ToArray();
            Assert(endpoints.Select(e => e.Service).SequenceEqual(WireGuardBackend.Names(profile.Id).Select(name => "WireGuardTunnel$" + name)) && endpoints[0].Service == "WireGuardTunnel$" + profile.Id.ToString("N"));
            Assert(endpoints.All(endpoint => endpoint.RemoteNetwork == "198.51.100.7/32" && endpoint.Protocol == 17 &&
                endpoint.RemotePort == new PortRange(51820, 51820) && endpoint.ApplicationPath == @"C:\Program Files\Darkwire\Service\Backends\WireGuard\wireguard.exe"));
            var context = t.Router.Context!;
            Assert(context.Tunnels!.FindApplication(Browser)!.ProfileId == profile.Id && context.Profiles.Single() == new TunnelDemand(profile.Id, "WireGuard", profile.CredentialsRevision));
            // The router evaluates the peer permits with the decision plan; relay, tunnel and guard filters stay in the kernel.
            Assert(Named(context.Plan.Filters, "Router: VPN endpoint").Count() == 3 && context.Plan.Filters.All(f => f.Name is not ("Router: VPN guard" or "Router: leak guard" or "Router: relay")));
            Assert(result.Message.Contains("VPN profiles are starting"));
            // Per-application assignments leave the Windows DNS client to core networking.
            Assert(!t.Backend.Installed.Any(f => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal)) && Named(t.Backend.Installed, "Core networking: DNS client").Count() == 4);
        });
        check("VPN assignments without matching service credentials refuse takeover before any change", () =>
        {
            using var t = new Rig();
            var missing = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [new() { Name = "Work", Applications = [Browser] }] }));
            Assert(!missing.Success && missing.Message.Contains("Work: store this configuration") && !t.Events.Contains("backup") && !t.Events.Contains("apply"));
            var stale = t.Vault.Store("Home", "WireGuard", "198.51.100.7:51820", Browser); stale.CredentialsRevision = Guid.NewGuid();
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [stale] })).Success && !t.Events.Contains("apply"));
            var kind = t.Vault.Store("Kind", "OpenVPN", "198.51.100.7:1194", Browser); kind.Kind = "WireGuard";
            Assert(!t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [kind] })).Success && !t.Events.Contains("apply"));
        });
        check("An OpenVPN profile from an earlier build refuses admission, saying Darkwire runs WireGuard only", () =>
        {
            using var t = new Rig(); var old = t.Vault.Store("Old", "OpenVPN", "198.51.100.7:1194", Browser);
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [old] }));
            Assert(!result.Success && result.Message.Contains("Old: Darkwire runs WireGuard tunnels only") && !t.Events.Contains("apply"), result.Message);
        });
        check("A default VPN route needs its credentials too, and guards every application once admitted", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Everything", "WireGuard", "vpn.example.net:51820");
            var refused = new AppState { Mode = FirewallMode.BlockNew, VpnProfiles = [new() { Name = "Unstored" }] };
            refused.DefaultOutboundVpnProfileId = refused.VpnProfiles[0].Id;
            Assert(!t.Service.Handle(new("takeover", refused)).Success && !t.Events.Contains("apply"));
            // With local and internal traffic in the tunnel too, the guard covers every address.
            var policy = new AppState { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id, LocalNetworkBypassesVpn = false };
            Assert(t.Service.Handle(new("takeover", policy)).Success);
            Assert(Named(t.Backend.Installed, "Router: VPN guard").All(f => f.ApplicationPath is null && f.RemoteNetwork is null) && Named(t.Backend.Installed, "Router: VPN guard").Count() == 4);
            // A host name allows the backend toward the peer's port in both families, for each of the profile's tunnel names.
            Assert(Named(t.Backend.Installed, "Router: VPN endpoint").Count() == 6 && t.Router.Context!.Tunnels!.DefaultProfileId == profile.Id);
            // The Windows DNS client may send DNS only into Darkwire's adapter, where the router takes it to the profile's resolver.
            Assert(Named(t.Backend.Installed, "Router: DNS client guard").Count() == 4 && Named(t.Backend.Installed, "Router: DNS client tunnel").Count() == 4 &&
                Named(t.Backend.Installed, "Router: DNS client loopback").Count() == 4 && t.Router.Context!.Plan.Filters.All(f => !f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal)));
            // Removing the default route returns the DNS client to core networking.
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], LocalNetworkBypassesVpn = false }, ExpectedRevision: 1)).Success);
            Assert(!t.Backend.Installed.Any(f => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal)) && t.Router.Context!.Tunnels is null);
        });
        check("A default profile whose tunnel names no resolver is reported once each time it comes up, since Windows lookups are refused", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Everything", "WireGuard", "198.51.100.7:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id })).Success);
            static bool Silent(string alert) => alert.Contains("VPN profile Everything carries Windows name lookups but names no DNS server");
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", DateTimeOffset.UtcNow, 9, ["10.64.0.2"], Resolvers: []));
            for (var i = 0; i < 10; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Silent) == 1);
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { State = "Failed", Resolvers = null, Error = "The tunnel stopped working." };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { State = "Up", Resolvers = [], Error = null };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Silent) == 2);
            // A resolver, or a profile that only carries assigned applications, is nothing to report.
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Resolvers = ["10.64.0.1"] };
            for (var i = 0; i < 10; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Silent) == 2);
            using var assigned = new Rig(); var work = assigned.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(assigned.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [work] })).Success);
            assigned.Router.TunnelStates.Add(new(work.Id, "WireGuard", "Up", DateTimeOffset.UtcNow, 9, ["10.64.0.2"], Resolvers: []));
            for (var i = 0; i < 10; i++) assigned.Service.Tick();
            Assert(!assigned.Service.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("names no DNS server")));
        });
        check("Darkwire's service and VPN backends cannot be assigned to a VPN profile", () =>
        {
            using var t = new Rig();
            foreach (var own in new[] { FakeRouter.TestPlan.ServicePath, @"C:\Program Files\Darkwire\Service\Backends\WireGuard\wireguard.exe" })
            {
                var profile = t.Vault.Store("Loop", "WireGuard", "198.51.100.7:51820", own);
                var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] }));
                Assert(!result.Success && result.Message.Contains("is part of Darkwire") && !t.Events.Contains("apply"), result.Message);
            }
        });
        check("VPN assignments refuse admission when their backend is not installed", () =>
        {
            using var t = new Rig(); t.Router.Backends.Remove("WireGuard");
            var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] }));
            Assert(!result.Success && result.Message.Contains(@"backend is not installed in Service\Backends\WireGuard") && !t.Events.Contains("apply"));
        });
        check("VPN assignments with connection routing off, or without the router runtime, are refused", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            var off = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], RouteConnections = false }));
            Assert(!off.Success && off.Message.Contains("need connection routing") && !t.Events.Contains("apply"));
            t.Router.Available = false;
            var missing = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] }));
            Assert(!missing.Success && missing.Message.Contains("VPN profiles run in the connection router") && !t.Events.Contains("apply"));
        });
        check("Open mode keeps routing for VPN assignments only, with guards but no leak guard or defaults", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            var open = t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open, VpnProfiles = [profile] }, ExpectedRevision: 1));
            Assert(open.Success, open.Message);
            Assert(t.Events.Contains("router-update") && !t.Events.Contains("router-stop") && t.Router.Running && t.Router.Context!.Mode == FirewallMode.Open);
            Assert(Named(t.Backend.Installed, "Router: VPN guard").Count() == 4 && Named(t.Backend.Installed, "Router: VPN endpoint").Any() && Named(t.Backend.Installed, "Router: relay").Any());
            Assert(!Named(t.Backend.Installed, "Router: leak guard").Any() && !Named(t.Backend.Installed, "Default policy").Any() && Named(t.Backend.Installed, "Loopback").Count() == 4);
            profile.Applications.Clear();
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open, VpnProfiles = [profile] }, ExpectedRevision: 2)).Success && t.Events.Contains("router-stop") && t.Backend.FilterCount == 0);
        });
        check("Lockdown keeps VPN-carried applications guarded and runs no tunnel", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Lockdown, VpnProfiles = [profile] })).Success);
            Assert(t.Router.Context!.Profiles.Count == 0 && t.Router.Context.Tunnels!.FindApplication(Browser) is not null);
            Assert(Named(t.Backend.Installed, "Router: VPN guard").Count() == 4 && !Named(t.Backend.Installed, "Router: VPN endpoint").Any());
        });
        check("Learning's route choice assigns the application to a stored profile and starts routing it", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "vpn.example.net:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning, VpnProfiles = [profile] })).Success);
            Assert(t.Router.Context!.Profiles.Count == 0, "An unused profile was started.");
            Assert(t.Router.Broker!.Ask(new("Browser", Browser, 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound, State: "Held")) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            var resolved = t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(resolved.Success, resolved.Message);
            var policy = t.Service.Handle(new("policy")).Policy!;
            Assert(policy.Rules.Single().Path == Browser && policy.VpnProfiles.Single().Applications.Single() == Browser);
            var context = t.Router.Context!;
            Assert(context.Tunnels!.FindApplication(Browser)!.ProfileId == profile.Id && context.Profiles.Single().ProfileId == profile.Id);
            Assert(context.Plan.Filters.Any(f => f.ApplicationPath == Browser && f.Action == RuleAction.Allow && f.RemoteNetwork == "203.0.113.7"));
            Assert(Named(t.Backend.Installed, "Router: VPN guard").All(f => f.ApplicationPath == Browser) && Named(t.Backend.Installed, "Router: VPN endpoint").Count() == 6);
            Assert(t.Service.Handle(new("pending")).Pending!.Count == 0);
        });
        check("A VPN route cannot be chosen for a service in a shared host, named or not, since the profile would carry all of svchost.exe", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning, VpnProfiles = [profile] })).Success);
            var svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");
            Assert(t.Router.Broker!.Ask(new("svchost", svchost, 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound, Service: "wuauserv")) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            var refused = t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(!refused.Success && refused.Message == VpnAssignments.ServiceHostRefusal && t.Service.Handle(new("pending")).Pending!.Single().Id == request.Id);
            Assert(t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new())).Success);
            // A service the prompt could not name gets a rule for every service svchost.exe runs; a profile would carry them all.
            Assert(t.Router.Broker!.Ask(new("svchost", svchost, 9, "203.0.113.8", 443, 50001, "TCP", TrafficDirection.Outbound)) is not null);
            var unnamed = t.Service.Handle(new("pending")).Pending!.Single();
            var all = t.Service.Handle(new("resolve", RequestId: unnamed.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(!all.Success && all.Message == VpnAssignments.ServiceHostRefusal, all.Message);
            Assert(t.Service.Handle(new("policy")).Policy!.VpnProfiles.Single().Applications.Count == 0, "svchost.exe was assigned to a profile.");
        });
        check("A service running alone in its own program outside Windows can take a VPN route from its prompt; a Windows service cannot", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning, VpnProfiles = [profile] })).Success);
            const string agent = @"C:\Program Files\Backup\agent.exe";
            Assert(t.Router.Broker!.Ask(new("agent", agent, 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound, Service: "BackupAgent", HostedServices: "BackupAgent")) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            var routed = t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(routed.Success && routed.Policy!.VpnProfiles.Single().Applications.Single() == agent, routed.Message);
            var spooler = Path.Combine(Environment.SystemDirectory, "spoolsv.exe");
            Assert(t.Router.Broker!.Ask(new("spoolsv", spooler, 10, "203.0.113.8", 443, 50001, "TCP", TrafficDirection.Outbound, Service: "Spooler", HostedServices: "Spooler")) is not null);
            var windows = t.Service.Handle(new("pending")).Pending!.Single();
            var refused = t.Service.Handle(new("resolve", RequestId: windows.Id, Action: RuleAction.Allow, LearningRoute: new(profile.Id)));
            Assert(!refused.Success && refused.Message == VpnAssignments.WindowsServiceRefusal, refused.Message);
        });
        check("A profile that cannot run later keeps its applications guarded, is left out and reported", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], [], [], [], [])]);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            t.Vault.Unreadable = true;
            t.Network.Snapshot = new([new(7, ["10.0.0.0/24"], [], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("cannot run")));
            Assert(Named(t.Backend.Installed, "Router: VPN guard").Count() == 4 && !Named(t.Backend.Installed, "Router: VPN endpoint").Any());
            Assert(t.Router.Context!.Profiles.Count == 0 && t.Router.Context.Tunnels!.FindApplication(Browser) is not null);
            // The same problem is not reported again on every pass.
            t.Network.Snapshot = new([new(7, ["10.1.0.0/24"], [], [], [], [])]);
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains("cannot run")) == 1);
        });
        check("VPN tunnel failures and recoveries are reported once each, and listed in status", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Failed", DateTimeOffset.UtcNow, Error: "The tunnel stopped working."));
            for (var i = 0; i < 10; i++) t.Service.Tick();
            var status = t.Service.Handle(new("status")).Status!;
            Assert(status.Alerts!.Count(a => a.Contains("VPN profile Work is down")) == 1 && status.Tunnels!.Single().State == "Failed");
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { State = "Up", Error = null };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.First().Contains("VPN profile Work is up again"));
        });
        check("A VPN backend starts only while Darkwire's installed filters are intact", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            t.Router.VerifyFilters!();
            t.Backend.IntegrityFailure = true;
            try { t.Router.VerifyFilters!(); throw new Exception("Changed filters were accepted."); } catch (InvalidDataException) { }
        });
        check("Stored credentials in use by the enforced policy cannot be replaced or removed", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            Assert(!t.Service.Handle(new("remove-vpn", VpnProfileId: profile.Id)).Success && t.Vault.Profiles.ContainsKey(profile.Id));
        });
        check("VPN routes apply on their own to the enforced policy, keeping rules it learned since the editor loaded it", () =>
        {
            using var idle = new Rig();
            Assert(!idle.Service.Handle(new("apply-vpn", Routes: new([], null))).Success && !idle.Events.Contains("apply"));
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820");
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            Assert(t.Service.Handle(new("status")).Status!.Routes is null, "A profile nothing routes through was reported.");
            // A rule the service took on after the editor's copy, which is now a revision behind.
            var learned = t.Service.Handle(new("policy")).Policy!;
            learned.Rules.Add(new() { ApplicationName = "Learned", Path = @"C:\Apps\learned.exe" });
            Assert(t.Service.Handle(new("apply", learned, ExpectedRevision: 1)).Success);
            profile.Applications.Add(Browser);
            var routed = t.Service.Handle(new("apply-vpn", Routes: new([profile], null)));
            Assert(routed.Success && routed.Message.Contains("VPN routes applied"), routed.Message);
            Assert(routed.Policy!.Rules.Single().ApplicationName == "Learned" && routed.Policy.VpnProfiles.Single().Applications.Single() == Browser);
            Assert(routed.Status!.PolicyRevision == 3 && t.Router.Context!.Tunnels!.FindApplication(Browser)!.ProfileId == profile.Id);
            Assert(routed.Status.Routes!.Single() is { Default: false } route && route.ProfileId == profile.Id && route.CredentialsRevision == profile.CredentialsRevision &&
                route.Applications.Single() == Browser);
            // A profile without matching credentials refuses the whole change.
            var unstored = new VpnProfile { Name = "Unstored", Applications = [@"C:\Apps\other.exe"] };
            var refused = t.Service.Handle(new("apply-vpn", Routes: new([profile, unstored], unstored.Id)));
            Assert(!refused.Success && refused.Message.Contains("Unstored: store this configuration") && t.Service.Handle(new("status")).Status!.PolicyRevision == 3, refused.Message);
            profile.Applications.Clear();
            var removed = t.Service.Handle(new("apply-vpn", Routes: new([profile], null)));
            Assert(removed.Success && removed.Message.Contains("removed") && removed.Status!.Routes is null && removed.Policy!.Rules.Count == 1, removed.Message);
        });
        check("Status names the VPN backends the service can run", () =>
        {
            using var t = new Rig(); Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew })).Success);
            Assert(t.Service.Handle(new("status")).Status!.VpnBackends!.SequenceEqual(["WireGuard"]));
            t.Router.Backends.Remove("WireGuard");
            Assert(t.Service.Handle(new("status")).Status!.VpnBackends!.Count == 0);
        });
        check("A profile the enforced policy only lists takes new credentials, which a route choice then uses", () =>
        {
            using var t = new Rig(); var listed = new VpnProfile { Name = "Later" };
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.Learning, VpnProfiles = [listed] })).Success);
            var key = Convert.ToBase64String(Enumerable.Repeat((byte)0x41, 32).ToArray());
            var config = $"[Interface]\nPrivateKey = {key}\nAddress = 10.50.0.2/32\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.9:51820\n";
            var stored = t.Service.Handle(new("import-vpn", VpnConfiguration: new(listed.Id, "WireGuard", config)));
            Assert(stored.Success, stored.Message);
            Assert(t.Router.Broker!.Ask(new("Browser", Browser, 9, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound, State: "Held")) is not null);
            var request = t.Service.Handle(new("pending")).Pending!.Single();
            var resolved = t.Service.Handle(new("resolve", RequestId: request.Id, Action: RuleAction.Allow, LearningRoute: new(listed.Id)));
            Assert(resolved.Success, resolved.Message);
            var profile = resolved.Policy!.VpnProfiles.Single();
            Assert(profile.CredentialsRevision == stored.VpnProfiles!.Single().Revision && profile.Endpoint == "198.51.100.9:51820" && profile.Applications.Single() == Browser);
            // Once the policy routes through it, its credentials stay put.
            Assert(!t.Service.Handle(new("import-vpn", VpnConfiguration: new(listed.Id, "WireGuard", config))).Success);
        });
        check("A connected profile runs its tunnel with nothing routed through it, guarding no application, in Open mode too", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Ready", "WireGuard", "198.51.100.7:51820"); profile.KeepConnected = true;
            var result = t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] }));
            Assert(result.Success, result.Message);
            var context = t.Router.Context!;
            Assert(context.Profiles.Single() == new TunnelDemand(profile.Id, "WireGuard", profile.CredentialsRevision) && context.Tunnels!.FindApplication(Browser) is null);
            Assert(!Named(t.Backend.Installed, "Router: VPN guard").Any() && Named(t.Backend.Installed, "Router: VPN endpoint").Count() == 3);
            Assert(t.Service.Handle(new("status")).Status!.Routes!.Single() is { Kept: true, Default: false, Applications.Count: 0 });
            Assert(t.Service.Handle(new("apply", new() { Mode = FirewallMode.Open, VpnProfiles = [profile] }, ExpectedRevision: 1)).Success);
            Assert(t.Router.Running && t.Router.Context!.Profiles.Single().ProfileId == profile.Id && !Named(t.Backend.Installed, "Router: leak guard").Any());
            profile.KeepConnected = false;
            var stopped = t.Service.Handle(new("apply-vpn", Routes: new([profile], null)));
            Assert(stopped.Success && stopped.Status!.Routes is null && t.Events.Contains("router-stop"), stopped.Message);
        });
        check("A default profile leaves the local networks to rules unless told to carry them, and status says which", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Everything", "WireGuard", "198.51.100.7:51820");
            t.Network.Snapshot = new([new(7, ["192.168.1.0/24"], [], [], [], [])]);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id })).Success);
            static bool Covers(NativeFilter f, string address) => f.RemoteNetwork is null || IpNetwork.TryParse(f.RemoteNetwork, out var network) && network.Contains(System.Net.IPAddress.Parse(address));
            var guards = Named(t.Backend.Installed, "Router: VPN guard").ToArray();
            Assert(!guards.Any(f => Covers(f, "192.168.1.50")) && guards.Any(f => Covers(f, "203.0.113.8")) && guards.Any(f => Covers(f, "2001:db8::8")) && t.Router.Context!.BypassLocal);
            Assert(t.Service.Handle(new("status")).Status!.LocalNetworkBypassesVpn == true);
            var carried = t.Service.Handle(new("apply-vpn", Routes: new([profile], profile.Id, BypassLocal: false)));
            Assert(carried.Success && Named(t.Backend.Installed, "Router: VPN guard").All(f => f.RemoteNetwork is null) && !t.Router.Context!.BypassLocal, carried.Message);
            Assert(carried.Status!.LocalNetworkBypassesVpn == false && carried.Policy!.LocalNetworkBypassesVpn == false);
        });
        check("A tunnel that sends but never hears from its server is reported once each time it comes up", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            static bool Unanswered(string alert) => alert.Contains("VPN profile Work is up, but its server has not answered");
            var since = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1);
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", since, 9, ["10.64.0.2"], SentBytes: 4_000));
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Unanswered) == 1);
            // An answer after the report is reported once; a tunnel just up is not; coming up again without one is reported again.
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { ReceivedBytes = 900 };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains("VPN profile Work's server is answering.")) == 1);
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Since = DateTimeOffset.UtcNow, ReceivedBytes = 0 };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Unanswered) == 1);
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Since = since.AddSeconds(30) };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Unanswered) == 2);
            // With nothing counted as sent, traffic the router routed into the tunnel is enough.
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Since = since.AddSeconds(40), SentBytes = 0, Routed = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(20) };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Unanswered) == 3);
            // Traffic routed in later, once the tunnel already sent unanswered, is the same silence.
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Since = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(30), SentBytes = 4_000, Routed = null };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Routed = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(20) };
            for (var i = 0; i < 5; i++) t.Service.Tick();
            Assert(t.Service.Handle(new("status")).Status!.Alerts!.Count(Unanswered) == 4);
        });
        check("A disconnected profile starts no tunnel and needs no stored credentials, while its application stays routed to it and so held; connecting starts it", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            Assert(t.Router.Context!.Profiles.Single().ProfileId == profile.Id);
            var guards = Named(t.Backend.Installed, "Router: VPN guard").Count();
            // Disconnected, with a configuration revision the service never stored: nothing needs it.
            var off = new VpnProfile { Id = profile.Id, Name = profile.Name, Kind = profile.Kind, Endpoint = profile.Endpoint, CredentialsRevision = Guid.NewGuid(), Applications = [Browser], Disconnected = true };
            var applied = t.Service.Handle(new("apply-vpn", Routes: new([off], null)));
            Assert(applied.Success && applied.Message.Contains("Disconnected: Work; what it carries is refused until you connect it."), applied.Message);
            Assert(t.Router.Context!.Profiles.Count == 0 && t.Router.Context.Tunnels!.Applications.Any(a => a.ProfileId == profile.Id), "A disconnected profile ran a tunnel, or let its application go.");
            Assert(applied.Status!.Routes!.Single() is { Disconnected: true } && Named(t.Backend.Installed, "Router: VPN guard").Count() == guards, "Disconnecting changed what guards the application.");
            var on = new VpnProfile { Id = profile.Id, Name = profile.Name, Kind = profile.Kind, Endpoint = profile.Endpoint, CredentialsRevision = profile.CredentialsRevision, Applications = [Browser], KeepConnected = true };
            Assert(t.Service.Handle(new("apply-vpn", Routes: new([on], null))).Success && t.Router.Context!.Profiles.Single().ProfileId == profile.Id, "Connecting did not start the tunnel.");
        });
        check("Reconnect asks the router to start a profile's tunnel again, and says why it cannot; both it and a check need an administrator", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            var early = t.Service.Handle(new("reconnect-vpn", VpnProfileId: profile.Id));
            Assert(!early.Success && early.Message == "Darkwire runs no VPN tunnels until it enforces policy.", early.Message);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            t.Router.CanReconnect = true;
            var asked = t.Service.Handle(new("reconnect-vpn", VpnProfileId: profile.Id));
            Assert(asked.Success && asked.Message.StartsWith("Reconnecting Work:") && t.Events.Contains("reconnect " + profile.Id), asked.Message);
            t.Router.CanReconnect = false;
            var none = t.Service.Handle(new("reconnect-vpn", VpnProfileId: profile.Id));
            Assert(!none.Success && none.Message == "Work has no tunnel to reconnect; connect it first.", none.Message);
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Starting", DateTimeOffset.UtcNow));
            var starting = t.Service.Handle(new("reconnect-vpn", VpnProfileId: profile.Id));
            Assert(!starting.Success && starting.Message == "Work is already connecting.", starting.Message);
            Assert(!ServiceClient.IsPublic("reconnect-vpn") && !ServiceClient.IsPublic("check-vpn"));
        });
        check("A tunnel check needs a tunnel up and a DNS server it carries, and says so otherwise", () =>
        {
            using var t = new Rig(); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            var down = t.Service.Handle(new("check-vpn", VpnProfileId: profile.Id));
            Assert(!down.Success && down.Message == "Work has no tunnel up to check." && down.Check is null, down.Message);
            // Up, naming a server only the physical network would reach: nothing to ask through the tunnel.
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", DateTimeOffset.UtcNow, 9, ["10.64.0.2"], Resolvers: ["10.64.0.1"]));
            var quiet = t.Service.Handle(new("check-vpn", VpnProfileId: profile.Id));
            Assert(quiet.Success && quiet.Message.Contains("names no DNS server its tunnel carries") && quiet.Check is { Answered: false, Server: null }, quiet.Message);
        });
        check("A tunnel's DNS server is asked from a socket pinned to its route: an answer or its host's refusal is timed, silence is none", () =>
        {
            using var server = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            server.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
            var endpoint = (System.Net.IPEndPoint)server.LocalEndPoint!;
            // Interface index 0 leaves the choice to Windows, which loopback needs.
            var route = new Darkwire.Vpn.Egress(1, 0, System.Net.IPAddress.Loopback, 8, 0);
            var answering = Task.Run(() =>
            {
                var buffer = new byte[512]; System.Net.EndPoint from = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                var length = server.ReceiveFrom(buffer, ref from);
                Assert(length == 17 && buffer[2] == 0x01 && buffer[12] == 0 && buffer[14] == 2, "The question was not the root zone's name servers.");
                buffer[2] |= 0x80; server.SendTo(buffer, length, System.Net.Sockets.SocketFlags.None, from);
            });
            Assert(TunnelProbe.Ask(route, endpoint, TimeSpan.FromSeconds(3)) is { } took && took < TimeSpan.FromSeconds(3), "An answer was not timed.");
            Assert(answering.Wait(TimeSpan.FromSeconds(3)));
            Assert(TunnelProbe.Ask(route, endpoint, TimeSpan.FromMilliseconds(300)) is null, "Silence counted as an answer.");
            server.Dispose();
            Assert(TunnelProbe.Ask(route, endpoint, TimeSpan.FromSeconds(3)) is not null, "The closed port's refusal through the route did not count.");
        });
        check("A tunnel reconnected for silence is reported at its first, second and fourth reconnect, never again as a new silence, and its server's answer once", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig(clock: clock); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            int Count(string text) => t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains(text));
            void Watch() { for (var i = 0; i < 5; i++) t.Service.Tick(); }
            const string First = "VPN profile Work's server stopped answering, so Darkwire reconnected its tunnel.", Again = "VPN profile Work's server still isn't answering",
                Answering = "VPN profile Work's server is answering.", Never = "VPN profile Work is up, but its server has not answered";
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", clock.Now - TimeSpan.FromMinutes(5), 9, ["10.64.0.2"], SentBytes: 4_000, ReceivedBytes: 9_000,
                LastReceived: clock.Now - TimeSpan.FromSeconds(60), Silent: clock.Now - TimeSpan.FromSeconds(50)));
            Watch();
            // Reconnected: connecting, then up with nothing answered yet, which is the same silence.
            t.Router.TunnelStates[0] = new(profile.Id, "WireGuard", "Starting", clock.Now, Reconnects: 1);
            Watch();
            t.Router.TunnelStates[0] = new(profile.Id, "WireGuard", "Up", clock.Now - TimeSpan.FromSeconds(30), 9, ["10.64.0.2"], SentBytes: 500, Reconnects: 1);
            Watch();
            Assert(Count(First) == 1 && Count(Never) == 0, "A reconnect was not reported once, or its silence was reported again as a new one.");
            foreach (var reconnects in new[] { 2, 3, 4 })
            {
                t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Reconnects = reconnects, Since = clock.Now - TimeSpan.FromSeconds(30) };
                Watch();
            }
            Assert(Count(Again) == 2 && Count(First) == 1 && Count(Never) == 0, "Reconnects were not reported at the second and fourth only.");
            // The server answers: the reconnects start over and the answer is reported once.
            t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { Reconnects = 0, ReceivedBytes = 300, LastReceived = clock.Now };
            Watch(); Watch();
            Assert(Count(Answering) == 1, "The answer after the reconnects was not reported once.");
        });
        check("A server that answered and then falls silent is reported, at most every ten minutes, and so is its answering again", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig(clock: clock); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            int Count(string text) => t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains(text));
            // The service looks at its tunnels every fifth tick.
            void Watch() { for (var i = 0; i < 5; i++) t.Service.Tick(); }
            const string Stopped = "VPN profile Work's server stopped answering at ", Answering = "VPN profile Work's server is answering.";
            var heard = new TunnelStatus(profile.Id, "WireGuard", "Up", clock.Now - TimeSpan.FromMinutes(5), 9, ["10.64.0.2"], SentBytes: 4_000, ReceivedBytes: 9_000,
                LastReceived: clock.Now - TimeSpan.FromSeconds(40));
            t.Router.TunnelStates.Add(heard with { Silent = clock.Now - TimeSpan.FromSeconds(5) });
            Watch();
            Assert(Count(Stopped) == 0, "A silence shorter than the limit was reported.");
            clock.Now += TimeSpan.FromSeconds(20); Watch(); Watch();
            Assert(Count(Stopped) == 1 && Count(Answering) == 0, "A server gone silent was not reported once.");
            t.Router.TunnelStates[0] = heard with { LastReceived = clock.Now };
            Watch(); Watch();
            Assert(Count(Stopped) == 1 && Count(Answering) == 1, "Its answering again was not reported once.");
            // Falling silent again within ten minutes shows on its card but is not reported again, nor is the answer after it.
            clock.Now += TimeSpan.FromMinutes(1);
            t.Router.TunnelStates[0] = heard with { Silent = clock.Now - TimeSpan.FromSeconds(30) };
            Watch();
            t.Router.TunnelStates[0] = heard with { LastReceived = clock.Now };
            Watch();
            Assert(Count(Stopped) == 1 && Count(Answering) == 1, "A silence soon after the last report was reported again.");
            clock.Now += TimeSpan.FromMinutes(10);
            t.Router.TunnelStates[0] = heard with { Silent = clock.Now - TimeSpan.FromSeconds(30) };
            Watch();
            Assert(Count(Stopped) == 2, "A silence ten minutes after the last report was not reported.");
            // A tunnel going down is no answer.
            t.Router.TunnelStates[0] = heard with { State = "Failed", Error = "The tunnel stopped working." };
            Watch();
            Assert(Count(Answering) == 1);
        });
        check("The app's start has the service check its tunnels end to end again, and restarts after failed checks are reported at the first, second and fourth", () =>
        {
            var clock = new Clock(DateTimeOffset.UtcNow);
            using var t = new Rig(clock: clock); var profile = t.Vault.Store("Work", "WireGuard", "198.51.100.7:51820", Browser);
            Assert(t.Service.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, VpnProfiles = [profile] })).Success);
            int Count(string text) => t.Service.Handle(new("status")).Status!.Alerts!.Count(a => a.Contains(text));
            void Watch() { for (var i = 0; i < 5; i++) t.Service.Tick(); }
            Assert(t.Service.Handle(new("check-tunnels")) is { Success: true, Message: var none } && none.StartsWith("No VPN tunnel", StringComparison.Ordinal) && t.Router.Rechecks == 0, "Tunnels were checked with none running.");
            t.Router.TunnelStates.Add(new(profile.Id, "WireGuard", "Up", clock.Now, 9, ["10.64.0.2"], Checking: true));
            Assert(t.Service.Handle(new("check-tunnels")) is { Success: true, Status.Tunnels: [{ Checking: true }] } && t.Router.Rechecks == 1, "The running tunnels were not checked again.");
            const string First = "VPN profile Work's DNS server did not answer through its tunnel when Darkwire checked it", Again = "VPN profile Work's tunnel still carries nothing back when checked";
            foreach (var restarts in new[] { 1, 2, 3, 4 })
            {
                t.Router.TunnelStates[0] = t.Router.TunnelStates[0] with { CheckRestarts = restarts };
                Watch();
            }
            Assert(Count(First) == 1 && Count(Again) == 2, "Restarts after failed checks were not reported at the first, second and fourth only.");
        });
    }

    /// <summary>A client end of a real pipe, as the desktop app opens it but without checking the server's identity.</summary>
    private static System.IO.Pipes.NamedPipeClientStream OpenPipe(string name)
    {
        var pipe = new System.IO.Pipes.NamedPipeClientStream(".", name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
        pipe.Connect(3000); return pipe;
    }

    private static ServiceResponse SendOverPipe(string name, ServiceRequest request)
    {
        using var pipe = OpenPipe(name);
        ServiceProtocol.WriteAsync(pipe, request, default).GetAwaiter().GetResult();
        return ServiceProtocol.ReadAsync<ServiceResponse>(pipe, default).GetAwaiter().GetResult();
    }

    private static MemoryStream RequestStream(ServiceRequest request)
    {
        var stream = new MemoryStream(); ServiceProtocol.WriteAsync(stream, request, default).GetAwaiter().GetResult();
        stream.Position = 0; return stream;
    }
    private sealed class Rig : IDisposable
    {
        public readonly List<string> Events = [];
        public readonly List<string> NativeErrors = [];
        public readonly FakeFirewall Firewall;
        public readonly FakeBackend Backend;
        public readonly FakeJournal Journal;
        public readonly FakeNetwork Network = new();
        public readonly FakeRouter Router;
        public readonly TakeoverCoordinator Service;
        public Rig(string phase = "Inactive", FlowAttribution? attribution = null, TimeProvider? clock = null, Func<IReadOnlyList<FlowProcess>>? connected = null, IResolverCatalog? resolvers = null)
        {
            Firewall = new(Events); Backend = new(Events); Journal = new(Events) { Value = new() { Phase = phase, Policy = new() { Mode = FirewallMode.BlockNew }, OriginalProfiles = new() { [1] = true, [2] = true, [4] = true } } };
            Router = new(Events); FirewallArea = new(Events);
            Service = new(Firewall, Journal, () => Backend, vpnVault: Vault, network: Network, nativePreflight: plan => NativeErrors.Count > 0 ? NativeErrors : WfpConditions.Preflight(plan),
                protections: () => Firewall.Disabled ? DisabledProtections : Protections, audit: Audit, createRouter: (broker, verify) => { Router.Broker = broker; Router.VerifyFilters = verify; return Router; },
                attribution: attribution, connected: connected, clock: clock, resolvers: resolvers, firewallArea: FirewallArea);
        }
        public readonly FakeFirewallArea FirewallArea;
        public readonly FakeAudit Audit = new();
        public readonly FakeVault Vault = new();
        public readonly Dictionary<string, int> Protections = new() { ["PROVIDER_MPSSVC_WSH"] = 200, ["PROVIDER_MPSSVC_APP_ISOLATION"] = 40 };
        public Dictionary<string, int> DisabledProtections = new() { ["PROVIDER_MPSSVC_WSH"] = 200, ["PROVIDER_MPSSVC_APP_ISOLATION"] = 40 };
        public void Dispose() => Service.Dispose();
    }
    internal sealed class FakeRouter(List<string> events) : IConnectionRouter
    {
        public static readonly RouterPlan TestPlan = new(@"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", ["198.18.0.0/15", "fd5a:9c33:21e7::/64"]);
        public RouterPlan Plan => TestPlan;
        public bool Available { get; set; } = true;
        public bool Running { get; set; }
        public string? Fault { get; set; }
        public bool StartFailure;
        public RouterContext? Context;
        public LearningBroker? Broker;
        public Action? VerifyFilters;
        public HashSet<string> Backends = ["WireGuard", TakeoverCoordinator.DnsBackend];
        public List<TunnelStatus> TunnelStates = [];
        public bool TunnelUp;
        public Func<System.Net.IPAddress, Guid?, Darkwire.Vpn.Egress?> OwnRoutes = (_, _) => null;
        public Darkwire.Vpn.Egress? OwnEgress(System.Net.IPAddress destination, Guid? profile) => OwnRoutes(destination, profile);
        public bool Supports(string kind) => Backends.Contains(kind);
        public IReadOnlyList<TunnelStatus> Tunnels => TunnelStates;
        public IReadOnlyList<RoutedConnection> Connections { get; set; } = [];
        /// <summary>Whether the fake has a tunnel to start again when asked to reconnect one.</summary>
        public bool CanReconnect;
        public bool Reconnect(Guid profile) { events.Add("reconnect " + profile); return CanReconnect; }
        /// <summary>How many times the tunnels were asked to be checked again.</summary>
        public int Rechecks;
        public void Recheck() => Rechecks++;
        public void Start(RouterContext context) { events.Add("router-start"); if (StartFailure) throw new IOException("Adapter failure"); Context = context; Running = true; Fault = null; }
        public void Update(RouterContext context) { events.Add("router-update"); Context = context; }
        public void Stop() { if (Running) events.Add("router-stop"); Running = false; }
        public void Dispose() => Stop();
    }
    private sealed class FakeNetwork : INetworkEnvironment
    {
        public NetworkSnapshot Snapshot = NetworkSnapshot.Empty;
        public NetworkSnapshot Capture() => Snapshot;
    }
    /// <summary>Service credential metadata only; nothing here can start a tunnel.</summary>
    internal sealed class FakeVault : IVpnProfileVault
    {
        public readonly Dictionary<Guid, StoredVpnProfile> Profiles = [];
        public bool Unreadable;
        public StoredVpnProfile Save(Guid id, string kind, string configuration) =>
            Profiles[id] = new(id, kind, Darkwire.Vpn.VpnConfiguration.Parse(kind, configuration).Endpoint, Guid.NewGuid(), DateTimeOffset.UtcNow);
        public IReadOnlyList<StoredVpnProfile> List() => Unreadable ? throw new IOException("Unreadable VPN storage.") : Profiles.Values.ToArray();
        public Darkwire.Vpn.ParsedVpnConfiguration Read(Guid id, Guid revision) => throw new InvalidOperationException("The fake vault holds no credentials.");
        public void Delete(Guid id) => Profiles.Remove(id);
        /// <summary>A profile stored in the service whose policy entry names the stored revision.</summary>
        public VpnProfile Store(string name, string kind, string endpoint, params string[] applications)
        {
            var profile = new VpnProfile { Name = name, Kind = kind, Endpoint = endpoint, Applications = [.. applications] };
            var stored = Profiles[profile.Id] = new(profile.Id, kind, endpoint, Guid.NewGuid(), DateTimeOffset.UtcNow);
            profile.CredentialsRevision = stored.Revision;
            return profile;
        }
    }
    private sealed class FakeAudit : IAuditPolicy
    {
        // Success auditing already on, failure off.
        public readonly Dictionary<Guid, uint> Values = new() { [WindowsAuditPolicy.FilteringConnection] = 0x1, [WindowsAuditPolicy.FilteringPacketDrop] = 0x1 };
        public IReadOnlyDictionary<Guid, uint> Query(IReadOnlyList<Guid> subcategories) => subcategories.ToDictionary(s => s, s => Values[s]);
        public void Set(IReadOnlyDictionary<Guid, uint> settings) { foreach (var (key, value) in settings) Values[key] = value; }
    }
    private sealed class FakeJournal(List<string> events) : IPolicyJournal
    {
        public ServiceJournal Value = new();
        public string? FailPhase;
        public ServiceJournal Read() => Value;
        public void Write(ServiceJournal journal) { if (journal.Phase == FailPhase) throw new IOException("Journal write failure"); Value = journal; events.Add("journal:" + journal.Phase); }
        public string BackupPath() => "memory.wfw";
    }
    private sealed class FakeFirewall(List<string> events) : IWindowsFirewallControl
    {
        public readonly List<FirewallRule> Rules = [];
        public readonly List<string> ConflictList = [];
        public bool ExportFailure, DisableFailure, RestoreFailure, Disabled;
        public Dictionary<int, bool> Profiles() => new() { [1] = !Disabled, [2] = !Disabled, [4] = !Disabled };
        public IReadOnlyList<string> Conflicts() => ConflictList;
        // Each read yields fresh objects, as the registry reader does.
        public FirewallSnapshot Read() => new(System.Text.Json.JsonSerializer.Deserialize<List<FirewallRule>>(System.Text.Json.JsonSerializer.Serialize(Rules, StateStore.JsonOptions), StateStore.JsonOptions)!,
            new() { [1] = true, [2] = true, [4] = true }, []) { InboundAllowed = new() { [1] = false, [2] = false, [4] = false }, OutboundAllowed = new() { [1] = true, [2] = true, [4] = true } };
        public void Export(string path) { events.Add("backup"); if (ExportFailure) throw new IOException("Backup failure"); }
        public void SetProfiles(IReadOnlyDictionary<int, bool> profiles)
        {
            var disabling = profiles.Values.All(v => !v); events.Add(disabling ? "disable" : "restore");
            if (disabling ? DisableFailure : RestoreFailure) throw new IOException("Profile change failure");
            Disabled = disabling;
        }
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
    /// <summary>Windows Security's firewall area policy value, unset unless a check sets it; checks never touch the real one.</summary>
    internal sealed class FakeFirewallArea(List<string> events) : IFirewallAreaPolicy
    {
        public int? Value;
        public bool Failure;
        public int? Read() => Value;
        public void Write(int? value)
        {
            if (Failure) throw new UnauthorizedAccessException("Access is denied.");
            events.Add("firewall-area " + (value?.ToString() ?? "unset")); Value = value;
        }
    }
    private sealed class FakeBackend(List<string> events) : IFilterBackend
    {
        public bool ApplyFailure, IntegrityFailure, EventsReady = true, ReleaseFailure, Released;
        /// <summary>The startup lock's filters last installed.</summary>
        public IReadOnlyList<NativeFilter> Locked { get; private set; } = [];
        public int? LockFilterCount => Locked.Count;
        public bool StartupLockReleased => Released;
        /// <summary>When set, applies register none of their plan's startup lock.</summary>
        public bool LoseLock;
        /// <summary>What an audit finds in WFP, when not what the last apply installed.</summary>
        public (int Filters, int Lock)? AuditFinds;
        public (int Filters, int Lock)? Audited { get; private set; }
        public void ReleaseStartupLock() { events.Add("release"); if (ReleaseFailure) throw new InvalidOperationException("Release failure"); Released = true; }
        public readonly Dictionary<string, long> Drops = [];
        public IReadOnlyDictionary<string, long> DropsByName => Drops;
        public List<Connection> Observed = [];
        /// <summary>When set, Apply waits for it, holding the coordinator lock as a slow WFP transaction would.</summary>
        public ManualResetEventSlim? HoldApply;
        public readonly ManualResetEventSlim ApplyEntered = new(false);
        public List<string> Permits = [];
        public IReadOnlyCollection<Guid> WireGuardTunnels = [];
        public IReadOnlyList<string> HardPermits(IReadOnlyCollection<Guid> wireGuardTunnels) { WireGuardTunnels = wireGuardTunnels; return Permits; }
        public readonly Queue<bool> Probes = new();
        public bool ProbeLearningEvents() => Probes.Count > 0 ? Probes.Dequeue() : EventsReady;
        public bool LearningEventsReady => EventsReady;
        public int FilterCount { get; private set; }
        public int BootFilterCount { get; private set; }
        public IReadOnlyList<NativeFilter> Installed { get; private set; } = [];
        public void VerifyIntegrity() { Audited = AuditFinds ?? (FilterCount, Locked.Count); if (IntegrityFailure) throw new InvalidDataException("Changed filters"); }
        public void Apply(FilterPlan plan)
        {
            events.Add("apply"); ApplyEntered.Set(); HoldApply?.Wait(TimeSpan.FromSeconds(30));
            if (ApplyFailure) throw new IOException("WFP transaction failure");
            FilterCount = plan.Filters.Count; Installed = plan.Filters; BootFilterCount = WfpInstallationPlan.Build(plan).Count(f => f.BootTime);
            Locked = LoseLock ? [] : WfpInstallationPlan.Build(plan).Where(r => r.Lock).Select(r => r.Filter).ToArray();
        }
        public void RemoveOwnedFilters() { events.Add("remove"); FilterCount = 0; Installed = []; BootFilterCount = 0; Locked = []; }
        public IReadOnlyList<Connection> DrainBlockedConnections() { var result = Observed.ToArray(); Observed.Clear(); return result; }
        public readonly List<(Connection Connection, string Filter)> NamedDrops = [];
        public IReadOnlyList<(Connection Connection, string Filter)> DrainNamedDrops() { var result = NamedDrops.ToArray(); NamedDrops.Clear(); return result; }
        public void Dispose() { }
    }
}
