using Darkwire.Core;
using Darkwire.Engine;
using System.Net;

/// <summary>Per-application VPN routing as the compiler lowers it, checked through the user-mode WFP arbitration model.</summary>
internal static class VpnRoutingChecks
{
    private const string Service = @"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", Browser = @"C:\Apps\browser.exe", Game = @"C:\Apps\game.exe", Other = @"C:\Apps\other.exe";
    private const string WireGuard = @"C:\Program Files\Darkwire\Service\Backends\WireGuard\wireguard.exe";
    private const string TunnelService = "WireGuardTunnel$0123456789abcdef0123456789abcdef";
    // A Teredo client address (2001::/32): IPv6 edge traffic that edge-traversal rules admit.
    private const string Teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2";
    private static readonly RouterPlan Router = new(Service, ["198.18.0.0/15", "fd5a:9c33:21e7::/64"]);
    private static readonly RouterPlan Vpn = Router with
    {
        TunneledApplications = [Browser],
        // A peer named by address, and one named by host name, which may be at any address.
        Endpoints = [new(WireGuard, TunnelService, 17, "198.51.100.7/32", 51820), new(WireGuard, TunnelService, 17, null, 51830)]
    };

    /// <summary>A downloaded FireHOL Level 1 with the given networks.</summary>
    private sealed class Listed(IReadOnlyList<string> networks) : IBlocklistContents
    {
        public IReadOnlyList<string>? Networks(string catalogId) => catalogId == "firehol-level1" ? networks : null;
    }

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool condition, string reason = "VPN routing invariant failed.") { if (!condition) throw new Exception(reason); }
        static FirewallRule Allow(string path) => new() { ApplicationName = Path.GetFileNameWithoutExtension(path), Path = path };
        static FirewallRule Inbound(string path, bool edgeTraversal = true) =>
            new() { ApplicationName = Path.GetFileNameWithoutExtension(path), Path = path, Direction = TrafficDirection.Inbound, EdgeTraversal = edgeTraversal };
        static FlowOwner Owner(string path, params string[] sids) => new(path.ToLowerInvariant(), new HashSet<string>(sids.Append("S-1-5-18"), StringComparer.OrdinalIgnoreCase), null);
        // Application IDs as the engine derives them: the kernel is System; other paths are expanded and made full, then compared without case.
        static PlanMatcher Matcher(FilterPlan plan) =>
            new(plan, p => IdentitySelectors.IsSystemApplication(p) ? p : Path.GetFullPath(Environment.ExpandEnvironmentVariables(p)).ToLowerInvariant(), a => a);
        static RuleAction? Verdict(PlanMatcher matcher, string local, string remote, ushort port, FlowOwner owner, byte protocol = 6, TrafficDirection direction = TrafficDirection.Outbound, uint flags = 0) =>
            matcher.Match(new(direction, protocol, IPAddress.Parse(local), 50_000, IPAddress.Parse(remote), port, owner, Flags: flags))?.Action;
        // An inbound connection to the application over IPv4, over IPv6, and over IPv6 arriving through Teredo.
        static PlanVerdict?[] Arrivals(PlanMatcher matcher, string application, string remote = "192.168.1.50", string remote6 = "2001:db8::50")
        {
            PlanVerdict? Arrive(string local, string from, uint? tunnel = null) =>
                matcher.Match(new(TrafficDirection.Inbound, 6, IPAddress.Parse(local), 50_000, IPAddress.Parse(from), 443, Owner(application), TunnelType: tunnel));
            return [Arrive("192.168.1.20", remote), Arrive("2001:db8::20", remote6), Arrive(Teredo, remote6, FilterCompiler.TeredoTunnelType)];
        }

        check("No VPN profile can carry svchost.exe, which every Windows service in a shared host runs from", () =>
        {
            foreach (var host in new[] { @"%SystemRoot%\system32\svchost.exe", @"C:\Windows\System32\SVCHOST.EXE" })
            {
                var state = new AppState { Mode = FirewallMode.BlockNew, RouteConnections = true, VpnProfiles = [new() { Name = "Work" }] };
                Expect(!VpnAssignments.Carriable(host));
                try { VpnAssignments.Assign(state, state.VpnProfiles[0].Id, host); throw new Exception("svchost.exe was assigned to a profile."); }
                catch (InvalidOperationException error) { Expect(error.Message == VpnAssignments.ServiceHostRefusal, error.Message); }
                // A policy that names it anyway, written by hand or by an older version, is refused before anything is enforced.
                state.VpnProfiles[0].Applications.Add(host);
                Expect(PolicyValidation.Validate(state).Contains(VpnAssignments.ServiceHostRefusal) && FilterCompiler.Compile(state).Errors.Contains(VpnAssignments.ServiceHostRefusal),
                    "A profile carrying svchost.exe compiled.");
            }
            Expect(VpnAssignments.Carriable(Browser));
        });
        check("A prompt may route a service through a VPN only when it runs alone in its own program and is not part of Windows", () =>
        {
            Expect(VpnAssignments.CarriableService(@"C:\Program Files\Backup\agent.exe", "BackupAgent"));
            Expect(!VpnAssignments.CarriableService(@"C:\Program Files\Backup\agent.exe", "BackupAgent, BackupScheduler"), "A program running two services was carriable.");
            Expect(!VpnAssignments.CarriableService(@"%SystemRoot%\system32\svchost.exe", "Dnscache"));
            Expect(!VpnAssignments.CarriableService(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "spoolsv.exe"), "Spooler"), "A Windows service was carriable.");
            Expect(!VpnAssignments.CarriableService(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MsMpEng.exe"), "WinDefend"));
            Expect(VpnAssignments.PartOfWindows(@"%SystemRoot%\explorer.exe") && !VpnAssignments.PartOfWindows(@"C:\WindowsApps\x.exe"), "A folder named like Windows' counted as Windows.");
        });
        check("Weights put backend permits above the tunnel permit, and the VPN guard between it and explicit allows", () =>
            Expect(FilterCompiler.CoreWeight > FilterCompiler.RouterServiceWeight && FilterCompiler.RouterServiceWeight > FilterCompiler.TunnelWeight &&
                FilterCompiler.TunnelWeight > FilterCompiler.VpnGuardWeight && FilterCompiler.VpnGuardWeight > FilterCompiler.AllowWeight &&
                FilterCompiler.AllowWeight > FilterCompiler.LeakGuardWeight));
        check("VPN backends may reach only their peers' ports, by executable and tunnel service, in both families for host names", () =>
        {
            var kernel = FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn);
            var endpoints = kernel.Filters.Where(f => f.Name == "Router: VPN endpoint").ToArray();
            Expect(endpoints.Length == 3 && endpoints.All(f => f.Action == RuleAction.Allow && f.Weight == FilterCompiler.RouterServiceWeight && f.Direction == TrafficDirection.Outbound &&
                f.ApplicationPath == WireGuard && f.Service == TunnelService && f.Protocol == 17));
            var literal = endpoints.Single(f => f.RemoteNetwork is not null);
            Expect(!literal.Ipv6 && literal.RemoteNetwork == "198.51.100.7/32" && literal.RemotePort == new PortRange(51820, 51820));
            var named = endpoints.Where(f => f.RemoteNetwork is null).ToArray();
            Expect(named.Select(f => f.Ipv6).Order().SequenceEqual([false, true]) && named.All(f => f.RemotePort == new PortRange(51830, 51830)));
            PersistentFilterSession.ValidatePlan(kernel);
        });
        check("The router evaluates the backend permits; only the kernel gets the relay, tunnel and guard filters", () =>
        {
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            var routed = FilterCompiler.Endpoints(decision, Vpn);
            Expect(routed.Filters.Take(decision.Filters.Count).SequenceEqual(decision.Filters) && routed.Filters.Skip(decision.Filters.Count).All(f => f.Name == "Router: VPN endpoint"));
            Expect(FilterCompiler.Endpoints(decision, Router).Filters.SequenceEqual(decision.Filters));
        });
        check("A VPN-carried application is guarded in both directions and both families; a default profile guards every application", () =>
        {
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            var guards = FilterCompiler.Route(decision, Vpn).Filters.Where(f => f.Name == "Router: VPN guard").ToArray();
            Expect(guards.Length == 4 && guards.All(f => f.ApplicationPath == Browser && f.Action == RuleAction.Deny && f.Weight == FilterCompiler.VpnGuardWeight && f.RemoteNetwork is null));
            Expect(guards.Select(f => (f.Ipv6, f.Direction)).Distinct().Count() == 4);
            var all = FilterCompiler.Route(decision, Vpn with { TunnelAll = true }).Filters.Where(f => f.Name == "Router: VPN guard").ToArray();
            Expect(all.Length == 4 && all.All(f => f.ApplicationPath is null));
            Expect(FilterCompiler.Route(decision, Router).Filters.All(f => f.Name != "Router: VPN guard"));
        });
        check("WFP arbitration keeps a VPN-carried application in the tunnel whatever its rules allow", () =>
        {
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Browser), Allow(Game)] }), Vpn));
            // Routed: the browser's socket sits on Darkwire's tunnel. Around it, its allow rule cannot pass the guard.
            Expect(Verdict(matcher, "198.18.0.1", "203.0.113.8", 443, Owner(Browser)) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Browser)) == RuleAction.Deny);
            Expect(Verdict(matcher, "10.64.0.2", "203.0.113.8", 443, Owner(Browser)) == RuleAction.Deny);
            Expect(Verdict(matcher, "fe80::20", "fe80::1", 53, Owner(Browser), 17) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "192.168.1.50", 50_000, Owner(Browser), direction: TrafficDirection.Inbound) == RuleAction.Deny);
            Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 8080, Owner(Browser), flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            // Another application's explicit allow still passes the leak guard; without one it is blocked.
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Game)) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Other)) == RuleAction.Deny);
            // The relay leaves through physical and tunnel interfaces alike.
            Expect(Verdict(matcher, "10.64.0.2", "203.0.113.8", 443, Owner(Service)) == RuleAction.Allow);
        });
        check("Edge-traversal allows drop beneath the VPN guard; only their Teredo part keeps the edge weight, under the VPN edge guard", () =>
        {
            Expect(FilterCompiler.DenyWeight > FilterCompiler.VpnEdgeGuardWeight && FilterCompiler.VpnEdgeGuardWeight > FilterCompiler.EdgeAllowWeight &&
                FilterCompiler.EdgeAllowWeight > FilterCompiler.EdgeGuardWeight && FilterCompiler.EdgeGuardWeight > FilterCompiler.CoreWeight);
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Inbound(Browser), Inbound("*")] });
            var edge = decision.Filters.Where(f => f.Weight == FilterCompiler.EdgeAllowWeight).ToArray();
            Expect(edge.Length == 4);
            var kernel = FilterCompiler.Route(decision, Vpn);
            Expect(edge.All(f => kernel.Filters.Contains(f with { Weight = FilterCompiler.AllowWeight })));
            Expect(kernel.Filters.Where(f => f.Weight == FilterCompiler.EdgeAllowWeight).SequenceEqual(edge.Where(f => f.Ipv6).Select(f => f with { TunnelType = FilterCompiler.TeredoTunnelType })));
            Expect(kernel.Filters.Single(f => f.Name == "Router: VPN edge guard") is
                { Ipv6: true, Direction: TrafficDirection.Inbound, Action: RuleAction.Deny, Weight: FilterCompiler.VpnEdgeGuardWeight, ApplicationPath: Browser, TunnelType: FilterCompiler.TeredoTunnelType });
            PersistentFilterSession.ValidatePlan(kernel);
            // A default profile leaves nothing at the edge weight; without guards, or without edge-traversal allows, nothing changes.
            Expect(FilterCompiler.Route(decision, Vpn with { TunnelAll = true }).Filters.All(f => f.Weight != FilterCompiler.EdgeAllowWeight && f.Name != "Router: VPN edge guard"));
            Expect(FilterCompiler.Route(decision, Router).Filters.Take(decision.Filters.Count).SequenceEqual(decision.Filters));
            Expect(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Browser)] }), Vpn).Filters.All(f => f.Name != "Router: VPN edge guard"));
        });
        check("WFP arbitration lets no edge-traversal allow pass a VPN-carried application's inbound traffic, in IPv4, IPv6 or over Teredo", () =>
        {
            var blocked = new FirewallRule { ApplicationName = "Blocked peer", RemoteAddresses = "192.0.2.66,2001:db8::66", Direction = TrafficDirection.Inbound, Action = RuleAction.Deny };
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Inbound(Browser), Inbound(Game), Inbound(Other, edgeTraversal: false), blocked] }), Vpn));
            // The browser's own edge-traversal allow meets the guard, and its Teredo part the VPN edge guard; loopback stays above both.
            Expect(Arrivals(matcher, Browser) is [{ Filter.Name: "Router: VPN guard" }, { Filter.Name: "Router: VPN guard" }, { Filter.Name: "Router: VPN edge guard" }]);
            Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 8080, Owner(Browser), direction: TrafficDirection.Inbound, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            Expect(Verdict(matcher, "::1", "::1", 8080, Owner(Browser), direction: TrafficDirection.Inbound, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            // Unassigned applications keep edge traversal; without it the edge traversal guard still blocks Teredo.
            Expect(Arrivals(matcher, Game).All(v => v?.Action == RuleAction.Allow));
            Expect(Arrivals(matcher, Other) is [{ Action: RuleAction.Allow }, { Action: RuleAction.Allow }, { Filter.Name: "Edge traversal guard" }]);
            // Explicit denies stay on top.
            Expect(Arrivals(matcher, Game, "192.0.2.66", "2001:db8::66").All(v => v?.Filter.RuleId == blocked.Id));
        });
        check("Edge-traversal allows for any program, or naming the assigned executable another way, stop at the guard too", () =>
        {
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Inbound("*"), Inbound("C:/APPS/Browser.EXE")] }), Vpn));
            Expect(Arrivals(matcher, Browser).All(v => v?.Action == RuleAction.Deny));
            Expect(Arrivals(matcher, Other).All(v => v?.Action == RuleAction.Allow));
        });
        check("WFP arbitration lets a WireGuard tunnel reach only its own peer", () =>
        {
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn));
            var sid = IdentitySelectors.ServiceSid(TunnelService);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.7", 51820, Owner(WireGuard, sid), 17) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.8", 51820, Owner(WireGuard, sid), 17) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.7", 51821, Owner(WireGuard, sid), 17) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.7", 51820, Owner(WireGuard), 17) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.7", 51820, Owner(Other, sid), 17) == RuleAction.Deny);
            // A peer named by host name: any address, on its port only, over UDP only.
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.9", 51830, Owner(WireGuard, sid), 17) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.9", 51830, Owner(WireGuard, sid), 6) == RuleAction.Deny);
        });
        check("Explicit denies still outrank the backend permits", () =>
        {
            var deny = new FirewallRule { ApplicationName = "Peer", RemoteAddresses = "198.51.100.7", Action = RuleAction.Deny };
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [deny] }), Vpn));
            Expect(Verdict(matcher, "192.168.1.20", "198.51.100.7", 51820, Owner(WireGuard, IdentitySelectors.ServiceSid(TunnelService)), 17) == RuleAction.Deny);
        });
        check("With a default profile nothing leaves around the tunnel except the relay, backends, loopback and core networking", () =>
        {
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Game)] }), Vpn with { TunnelAll = true }));
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Game)) == RuleAction.Deny);
            Expect(Verdict(matcher, "198.18.0.1", "203.0.113.8", 443, Owner(Game)) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Service)) == RuleAction.Allow);
            var svchost = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\system32\svchost.exe");
            var dhcp = new FlowQuery(TrafficDirection.Outbound, 17, IPAddress.Parse("192.168.1.20"), 68, IPAddress.Parse("192.168.1.1"), 67, Owner(svchost, IdentitySelectors.ServiceSid("Dhcp")));
            Expect(new PlanMatcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn with { TunnelAll = true }),
                p => Environment.ExpandEnvironmentVariables(p).ToLowerInvariant(), a => a).Match(dhcp)?.Action == RuleAction.Allow);
        });
        check("A default profile that keeps local traffic local guards only the unicast space outside the local networks, so rules decide them both ways", () =>
        {
            var local = Vpn with { TunneledApplications = [], TunnelAll = true, LocalNetworks = ["192.168.1.0/24", "2001:db8:1::/64"] };
            // Internal networks follow the rules here, as they do when the user picks that.
            var kernel = FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Game), Inbound(Game, edgeTraversal: false)], InternalNetworks = InternalAccess.Rules }), local);
            var guards = kernel.Filters.Where(f => f.Name == "Router: VPN guard").ToArray();
            Expect(guards.Length > 4 && guards.All(f => f.ApplicationPath is null && f.RemoteNetwork is not null), "The guard still covers every address.");
            var matcher = Matcher(kernel);
            // Around the tunnel, a local peer in either direction is up to the rules: allowed for the game, blocked for another.
            Expect(Verdict(matcher, "192.168.1.20", "192.168.1.50", 445, Owner(Game)) == RuleAction.Allow);
            Expect(Verdict(matcher, "192.168.1.20", "192.168.1.50", 445, Owner(Other)) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "192.168.1.50", 3389, Owner(Game), direction: TrafficDirection.Inbound) == RuleAction.Allow);
            Expect(Verdict(matcher, "2001:db8:1::20", "2001:db8:1::50", 445, Owner(Game)) == RuleAction.Allow);
            // Anything else stays inside the tunnel, whatever the rules allow.
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Game)) == RuleAction.Deny);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 3389, Owner(Game), direction: TrafficDirection.Inbound) == RuleAction.Deny);
            Expect(Verdict(matcher, "2001:db8:1::20", "2001:db8:2::50", 445, Owner(Game)) == RuleAction.Deny);
            Expect(Verdict(matcher, "198.18.0.1", "203.0.113.8", 443, Owner(Game)) == RuleAction.Allow);
            // Applications a profile carries stay guarded everywhere, and so does everything when local traffic goes through the tunnel.
            Expect(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn with { LocalNetworks = ["192.168.1.0/24"] })
                .Filters.Where(f => f.Name == "Router: VPN guard").All(f => f.RemoteNetwork is null));
            Expect(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn with { TunnelAll = true })
                .Filters.Where(f => f.Name == "Router: VPN guard").All(f => f.RemoteNetwork is null));
            PersistentFilterSession.ValidatePlan(kernel);
        });
        check("Local networks are the other interfaces' own subnets, and the guarded space is exactly what lies outside them", () =>
        {
            var network = new NetworkSnapshot([
                new(7, ["192.168.1.37/24", "2001:db8:1::37/64", "fe80::37/64", "169.254.3.4/16"], [], [], [], []),
                new(900, ["10.64.0.2/32", "10.8.0.6/24"], [], [], [], []),
                new(8, ["198.18.0.1/15", "10.0.0.5/32"], [], [], [], [])]);
            Expect(network.LocalNetworks(luid => luid == 900).SequenceEqual(["192.168.1.0/24", "2001:db8:1::/64"]), string.Join(", ", network.LocalNetworks(luid => luid == 900)));
            var outside = AddressRanges.Without(["0.0.0.0/0"], ["192.168.1.0/24"]);
            Expect(outside.Count == 24 && outside.Contains("0.0.0.0/1") && outside.Contains("192.168.0.0/24") && outside.Contains("192.168.2.0/23") && !outside.Contains("192.168.1.0/24"));
            Expect(AddressRanges.Without(["10.0.0.0/8", "2001:db8::/32"], ["10.0.0.0/8"]).SequenceEqual(["2001:db8::/32"]));
        });
        check("A default profile confines the Windows DNS client to Darkwire's adapter and loopback, above core networking and below explicit denies", () =>
        {
            Expect(FilterCompiler.DenyWeight > FilterCompiler.EdgeGuardWeight && FilterCompiler.EdgeGuardWeight > FilterCompiler.DnsClientWeight &&
                FilterCompiler.DnsClientWeight > FilterCompiler.DnsClientGuardWeight && FilterCompiler.DnsClientGuardWeight > FilterCompiler.CoreWeight);
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            var kernel = FilterCompiler.Route(decision, Vpn with { TunnelAll = true });
            static bool Confining(NativeFilter f) => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal);
            var dns = kernel.Filters.Where(Confining).ToArray();
            Expect(dns.Length == 12 && dns.All(f => f.ApplicationPath == @"%SystemRoot%\system32\svchost.exe" && f.Service == "Dnscache" && f.RemotePort == new PortRange(53, 53) &&
                f.Direction == TrafficDirection.Outbound && f.Protocol is 6 or 17 && f.RemoteNetwork is null));
            Expect(dns.Where(f => f.Name == "Router: DNS client guard").All(f => f.Action == RuleAction.Deny && f.Weight == FilterCompiler.DnsClientGuardWeight && f.LocalNetwork is null && f.RequiredFlags is null));
            Expect(dns.Where(f => f.Name == "Router: DNS client tunnel").Select(f => f.LocalNetwork).Order().SequenceEqual(["198.18.0.0/15", "198.18.0.0/15", "fd5a:9c33:21e7::/64", "fd5a:9c33:21e7::/64"]));
            Expect(dns.Where(f => f.Action == RuleAction.Allow).All(f => f.Weight == FilterCompiler.DnsClientWeight) && dns.Count(f => f.Name == "Router: DNS client loopback" && f.RequiredFlags == FilterCompiler.LoopbackFlag) == 4);
            // The router evaluates the decision plan, where core networking admits the DNS client; the confinement is the kernel's.
            Expect(FilterCompiler.Endpoints(decision, Vpn with { TunnelAll = true }).Filters.All(f => !Confining(f)));
            // Per-application assignments alone leave the DNS client to core networking: its lookups cannot be attributed to them.
            Expect(FilterCompiler.Route(decision, Vpn).Filters.All(f => !Confining(f)) && FilterCompiler.Route(decision, Router).Filters.All(f => !Confining(f)));
            PersistentFilterSession.ValidatePlan(kernel);
        });
        check("With a default profile, the largest catalog list the compiler keeps still leaves room for everything routing adds", () =>
        {
            var profile = new VpnProfile { Applications = [Browser, Game] };
            var policy = new AppState { Mode = FirewallMode.BlockNew, VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id,
                Blocklists = [new() { CatalogId = "firehol-level1", Name = BlocklistCatalog.Find("firehol-level1")!.Name }] };
            FilterPlan Compile(int count) => FilterCompiler.Compile(policy, lists: new Listed([.. Enumerable.Range(0, count).Select(i => $"203.{i / 256}.{i % 256}.0/24")]));
            int low = 0, high = 10_000;
            while (low < high) { var middle = (low + high + 1) / 2; if (Compile(middle).Warnings.Count == 0) low = middle; else high = middle - 1; }
            var full = Compile(low);
            Expect(low > 9_000 && full.CanApply && full.Warnings.Count == 0 && Compile(low + 1).Warnings.Count == 1);
            var kernel = FilterCompiler.Route(full, Vpn with { TunneledApplications = [Browser, Game], TunnelAll = true });
            Expect(kernel.CanApply && kernel.Filters.Count(f => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal)) == 12, string.Join(" ", kernel.Errors));
        });
        check("WFP arbitration lets the Windows DNS client send DNS only into Darkwire's adapter or over loopback while a default profile carries everything", () =>
        {
            var svchost = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\system32\svchost.exe");
            var client = Owner(svchost, IdentitySelectors.ServiceSid("Dnscache"));
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Game)] }), Vpn with { TunnelAll = true }));
            foreach (var protocol in new byte[] { 17, 6 })
            {
                // The physical network's servers, link-local ones included, in both families.
                foreach (var (local, server) in new[] { ("192.168.1.20", "192.168.1.1"), ("192.168.1.20", "8.8.8.8"), ("169.254.7.7", "169.254.1.1"), ("2001:db8::20", "2001:db8::1"), ("fe80::20", "fe80::1") })
                    Expect(matcher.Match(new(TrafficDirection.Outbound, protocol, IPAddress.Parse(local), 50_000, IPAddress.Parse(server), 53, client)) is
                        { Action: RuleAction.Deny, Filter.Name: "Router: DNS client guard" }, "The DNS client reached " + server);
                // Darkwire's resolver on its adapter, whose queries the router relays, and a local resolver over loopback.
                Expect(Verdict(matcher, "198.18.0.1", "198.18.0.2", 53, client, protocol) == RuleAction.Allow);
                Expect(Verdict(matcher, "fd5a:9c33:21e7::1", "fd5a:9c33:21e7::2", 53, client, protocol) == RuleAction.Allow);
                Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 53, client, protocol, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
                Expect(Verdict(matcher, "::1", "::1", 53, client, protocol, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            }
            // The client's other traffic around the tunnel, such as DNS over HTTPS, meets the VPN guard; other applications' DNS is unchanged.
            Expect(matcher.Match(new(TrafficDirection.Outbound, 6, IPAddress.Parse("192.168.1.20"), 50_000, IPAddress.Parse("1.1.1.1"), 443, client)) is { Filter.Name: "Router: VPN guard" });
            Expect(matcher.Match(new(TrafficDirection.Outbound, 17, IPAddress.Parse("192.168.1.20"), 50_000, IPAddress.Parse("192.168.1.1"), 53, Owner(Game))) is { Filter.Name: "Router: VPN guard" });
            Expect(Verdict(matcher, "198.18.0.1", "192.168.1.1", 53, Owner(Game), 17) == RuleAction.Allow);
            // Explicit denies still outrank the permit.
            var deny = new FirewallRule { ApplicationName = "Resolver", Path = svchost, Service = "Dnscache", RemoteAddresses = "198.18.0.2", Action = RuleAction.Deny };
            var denied = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [deny] }), Vpn with { TunnelAll = true }));
            Expect(Verdict(denied, "198.18.0.1", "198.18.0.2", 53, client, 17) == RuleAction.Deny);
            // Without a default profile the DNS client keeps core networking: the remaining per-application gap.
            Expect(Verdict(Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }), Vpn)), "192.168.1.20", "192.168.1.1", 53, client, 17) == RuleAction.Allow);
        });
        check("Domain lists confine the Windows DNS client to Darkwire's adapter and loopback, with or without VPN profiles", () =>
        {
            var svchost = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\system32\svchost.exe");
            var client = Owner(svchost, IdentitySelectors.ServiceSid("Dnscache"));
            static bool Confining(NativeFilter f) => f.Name.StartsWith("Router: DNS client", StringComparison.Ordinal);
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Allow(Game)], Blocklists = [new() { CatalogId = "hagezi-light", Name = "HaGeZi Multi Light" }] });
            foreach (var plan in new[] { Router with { FiltersDns = true }, Vpn with { FiltersDns = true } })
            {
                var kernel = FilterCompiler.Route(decision, plan);
                Expect(kernel.CanApply && kernel.Filters.Count(Confining) == 12, string.Join(" ", kernel.Errors));
                var matcher = Matcher(kernel);
                foreach (var protocol in new byte[] { 17, 6 })
                {
                    // Every server the physical network names, link-local ones included, in both families.
                    foreach (var (local, server) in new[] { ("192.168.1.20", "192.168.1.1"), ("192.168.1.20", "8.8.8.8"), ("2001:db8::20", "2001:db8::1"), ("fe80::20", "fe80::1") })
                        Expect(matcher.Match(new(TrafficDirection.Outbound, protocol, IPAddress.Parse(local), 50_000, IPAddress.Parse(server), 53, client))?.Action == RuleAction.Deny, "The DNS client reached " + server);
                    Expect(Verdict(matcher, "198.18.0.1", "198.18.0.2", 53, client, protocol) == RuleAction.Allow);
                    Expect(Verdict(matcher, "fd5a:9c33:21e7::1", "fd5a:9c33:21e7::2", 53, client, protocol) == RuleAction.Allow);
                    Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 53, client, protocol, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
                }
                // Other applications' DNS still follows their rules, through the router.
                Expect(Verdict(matcher, "198.18.0.1", "192.168.1.1", 53, Owner(Game), 17) == RuleAction.Allow);
                PersistentFilterSession.ValidatePlan(kernel);
            }
            // The router evaluates the decision plan, where core networking still admits the client's DNS to the resolver address.
            Expect(FilterCompiler.Endpoints(decision, Vpn with { FiltersDns = true }).Filters.All(f => !Confining(f)));
        });
        check("With a default profile edge-traversal allows admit nothing around the tunnel in either family; loopback and core networking still pass", () =>
        {
            var matcher = Matcher(FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [Inbound(Browser), Inbound(Game), Inbound("*")] }), Vpn with { TunnelAll = true }));
            foreach (var application in new[] { Browser, Game, Other })
                Expect(Arrivals(matcher, application) is [{ Filter.Name: "Router: VPN guard" }, { Filter.Name: "Router: VPN guard" }, { Filter.Name: "Edge traversal guard" }]);
            Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 8080, Owner(Game), direction: TrafficDirection.Inbound, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            Expect(Verdict(matcher, "::1", "::1", 8080, Owner(Game), direction: TrafficDirection.Inbound, flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            // Path MTU discovery stays with core networking in both families.
            var system = Owner(IdentitySelectors.SystemApplication);
            Expect(matcher.Match(new(TrafficDirection.Inbound, 1, IPAddress.Parse("192.168.1.20"), 0, IPAddress.Parse("192.168.1.1"), 0, system, IcmpType: 3, IcmpCode: 4))?.Action == RuleAction.Allow);
            Expect(matcher.Match(new(TrafficDirection.Inbound, 58, IPAddress.Parse("2001:db8::20"), 0, IPAddress.Parse("2001:db8::1"), 0, system, IcmpType: 2, IcmpCode: 0))?.Action == RuleAction.Allow);
        });
        check("Open mode with VPN routing keeps loopback and core networking, guards carried applications and has no leak guard", () =>
        {
            var policy = new AppState { Mode = FirewallMode.Open, VpnProfiles = [new() { Applications = [Browser] }] };
            var decision = FilterCompiler.Compile(policy);
            Expect(decision.CanApply && decision.Filters.Count > 0 && decision.Filters.All(f => f.Action == RuleAction.Allow && f.Weight == FilterCompiler.CoreWeight));
            var kernel = FilterCompiler.Route(decision, Vpn with { LeakGuard = false });
            Expect(kernel.Filters.All(f => f.Name != "Router: leak guard" && f.Name != "Default policy") && kernel.Filters.Any(f => f.Name == "Router: VPN guard"));
            var matcher = Matcher(kernel);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Other)) is null);
            Expect(Verdict(matcher, "192.168.1.20", "203.0.113.8", 443, Owner(Browser)) == RuleAction.Deny);
            Expect(Verdict(matcher, "127.0.0.1", "127.0.0.1", 8080, Owner(Browser), flags: FilterCompiler.LoopbackFlag) == RuleAction.Allow);
            Expect(FilterCompiler.Compile(new() { Mode = FirewallMode.Open }).Filters.Count == 0);
            PersistentFilterSession.ValidatePlan(kernel);
        });
        check("Invalid VPN router plans are refused", () =>
        {
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            foreach (var bad in new[]
            {
                Vpn with { TunneledApplications = ["browser.exe"] },
                Vpn with { Endpoints = [new("wireguard.exe", null, 17, null, 51820)] },
                Vpn with { Endpoints = [new(WireGuard, null, 1, null, 51820)] },
                Vpn with { Endpoints = [new(WireGuard, null, 17, null, 0)] },
                Vpn with { Endpoints = [new(WireGuard, null, 17, "198.51.100.0/24", 51820)] },
                Vpn with { Endpoints = [new(WireGuard, "*", 17, null, 51820)] }
            })
            {
                Expect(!FilterCompiler.Route(decision, bad).CanApply);
                Expect(!FilterCompiler.Endpoints(decision, bad).CanApply);
            }
        });
    }
}
