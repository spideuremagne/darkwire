using Darkwire.Core;
using Darkwire.Engine;
using System.Net;

internal static class EnforcementChecks
{
    internal static void Run(Action<string, Action> check)
    {
        static void Assert(bool condition) { if (!condition) throw new Exception("Enforcement invariant failed."); }
        static Connection Flow(int port = 443) => new("Browser", @"C:\Apps\browser.exe", 42, "203.0.113.7", port, 50123, "TCP", TrafficDirection.Outbound);
        check("Service protocol preserves framed requests", () =>
        {
            using var stream = new MemoryStream(); var request = new ServiceRequest("preflight", new());
            ServiceProtocol.WriteAsync(stream, request, default).GetAwaiter().GetResult(); stream.Position = 0;
            var read = ServiceProtocol.ReadAsync<ServiceRequest>(stream, default).GetAwaiter().GetResult();
            Assert(read.Command == "preflight" && read.Policy?.Mode == FirewallMode.Learning);
        });
        check("Service protocol rejects oversized frames before allocating a payload", () =>
        {
            using var stream = new MemoryStream(BitConverter.GetBytes(ServiceProtocol.MaximumMessageBytes + 1));
            try { ServiceProtocol.ReadAsync<ServiceRequest>(stream, default).GetAwaiter().GetResult(); throw new Exception("Oversized frame accepted."); } catch (InvalidDataException) { }
        });
        check("Policy admission rejects null fields and duplicate identities", () =>
        {
            var rule = new FirewallRule(); var policy = new AppState { Mode = FirewallMode.BlockNew, Rules = [rule, rule] };
            Assert(!FilterCompiler.Compile(policy).CanApply);
            rule.Path = null!; Assert(!FilterCompiler.Compile(policy).CanApply);
        });
        check("Policy admission rejects malformed country and ASN restrictions", () =>
            Assert(!FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, BlockedCountries = ["USA"], BlockedAsns = [0] }).CanApply));
        check("VPN storage accepts 100 configurations and rejects 101", () =>
        {
            var policy = new AppState { VpnProfiles = Enumerable.Range(0, 100).Select(i => new VpnProfile { Name = "Tunnel " + i }).ToList() };
            Assert(PolicyValidation.Validate(policy).Count == 0); policy.VpnProfiles.Add(new());
            Assert(PolicyValidation.Validate(policy).Count > 0);
        });
        check("VPN reassignment moves an app to exactly one selected configuration", () =>
        {
            var first = new VpnProfile { Applications = [@"C:\Apps\browser.exe"] }; var second = new VpnProfile();
            var policy = new AppState { VpnProfiles = [first, second] };
            VpnAssignments.Assign(policy, second.Id, @"C:\Apps\BROWSER.exe");
            Assert(first.Applications.Count == 0 && second.Applications.Count == 1);
            VpnAssignments.Assign(policy, second.Id, @"C:\Apps\BROWSER.exe"); Assert(second.Applications.Count == 1);
        });
        check("Conflicting VPN assignments cannot enter service policy", () =>
        {
            var policy = new AppState { VpnProfiles = [new() { Applications = [@"C:\Apps\browser.exe"] }, new() { Applications = [@"C:\Apps\BROWSER.exe"] }] };
            Assert(PolicyValidation.Validate(policy).Count > 0);
        });
        check("VPN assignments compile in every mode, Open included, but never without connection routing", () =>
        {
            foreach (var mode in Enum.GetValues<FirewallMode>())
            {
                var policy = new AppState { Mode = mode, VpnProfiles = [new() { Applications = [@"C:\Apps\browser.exe"] }] };
                Assert(FilterCompiler.Compile(policy, learningNotificationsReady: true).CanApply);
                policy.RouteConnections = false;
                Assert(!FilterCompiler.Compile(policy, learningNotificationsReady: true).CanApply);
                policy.VpnProfiles[0].Applications.Clear(); policy.DefaultOutboundVpnProfileId = policy.VpnProfiles[0].Id;
                Assert(!FilterCompiler.Compile(policy, learningNotificationsReady: true).CanApply);
            }
        });
        check("Learning service compiler blocks unmatched IPv4 and IPv6", () =>
        {
            var plan = FilterCompiler.Compile(new(), learningNotificationsReady: true);
            var defaults = plan.Filters.Where(f => f.Name == "Default policy").ToArray();
            Assert(plan.CanApply && defaults.Length == 4 && defaults.All(f => f.Action == RuleAction.Deny) && defaults.Count(f => f.Ipv6) == 2);
            // Besides core networking, only internal networks are allowed by default.
            Assert(plan.Filters.Where(f => f.Action == RuleAction.Allow).All(f => f.Weight == FilterCompiler.CoreWeight || f.Name == "Internal networks" && f.RemoteNetwork is not null));
        });
        check("Learning duplicate attempts share a single bounded prompt", () =>
        {
            var broker = new LearningBroker(new()); var first = broker.Observe(Flow())!;
            var again = broker.Observe(Flow() with { LocalPort = 50124 })!;
            Assert(first.Id == again.Id && again.Attempts == 2 && broker.Pending.Count == 1);
        });
        check("Learning approval creates an exact app and remote endpoint rule", () =>
        {
            var broker = new LearningBroker(new()); var request = broker.Observe(Flow())!;
            var rule = broker.Resolve(request.Id, RuleAction.Allow).Single();
            Assert(rule.Path == Flow().Path && rule.RemoteAddresses == "203.0.113.7" && rule.RemotePorts == "443" && rule.LocalPorts == "*" && rule.Protocol == "TCP" && rule.Direction == TrafficDirection.Outbound);
            Assert(broker.Pending.Count == 0);
            try { broker.Resolve(request.Id, RuleAction.Allow); throw new Exception("Replay accepted."); } catch (InvalidOperationException) { }
        });
        check("Learning inbound approval retains the local listening port, never the peer's ephemeral one", () =>
        {
            var broker = new LearningBroker(new()); var request = broker.Observe(Flow(51515) with { LocalPort = 443, Direction = TrafficDirection.Inbound })!;
            // The peer's next attempt comes from another port and folds into the same prompt.
            Assert(broker.Observe(Flow(51516) with { LocalPort = 443, Direction = TrafficDirection.Inbound })!.Id == request.Id && broker.Pending.Count == 1);
            Assert(broker.Resolve(request.Id, RuleAction.Deny).Single() is { LocalPorts: "443", RemotePorts: "*", RemoteAddresses: "203.0.113.7", Direction: TrafficDirection.Inbound });
        });
        check("Learning decisions widen only to the host or port the user chose, for the same app, service and direction; a port's answer takes TCP and UDP, any port's every protocol", () =>
        {
            IReadOnlyList<FirewallRule> Decide(LearningScope scope, TrafficDirection direction = TrafficDirection.Outbound, string protocol = "TCP")
            {
                var broker = new LearningBroker(new());
                var request = broker.Observe(Flow() with { Direction = direction, LocalPort = direction == TrafficDirection.Inbound ? 8080 : 50123, Service = "Dnscache", Protocol = protocol })!;
                return broker.Resolve(request.Id, RuleAction.Allow, scope);
            }
            Assert(Decide(LearningScope.Exact) is [{ RemoteAddresses: "203.0.113.7", RemotePorts: "443", LocalPorts: "*", Protocol: "TCP" }]);
            Assert(Decide(LearningScope.AnyHost) is [{ RemoteAddresses: "*", RemotePorts: "443", LocalPorts: "*", Protocol: "TCP" }, { RemoteAddresses: "*", RemotePorts: "443", LocalPorts: "*", Protocol: "UDP" }]);
            Assert(Decide(LearningScope.AnyHost, protocol: "UDP") is [{ Protocol: "UDP" }, { Protocol: "TCP" }] && Decide(LearningScope.Exact, protocol: "UDP") is [{ Protocol: "UDP" }]);
            Assert(Decide(LearningScope.AnyPort) is [{ RemoteAddresses: "203.0.113.7", RemotePorts: "*", LocalPorts: "*", Protocol: "Any" }]);
            Assert(Decide(LearningScope.AnyHostAndPort) is [{ RemoteAddresses: "*", RemotePorts: "*", LocalPorts: "*", Protocol: "Any" }]);
            Assert(Decide(LearningScope.AnyHost, TrafficDirection.Inbound) is [{ RemoteAddresses: "*", RemotePorts: "*", LocalPorts: "8080", Protocol: "TCP" }, { LocalPorts: "8080", Protocol: "UDP" }]);
            Assert(Decide(LearningScope.AnyPort, TrafficDirection.Inbound) is [{ RemoteAddresses: "203.0.113.7", RemotePorts: "*", LocalPorts: "*", Protocol: "Any" }]);
            foreach (var scope in Enum.GetValues<LearningScope>())
            {
                var rules = Decide(scope);
                Assert(rules.All(rule => rule is { Path: @"C:\Apps\browser.exe", Service: "Dnscache", Direction: TrafficDirection.Outbound, Action: RuleAction.Allow } && RuleValidator.Validate(rule).Count == 0));
                // Ports stay with TCP and UDP, which the compiler requires of them.
                Assert(FilterCompiler.Compile(new() { Rules = [.. rules] }, learningNotificationsReady: true).CanApply);
            }
            var broker = new LearningBroker(new()); var request = broker.Observe(Flow())!;
            try { broker.Resolve(request.Id, RuleAction.Allow, (LearningScope)42); throw new Exception("An unknown scope was accepted."); } catch (ArgumentOutOfRangeException) { }
            Assert(broker.Pending.Count == 1);
        });
        check("Learning timeouts stay denied and cannot be approved", () =>
        {
            var time = new TestClock(); var broker = new LearningBroker(new(), time); var request = broker.Observe(Flow())!;
            time.Now += LearningBroker.PromptLifetime;
            Assert(broker.Pending.Count == 0);
            try { broker.Resolve(request.Id, RuleAction.Allow); throw new Exception("Expired request accepted."); } catch (InvalidOperationException) { }
        });
        check("Learning policy changes invalidate outstanding approvals", () =>
        {
            var broker = new LearningBroker(new()); var request = broker.Observe(Flow())!;
            broker.UpdatePolicy(new() { Mode = FirewallMode.Lockdown });
            Assert(broker.Pending.Count == 0 && broker.Observe(Flow()) is null);
            try { broker.Resolve(request.Id, RuleAction.Allow); throw new Exception("Stale request accepted."); } catch (InvalidOperationException) { }
        });
        check("A broader learning answer withdraws the waiting requests it covers; the rest stay, answerable under the new policy", () =>
        {
            var broker = new LearningBroker(new());
            var asked = broker.Observe(Flow())!; var quic = broker.Observe(Flow() with { Protocol = "UDP" })!;
            var elsewhere = broker.Observe(Flow() with { RemoteAddress = "198.51.100.9" })!; var web = broker.Observe(Flow(80))!;
            var mail = broker.Observe(Flow() with { Application = "Mail", Path = @"C:\Apps\mail.exe" })!;
            var listening = broker.Observe(Flow() with { Direction = TrafficDirection.Inbound, LocalPort = 8080, RemotePort = 51515 })!;
            var policy = new AppState(); policy.Rules.AddRange(broker.Resolve(asked.Id, RuleAction.Allow, LearningScope.AnyHost));
            broker.UpdatePolicy(policy);
            IEnumerable<Guid> Waiting() => broker.Pending.Select(p => p.Id).Order();
            Assert(Waiting().SequenceEqual(new[] { web.Id, mail.Id, listening.Id }.Order()) && !Waiting().Contains(quic.Id) && !Waiting().Contains(elsewhere.Id));
            // Everything the application sends, whatever the port or protocol, leaves its inbound and other applications' requests.
            policy.Rules.AddRange(broker.Resolve(web.Id, RuleAction.Allow, LearningScope.AnyHostAndPort));
            broker.UpdatePolicy(policy);
            Assert(Waiting().SequenceEqual(new[] { mail.Id, listening.Id }.Order()));
            Assert(broker.Resolve(listening.Id, RuleAction.Deny).Single() is { Direction: TrafficDirection.Inbound, LocalPorts: "8080" });
        });
        check("Learning cannot prompt for an explicit deny", () =>
        {
            var policy = new AppState(); policy.Rules.Add(new() { Action = RuleAction.Deny });
            Assert(new LearningBroker(policy).Observe(Flow()) is null);
        });
        check("Learning ignores unknown direction and missing application identity", () =>
        {
            var broker = new LearningBroker(new());
            Assert(broker.Observe(Flow() with { Direction = TrafficDirection.Unknown }) is null && broker.Observe(Flow() with { Path = "" }) is null);
        });
        check("Learning queue overflow never creates an implicit allow", () =>
        {
            var broker = new LearningBroker(new());
            for (var i = 1; i <= LearningBroker.MaximumPending; i++) Assert(broker.Observe(Flow(i)) is not null);
            Assert(broker.Observe(Flow(300)) is null && broker.Pending.Count == LearningBroker.MaximumPending);
        });
        const string csv = "network,country,country_name,city,latitude,longitude,asn,organization\n203.0.113.0/24,US,United States,Seattle,47,-122,64496,Example\n203.0.113.7/32,CA,Canada,Toronto,43,-79,64497,Example\n2001:db8::/32,DE,Germany,Berlin,52,13,64498,Example\n";
        check("Geographic kernel expansion preserves longest-prefix exceptions", () =>
        {
            var database = GeoDatabase.Load(new StringReader(csv)); var networks = database.RestrictedNetworks(["US"], []);
            bool Matches(string ip) => networks.Any(n => IpNetwork.TryParse(n, out var subnet) && subnet.Contains(IPAddress.Parse(ip)));
            Assert(!Matches("203.0.113.7") && Matches("203.0.113.6") && Matches("203.0.113.8") && !Matches("203.0.114.0"));
        });
        check("Geographic compiler supports country and ASN restrictions on both directions", () =>
        {
            var database = GeoDatabase.Load(new StringReader(csv));
            var plan = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, BlockedAsns = [64498] }, geoDatabase: database);
            var geographic = plan.Filters.Where(f => f.Name == "Geographic restriction").ToArray();
            Assert(plan.CanApply && geographic.Length == 2 && geographic.All(f => f.RemoteNetwork == "2001:db8::/32" && f.Weight == FilterCompiler.DenyWeight));
        });
        check("Geographic compiler fails closed without its database", () => Assert(!FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, BlockedCountries = ["US"] }).CanApply));
        check("Geographic expansion refuses excessive filter counts", () =>
        {
            try { GeoDatabase.Load(new StringReader(csv)).RestrictedNetworks(["US"], [], 1); throw new Exception("Unbounded expansion accepted."); } catch (InvalidDataException) { }
        });
    }
    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-10-14T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
