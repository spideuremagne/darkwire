using Darkwire.Core;
using Darkwire.Engine;
using System.Text.Json;

internal static class RuleScopeChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool condition) { if (!condition) throw new Exception("Scope was not preserved."); }
        static FirewallRule Rule() => new() { ApplicationName = "Scope test", Protocol = "TCP", LocalAddresses = "192.0.2.0/24", RemoteAddresses = "203.0.113.0/24", LocalPorts = "5000", RemotePorts = "443" };
        static AppState Policy(FirewallRule rule) => new() { Mode = FirewallMode.BlockNew, Rules = [rule] };
        static IEnumerable<NativeFilter> Scoped(FilterPlan plan, FirewallRule rule) => plan.Filters.Where(f => f.RuleId == rule.Id);
        var engine = new PolicyEngine();
        var connection = new Connection("App", "C:\\app.exe", 42, "203.0.113.2", 443, 5000, "TCP", TrafficDirection.Outbound, LocalAddress: "192.0.2.3");
        check("Local and remote address scopes are conjunctive in preview", () =>
        {
            var p = Policy(Rule()); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Allow);
            Expect(engine.Evaluate(p, connection with { LocalAddress = "192.0.3.3" }).Kind == DecisionKind.Deny);
            Expect(engine.Evaluate(p, connection with { RemoteAddress = "203.0.114.2" }).Kind == DecisionKind.Deny);
            Expect(engine.Evaluate(p, connection with { LocalAddress = "" }).Kind == DecisionKind.Deny);
        });
        check("Native local and remote scope preserves ports and family", () =>
        {
            var rule = Rule(); var plan = FilterCompiler.Compile(Policy(rule)); var f = Scoped(plan, rule).Single();
            Expect(plan.CanApply && !f.Ipv6 && f.LocalNetwork == "192.0.2.0/24" && f.RemoteNetwork == "203.0.113.0/24" && f.LocalPort?.Low == 5000 && f.RemotePort?.Low == 443);
            PersistentFilterSession.ValidatePlan(plan);
        });
        check("Local IPv6 range expands without broadening remote scope", () =>
        {
            var r = Rule(); r.LocalAddresses = "2001:db8::1-2001:db8::3"; r.RemoteAddresses = "2001:db8:1::/48";
            var plan = FilterCompiler.Compile(Policy(r)); Expect(plan.CanApply && Scoped(plan, r).Count() == 2);
            Expect(Scoped(plan, r).All(f => f.Ipv6 && f.LocalNetwork is not null && f.RemoteNetwork == r.RemoteAddresses));
        });
        check("Incompatible local and remote families reject the rule", () => { var r = Rule(); r.LocalAddresses = "2001:db8::/32"; var plan = FilterCompiler.Compile(Policy(r)); Expect(!plan.CanApply && plan.Filters.Count == 0); });
        check("Mixed local and remote families emit no cross-family combinations", () =>
        {
            var r = Rule(); r.LocalAddresses += ",2001:db8::/32"; r.RemoteAddresses += ",2001:db8:1::/48";
            var plan = FilterCompiler.Compile(Policy(r)); Expect(plan.CanApply && Scoped(plan, r).Count() == 2); PersistentFilterSession.ValidatePlan(plan);
        });
        check("Local-address product counts against the global filter budget", () =>
        {
            var r = Rule(); r.LocalAddresses = string.Join(',', Enumerable.Range(0, 150).Select(i => $"192.0.2.{i}"));
            r.RemoteAddresses = string.Join(',', Enumerable.Range(0, 150).Select(i => $"203.0.113.{i}"));
            var plan = FilterCompiler.Compile(Policy(r)); Expect(!plan.CanApply && plan.Filters.Count == 0);
        });
        check("All numeric IP protocols round-trip including zero and 255", () =>
        {
            for (var i = 0; i <= 255; i++) Expect(IpProtocol.TryParse(IpProtocol.Name(i), out var protocol) && protocol == i);
            Expect(IpProtocol.TryParse("Any", out var any) && any is null);
            foreach (var invalid in new[] { "IP 256", "IP -1", "IP +6", "IP 6 ", "GRE" }) Expect(!IpProtocol.TryParse(invalid, out _));
        });
        check("Numeric protocols preserve exact native matching and forbid transport ports", () =>
        {
            var r = Rule(); r.Protocol = "IP 47"; Expect(!FilterCompiler.Compile(Policy(r)).CanApply);
            r.LocalPorts = r.RemotePorts = "*"; var plan = FilterCompiler.Compile(Policy(r));
            Expect(plan.CanApply && Scoped(plan, r).Single().Protocol == 47);
        });
        check("ICMP type-code alternatives retain family and addresses", () =>
        {
            var r = Rule(); r.Protocol = "ICMPv4"; r.LocalPorts = r.RemotePorts = "*"; r.IcmpTypesAndCodes = "8:0,3:*";
            var plan = FilterCompiler.Compile(Policy(r)); var scoped = Scoped(plan, r).ToArray();
            Expect(plan.CanApply && scoped.Length == 2 && scoped.All(f => f.Protocol == 1 && !f.Ipv6 && f.LocalNetwork == r.LocalAddresses && f.RemoteNetwork == r.RemoteAddresses));
            Expect(scoped[0].IcmpType == 8 && scoped[0].IcmpCode == 0 && scoped[1].IcmpType == 3 && scoped[1].IcmpCode is null); PersistentFilterSession.ValidatePlan(plan);
        });
        check("ICMP preview never infers missing type or code", () =>
        {
            var r = Rule(); r.Protocol = "ICMPv4"; r.LocalPorts = r.RemotePorts = "*"; r.IcmpTypesAndCodes = "8:0";
            var c = connection with { Protocol = "IP 1", IcmpType = 8, IcmpCode = 0 };
            Expect(engine.Evaluate(Policy(r), c).Kind == DecisionKind.Allow);
            Expect(engine.Evaluate(Policy(r), c with { IcmpType = null }).Kind == DecisionKind.Deny);
            Expect(engine.Evaluate(Policy(r), c with { IcmpCode = null }).Kind == DecisionKind.Deny);
            r.IcmpTypesAndCodes = "8:*"; Expect(engine.Evaluate(Policy(r), c with { IcmpCode = null }).Kind == DecisionKind.Allow);
        });
        check("ICMPv6 wildcard addresses stay on IPv6 layers", () =>
        {
            var r = new FirewallRule { Protocol = "ICMPv6", IcmpTypesAndCodes = "128:0", Direction = TrafficDirection.Any };
            var plan = FilterCompiler.Compile(Policy(r)); Expect(plan.CanApply && Scoped(plan, r).Count() == 2 && Scoped(plan, r).All(f => f.Ipv6 && f.IcmpType == 128));
        });
        check("Malformed ICMP and non-ICMP type scope fail closed", () =>
        {
            foreach (var invalid in new[] { "8", "8:", "*:0", "256:0", "8:256", "-1:0", "8:0,", "8:0:0", "8: 0" }) Expect(!IcmpSelectors.TryParse(invalid, out _));
            var r = Rule(); r.IcmpTypesAndCodes = "8:0"; Expect(!FilterCompiler.Compile(Policy(r)).CanApply);
        });
        check("ICMP type and code use the ICMP_TYPE and ICMP_CODE aliases, not ORIGINAL_ICMP_TYPE", () =>
        {
            var conditions = WfpConditions.Resolve(new("Echo", null, false, TrafficDirection.Inbound, RuleAction.Allow, 200, Protocol: 1, IcmpType: 8, IcmpCode: 0));
            var localPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b"); var remotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
            Expect(conditions.Single(c => c.Field == localPort).Number == 8 && conditions.Single(c => c.Field == remotePort).Number == 0);
            Expect(conditions.All(c => c.Field != new Guid("076dfdbe-c56c-4f72-ae8a-2cfe7e5c8286")));
        });
        check("Windows network profile names map to WFP profile IDs", () =>
        {
            foreach (var (profile, category) in new[] { ("Domain", 3u), ("Private", 2u), ("Public", 1u) })
            {
                var rule = WindowsImportChecks.Import($"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|Profile={profile}|Name=Web|");
                var plan = FilterCompiler.Compile(Policy(rule));
                Expect(rule.Import == ImportOutcome.Exact && plan.CanApply && Scoped(plan, rule).All(f => f.CurrentProfileId == category));
            }
        });
        check("Multiple network categories remain disjunctions without losing other conditions", () =>
        {
            var rule = Rule(); rule.Location = "Private,Public"; var plan = FilterCompiler.Compile(Policy(rule));
            Expect(plan.CanApply && Scoped(plan, rule).Count() == 2);
            Expect(Scoped(plan, rule).Select(f => f.CurrentProfileId).ToHashSet().SetEquals(new uint?[] { 1, 2 }));
            Expect(Scoped(plan, rule).All(f => f.RemotePort == new PortRange(443, 443) && f.LocalNetwork == rule.LocalAddresses));
            rule.Location = "Any,Public"; Expect(!FilterCompiler.Compile(Policy(rule)).CanApply);
        });
        check("Native network category rejects out-of-range profile bit masks", () =>
        {
            try { PersistentFilterSession.ValidatePlan(new([new("Bad profile", null, false, TrafficDirection.Outbound, RuleAction.Allow, 200, CurrentProfileId: 4)], [])); throw new Exception("Profile mask was treated as category"); }
            catch (InvalidDataException) { }
        });
        check("Saved rule selectors survive policy serialization", () =>
        {
            var r = Rule(); r.Protocol = "ICMPv4"; r.LocalPorts = r.RemotePorts = "*"; r.IcmpTypesAndCodes = "3:1"; r.Package = "S-1-15-2-1-2-3"; r.EdgeTraversal = true;
            var read = JsonSerializer.Deserialize<AppState>(JsonSerializer.Serialize(Policy(r)))!;
            Expect(read.Rules[0].LocalAddresses == r.LocalAddresses && read.Rules[0].IcmpTypesAndCodes == r.IcmpTypesAndCodes && read.Rules[0].Package == r.Package && read.Rules[0].EdgeTraversal);
            Expect(FilterCompiler.Compile(read).CanApply);
        });
    }
}
