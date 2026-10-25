using Darkwire.Core;
using System.Net;
using System.Numerics;

internal static class AddressRangeChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string message = "Address-range assertion failed") { if (!value) throw new Exception(message); }
        static IpAddressRange Range(string value) { if (!IpAddressRange.TryParse(value, out var range)) throw new Exception("Range rejected: " + value); return range; }
        static BigInteger Number(IPAddress value) => new(value.GetAddressBytes(), true, true);
        static void ExactCoverage(string selector, string first, string last)
        {
            var networks = Range(selector).ToNetworks(); var next = Number(IPAddress.Parse(first));
            foreach (var network in networks)
            {
                var current = Number(network.Address); var size = BigInteger.One << (network.Address.GetAddressBytes().Length * 8 - network.Prefix);
                Assert(current == next, "Coverage has a gap, overlap, or widened start.");
                Assert((current % size).IsZero, "CIDR base is not aligned."); next += size;
            }
            Assert(next == Number(IPAddress.Parse(last)) + 1, "Coverage widens or omits the final endpoint.");
            Assert(networks.Count <= IpAddressRange.MaximumNetworks);
        }
        static FirewallRule Rule(string addresses) => new() { ApplicationName = "Range test", RemoteAddresses = addresses, Protocol = "TCP", Direction = TrafficDirection.Outbound, Action = RuleAction.Allow };
        static AppState Policy(FirewallRule rule) => new() { Mode = FirewallMode.BlockNew, Rules = [rule] };

        check("IPv4 inclusive range preserves both endpoints", () =>
        {
            var range = Range("192.0.2.1-192.0.2.20");
            Assert(range.Contains(IPAddress.Parse("192.0.2.1")) && range.Contains(IPAddress.Parse("192.0.2.20")));
            Assert(!range.Contains(IPAddress.Parse("192.0.2.0")) && !range.Contains(IPAddress.Parse("192.0.2.21")));
            ExactCoverage("192.0.2.1-192.0.2.20", "192.0.2.1", "192.0.2.20");
        });
        check("IPv6 inclusive range preserves byte-boundary carries", () =>
        {
            ExactCoverage("2001:db8::ff-2001:db8::101", "2001:db8::ff", "2001:db8::101");
            var range = Range("2001:db8::ff-2001:db8::101");
            Assert(range.Contains(IPAddress.Parse("2001:db8::100")) && !range.Contains(IPAddress.Parse("2001:db8::102")));
        });
        check("Full IPv4 range compiles to one /0 without overflow", () =>
        {
            var networks = Range("0.0.0.0-255.255.255.255").ToNetworks(); Assert(networks.Count == 1 && networks[0].Prefix == 0);
            ExactCoverage("0.0.0.0-255.255.255.255", "0.0.0.0", "255.255.255.255");
        });
        check("Full IPv6 range compiles to one /0 without overflow", () =>
        {
            const string maximum = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
            var networks = Range("::-" + maximum).ToNetworks(); Assert(networks.Count == 1 && networks[0].Prefix == 0);
            ExactCoverage("::-" + maximum, "::", maximum);
        });
        check("Maximum single IPv4 and IPv6 endpoints do not wrap", () =>
        {
            foreach (var value in new[] { "255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" })
            {
                var networks = Range(value + "-" + value).ToNetworks(); Assert(networks.Count == 1);
                Assert(networks[0].Prefix == IPAddress.Parse(value).GetAddressBytes().Length * 8);
                ExactCoverage(value + "-" + value, value, value);
            }
        });
        check("Unaligned near-full ranges have bounded exact CIDR coverage", () =>
        {
            ExactCoverage("0.0.0.1-255.255.255.254", "0.0.0.1", "255.255.255.254");
            ExactCoverage("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe");
            Assert(Range("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe").ToNetworks().Count == 254);
        });
        check("Small ranges exactly cover every address without extras", () =>
        {
            for (var first = 0; first < 32; first++)
            for (var last = first; last < 32; last++)
            {
                var networks = Range($"192.0.2.{first}-192.0.2.{last}").ToNetworks();
                for (var candidate = 0; candidate < 34; candidate++)
                {
                    var count = networks.Count(network => network.Contains(IPAddress.Parse($"192.0.2.{candidate}")));
                    Assert(count == (candidate >= first && candidate <= last ? 1 : 0), "Small-range decomposition differs from inclusive range membership.");
                }
            }
        });
        check("Range parser rejects mixed families and mapped-family substitutions", () =>
        {
            Assert(!IpAddressRange.TryParse("192.0.2.1-2001:db8::2", out _));
            Assert(!IpAddressRange.TryParse("192.0.2.1-::ffff:192.0.2.20", out _));
            Assert(!Range("192.0.2.1-192.0.2.20").Contains(IPAddress.Parse("::ffff:192.0.2.10")));
        });
        check("Range parser rejects reversed and malformed endpoints", () =>
        {
            foreach (var value in new[] { "192.0.2.20-192.0.2.1", "2001:db8::2-2001:db8::1", "192.0.2.1-", "-192.0.2.1", "192.0.2.1-192.0.2.2-192.0.2.3", "192.0.2.1/24-192.0.2.20", "example.test-192.0.2.1", "[::1]-[::2]" })
                Assert(!IpAddressRange.TryParse(value, out _), "Malformed range accepted: " + value);
        });
        check("Scoped IPv6 selectors cannot silently lose their zone ID", () =>
        {
            foreach (var value in new[] { "fe80::1%3", "fe80::1%3/64", "fe80::1%0/128" }) Assert(!IpNetwork.TryParse(value, out _));
            Assert(!IpAddressRange.TryParse("fe80::1%3-fe80::20%3", out _));
            Assert(!FilterCompiler.Compile(Policy(Rule("fe80::1%3-fe80::20%3"))).CanApply);
        });
        check("Explicit CIDR quota refuses partial range output", () =>
        {
            try { Range("192.0.2.1-192.0.2.20").ToNetworks(1); throw new Exception("CIDR quota ignored"); } catch (InvalidDataException) { }
        });
        check("Rule validator accepts mixed lists of literals CIDRs and ranges", () =>
            Assert(RuleValidator.Validate(Rule("192.0.2.1-192.0.2.20, 198.51.100.2, 2001:db8::1-2001:db8::10, 203.0.113.0/24")).Count == 0));
        check("Rule evaluator range matching agrees with exact native expansion", () =>
        {
            var rule = Rule("192.0.2.1-192.0.2.20"); var state = Policy(rule); var evaluator = new PolicyEngine(); var plan = FilterCompiler.Compile(state);
            Assert(plan.CanApply && plan.Filters.Where(f => f.RuleId == rule.Id).All(f => !f.Ipv6 && f.ApplicationPath is null && f.Protocol == 6 && f.Direction == TrafficDirection.Outbound));
            for (var last = 0; last <= 22; last++)
            {
                var remote = "192.0.2." + last; var flow = new Connection("App", @"C:\Apps\app.exe", 42, remote, 443, 50000, "TCP", TrafficDirection.Outbound);
                var expected = last is >= 1 and <= 20;
                Assert((evaluator.Evaluate(state, flow).Kind == DecisionKind.Allow) == expected);
                Assert(plan.Filters.Where(f => f.RuleId == rule.Id).Any(f => IpNetwork.TryParse(f.RemoteNetwork, out var net) && net.Contains(IPAddress.Parse(remote))) == expected);
            }
        });
        check("Range expansion preserves every port application and direction constraint", () =>
        {
            var rule = Rule("2001:db8::1-2001:db8::20"); rule.Path = @"C:\Apps\app.exe"; rule.LocalPorts = "100-200"; rule.RemotePorts = "443,8443"; rule.Direction = TrafficDirection.Inbound;
            var plan = FilterCompiler.Compile(Policy(rule)); Assert(plan.CanApply);
            var filters = plan.Filters.Where(f => f.RuleId == rule.Id).ToArray(); Assert(filters.Length == Range(rule.RemoteAddresses).ToNetworks().Count * 2);
            Assert(filters.All(f => f.Ipv6 && f.ApplicationPath == rule.Path && f.Direction == TrafficDirection.Inbound && f.LocalPort == new PortRange(100, 200) && f.RemotePort?.Low is 443 or 8443));
        });
        check("Filter budget includes defaults and rejects oversized range products", () =>
        {
            // The per-field text limit intentionally prevents using one huge ports field; distribute the exact budget across rules.
            var state = new AppState { Mode = FirewallMode.BlockNew };
            var available = FilterCompiler.MaximumFilters - FilterCompiler.Compile(state).Filters.Count;
            for (var i = 0; available > 0; i++)
            {
                var ports = Math.Min(4999, available); available -= ports;
                var item = Rule("192.0.2.1-192.0.2.1"); item.RemotePorts = string.Join(',', Enumerable.Range(0, ports)); state.Rules.Add(item);
            }
            var exact = FilterCompiler.Compile(state); Assert(exact.CanApply && exact.Filters.Count == FilterCompiler.MaximumFilters);
            state.Rules.Add(Rule("192.0.2.1-192.0.2.2")); var excessive = FilterCompiler.Compile(state);
            Assert(!excessive.CanApply && excessive.Filters.Count == 0, "Oversized native policy was partially returned.");
        });
        check("Large IPv6 range expansion stops at global budget", () =>
        {
            var rule = Rule(string.Join(',', Enumerable.Repeat("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 100)));
            var plan = FilterCompiler.Compile(Policy(rule)); Assert(!plan.CanApply && plan.Filters.Count == 0);
        });
    }
}
