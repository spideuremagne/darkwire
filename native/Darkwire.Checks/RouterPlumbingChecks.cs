using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Net;

internal static class RouterPlumbingChecks
{
    private static readonly RouterPlan Router = new(@"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", ["198.18.0.0/15", "fd5a:9c33:21e7::/64"]);

    public static void Run(Action<string, Action> check, bool native)
    {
        static void Expect(bool condition, string reason = "Router plumbing invariant failed.") { if (!condition) throw new Exception(reason); }
        static bool Guarded(string address) => RouterPlan.GuardedNetworks.Any(n => IpNetwork.TryParse(n, out var network) && network.Contains(IPAddress.Parse(address)));

        check("Leak guard covers routable unicast and leaves link-local, multicast and broadcast to rules", () =>
        {
            foreach (var address in new[] { "8.8.8.8", "192.168.1.5", "10.0.0.1", "169.255.0.1", "223.255.255.254", "2001:db8::1", "fd00::1", "fec0::1" })
                Expect(Guarded(address), address + " escapes the leak guard.");
            foreach (var address in new[] { "169.254.10.1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "fe80::1", "ff02::fb" })
                Expect(!Guarded(address), address + " should stay with rules.");
        });
        check("Router mode adds relay, listener, tunnel and leak-guard filters in weight order", () =>
        {
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            var kernel = FilterCompiler.Route(decision, Router);
            Expect(kernel.CanApply && kernel.Filters.Take(decision.Filters.Count).SequenceEqual(decision.Filters));
            var added = kernel.Filters.Skip(decision.Filters.Count).ToArray();
            Expect(added.Count(f => f.Name == "Router: relay") == 2 && added.All(f => f.Name != "Router: relay" || f.ApplicationPath == Router.ServicePath && f.Action == RuleAction.Allow && f.Weight == FilterCompiler.RouterServiceWeight));
            Expect(added.Count(f => f.Name == "Router: listener") == 2 && added.Where(f => f.Name == "Router: listener").All(f => f.Direction == TrafficDirection.Inbound && f.LocalNetwork is not null));
            Expect(added.Where(f => f.Name == "Router: tunnel").All(f => f.Weight == FilterCompiler.TunnelWeight && f.ApplicationPath is null && f.Direction == TrafficDirection.Outbound));
            Expect(added.Where(f => f.Name == "Router: leak guard").All(f => f.Action == RuleAction.Deny && f.Weight == FilterCompiler.LeakGuardWeight && f.Direction == TrafficDirection.Outbound));
            Expect(FilterCompiler.DenyWeight > FilterCompiler.CoreWeight && FilterCompiler.CoreWeight > FilterCompiler.RouterServiceWeight && FilterCompiler.RouterServiceWeight > FilterCompiler.TunnelWeight &&
                FilterCompiler.TunnelWeight > FilterCompiler.VpnGuardWeight && FilterCompiler.VpnGuardWeight > FilterCompiler.AllowWeight &&
                FilterCompiler.AllowWeight > FilterCompiler.LeakGuardWeight && FilterCompiler.LeakGuardWeight > FilterCompiler.DefaultWeight);
            Expect(added.All(f => f.Name is not ("Router: VPN guard" or "Router: VPN endpoint")));
            PersistentFilterSession.ValidatePlan(kernel);
        });
        check("Explicit denies outrank the tunnel permit; only explicit allows pass the leak guard", () =>
        {
            var deny = new FirewallRule { ApplicationName = "Blocked", Path = @"C:\Apps\blocked.exe", Action = RuleAction.Deny };
            var kernel = FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [deny, new() { ApplicationName = "Allowed", Path = @"C:\Apps\ok.exe" }] }), Router);
            Expect(kernel.Filters.Where(f => f.RuleId == deny.Id).All(f => f.Weight > FilterCompiler.TunnelWeight));
            Expect(kernel.Filters.Where(f => f.Action == RuleAction.Allow && f.RuleId is not null).All(f => f.Weight > FilterCompiler.LeakGuardWeight && f.Weight < FilterCompiler.TunnelWeight));
        });
        check("Invalid router plans are refused", () =>
        {
            var decision = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            Expect(!FilterCompiler.Route(decision, Router with { ServicePath = "service.exe" }).CanApply);
            Expect(!FilterCompiler.Route(decision, Router with { TunnelNetworks = ["0.0.0.0/0"] }).CanApply);
        });
        check("IP Helper structures match the x64 ABI", () => Expect(TunnelNetwork.LayoutMatches()));
        if (!native) return;
        check("Live egress lookup skips nothing it should use", () =>
        {
            var interfaces = new NetworkEnvironment().Capture().Interfaces.Select(i => i.Luid).ToArray();
            var route = new EgressSelector(() => interfaces).Select(IPAddress.Parse("1.1.1.1"));
            Console.WriteLine(route is null ? "  no IPv4 egress on this machine" : $"  1.1.1.1 leaves interface {route.Index} from {route.Source} (/{route.PrefixLength}, metric {route.Metric})");
            Expect(route is null || interfaces.Contains(route.Luid) && !IPAddress.IsLoopback(route.Source));
        });
        check("Live network profiles read per interface", () =>
        {
            var profiles = NetworkProfiles.Read();
            Console.WriteLine("  " + (profiles.Count == 0 ? "no connected networks" : string.Join(", ", profiles.Select(p => $"{p.Key:X}: {p.Value switch { 1 => "Public", 2 => "Private", _ => "Domain" }}"))));
            Expect(profiles.Values.All(p => p is >= 1 and <= 3));
        });
        foreach (var loopback in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
            check("Live ICMP echo through the IP Helper API (" + loopback + ")", () =>
            {
                var data = Enumerable.Range(0, 48).Select(i => (byte)i).ToArray();
                Expect(IcmpEcho.Send(loopback, loopback, data, TimeSpan.FromSeconds(2)) is { } reply && reply.SequenceEqual(data), "The echo did not come back intact.");
            });
    }
}
