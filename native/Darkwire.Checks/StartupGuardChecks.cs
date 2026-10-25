using Darkwire.Core;
using Darkwire.Engine;

internal static class StartupGuardChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool condition) { if (!condition) throw new Exception("Startup guard invariant failed."); }
        check("Enforced policy installs separate runtime and boot-time filters", () =>
        {
            var policy = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew });
            var registrations = WfpInstallationPlan.Build(policy);
            Assert(registrations.Count == policy.Filters.Count + 4);
            Assert(registrations.Count(r => r.Flags == 1) == policy.Filters.Count && registrations.Count(r => r.Flags == 2) == 4);
            Assert(registrations.All(r => r.Flags != 3));
        });
        check("Startup guards cover all IPv4 IPv6 and inbound outbound packet layers", () =>
        {
            var guards = WfpInstallationPlan.Build(FilterCompiler.Compile(new() { Mode = FirewallMode.Lockdown })).Where(r => r.BootTime).ToArray();
            Assert(guards.Select(r => r.Layer).ToHashSet().SetEquals(new Guid[] {
                new("c86fd1bf-21cd-497e-a0bb-17425c885c58"), new("f52032cb-991c-46e7-971d-2601459a91ca"),
                new("1e5c9fae-8a84-4135-a331-950b54229ecd"), new("a3b3ab6b-3564-488c-9117-f34e82142763") }));
            Assert(guards.All(r => r.Filter.Action == RuleAction.Deny && r.Filter.ApplicationPath is null && r.Filter.Protocol is null &&
                r.Filter.LocalPort is null && r.Filter.RemotePort is null && r.Filter.RemoteNetwork is null));
        });
        check("Runtime allow rules cannot become boot-time exceptions", () =>
        {
            var plan = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = [new() { Action = RuleAction.Allow }] });
            var registrations = WfpInstallationPlan.Build(plan);
            Assert(registrations.Where(r => r.BootTime).All(r => r.Filter.Action == RuleAction.Deny));
            Assert(registrations.Where(r => !r.BootTime).Select(r => r.Filter).SequenceEqual(plan.Filters));
        });
        check("Open and restoration plans remove startup policy too", () =>
        {
            Assert(WfpInstallationPlan.Build(FilterCompiler.Compile(new() { Mode = FirewallMode.Open })).Count == 0);
            Assert(WfpInstallationPlan.Build(new([], [])).Count == 0);
        });
        check("The startup lock blocks everything in its own sublayer beneath exceptions for what restoring needs", () =>
        {
            const string service = @"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", wireguard = @"C:\Program Files\Darkwire\Service\Backends\WireGuard\wireguard.exe";
            const string proxy = @"C:\Program Files\Darkwire\Service\Backends\DnsCrypt\dnscrypt-proxy.exe";
            var router = new RouterPlan(service, ["198.18.0.0/15"]) { Endpoints = [new(wireguard, "WireGuardTunnel$office", 17, "198.51.100.7/32", 51820)], OwnApplications = [proxy] };
            var policy = FilterCompiler.Route(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }, network: NetworkSnapshot.Empty), router);
            var locked = FilterCompiler.StartupLock(new(), policy, service, router);
            var blocks = locked.Where(f => f.Action == RuleAction.Deny).ToArray();
            Assert(blocks.Length == 4 && blocks.All(f => f.Weight == FilterCompiler.LockWeight && f.ApplicationPath is null && f.Protocol is null && f.RemoteNetwork is null && f.RequiredFlags is null));
            Assert(blocks.Select(f => (f.Ipv6, f.Direction)).Distinct().Count() == 4);
            var exceptions = locked.Where(f => f.Action == RuleAction.Allow).ToArray();
            Assert(exceptions.All(f => f.Weight == FilterCompiler.LockExceptionWeight) && FilterCompiler.LockReleaseWeight > FilterCompiler.LockExceptionWeight);
            // Loopback both ways; DHCP and IPv6 discovery; the DNS client's lookups; Darkwire's service and DNS proxy out, and the
            // relay's listener in on the tunnel network; the backend to its peer only.
            Assert(exceptions.Count(f => f.RequiredFlags == FilterCompiler.LoopbackFlag) == 4);
            Assert(exceptions.All(f => f.RequiredFlags == FilterCompiler.LoopbackFlag || f.Service is "Dhcp" || f.Protocol == 58 && f.ApplicationPath == IdentitySelectors.SystemApplication ||
                f.Service == "Dnscache" && f.RemotePort == new PortRange(53, 53) && f.Direction == TrafficDirection.Outbound ||
                f.ApplicationPath is service or proxy && f.Direction == TrafficDirection.Outbound && f.RemoteNetwork is null && f.LocalNetwork is null ||
                f.ApplicationPath == service && f.Direction == TrafficDirection.Inbound && f.LocalNetwork == "198.18.0.0/15" && !f.Ipv6 ||
                f.ApplicationPath == wireguard && f.RemoteNetwork == "198.51.100.7/32" && f.RemotePort == new PortRange(51820, 51820)));
            Assert(exceptions.Any(f => f.ApplicationPath == wireguard) && exceptions.Count(f => f.ApplicationPath == service) == 3 && exceptions.Count(f => f.ApplicationPath == proxy) == 2);
            var registrations = WfpInstallationPlan.Build(policy with { StartupLock = locked });
            Assert(registrations.Count(r => r.Lock) == locked.Count && registrations.Where(r => r.Lock).All(r => r.Flags == 1 && !r.BootTime));
            Assert(registrations.Where(r => !r.Lock && !r.BootTime).Select(r => r.Filter).SequenceEqual(policy.Filters));
            // Without encrypted DNS no DNS proxy passes, and one named by a relative path makes the router plan invalid.
            Assert(FilterCompiler.StartupLock(new(), policy, service, router with { OwnApplications = [] }).All(f => f.ApplicationPath != proxy));
            Assert(!FilterCompiler.Route(policy, router with { OwnApplications = ["dnscrypt-proxy.exe"] }).CanApply);
        });
        check("No startup lock with the lock off, for an empty or refused plan, and none outlives restoration", () =>
        {
            var policy = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }, network: NetworkSnapshot.Empty);
            Assert(FilterCompiler.StartupLock(new() { StartupLock = false }, policy, @"C:\Darkwire\Darkwire.Service.exe", null).Count == 0);
            Assert(FilterCompiler.StartupLock(new(), new([], []), @"C:\Darkwire\Darkwire.Service.exe", null).Count == 0);
            Assert(FilterCompiler.StartupLock(new(), new([], ["Refused"]), @"C:\Darkwire\Darkwire.Service.exe", null).Count == 0);
            // Without routing the service still passes, which its learning probe needs; no backend does.
            var plain = FilterCompiler.StartupLock(new(), policy, @"C:\Darkwire\Darkwire.Service.exe", null);
            Assert(plain.Count(f => f.ApplicationPath == @"C:\Darkwire\Darkwire.Service.exe") == 2 && plain.All(f => f.ApplicationPath is null or @"C:\Darkwire\Darkwire.Service.exe" || f.Service is "Dhcp" or "Dnscache" || f.Protocol == 58));
            Assert(WfpInstallationPlan.Build(new FilterPlan([], []) { StartupLock = plain }).Count == 0);
        });
        check("Invalid runtime policy cannot produce a partial startup installation", () =>
        {
            try { WfpInstallationPlan.Build(new([], ["Unsupported rule"])); throw new Exception("Invalid plan admitted."); }
            catch (InvalidOperationException) { }
        });
    }
}
