using Darkwire.Core;
using System.Net;

/// <summary>
/// Internal networks and the country allow list, as the compiler lowers them (checked through the user-mode WFP arbitration
/// model) and as the engine previews them.
/// </summary>
internal static class InternalNetworkChecks
{
    private const string Browser = @"C:\Apps\browser.exe";

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool condition, string reason = "Internal network invariant failed.") { if (!condition) throw new Exception(reason); }
        static Connection Flow(string remote, TrafficDirection direction = TrafficDirection.Outbound, string location = "Public", string country = "") =>
            new("Browser", Browser, 7, remote, 445, 50_000, "TCP", direction, location, Country: country);
        static FilterPlan Plan(InternalAccess access, params FirewallRule[] rules) => FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, InternalNetworks = access, Rules = [.. rules] });
        // The verdict WFP would reach for the browser's flow, on a network Windows calls private (2) or public (1).
        static RuleAction? Kernel(FilterPlan plan, string remote, TrafficDirection direction = TrafficDirection.Outbound, uint profile = 1)
        {
            var matcher = new PlanMatcher(plan, p => IdentitySelectors.IsSystemApplication(p) ? p : Path.GetFullPath(Environment.ExpandEnvironmentVariables(p)).ToLowerInvariant(), a => a);
            var local = IPAddress.Parse(remote.Contains(':') ? "fd00::20" : "192.168.1.20");
            return matcher.Match(new(direction, 6, local, 50_000, IPAddress.Parse(remote), 445,
                new(Browser.ToLowerInvariant(), new HashSet<string>(["S-1-5-21-1-2-3-1001"], StringComparer.OrdinalIgnoreCase), null), ProfileId: profile))?.Action;
        }

        check("Internal networks are allowed by default: out to private, link-local and unique local hosts, multicast and broadcast, in only on private and domain networks", () =>
        {
            Expect(new AppState().InternalNetworks == InternalAccess.Allow);
            var plan = Plan(InternalAccess.Allow);
            foreach (var host in new[] { "10.1.2.3", "172.20.0.9", "192.168.1.50", "169.254.10.1", "fd12:3456::1", "fe80::1", "224.0.0.251", "255.255.255.255", "ff02::fb" })
                Expect(Kernel(plan, host) == RuleAction.Allow, host + " was not reachable.");
            Expect(Kernel(plan, "192.168.1.50", TrafficDirection.Inbound, profile: 2) == RuleAction.Allow, "A private network's host could not connect in.");
            Expect(Kernel(plan, "192.168.1.50", TrafficDirection.Inbound, profile: 1) == RuleAction.Deny, "A public network's host could connect in.");
            Expect(Kernel(plan, "203.0.113.8") == RuleAction.Deny, "Internal access reached a public address.");
            Expect(plan.Filters.Where(f => f.Name == "Internal networks").All(f => f.Action == RuleAction.Allow && f.Weight == FilterCompiler.AllowWeight &&
                (f.Direction == TrafficDirection.Outbound || f.CurrentProfileId is 2 or 3)));
        });
        check("Blocked internal networks refuse both ways beneath explicit allows; left to rules they add no filters", () =>
        {
            var blocked = Plan(InternalAccess.Block);
            Expect(Kernel(blocked, "192.168.1.50") == RuleAction.Deny && Kernel(blocked, "192.168.1.50", TrafficDirection.Inbound, profile: 2) == RuleAction.Deny);
            Expect(blocked.Filters.Where(f => f.Name == "Internal networks").All(f => f.Action == RuleAction.Deny && f.Weight == FilterCompiler.InternalBlockWeight));
            Expect(FilterCompiler.InternalBlockWeight < FilterCompiler.AllowWeight && FilterCompiler.InternalBlockWeight > FilterCompiler.LeakGuardWeight);
            // A rule still opens one host.
            var share = new FirewallRule { ApplicationName = "Browser", Path = Browser, Protocol = "TCP", RemoteAddresses = "192.168.1.50", RemotePorts = "445" };
            Expect(Kernel(Plan(InternalAccess.Block, share), "192.168.1.50") == RuleAction.Allow && Kernel(Plan(InternalAccess.Block, share), "192.168.1.51") == RuleAction.Deny);
            Expect(Plan(InternalAccess.Rules).Filters.All(f => f.Name != "Internal networks") && Kernel(Plan(InternalAccess.Rules), "192.168.1.50") == RuleAction.Deny);
        });
        check("The engine previews internal access as the kernel enforces it, after explicit rules", () =>
        {
            var engine = new PolicyEngine();
            var state = new AppState { Mode = FirewallMode.BlockNew };
            Expect(engine.Evaluate(state, Flow("192.168.1.50")).Kind == DecisionKind.Allow && engine.Evaluate(state, Flow("ff02::fb")).Kind == DecisionKind.Allow);
            Expect(engine.Evaluate(state, Flow("192.168.1.50", TrafficDirection.Inbound, "Private")).Kind == DecisionKind.Allow);
            Expect(engine.Evaluate(state, Flow("192.168.1.50", TrafficDirection.Inbound, "Public")).Kind != DecisionKind.Allow, "A public network's host was let in.");
            state.InternalNetworks = InternalAccess.Block;
            Expect(engine.Evaluate(state, Flow("10.0.0.5")).Kind == DecisionKind.Deny);
            state.InternalNetworks = InternalAccess.Rules;
            Expect(InternalNetworks.Decide(state, Flow("10.0.0.5")) is null && engine.Evaluate(state, Flow("10.0.0.5")).Kind != DecisionKind.Allow);
            Expect(InternalNetworks.IsUnicast(IPAddress.Parse("::ffff:192.168.1.1")) && !InternalNetworks.IsUnicast(IPAddress.Parse("8.8.8.8")) && InternalNetworks.IsGroup(IPAddress.Parse("239.255.255.250")));
        });
        check("A country allow list lets only its countries through, needs routing and GeoIP, and must name one", () =>
        {
            var engine = new PolicyEngine();
            var state = new AppState { Mode = FirewallMode.BlockNew, Rules = [new() { ApplicationName = "Browser", Path = Browser }], CountryAllowList = true, AllowedCountries = ["CH"], BlockedCountries = ["CH"] };
            Expect(engine.Evaluate(state, Flow("203.0.113.8", country: "CH")).Kind == DecisionKind.Allow, "An allowed country was refused, or a block list waiting unused applied.");
            Expect(engine.Evaluate(state, Flow("203.0.113.9", country: "DE")) is { Kind: DecisionKind.Deny, Reason: "Country policy" });
            // An address no country claims, such as an internal one, is not the list's to refuse.
            Expect(engine.Evaluate(state, Flow("192.168.1.50")).Kind == DecisionKind.Allow);
            Expect(FilterCompiler.Compile(state).Errors.Any(e => e.Contains("verified GeoIP")), "An allow list compiled without GeoIP.");
            var unrouted = new AppState { Mode = FirewallMode.BlockNew, CountryAllowList = true, AllowedCountries = ["CH"], RouteConnections = false };
            Expect(FilterCompiler.Compile(unrouted).Errors.Any(e => e.Contains("connection router")), "An allow list compiled without routing.");
            Expect(PolicyValidation.Validate(new() { CountryAllowList = true }).Any(e => e.Contains("Choose at least one country")));
            Expect(PolicyValidation.Validate(new() { CountryAllowList = true, AllowedCountries = ["ZZZ"] }).Count > 0);
            Expect(PolicyValidation.Validate(new() { AllowedCountries = ["CH"] }).Count == 0, "A list kept while blocking countries was refused.");
        });
    }
}
