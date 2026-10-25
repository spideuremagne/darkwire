using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Net;

namespace Darkwire.Service;

internal static class RouterDecisionTests
{
    private const string Browser = @"C:\Apps\browser.exe";
    private static readonly NetEndpoint Tunnel = new(RouterAddresses.Tunnel4, 50_000), Remote = new(NetAddress.Parse("203.0.113.8"), 443);
    private static readonly Egress Lan = new(42, 7, IPAddress.Parse("192.168.1.20"), 0, 25);

    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string reason = "Router decision invariant failed.") { if (!value) throw new Exception(reason); }
        static RouterFlow Flow(byte protocol = 6, NetEndpoint? to = null) => new(1, protocol, Tunnel, to ?? Remote, DateTimeOffset.UnixEpoch);
        static FlowProcess Process(string path = Browser, params string[] sids) =>
            new(77, 1, path, new(path.ToLowerInvariant(), new HashSet<string>(sids.Append("S-1-5-21-1-2-3-1001"), StringComparer.OrdinalIgnoreCase), null));
        static RouterDecisions Decisions(FirewallMode mode, params FirewallRule[] rules) => DecisionsFor(new() { Mode = mode, Rules = [.. rules] });
        static RouterDecisions DecisionsFor(AppState state)
        {
            var plan = FilterCompiler.Compile(state, true, network: new([new(42, ["192.168.1.0/24"], [], [], [], [])]));
            if (!plan.CanApply) throw new Exception(string.Join("; ", plan.Errors));
            return new(new PlanMatcher(plan, p => Environment.ExpandEnvironmentVariables(p).ToLowerInvariant(), a => a), state.Mode, new Dictionary<ulong, uint> { [42] = 2 }, [42]);
        }
        static FirewallRule Allow(string remote = "203.0.113.8", string location = "Any") =>
            new() { ApplicationName = "Browser", Path = Browser, Protocol = "TCP", RemoteAddresses = remote, RemotePorts = "443", Location = location };

        check("Router releases a flow its rule allows", () =>
            Assert(Decisions(FirewallMode.Learning, Allow()).Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Allow));
        check("Router holds an unmatched, attributed flow for a prompt in Learning", () =>
        {
            var (verdict, prompt) = Decisions(FirewallMode.Learning).Decide(new(Flow(), Process(), Lan));
            Assert(verdict == RouterVerdict.Ask && prompt is not null);
            Assert(prompt!.Path == Browser && prompt.Protocol == "TCP" && prompt.RemoteAddress == "203.0.113.8" && prompt.RemotePort == 443 && prompt.LocalPort == 50_000);
            Assert(prompt.Location == "Private" && prompt.LocalAddress == "192.168.1.20" && prompt.Direction == TrafficDirection.Outbound && prompt.Service == "");
        });
        check("Router refuses unmatched flows outside Learning", () =>
            Assert(Decisions(FirewallMode.BlockNew).Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Block));
        check("Router refuses unattributed flows it cannot ask about", () =>
            Assert(Decisions(FirewallMode.Learning).Decide(new(Flow(), null, Lan)).Verdict == RouterVerdict.Block));
        check("Router refuses an explicitly denied flow even in Learning", () =>
        {
            var deny = Allow(); deny.Action = RuleAction.Deny;
            Assert(Decisions(FirewallMode.Learning, Allow(), deny).Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Block);
        });
        check("Router asks for a service host only when the flow names its service, and that service's rule covers its whole process", () =>
        {
            var svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");
            var decisions = Decisions(FirewallMode.Learning);
            var shared = Process(svchost, IdentitySelectors.ServiceSid("Dnscache"), IdentitySelectors.ServiceSid("Dhcp"));
            Assert(decisions.Decide(new(Flow(), shared, Lan)).Verdict == RouterVerdict.Block);
            // Windows tagged the socket with a service the token names: the prompt names it and the service sharing its process.
            var (verdict, prompt) = decisions.Decide(new(Flow(), shared with { TaggedService = "dhcp" }, Lan));
            Assert(verdict == RouterVerdict.Ask && prompt is { Service: "Dhcp" } && prompt.SharedServices() is ["Dnscache"], "The tagged service was not asked about.");
            Assert(decisions.Decide(new(Flow(), shared with { TaggedService = "BITS" }, Lan)).Verdict == RouterVerdict.Block, "A tag outside the token named a service.");
            (verdict, prompt) = decisions.Decide(new(Flow(), Process(svchost, IdentitySelectors.ServiceSid("Dnscache"), "S-1-5-80-0"), Lan));
            Assert(verdict == RouterVerdict.Ask && prompt!.Service.Equals("Dnscache", StringComparison.OrdinalIgnoreCase));
            // WFP sees the token, not the service, so one service's rule releases the flows of every service in its process.
            var rule = new FirewallRule { ApplicationName = "svchost", Path = svchost, Service = "Dhcp", Protocol = "TCP", RemoteAddresses = "203.0.113.8", RemotePorts = "443" };
            Assert(Decisions(FirewallMode.Learning, rule).Decide(new(Flow(), shared, Lan)).Verdict == RouterVerdict.Allow);
        });
        check("Router never prompts for ICMP", () =>
            Assert(Decisions(FirewallMode.Learning).Decide(new(Flow(1, new(Remote.Address, 0)), null, Lan)).Verdict == RouterVerdict.Block));
        check("Internal addresses leave physically under a default profile, unless its tunnel routes that private network itself; DNS to them still goes through it", () =>
        {
            var profile = Guid.NewGuid(); var office = NetAddress.Parse("10.8.0.5");
            var decisions = Decisions(FirewallMode.BlockNew) with
            {
                DefaultTunnel = profile, Internal = [.. InternalNetworks.Unicast.Select(NetPrefix.Parse)], RoutesPrivately = (_, address) => address == office
            };
            Assert(decisions.Path(Process(), Flow(6, new(NetAddress.Parse("172.16.4.4"), 445))) == FlowPath.Physical, "An internal host went into the tunnel.");
            Assert(decisions.Path(Process(), Flow(6, new(office, 445))).Tunnel == profile, "The tunnel's own private network went around it.");
            Assert(decisions.Path(Process(), Flow(17, new(NetAddress.Parse("172.16.4.4"), 53))).Tunnel == profile, "DNS to an internal server went around the tunnel.");
            Assert(decisions.Path(Process(), Flow()).Tunnel == profile);
        });
        check("A country allow list refuses other countries' addresses whatever rules allow, and passes addresses no country claims", () =>
        {
            static string? Country(IPAddress address) => address.ToString() switch { "203.0.113.8" => "DE", "198.51.100.9" => "CH", _ => null };
            var decisions = Decisions(FirewallMode.BlockNew, Allow("*")) with { AllowedCountries = new HashSet<string>(["CH"]), CountryOf = Country };
            Assert(decisions.Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Block, "A country outside the list was reached.");
            Assert(decisions.Decide(new(Flow(6, new(NetAddress.Parse("198.51.100.9"), 443)), Process(), Lan)).Verdict == RouterVerdict.Allow);
            Assert(decisions.Decide(new(Flow(6, new(NetAddress.Parse("192.0.2.1"), 443)), Process(), Lan)).Verdict == RouterVerdict.Allow, "An address no country claims was refused.");
        });
        check("Router evaluates keyword and profile scopes on the egress interface", () =>
        {
            var lan = new NetEndpoint(NetAddress.Parse("192.168.1.50"), 443);
            // Internal networks are left to rules here, so only the keyword rule can allow the LAN host.
            var keyword = DecisionsFor(new() { Mode = FirewallMode.BlockNew, Rules = [Allow("LocalSubnet")], InternalNetworks = InternalAccess.Rules });
            Assert(keyword.Decide(new(Flow(6, lan), Process(), Lan)).Verdict == RouterVerdict.Allow);
            Assert(keyword.Decide(new(Flow(6, lan), Process(), null)).Verdict == RouterVerdict.Block);
            var profile = Decisions(FirewallMode.BlockNew, Allow(location: "Private"));
            Assert(profile.Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Allow);
            Assert((profile with { Profiles = new Dictionary<ulong, uint>() }).Decide(new(Flow(), Process(), Lan)).Verdict == RouterVerdict.Block);
        });
    }
}
