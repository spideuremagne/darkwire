using Darkwire.Core;
using System.Net;

internal static class PlanMatcherChecks
{
    private const string Browser = @"C:\Apps\browser.exe", Other = @"C:\Apps\other.exe";

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool condition, string reason = "The plan matcher disagreed with the compiled plan.") { if (!condition) throw new Exception(reason); }
        static FirewallRule Rule(RuleAction action = RuleAction.Allow, string path = Browser) =>
            new() { ApplicationName = "Matcher test", Path = path, Action = action, Protocol = "TCP", RemotePorts = "443" };
        static PlanMatcher Matcher(FirewallRule[] rules, FirewallMode mode = FirewallMode.BlockNew, NetworkSnapshot? network = null)
        {
            var plan = FilterCompiler.Compile(new() { Mode = mode, Rules = [.. rules] }, true, network: network);
            if (!plan.CanApply) throw new Exception(string.Join("; ", plan.Errors));
            return new(plan, path => Environment.ExpandEnvironmentVariables(path).ToLowerInvariant(), account => account);
        }
        static FlowOwner Owner(string path = Browser, string? package = null, params string[] sids) =>
            new(path.ToLowerInvariant(), new HashSet<string>(sids.Append("S-1-5-21-1-2-3-1001"), StringComparer.OrdinalIgnoreCase), package);
        static FlowQuery Query(FlowOwner? owner, string remote = "203.0.113.8", ushort port = 443, byte protocol = 6) =>
            new(TrafficDirection.Outbound, protocol, IPAddress.Parse(remote.Contains(':') ? "2001:db8::2" : "192.0.2.2"), 50_000, IPAddress.Parse(remote), port, owner);

        check("Matched allow rule decides with certainty", () =>
        {
            var verdict = Matcher([Rule()]).Match(Query(Owner()));
            Expect(verdict is { Action: RuleAction.Allow, Certain: true, IsDefault: false });
        });
        check("Deny outranks allow for the same flow", () =>
            Expect(Matcher([Rule(), Rule(RuleAction.Deny)]).Match(Query(Owner())) is { Action: RuleAction.Deny, IsDefault: false }));
        check("Another application falls to the default", () =>
            Expect(Matcher([Rule()]).Match(Query(Owner(Other))) is { Action: RuleAction.Deny, IsDefault: true, Certain: true }));
        check("Ports, protocol and family must all match", () =>
        {
            var matcher = Matcher([Rule()]);
            Expect(matcher.Match(Query(Owner(), port: 80))!.IsDefault && matcher.Match(Query(Owner(), protocol: 17))!.IsDefault);
            Expect(!matcher.Match(Query(Owner(), "2001:db8::8"))!.IsDefault);
        });
        check("An unattributed flow cannot use an application allow", () =>
            Expect(Matcher([Rule()]).Match(Query(null)) is { IsDefault: true }));
        check("An unattributed flow is blocked by an application deny it might match", () =>
            Expect(Matcher([Rule(RuleAction.Deny, Other), Rule(RuleAction.Allow, "*")]).Match(Query(null)) is { Action: RuleAction.Deny, Certain: false, IsDefault: false }));
        check("An application-independent allow covers an unattributed flow", () =>
            Expect(Matcher([Rule(RuleAction.Allow, "*")]).Match(Query(null)) is { Action: RuleAction.Allow, Certain: true }));
        check("Service scope requires the service SID in the token", () =>
        {
            var rule = Rule(); rule.Path = @"%SystemRoot%\system32\svchost.exe"; rule.Service = "Dnscache";
            var matcher = Matcher([rule]); var svchost = Environment.ExpandEnvironmentVariables(rule.Path);
            Expect(!matcher.Match(Query(Owner(svchost, null, IdentitySelectors.ServiceSid("dnscache"))))!.IsDefault);
            Expect(matcher.Match(Query(Owner(svchost, null, IdentitySelectors.ServiceSid("Dhcp"))))!.IsDefault);
        });
        check("AllServices matches any service process", () =>
        {
            var rule = Rule(); rule.Service = IdentitySelectors.AllServices;
            var matcher = Matcher([rule]);
            Expect(!matcher.Match(Query(Owner(Browser, null, "S-1-5-6")))!.IsDefault && matcher.Match(Query(Owner()))!.IsDefault);
        });
        check("Service and user scopes must hold together", () =>
        {
            var rule = Rule(); rule.Service = "Dnscache"; rule.User = "S-1-5-20";
            var matcher = Matcher([rule]); var service = IdentitySelectors.ServiceSid("Dnscache");
            Expect(!matcher.Match(Query(Owner(Browser, null, service, "S-1-5-20")))!.IsDefault);
            Expect(matcher.Match(Query(Owner(Browser, null, service)))!.IsDefault && matcher.Match(Query(Owner(Browser, null, "S-1-5-20")))!.IsDefault);
        });
        check("Package scopes distinguish AppContainers", () =>
        {
            var any = Rule(); any.Package = IdentitySelectors.AllPackages;
            var one = Rule(); one.Package = "S-1-15-2-1-2-3-4-5-6-7";
            var anyMatcher = Matcher([any]); var oneMatcher = Matcher([one]);
            Expect(!anyMatcher.Match(Query(Owner(Browser, "S-1-15-2-9-9-9-9-9-9-9")))!.IsDefault && anyMatcher.Match(Query(Owner()))!.IsDefault);
            Expect(!oneMatcher.Match(Query(Owner(Browser, "S-1-15-2-1-2-3-4-5-6-7")))!.IsDefault && oneMatcher.Match(Query(Owner(Browser, "S-1-15-2-9-9-9-9-9-9-9")))!.IsDefault);
        });
        check("Keyword allows need the egress interface; keyword denies apply without it", () =>
        {
            var network = new NetworkSnapshot([new(42, ["203.0.113.0/24"], [], [], [], [])]);
            var allow = Rule(); allow.RemoteAddresses = "LocalSubnet";
            var deny = Rule(RuleAction.Deny, Other); deny.RemoteAddresses = "LocalSubnet";
            var matcher = Matcher([allow, deny], network: network);
            Expect(matcher.Match(Query(Owner()))!.IsDefault);
            Expect(matcher.Match(Query(Owner()) with { InterfaceLuid = 42 }) is { Action: RuleAction.Allow, Certain: true });
            Expect(matcher.Match(Query(Owner()) with { InterfaceLuid = 7 })!.IsDefault);
            Expect(matcher.Match(Query(Owner(Other))) is { Action: RuleAction.Deny, IsDefault: false });
        });
        check("Profile scope needs the network profile", () =>
        {
            var rule = Rule(); rule.Location = "Private";
            var matcher = Matcher([rule]);
            Expect(matcher.Match(Query(Owner()))!.IsDefault && matcher.Match(Query(Owner()) with { ProfileId = 1 })!.IsDefault);
            Expect(!matcher.Match(Query(Owner()) with { ProfileId = 2 })!.IsDefault);
        });
        check("Core DNS exception admits the DNS client service only", () =>
        {
            var matcher = Matcher([]); var svchost = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\system32\svchost.exe");
            var dns = Query(Owner(svchost, null, IdentitySelectors.ServiceSid("Dnscache")), "198.51.100.53", 53, 17);
            Expect(matcher.Match(dns) is { Action: RuleAction.Allow, IsDefault: false });
            Expect(matcher.Match(dns with { Owner = Owner(Browser) })!.IsDefault);
        });
        check("Loopback exceptions never cover routed flows", () =>
        {
            var matcher = Matcher([]);
            Expect(matcher.Match(Query(Owner()))!.IsDefault && matcher.Match(Query(Owner()) with { Flags = FilterCompiler.LoopbackFlag }) is { Action: RuleAction.Allow });
        });
        check("ICMP rules match on type and code", () =>
        {
            var rule = new FirewallRule { ApplicationName = "Ping", Path = "*", Protocol = "ICMPv4", IcmpTypesAndCodes = "8:*" };
            var matcher = Matcher([rule]);
            Expect(matcher.Match(Query(null, protocol: 1) with { RemotePort = 0, IcmpType = 8, IcmpCode = 0 }) is { Action: RuleAction.Allow });
            Expect(matcher.Match(Query(null, protocol: 1) with { RemotePort = 0, IcmpType = 13, IcmpCode = 0 })!.IsDefault);
        });
        check("Lockdown denies everything but link essentials; Open has no plan", () =>
        {
            Expect(Matcher([Rule()], FirewallMode.Lockdown).Match(Query(Owner())) is { IsDefault: true });
            Expect(new PlanMatcher(FilterCompiler.Compile(new() { Mode = FirewallMode.Open }), p => p, a => a).Match(Query(Owner())) is null);
        });
        check("A plan with errors is refused", () =>
        {
            try { _ = new PlanMatcher(new([], ["broken"]), p => p, a => a); throw new Exception("Accepted."); }
            catch (InvalidOperationException) { }
        });
    }
}
