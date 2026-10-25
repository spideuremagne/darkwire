using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Host;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;

var passed = 0; var failed = 0;
void Check(string name, Action test) { try { test(); Console.WriteLine("PASS " + name); passed++; } catch (Exception ex) { Console.WriteLine("FAIL " + name + ": " + ex.Message); failed++; } }
void Expect(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
var engine = new PolicyEngine();
var connection = new Connection("Browser", @"C:\Apps\browser.exe", 123, "203.0.113.7", 443, 50123, "TCP", TrafficDirection.Outbound, "Private", Country: "US", Asn: 64496, Hostname: "sub.tracker.example.com");
FirewallRule Allow() => new() { ApplicationName = "Browser", Path = @"C:\Apps\browser.exe", RemotePorts = "443", Protocol = "TCP" };
AppState Policy(FirewallMode mode = FirewallMode.Learning) => new() { Mode = mode };

foreach (var (mode, expected) in new[] { (FirewallMode.Open, DecisionKind.Allow), (FirewallMode.Learning, DecisionKind.Prompt), (FirewallMode.BlockNew, DecisionKind.Deny), (FirewallMode.Lockdown, DecisionKind.Deny) })
    Check("Unmatched connection: " + mode, () => Expect(engine.Evaluate(Policy(mode), connection).Kind == expected));
Check("Allow rule matches application and remote port", () => { var p = Policy(); p.Rules.Add(Allow()); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Allow); });
Check("Application match is case insensitive", () => { var p = Policy(); var r = Allow(); r.Path = r.Path.ToUpperInvariant(); p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Allow); });
Check("Different executable cannot use an allow rule", () => { var p = Policy(); p.Rules.Add(Allow()); Expect(engine.Evaluate(p, connection with { Path = @"C:\Malware\browser.exe" }).Kind == DecisionKind.Prompt); });
Check("Deny takes precedence over allow", () => { var p = Policy(); p.Rules.Add(Allow()); p.Rules.Add(new() { Action = RuleAction.Deny }); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Deny); });
Check("Disabled deny rule has no effect", () => { var p = Policy(); p.Rules.Add(Allow()); p.Rules.Add(new() { Action = RuleAction.Deny, Enabled = false }); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Allow); });
Check("Lockdown overrides an allow rule", () => { var p = Policy(FirewallMode.Lockdown); p.Rules.Add(Allow()); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Deny); });
Check("Open mode bypasses deny and geographic policy", () => { var p = Policy(FirewallMode.Open); p.Rules.Add(new() { Action = RuleAction.Deny }); p.BlockedCountries.Add("US"); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Allow); });
Check("Country restriction overrides allow", () => { var p = Policy(); p.Rules.Add(Allow()); p.BlockedCountries.Add("us"); Expect(engine.Evaluate(p, connection).Reason == "Country policy"); });
Check("ASN restriction overrides allow", () => { var p = Policy(); p.Rules.Add(Allow()); p.BlockedAsns.Add(64496); Expect(engine.Evaluate(p, connection).Reason == "ASN policy"); });
Check("Unknown ASN never matches ASN zero", () => { var p = Policy(); p.BlockedAsns.Add(0); Expect(engine.Evaluate(p, connection with { Asn = 0 }).Kind == DecisionKind.Prompt); });
Check("Scoped service is not broadened", () => { var p = Policy(); var r = Allow(); r.Service = "wuauserv"; p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); });
Check("Scoped user is not broadened", () => { var p = Policy(); var r = Allow(); r.User = "Alice"; p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); });
Check("Network location must match", () => { var p = Policy(); var r = Allow(); r.Location = "Public"; p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); });
Check("Unknown TCP direction cannot match outbound policy", () => { var p = Policy(); p.Rules.Add(Allow()); Expect(engine.Evaluate(p, connection with { Direction = TrafficDirection.Unknown }).Kind == DecisionKind.Prompt); });
Check("Imported rule with unresolved scope cannot allow traffic", () => { var p = Policy(); var r = Allow(); r.Import = ImportOutcome.Unenforced; r.ImportWarning = "Not translatable: package."; r.WindowsRuleId = "x"; p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); r.NarrowingAccepted = true; Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); });
Check("Invalid action enum cannot accidentally allow", () => { var p = Policy(); var r = Allow(); r.Action = (RuleAction)42; p.Rules.Add(r); Expect(engine.Evaluate(p, connection).Kind == DecisionKind.Prompt); });
Check("Unknown mode fails closed", () => Expect(engine.Evaluate(Policy((FirewallMode)99), connection).Kind == DecisionKind.Deny));
foreach (var port in new[] { "*", "0", "65535", "80,443", "1000-2000,443" }) Check("Valid port syntax: " + port, () => Expect(RuleValidator.ValidPorts(port)));
foreach (var port in new[] { "", "-1", "65536", "100-20", "abc", "1-2-3" }) Check("Reject port syntax: " + port, () => Expect(!RuleValidator.ValidPorts(port)));
Check("Port ranges include boundaries", () => Expect(RuleValidator.PortMatches("100-200", 100) && RuleValidator.PortMatches("100-200", 200) && !RuleValidator.PortMatches("100-200", 201)));
Check("IPv4 CIDR masking", () => { Expect(IpNetwork.TryParse("203.0.113.42/24", out var n)); Expect(n.Contains(IPAddress.Parse("203.0.113.255"))); Expect(!n.Contains(IPAddress.Parse("203.0.114.1"))); });
Check("IPv6 prefix matching", () => { Expect(IpNetwork.TryParse("2001:db8::/32", out var n)); Expect(n.Contains(IPAddress.Parse("2001:db8:abcd::1"))); Expect(!n.Contains(IPAddress.Parse("2001:db9::1"))); });
Check("IPv4 default route cannot match IPv6", () => { IpNetwork.TryParse("0.0.0.0/0", out var n); Expect(n.Contains(IPAddress.Parse("10.1.1.1"))); Expect(!n.Contains(IPAddress.Parse("::1"))); });
foreach (var value in new[] { "1.2.3.4/33", "::1/129", "::1/-1", "bogus", "1.2.3.4/24/4" }) Check("Reject invalid CIDR " + value, () => Expect(!IpNetwork.TryParse(value, out _)));
Check("Blocklist hosts, domains and CIDRs parse", () => { var entries = BlocklistParser.Parse("#comment\n0.0.0.0 tracker.example.com ads.example.com\n||analytics.example.com^\n203.0.113.0/24\nlocalhost\n!ignored\n"); Expect(entries.Count == 4); });
Check("Domain suffix boundary is respected", () => { Expect(BlocklistParser.Matches("tracker.example.com", connection)); Expect(!BlocklistParser.Matches("acker.example.com", connection)); });
Check("Unknown hostname does not match domain rules", () => Expect(!BlocklistParser.Matches("tracker.example.com", connection with { Hostname = "" })));
Check("IPv4 blocklist matches subnet", () => Expect(BlocklistParser.Matches("203.0.113.0/24", connection)));
var csv = "network,country,country_name,city,latitude,longitude,asn,organization\n203.0.113.0/24,US,United States,Seattle,47.6,-122.3,64496,Example\n203.0.113.7/32,CA,Canada,\"Toronto, ON\",43.6,-79.3,AS64497,\"Example, Inc\"\n2001:db8::/32,DE,Germany,Berlin,52.5,13.4,64498,Example\n";
Check("GeoIP longest prefix wins", () => { var geo = GeoDatabase.Load(new StringReader(csv)); Expect(geo.Count == 3); Expect(geo.Lookup("203.0.113.7")?.Country == "CA"); Expect(geo.Lookup("203.0.113.8")?.Country == "US"); });
Check("GeoIP quoted fields retained", () => Expect(GeoDatabase.Load(new StringReader(csv)).Lookup("203.0.113.7")?.Organization == "Example, Inc"));
Check("GeoIP IPv6 lookup", () => Expect(GeoDatabase.Load(new StringReader(csv)).Lookup("2001:db8::1234")?.Asn == 64498));
Check("GeoIP unknown address stays unresolved", () => Expect(GeoDatabase.Load(new StringReader(csv)).Lookup("192.0.2.4") is null));
Check("Invalid GeoIP rejects entire update", () => Throws<InvalidDataException>(() => GeoDatabase.Load(new StringReader(csv + "bad,data\n"))));
Check("NaN GeoIP latitude is rejected", () => Throws<InvalidDataException>(() => GeoDatabase.Load(new StringReader(csv.Replace("47.6", "NaN")))));
Check("Invalid GeoIP header rejected", () => Throws<InvalidDataException>(() => GeoDatabase.Load(new StringReader("foo,bar\n1,2"))));
Check("Malformed CSV quote rejected", () => Throws<InvalidDataException>(() => GeoDatabase.CsvLine("a,\"b")));
Check("Atomic settings round trip", () => { var path = Path.Combine(Path.GetTempPath(), "darkwire-test-" + Guid.NewGuid() + ".json"); try { var state = Policy(); state.Rules.Add(Allow()); StateStore.Write(path, state); state.Mode = FirewallMode.BlockNew; StateStore.Write(path, state); var read = StateStore.Read(path); Expect(read.Rules.Count == 1 && read.Mode == FirewallMode.BlockNew); } finally { File.Delete(path); } });
Check("Unknown schema rejected without rewriting", () => { var path = Path.Combine(Path.GetTempPath(), "darkwire-test-" + Guid.NewGuid() + ".json"); try { File.WriteAllText(path, "{\"SchemaVersion\":99}"); Throws<InvalidDataException>(() => StateStore.Read(path)); Expect(File.ReadAllText(path).Contains("99")); } finally { File.Delete(path); } });
IEnumerable<NativeFilter> Defaults(FilterPlan plan) => plan.Filters.Where(f => f.Name == "Default policy" && f.RuleId is null);
Check("Block-new compiler emits four family/direction default denies", () => { var plan = FilterCompiler.Compile(Policy(FirewallMode.BlockNew)); Expect(plan.CanApply && Defaults(plan).Count() == 4 && Defaults(plan).All(f => f.Action == RuleAction.Deny && f.Weight == FilterCompiler.DefaultWeight)); });
Check("Open compiler emits no blocking filters", () => Expect(FilterCompiler.Compile(Policy(FirewallMode.Open)).Filters.Count == 0));
Check("Learning cannot silently compile to allow", () => Expect(!FilterCompiler.Compile(Policy(FirewallMode.Learning)).CanApply));
Check("Lockdown defaults cover IPv4 and IPv6", () => { var plan = FilterCompiler.Compile(Policy(FirewallMode.Lockdown)); Expect(plan.CanApply && Defaults(plan).Count(f => f.Ipv6) == 2 && plan.Filters.All(f => f.RuleId is null)); });
Check("Compiler expands OR ports without weakening AND scopes", () => { var p = Policy(FirewallMode.BlockNew); var r = Allow(); r.RemotePorts = "80,443"; p.Rules.Add(r); var plan = FilterCompiler.Compile(p); Expect(plan.CanApply && plan.Filters.Count(f => f.RuleId == r.Id) == 4); Expect(plan.Filters.Count(f => f.ApplicationPath != null && f.RuleId == r.Id && f.RemotePort?.Low == 443) == 2); });
Check("Compiler carries service scope into native filters", () => { var p = Policy(FirewallMode.BlockNew); var r = Allow(); r.Service = "wuauserv"; p.Rules.Add(r); var plan = FilterCompiler.Compile(p); Expect(plan.CanApply && plan.Filters.Where(f => f.RuleId == r.Id).All(f => f.Service == "wuauserv")); });
Check("Compiler ignores disabled kept-disabled imports", () => { var p = Policy(FirewallMode.BlockNew); p.Rules.Add(new() { Enabled = false, Import = ImportOutcome.Inert, ImportWarning = "Package ID", WindowsRuleId = "x" }); Expect(FilterCompiler.Compile(p).CanApply); });
Check("Compiler never silently drops domain lists", () => { var p = Policy(FirewallMode.BlockNew); p.RouteConnections = false; p.Blocklists.Add(new() { Entries = ["example.com"] }); Expect(!FilterCompiler.Compile(p).CanApply); });
Check("Compiler rejects ports without a transport protocol", () => { var p = Policy(FirewallMode.BlockNew); p.Rules.Add(new() { RemotePorts = "443" }); Expect(!FilterCompiler.Compile(p).CanApply); });
Check("Compiler IPv6 address stays on IPv6 layer", () => { var p = Policy(FirewallMode.BlockNew); var r = Allow(); r.RemoteAddresses = "2001:db8::/32"; p.Rules.Add(r); var plan = FilterCompiler.Compile(p); Expect(plan.CanApply && plan.Filters.Single(f => f.RuleId != null).Ipv6); });
// FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SESSION0 and FWP_VALUE0 as the 64-bit fwpuclnt.dll lays them out.
Check("WFP x64 native structure layout", () => { var filter = Marshal.SizeOf<WfpNative.Filter>(); Expect(filter == 200, "Filter size " + filter); Expect(Marshal.SizeOf<WfpNative.Condition>() == 40); Expect(Marshal.SizeOf<WfpNative.Session>() == 72); Expect(Marshal.SizeOf<WfpNative.Value>() == 16); });
Check("VPN config protected by Windows DPAPI", () => { var encrypted = SecureConfig.Protect("PrivateKey=secret-test-only"); Expect(encrypted.Length > 30 && !encrypted.Contains("secret")); });

EnforcementChecks.Run(Check);
AddressRangeChecks.Run(Check);
RuleScopeChecks.Run(Check);
WindowsImportChecks.Run(Check);
StartupGuardChecks.Run(Check);
InternalNetworkChecks.Run(Check);
ConnectionChecks.Run(Check);
ApplicationIconChecks.Run(Check);
AppearanceChecks.Run(Check);
AtlasProjectionChecks.Run(Check);
WorldMapChecks.Run(Check);
MapOriginChecks.Run(Check);
SetupChecks.Run(Check);
InstalledBuildChecks.Run(Check);
VpnStateChecks.Run(Check);
GeoIpChecks.Run(Check);
BlocklistChecks.Run(Check);
PlanMatcherChecks.Run(Check);
FilterDeltaChecks.Run(Check);
AttributionChecks.Run(Check, args.Contains("--native-readonly"));
RouterPlumbingChecks.Run(Check, args.Contains("--native-readonly"));
VpnRoutingChecks.Run(Check);
EncryptedDnsChecks.Run(Check);

if (args.Contains("--native-readonly"))
{
    Check("Native TCP snapshot read", () => { var rows = WindowsTelemetry.Snapshot(); Expect(rows.All(r => r.RemotePort is > 0 and <= 65535)); Console.WriteLine($"  {rows.Count} TCP endpoints"); });
    Check("Windows Firewall rule store is read losslessly", () =>
    {
        var read = WindowsFirewallReader.Read(); Expect(read.Profiles.Count == 3 && read.Errors.Count == 0, string.Join(" ", read.Errors));
        Expect(read.Rules.All(r => r.WindowsRuleId is not null && r.OriginalDefinition is not null && r.Import is not null && RuleValidator.Validate(r).Count == 0 || r.Import == ImportOutcome.Refused));
        var outcomes = read.Rules.GroupBy(r => r.Import).OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Count()} ({g.Count(r => r.Enabled)} enabled)");
        Console.WriteLine($"  {read.Rules.Count} rules: {string.Join(", ", outcomes)}; consent needed for {read.Rules.Count(RuleEnforcement.NeedsConsent)}");
    });
    Check("Live keyword rules resolve and the inherited policy builds natively", () =>
    {
        var read = WindowsFirewallReader.Read(); foreach (var rule in read.Rules) rule.NarrowingAccepted = true;
        var policy = new AppState { Mode = FirewallMode.BlockNew, Rules = read.Rules.Where(r => !(r.Enabled && r.Import == ImportOutcome.Refused)).ToList() };
        var plan = FilterCompiler.Compile(policy, network: new NetworkEnvironment().Capture());
        Expect(plan.CanApply, string.Join(" ", plan.Errors.Take(5)));
        var native = WfpConditions.Preflight(plan); Expect(native.Count == 0, string.Join(" ", native.Take(5)));
        Console.WriteLine($"  {plan.Filters.Count} native filters after accepting reduced imports");
    });
    Check("Manual application IDs match Windows for existing files", () =>
    {
        foreach (var path in new[] { Environment.ProcessPath!, Path.Combine(Environment.SystemDirectory, "svchost.exe") })
        {
            var manual = System.Text.Encoding.Unicode.GetBytes(WfpConditions.DevicePath(Path.GetFullPath(path)).ToLowerInvariant() + "\0");
            Expect(WfpConditions.ApplicationId(path).SequenceEqual(manual), "Application ID differs for " + path);
        }
    });
}
Console.WriteLine($"\n{passed} passed; {failed} failed. No filtering session was opened.");
return failed == 0 ? 0 : 1;
