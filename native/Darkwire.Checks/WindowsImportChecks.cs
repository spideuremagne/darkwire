using Darkwire.Core;
using Darkwire.Engine;
using System.Security.AccessControl;

/// <summary>Registry-grammar import, non-widening translation, consent, keywords and built-in filters. No Windows state is read.</summary>
internal static class WindowsImportChecks
{
    private const string User = "S-1-5-21-1000-2000-3000-1001", Package = "S-1-15-2-1-2-3-4-5-6-7";
    public static readonly WindowsRuleContext Context = new(
        text => text.StartsWith('@') ? text == "@FirewallAPI.dll,-25000" ? "Core Networking" : null : text,
        family => family == "Example.App_8wekyb3d8bbwe" ? Package : null, new Version(10, 0, 26100));
    public static FirewallRule Import(string raw, string id = "Rule-1") => WindowsRuleTranslator.Translate(WindowsRuleGrammar.Parse(id, raw), Context);

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool condition, string message = "Import invariant failed.") { if (!condition) throw new Exception(message); }
        static AppState Policy(params FirewallRule[] rules) => new() { Mode = FirewallMode.BlockNew, Rules = [.. rules] };
        static IEnumerable<NativeFilter> Scoped(FilterPlan plan, FirewallRule rule) => plan.Filters.Where(f => f.RuleId == rule.Id);
        var lan = new NetworkSnapshot([
            new(11, ["192.168.1.0/24", "fe80::/64"], ["192.168.1.1/32"], ["192.168.1.1/32"], ["192.168.1.1/32"], []),
            new(22, ["10.8.0.0/24"], [], [], [], [])]);

        check("Rule grammar keeps repeated fields and rejects malformed strings", () =>
        {
            var record = WindowsRuleGrammar.Parse("Id", "v2.33|Action=Allow|Profile=Domain|Profile=Public|LUAuth=O:LSD:(A;;CC;;;SY)|");
            Expect(record.Version == "2.33" && record.All("Profile").Count() == 2 && record.All("LUAuth").Single() == "O:LSD:(A;;CC;;;SY)");
            foreach (var bad in new[] { "Action=Allow|", "v2|Action=Allow|", "v2.33|Action=Allow||Dir=In|", "v2.33|Action|", "v2.33|=Allow|" })
                try { WindowsRuleGrammar.Parse("Id", bad); throw new Exception("Accepted " + bad); } catch (InvalidDataException) { }
        });
        check("Exact service rule keeps identity, ports and group", () =>
        {
            var rule = Import(@"v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\system32\svchost.exe|Svc=dnscache|Name=DNS|EmbedCtxt=@FirewallAPI.dll,-25000|");
            Expect(rule.Import == ImportOutcome.Exact && rule.ImportWarning is null && rule.Service == "dnscache" && rule.RemotePorts == "53" && rule.Protocol == "UDP");
            Expect(rule.Group == "Core Networking" && rule.WindowsRuleId == "Rule-1" && rule.OriginalDefinition!.StartsWith("v2.33") && rule.Enabled);
        });
        check("Dotted masks become CIDRs and literal families are kept", () =>
        {
            var rule = Import("v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RA4=127.0.0.0/255.0.0.0|RA6=::/127|LUAuth=O:LSD:(A;;CC;;;" + User + ")|Name=Block|");
            Expect(rule.Import == ImportOutcome.Exact && rule.RemoteAddresses == "127.0.0.0/8,::/127" && rule.User == User && rule.Action == RuleAction.Deny);
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|RA4=10.0.0.0/255.0.255.0|Name=Odd|").Import == ImportOutcome.Unenforced, "A non-contiguous mask was accepted.");
        });
        check("LocalSubnet keeps its family and becomes a dynamic keyword", () =>
        {
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|Name=SMB|").RemoteAddresses == "LocalSubnet");
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|RA4=LocalSubnet|Name=SMB|").RemoteAddresses == "LocalSubnet4");
        });
        check("Trust-tuple scope leaves allow rules unenforced and broadens block rules", () =>
        {
            var allow = Import(@"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\system32\proximityuxhost.exe|TTK=ProxSharing|Name=Share|");
            Expect(allow.Import == ImportOutcome.Unenforced && allow.ImportWarning!.Contains("proximity sharing"));
            var block = Import("v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|TTK=ProxSharing|Name=Share|");
            Expect(block.Import == ImportOutcome.Narrowed && block.Action == RuleAction.Deny && block.RemoteAddresses == "*");
        });
        check("Untranslatable alternatives shrink allow rules and broaden block rules", () =>
        {
            var playTo = Import(@"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=23554|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\system32\mdeserver.exe|Name=PlayTo|");
            Expect(playTo.Import == ImportOutcome.Unenforced, "An emptied address set was treated as any address.");
            var mixed = Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|LPort=135|RA4=Ply2Renders|RA4=192.0.2.1|Name=Mixed|");
            Expect(mixed.Import == ImportOutcome.Narrowed && mixed.LocalPorts == "135" && mixed.RemoteAddresses == "192.0.2.1");
            var block = Import("v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|LPort=135|Name=Block RPC|");
            Expect(block.Import == ImportOutcome.Narrowed && block.LocalPorts == "*");
        });
        check("Disabled untranslatable rules stay disabled and cannot be enabled", () =>
        {
            var rule = Import("v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|Name=RPC|");
            Expect(rule.Import == ImportOutcome.Inert && !rule.Enabled && RuleValidator.Validate(rule).Count == 0 && FilterCompiler.Compile(Policy(rule)).CanApply);
            rule.Enabled = true; Expect(RuleValidator.Validate(rule).Count > 0 && !FilterCompiler.Compile(Policy(rule)).CanApply);
        });
        check("Package rules resolve their AppContainer SID and owner", () =>
        {
            var user = Import($"v2.33|Action=Allow|Active=TRUE|Dir=Out|PFN=Example.App_8wekyb3d8bbwe|LUOwn={User}|Name=@{{Example.App_1.0.0.0_x64__8wekyb3d8bbwe?ms-resource://Example/Name}}|");
            Expect(user.Import == ImportOutcome.Exact && user.Package == Package && user.User == User && user.ApplicationName == "Example.App");
            var system = Import("v2.33|Action=Allow|Active=TRUE|Dir=Out|PFN=Example.App_8wekyb3d8bbwe|LUOwn=S-1-5-18|Name=App|");
            Expect(system.Package == Package && system.User == "*");
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=Out|PFN=Unknown.App_8wekyb3d8bbwe|LUOwn=S-1-5-18|Name=App|").Import == ImportOutcome.Unenforced);
        });
        check("Only simple local-user allow lists translate", () =>
        {
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|LUAuth=O:LSD:(A;;CC;;;BA)(A;;CC;;;" + User + ")|Name=Users|").User == "S-1-5-32-544," + User);
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|LUAuth=O:LSD:(D;;CC;;;" + User + ")|Name=Deny|").Import == ImportOutcome.Unenforced);
            var block = Import("v2.33|Action=Block|Active=TRUE|Dir=In|LUAuth=O:LSD:(D;;CC;;;" + User + ")|Name=Deny|");
            Expect(block.Import == ImportOutcome.Narrowed && block.User == "*");
        });
        check("Edge traversal translates and deferral is reduced", () =>
        {
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=136:*|App=System|Edge=TRUE|Name=NDP|") is { Import: ImportOutcome.Exact, EdgeTraversal: true, Path: "System", IcmpTypesAndCodes: "136:*" });
            var deferred = Import(@"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=C:\app.exe|Edge=TRUE|Defer=App|Name=Shadow|");
            Expect(deferred.Import == ImportOutcome.Narrowed && !deferred.EdgeTraversal);
        });
        check("Version conditions decide applicability", () =>
        {
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=Out|Platform=2:6:2|Platform2=GTEQ|Name=New|").Import == ImportOutcome.Exact);
            var old = Import("v2.33|Action=Allow|Active=TRUE|Dir=Out|Platform=2:6:1|Name=Old|");
            Expect(old.Import == ImportOutcome.Inert && !old.Enabled);
        });
        check("Malformed allow rules stay unenforced; malformed block rules refuse until disabled", () =>
        {
            var allow = Import("v2.33|Action=Allow|Active=TRUE|Dir=Sideways|Protocol=300|Future=1|Name=Odd|");
            Expect(allow.Import == ImportOutcome.Unenforced && RuleValidator.Validate(allow).Count == 0);
            var block = Import("v2.33|Action=Block|Active=TRUE|Dir=In|Future=1|Name=Odd|");
            Expect(block.Import == ImportOutcome.Refused && !FilterCompiler.Compile(Policy(block)).CanApply);
            block.Enabled = false; Expect(FilterCompiler.Compile(Policy(block)).CanApply);
            Expect(WindowsFirewallReader.Unreadable("Bad", "v2.33|Action=Block|Active=TRUE|Dir=In|broken", "Malformed").Import == ImportOutcome.Refused);
            Expect(WindowsFirewallReader.Unreadable("Bad", "v2.33|Action=Allow|Active=FALSE|broken", "Malformed").Import == ImportOutcome.Inert);
        });
        check("Service wildcard means services only, never every application", () =>
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=Out|Svc=*|Name=Services|").Service == IdentitySelectors.AllServices));
        check("Authenticated bypass and IPsec requirements are never enforced as plain allows", () =>
        {
            Expect(Import("v2.33|Action=ByPass|Active=TRUE|Dir=In|Name=Bypass|").Import == ImportOutcome.Unenforced);
            Expect(Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Security=AuthenticateEncrypt|Name=Secure|").Import == ImportOutcome.Unenforced);
        });
        check("Reduced allows install without consent, unenforced allows install nothing, broader blocks need consent", () =>
        {
            var narrowed = Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|LPort=135|Name=Mixed|");
            var unenforced = Import("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|TTK=ProxSharing|Name=Share|", "Rule-2");
            var broader = Import("v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|LPort=135|Name=Wide|", "Rule-3");
            Expect(!RuleEnforcement.NeedsConsent(narrowed) && !RuleEnforcement.NeedsConsent(unenforced) && RuleEnforcement.NeedsConsent(broader));
            var plan = FilterCompiler.Compile(Policy(narrowed, unenforced));
            Expect(plan.CanApply && Scoped(plan, narrowed).All(f => f.LocalPort == new PortRange(135, 135)) && Scoped(plan, narrowed).Any() && !Scoped(plan, unenforced).Any());
            Expect(!FilterCompiler.Compile(Policy(narrowed, unenforced, broader)).CanApply);
            broader.NarrowingAccepted = true;
            var accepted = FilterCompiler.Compile(Policy(narrowed, unenforced, broader));
            Expect(accepted.CanApply && Scoped(accepted, broader).Any() && Scoped(accepted, broader).All(f => f.LocalPort is null));
        });
        check("Address keywords pair with interfaces for allow rules and use the union for deny rules", () =>
        {
            var allow = new FirewallRule { ApplicationName = "SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "LocalSubnet" };
            var deny = new FirewallRule { ApplicationName = "No SMB", Protocol = "TCP", Direction = TrafficDirection.Inbound, LocalPorts = "139", RemoteAddresses = "LocalSubnet4", Action = RuleAction.Deny };
            var plan = FilterCompiler.Compile(Policy(allow, deny), network: lan);
            Expect(plan.CanApply && Scoped(plan, allow).Count() == 3 && Scoped(plan, allow).All(f => f.LocalInterfaceLuid is 11 or 22));
            Expect(Scoped(plan, allow).Any(f => f.RemoteNetwork == "fe80::/64" && f.LocalInterfaceLuid == 11));
            Expect(Scoped(plan, deny).Count() == 2 && Scoped(plan, deny).All(f => f.LocalInterfaceLuid is null && !f.Ipv6));
            Expect(!FilterCompiler.Compile(Policy(allow)).CanApply, "A keyword compiled without interface data.");
            var empty = FilterCompiler.Compile(Policy(allow), network: NetworkSnapshot.Empty);
            Expect(empty.CanApply && !Scoped(empty, allow).Any());
            Expect(FilterCompiler.Compile(Policy(new FirewallRule { RemoteAddresses = "DNS", Protocol = "UDP", RemotePorts = "53" }), network: lan).CanApply);
        });
        check("Identity scopes reach native filters and build descriptors", () =>
        {
            var rule = new FirewallRule { ApplicationName = "Updates", Path = @"%SystemRoot%\system32\svchost.exe", Service = "wuauserv", Protocol = "TCP", RemotePorts = "443" };
            var plan = FilterCompiler.Compile(Policy(rule)); Expect(plan.CanApply && Scoped(plan, rule).All(f => f.Service == "wuauserv" && f.Users is null && f.Package is null));
            var descriptor = new RawSecurityDescriptor(WfpConditions.UserDescriptor("Dnscache", null), 0);
            Expect(descriptor.GetSddlForm(AccessControlSections.Access).Contains("(A;;CC;;;" + IdentitySelectors.ServiceSid("Dnscache") + ")"));
            Expect(new RawSecurityDescriptor(WfpConditions.UserDescriptor(null, "S-1-5-32-544," + User), 0).DiscretionaryAcl!.Count == 2);
            Expect(WfpConditions.UserDescriptor(IdentitySelectors.AllServices, "S-1-5-18").Length > 20, "A combined service and user scope did not build.");
            Expect(IdentitySelectors.ServiceSid("TrustedInstaller") == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        });
        check("Kernel and missing executables get exact application IDs", () =>
        {
            Expect(System.Text.Encoding.Unicode.GetString(WfpConditions.ApplicationId("System")) == "System\0");
            var missing = WfpConditions.ApplicationId(@"C:\Darkwire-missing\Example\App.EXE");
            var text = System.Text.Encoding.Unicode.GetString(missing);
            Expect(text.StartsWith(@"\device\", StringComparison.Ordinal) && text.EndsWith(@"\darkwire-missing\example\app.exe" + "\0", StringComparison.Ordinal) && text == text.ToLowerInvariant());
        });
        check("Loopback, core networking and the edge guard are built in", () =>
        {
            var plan = FilterCompiler.Compile(Policy());
            Expect(plan.Filters.Count(f => f.RequiredFlags == FilterCompiler.LoopbackFlag && f.Action == RuleAction.Allow && f.Weight == FilterCompiler.CoreWeight) == 4);
            Expect(plan.Filters.Count(f => f.Name == "Default policy" && f.Weight == FilterCompiler.DefaultWeight && f.Action == RuleAction.Deny) == 4);
            Expect(plan.Filters.Single(f => f.TunnelType == FilterCompiler.TeredoTunnelType) is { Ipv6: true, Direction: TrafficDirection.Inbound, Action: RuleAction.Deny });
            Expect(plan.Filters.Any(f => f.Service == "Dnscache" && f.RemotePort == new PortRange(53, 53)) && plan.Filters.Any(f => f.Service == "Dhcp" && f.LocalPort == new PortRange(68, 68)));
            var lockdown = FilterCompiler.Compile(new() { Mode = FirewallMode.Lockdown });
            Expect(lockdown.Filters.Count(f => f.RequiredFlags == FilterCompiler.LoopbackFlag) == 4 && lockdown.Filters.All(f => f.Service != "Dnscache") && lockdown.Filters.All(f => f.TunnelType is null));
            Expect(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, CoreNetworking = false }).Filters.All(f => !f.Name.StartsWith("Core networking", StringComparison.Ordinal)));
            // Scoped as Windows' Core Networking rules: no redirects, and router advertisements and listener messages only from link-local senders.
            var discovery = plan.Filters.Where(f => f.Name == "Core networking: IPv6 discovery").ToList();
            Expect(discovery.Count == 16 && discovery.All(f => f.IcmpType != 137));
            Expect(discovery.Where(f => f.Direction == TrafficDirection.Inbound).All(f => f.IcmpType is 133 or 135 or 136 ? f.RemoteNetwork is null : f.RemoteNetwork == "fe80::/64"));
            Expect(discovery.Where(f => f.Direction == TrafficDirection.Outbound).All(f => f.RemoteNetwork is null));
            PersistentFilterSession.ValidatePlan(plan); PersistentFilterSession.ValidatePlan(lockdown);
        });
        check("Explicit denies outrank loopback and core allows; edge rules outrank the edge guard", () =>
        {
            Expect(FilterCompiler.DenyWeight > FilterCompiler.EdgeAllowWeight && FilterCompiler.EdgeAllowWeight > FilterCompiler.EdgeGuardWeight &&
                FilterCompiler.EdgeGuardWeight > FilterCompiler.CoreWeight && FilterCompiler.CoreWeight > FilterCompiler.AllowWeight && FilterCompiler.AllowWeight > FilterCompiler.DefaultWeight);
            var edge = new FirewallRule { ApplicationName = "Edge", Direction = TrafficDirection.Any, EdgeTraversal = true };
            var plan = FilterCompiler.Compile(Policy(edge));
            Expect(Scoped(plan, edge).Where(f => f.Direction == TrafficDirection.Inbound).All(f => f.Weight == FilterCompiler.EdgeAllowWeight));
            Expect(Scoped(plan, edge).Where(f => f.Direction == TrafficDirection.Outbound).All(f => f.Weight == FilterCompiler.AllowWeight));
        });
    }
}
