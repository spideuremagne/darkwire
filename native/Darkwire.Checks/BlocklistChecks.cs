using Darkwire.Core;

internal static class BlocklistChecks
{
    private static void Expect(bool value, string message = "Blocklist invariant failed.") { if (!value) throw new Exception(message); }
    private static BlocklistContent Parse(string text, BlocklistFormat format) => BlocklistContent.Parse(new StringReader(text), format);
    private sealed class Stored(params (string Id, IReadOnlyList<string> Networks)[] lists) : IBlocklistContents
    {
        public IReadOnlyList<string>? Networks(string catalogId) => lists.FirstOrDefault(l => l.Id == catalogId).Networks;
    }
    private static AppState Policy(params string[] catalog) => new() { Mode = FirewallMode.BlockNew, Blocklists = catalog.Select(id => new BlocklistSource { CatalogId = id, Name = BlocklistCatalog.Find(id)!.Name }).ToList() };

    public static void Run(Action<string, Action> check)
    {
        check("Catalog lists have unique IDs and HTTPS sources, and their hosts stay resolvable", () =>
        {
            Expect(BlocklistCatalog.Entries.Select(e => e.Id).Distinct().Count() == BlocklistCatalog.Entries.Count && BlocklistCatalog.Entries.Count == 13);
            Expect(BlocklistCatalog.Entries.All(e => new Uri(e.Url).Scheme == Uri.UriSchemeHttps && e.Estimate > 0 && BlocklistCatalog.Find(e.Id) == e));
            Expect(BlocklistCatalog.Entries.Count(e => !e.Domains) == 1 && BlocklistCatalog.Find("unknown") is null && BlocklistCatalog.Find(null) is null);
            Expect(new[] { "cdn.jsdelivr.net", "raw.githubusercontent.com", "small.oisd.nl", "malware-filter.gitlab.io", "download.db-ip.com" }.All(BlocklistCatalog.SourceHosts.Contains));
        });
        check("Hosts files block exact hosts and skip addresses, local names and junk", () =>
        {
            var list = Parse("# AdAway\n127.0.0.1  localhost\n::1  localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.example.com tracker.example.com # inline\n" +
                "127.0.0.1\tMetrics.Example.COM.\nbare.example.org\n0.0.0.0 bad!name.example.com\n0.0.0.0 localhost.localdomain\n0.0.0.0 under_score.example.net\n", BlocklistFormat.Hosts);
            Expect(list.Hosts.SequenceEqual(["ads.example.com", "bare.example.org", "metrics.example.com", "tracker.example.com", "under_score.example.net"]), string.Join(",", list.Hosts));
            Expect(list.Domains.Count == 0 && list.Networks.Count == 0 && list.Count == 5);
        });
        check("Wildcard lists and adblock rules block whole domains; exceptions and browser rules are kept apart", () =>
        {
            var wild = Parse("# Syntax: Domains (wildcards) without *.\nexample.com\n*.wild.example.net\n10.0.0.1\nexample.com\n", BlocklistFormat.Wildcards);
            Expect(wild.Domains.SequenceEqual(["example.com", "wild.example.net"]) && wild.Hosts.Count == 0);
            var adblock = Parse("! Title\n[Adblock Plus 2.0]\n||ads.example.com^\n||imp.example.com^$important\n||third.example.com^$third-party\n" +
                "@@||good.ads.example.com^\nexample.com##.banner\n||path.example.com/ads^\n|http://example.org^\n", BlocklistFormat.Adblock);
            Expect(adblock.Domains.SequenceEqual(["ads.example.com", "imp.example.com"]) && adblock.Exceptions.SequenceEqual(["good.ads.example.com"]), string.Join(",", adblock.Domains));
        });
        check("Network lists merge into exact CIDRs and never block local or special-purpose space", () =>
        {
            var list = Parse("# netset\n1.2.3.0/25\n1.2.3.128/25\n10.0.0.0/8\n0.0.0.0/7\n192.168.1.1\n224.0.0.0/3\n8.8.8.8\n198.18.0.1\n" +
                "2001:db8::/32\nfe80::/10\nfd00::/8\n203.0.113.0-203.0.113.9\nnot-an-address\n", BlocklistFormat.Networks);
            Expect(list.Networks.SequenceEqual(["1.0.0.0/8", "8.8.8.8/32", "203.0.113.0/29", "203.0.113.8/31", "2001:db8::/32"]), string.Join(",", list.Networks));
            Expect(AddressRanges.Normalize([new(System.Net.IPAddress.Parse("0.0.0.0"), 0)]).Count > 10 && AddressRanges.Normalize([new(System.Net.IPAddress.Parse("127.0.0.1"), 32)]).Count == 0);
        });
        check("DNS filtering matches on label boundaries, ignores case, and lets exceptions win", () =>
        {
            var filter = new DomainFilter(["ads.example.com"], ["tracker.net"], ["ok.tracker.net"]);
            Expect(filter.Blocks("ads.example.com") && filter.Blocks("ADS.Example.Com.") && !filter.Blocks("x.ads.example.com") && !filter.Blocks("example.com"));
            Expect(filter.Blocks("tracker.net") && filter.Blocks("a.b.tracker.net") && !filter.Blocks("eviltracker.net") && !filter.Blocks("tracker.net.example"));
            Expect(!filter.Blocks("ok.tracker.net") && !filter.Blocks("deep.ok.tracker.net") && !filter.Blocks("") && !filter.Blocks("net") && !filter.Blocks("bad name.tracker.net"));
            Expect(filter.Count == 2 && !DomainFilter.Empty.Blocks("tracker.net"));
        });
        check("Combined filters keep every list's names and exceptions, counting shared names once", () =>
        {
            var first = new DomainFilter([], ["one.example", "shared.example"], []); var second = new DomainFilter(["host.example"], ["shared.example"], ["keep.one.example"]);
            var both = DomainFilter.Combine([first, second]);
            Expect(both.Count == 3 && both.Blocks("x.one.example") && both.Blocks("host.example") && both.Blocks("shared.example") && !both.Blocks("keep.one.example"));
            Expect(both.SameAs(DomainFilter.Combine([second, first])) && !both.SameAs(first) && DomainFilter.Combine([first]) == first);
        });
        check("Stored lists round-trip and refuse damage", () =>
        {
            var list = Parse("||ads.example.com^\n@@||ok.ads.example.com^\n", BlocklistFormat.Adblock);
            var writer = new StringWriter(); list.Write(writer);
            var read = BlocklistContent.Read(new StringReader(writer.ToString()));
            Expect(read.Domains.SequenceEqual(list.Domains) && read.Exceptions.SequenceEqual(list.Exceptions) && read.Count == 1);
            var networks = Parse("198.51.100.0/24\n", BlocklistFormat.Networks); writer = new StringWriter(); networks.Write(writer);
            Expect(BlocklistContent.Read(new StringReader(writer.ToString())).Networks.SequenceEqual(["198.51.100.0/24"]));
            foreach (var damaged in new[] { "", "# Darkwire blocklist 1\n=bad name\n", "# Darkwire blocklist 1\n@198.51.100.7\n", "# Darkwire blocklist 1\n?x.example\n", "# Other\n=ads.example.com\n" })
            {
                try { BlocklistContent.Read(new StringReader(damaged)); throw new Exception("A damaged stored list was read."); }
                catch (InvalidDataException) { }
            }
        });
        check("Downloaded catalog network lists become kernel denies; one that no longer fits is left out and reported", () =>
        {
            var plan = FilterCompiler.Compile(Policy("firehol-level1"), lists: new Stored(("firehol-level1", ["198.51.100.0/24", "2001:db8::/32"])));
            var listed = plan.Filters.Where(f => f.Name == "FireHOL Level 1").ToArray();
            Expect(plan.CanApply && plan.Warnings.Count == 0 && listed.Length == 4 && listed.All(f => f.Action == RuleAction.Deny && f.Weight == FilterCompiler.DenyWeight));
            Expect(listed.Count(f => f.Ipv6) == 2 && listed.Count(f => f.Direction == TrafficDirection.Inbound) == 2);
            var missing = FilterCompiler.Compile(Policy("firehol-level1"));
            Expect(missing.CanApply && missing.Warnings.Count == 0 && missing.Filters.All(f => f.Name != "FireHOL Level 1"));
            var huge = Enumerable.Range(0, 10_000).Select(i => $"203.{i / 256}.{i % 256}.0/24").ToArray();
            var oversized = FilterCompiler.Compile(Policy("firehol-level1"), lists: new Stored(("firehol-level1", huge)));
            Expect(oversized.CanApply && oversized.Warnings.Single().Contains("FireHOL Level 1") && oversized.Filters.All(f => f.Name != "FireHOL Level 1"));
            var routed = FilterCompiler.Route(oversized, new(@"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", ["198.18.0.0/15", "fd5a:9c33:21e7::/64"]));
            Expect(routed.CanApply && routed.Warnings.Count == 1, "Routing dropped the plan's warnings.");
        });
        check("Domain lists are enforced by DNS filtering with routing, guard link-local DNS, and fail closed without routing", () =>
        {
            foreach (var policy in new[] { Policy("hagezi-light"), new AppState { Mode = FirewallMode.BlockNew, Blocklists = [new() { Entries = ["tracker.example.com", "198.51.100.0/24"] }] } })
            {
                var plan = FilterCompiler.Compile(policy);
                var guards = plan.Filters.Where(f => f.Name == "DNS filtering: unrouted server").ToArray();
                Expect(plan.CanApply && guards.Length == 4 && guards.All(f => f.Action == RuleAction.Deny && f.Weight > FilterCompiler.CoreWeight && f.RemotePort == new PortRange(53, 53)));
                Expect(guards.Select(f => f.RemoteNetwork).Distinct().Order().SequenceEqual(["169.254.0.0/16", "fe80::/10"]) && plan.Filters.All(f => f.RemoteNetwork != "tracker.example.com"));
                policy.RouteConnections = false;
                Expect(FilterCompiler.Compile(policy).Errors.Any(e => e.Contains("connection routing")), "A domain list compiled without routing.");
            }
            Expect(FilterCompiler.Compile(Policy("firehol-level1")).Filters.All(f => f.Name != "DNS filtering: unrouted server"));
            var open = Policy("hagezi-light"); open.Mode = FirewallMode.Open; Expect(FilterCompiler.Compile(open).Filters.Count == 0);
        });
        check("Custom network lists are merged, skip local space, and must fit", () =>
        {
            var policy = new AppState { Mode = FirewallMode.BlockNew, Blocklists = [new() { Name = "Mine", Entries = ["198.51.100.0/25", "198.51.100.128/25", "192.168.0.0/16"] }] };
            var plan = FilterCompiler.Compile(policy);
            Expect(plan.CanApply && plan.Filters.Where(f => f.Name == "Mine").Select(f => f.RemoteNetwork).Distinct().SequenceEqual(["198.51.100.0/24"]));
            policy.Blocklists[0].Entries = Enumerable.Range(0, 10_000).Select(i => $"203.{i / 256}.{i % 256}.1").ToList();
            Expect(!FilterCompiler.Compile(policy).CanApply, "An oversized custom list was dropped instead of refused.");
        });
        check("Policies name catalog lists once, carry none of their entries, and only known ones", () =>
        {
            Expect(PolicyValidation.Validate(Policy("hagezi-light", "firehol-level1")).Count == 0);
            Expect(PolicyValidation.Validate(Policy("hagezi-light", "hagezi-light")).Any(e => e.Contains("once")));
            Expect(PolicyValidation.Validate(new AppState { Blocklists = [new() { CatalogId = "made-up" }] }).Count > 0);
            Expect(PolicyValidation.Validate(new AppState { Blocklists = [new() { CatalogId = "adaway", Entries = ["smuggled.example.com"] }] }).Count > 0);
        });
    }
}
