using Darkwire.Core;
using Darkwire.Engine;

namespace Darkwire.Service;

internal static class BlocklistTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
    private static void Assert(bool condition, string reason = "Blocklist invariant failed.") { if (!condition) throw new Exception(reason); }
    private static bool DnsClient(NativeFilter filter) => filter.Name.StartsWith("Router: DNS client", StringComparison.Ordinal);

    public static void Run(Action<string, Action> check)
    {
        check("Catalog downloads are normalized, counted and kept; a failed or empty refresh keeps the copy", () => InTemporary(root =>
        {
            var clock = new Clock(new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero)); string? body = "# AdAway\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 metrics.example.net\n";
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            {
                Assert(uri.AbsoluteUri == BlocklistCatalog.Find("adaway")!.Url && limit > 0, "The store fetched something other than the catalog URL.");
                if (body is null) throw new HttpRequestException("Offline.");
                File.WriteAllText(destination, body); return Task.CompletedTask;
            }
            var store = new BlocklistStore(Download, root, clock); var changes = 0; store.Changed = () => changes++;
            store.FetchAsync("adaway", default).GetAwaiter().GetResult();
            Assert(store.Status().Single(s => s.Id == "adaway") is { Count: 2, Downloading: false, Error: null } status && status.UpdatedAt == clock.Now && changes == 1);
            Assert(store.Names("adaway")!.Blocks("ads.example.com") && !store.Names("adaway")!.Blocks("example.com") && store.Networks("adaway") is null);
            Assert(Directory.GetFiles(root).Select(Path.GetFileName).Order().SequenceEqual(["adaway.json", "adaway.txt"]), "Downloads were left behind.");
            var reopened = new BlocklistStore(Download, root, clock);
            Assert(reopened.Status().Single(s => s.Id == "adaway").Count == 2 && reopened.Names("adaway")!.Blocks("metrics.example.net"));
            var version = store.Version;
            foreach (var next in new[] { null, "# nothing to block\n127.0.0.1 localhost\n" })
            {
                body = next; store.FetchAsync("adaway", default).GetAwaiter().GetResult();
                Assert(store.Status().Single(s => s.Id == "adaway") is { Count: 2, Error: not null } && store.Version == version && changes == 1 && store.Names("adaway")!.Blocks("ads.example.com"));
            }
            File.WriteAllText(Path.Combine(root, "adaway.txt"), "# Darkwire blocklist 1\n=bad name\n");
            var damaged = new BlocklistStore(Download, root, clock);
            Assert(damaged.Names("adaway") is null && damaged.Status().Single(s => s.Id == "adaway") is { Count: 0, Downloading: true }, "A damaged copy was used or not fetched again.");
        }));
        check("A refresh holding a tenth of the kept copy is refused as broken", () => InTemporary(root =>
        {
            var size = 2_000;
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            { File.WriteAllLines(destination, Enumerable.Range(0, size).Select(i => $"host{i}.example.com")); return Task.CompletedTask; }
            var store = new BlocklistStore(Download, root, new Clock(DateTimeOffset.UnixEpoch));
            store.FetchAsync("oisd-big", default).GetAwaiter().GetResult();
            size = 150; store.FetchAsync("oisd-big", default).GetAwaiter().GetResult();
            Assert(store.Status().Single(s => s.Id == "oisd-big") is { Count: 2_000, Error: not null } && store.Names("oisd-big")!.Blocks("host1999.example.com"));
            size = 900; store.FetchAsync("oisd-big", default).GetAwaiter().GetResult();
            Assert(store.Status().Single(s => s.Id == "oisd-big") is { Count: 900, Error: null }, "A list that shrank within bounds was refused.");
        }));
        check("Network lists are kept as merged CIDRs without local space", () => InTemporary(root =>
        {
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            { File.WriteAllText(destination, "# firehol\n10.0.0.0/8\n198.51.100.0/25\n198.51.100.128/25\n"); return Task.CompletedTask; }
            var store = new BlocklistStore(Download, root, new Clock(DateTimeOffset.UnixEpoch));
            store.FetchAsync("firehol-level1", default).GetAwaiter().GetResult();
            Assert(store.Networks("firehol-level1")!.SequenceEqual(["198.51.100.0/24"]) && store.Names("firehol-level1") is null && store.Status().Single(s => s.Id == "firehol-level1").Count == 1);
        }));
        check("Lists are fetched again only when stale; a failed preload waits a minute, a failed refresh an hour", () => InTemporary(root =>
        {
            var clock = new Clock(new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero)); var fail = false;
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            { if (fail) throw new HttpRequestException("Offline."); File.WriteAllText(destination, "example.com\n"); return Task.CompletedTask; }
            var store = new BlocklistStore(Download, root, clock);
            bool Queued(string id) => store.Status().Single(s => s.Id == id).Downloading;
            store.Request("oisd-small", BlocklistStore.Preload); Assert(Queued("oisd-small"));
            store.Request("oisd-small", BlocklistStore.Preload);
            store.FetchAsync("oisd-small", default).GetAwaiter().GetResult(); Assert(!Queued("oisd-small"));
            store.Request("oisd-small", BlocklistStore.Preload); store.Request("oisd-small", BlocklistStore.Refresh);
            Assert(!Queued("oisd-small"), "A fresh list was fetched again.");
            clock.Now = clock.Now.AddHours(25); store.Request("oisd-small", BlocklistStore.Refresh); Assert(Queued("oisd-small"));
            fail = true; store.FetchAsync("oisd-small", default).GetAwaiter().GetResult();
            store.Request("oisd-small", BlocklistStore.Preload); Assert(!Queued("oisd-small"), "A failed list was retried at once.");
            clock.Now = clock.Now.AddMinutes(2); store.Request("oisd-small", BlocklistStore.Refresh); Assert(!Queued("oisd-small"), "A refresh ignored the hour's back-off.");
            store.Request("oisd-small", BlocklistStore.Preload); Assert(Queued("oisd-small"));
            try { store.Request("https://example.com/list.txt", BlocklistStore.Preload); throw new Exception("A non-catalog list was queued."); } catch (InvalidDataException) { }
        }));
        check("A list with no copy yet tries again a minute after failing, then twice as long each time up to an hour, and says when", () => InTemporary(root =>
        {
            var clock = new Clock(new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero)); var fail = true;
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            { if (fail) throw new HttpRequestException("No such host is known. (cdn.jsdelivr.net:443)"); File.WriteAllText(destination, "example.com\n"); return Task.CompletedTask; }
            var store = new BlocklistStore(Download, root, clock);
            string[] enabled = ["hagezi-light"];
            BlocklistStatus Status() => store.Status().Single(s => s.Id == "hagezi-light");
            Assert(store.NextCheck(enabled) == TimeSpan.FromHours(1), "A list that never failed was checked early.");
            foreach (var minutes in new[] { 1, 2, 4, 8, 16, 32, 60, 60 })
            {
                store.FetchAsync("hagezi-light", default).GetAwaiter().GetResult();
                var wait = TimeSpan.FromMinutes(minutes);
                Assert(store.NextCheck(enabled) == wait, $"The wait after a failure was not {minutes} minutes.");
                Assert(Status().Error == $"Download failed: No such host is known. (cdn.jsdelivr.net:443). Trying again at {(clock.Now + wait).ToLocalTime():HH:mm}.", Status().Error ?? "No error.");
                clock.Now += wait - TimeSpan.FromSeconds(1);
                store.Request("hagezi-light", BlocklistStore.Refresh);
                Assert(!Status().Downloading && store.NextCheck(enabled) == TimeSpan.FromSeconds(1), "A list was fetched again before its wait was over.");
                clock.Now += TimeSpan.FromSeconds(1);
                store.Request("hagezi-light", BlocklistStore.Refresh); Assert(Status().Downloading, "A list was not fetched again after its wait.");
            }
            fail = false; store.FetchAsync("hagezi-light", default).GetAwaiter().GetResult();
            Assert(Status() is { Count: 1, Error: null } && store.NextCheck(enabled) == TimeSpan.FromHours(1));
            var updated = clock.Now;
            // A fresh copy fetched again ahead of its refresh, and failing, is fetched again once the copy goes stale.
            clock.Now += TimeSpan.FromMinutes(30); fail = true;
            store.Request("hagezi-light", BlocklistStore.Preload); store.FetchAsync("hagezi-light", default).GetAwaiter().GetResult();
            Assert(Status().Error!.EndsWith($"Trying again at {(updated + BlocklistStore.Refresh).ToLocalTime():HH:mm}.", StringComparison.Ordinal));
            clock.Now += TimeSpan.FromHours(2);
            Assert(store.NextCheck(enabled) == TimeSpan.FromHours(1), "A failed list with a fresh copy kept the refresh waking.");
            // Once its copy is stale, which stays in force, a failed refresh waits the hour.
            clock.Now += TimeSpan.FromDays(2); store.FetchAsync("hagezi-light", default).GetAwaiter().GetResult();
            Assert(Status().Error!.EndsWith($"Trying again at {(clock.Now + TimeSpan.FromHours(1)).ToLocalTime():HH:mm}.", StringComparison.Ordinal) && store.Names("hagezi-light")!.Blocks("example.com"));
        }));
        check("Enabled lists reach the kernel and the router's DNS filter, and downloads apply in place", () =>
        {
            var lists = new MemoryLists(); var router = new ServiceSelfTests.FakeRouter([]); var backend = new MemoryBackend();
            lists.Addresses["firehol-level1"] = ["198.51.100.0/24"];
            lists.Domains["hagezi-light"] = new([], ["ads.example.com", "cdn.jsdelivr.net"], []);
            using var coordinator = Coordinator(lists, backend, router);
            List<BlocklistSource> enabled = [new() { CatalogId = "hagezi-light", Name = "HaGeZi Multi Light" }, new() { CatalogId = "firehol-level1", Name = "FireHOL Level 1" }];
            Assert(coordinator.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, Blocklists = enabled })).Success);
            Assert(backend.Plan!.Filters.Count(f => f.Name == "FireHOL Level 1") == 2 && backend.Plan.Filters.Count(f => f.Name == "DNS filtering: unrouted server") == 4);
            // The Windows DNS client may ask only Darkwire's resolver, where the filter sees every lookup.
            Assert(backend.Plan.Filters.Count(DnsClient) == 12 && router.Context!.ResolvesSystemDns && router.Context.Tunnels is null);
            var names = router.Context!.Names!;
            Assert(names.Blocks("x.ads.example.com") && names.Blocks(BlocklistCatalog.Canary) && !names.Blocks("cdn.jsdelivr.net") && !names.Blocks("example.com"));
            Assert(lists.Requested.Order().SequenceEqual(["firehol-level1", "hagezi-light"]) && coordinator.EnabledBlocklists().Count == 2);
            var status = coordinator.Handle(new("blocklists")).Blocklists!;
            Assert(status.Single(s => s.Id == "hagezi-light").Enforced && status.Single(s => s.Id == "firehol-level1").Enforced && !status.Single(s => s.Id == "adaway").Enforced);
            lists.Addresses["firehol-level1"] = ["203.0.113.0/24"]; lists.Domains["hagezi-light"] = new([], ["tracker.example.net"], []); lists.Version++;
            coordinator.UpdateBlocklists();
            Assert(backend.Plan.Filters.Any(f => f.RemoteNetwork == "203.0.113.0/24") && backend.Plan.Filters.All(f => f.RemoteNetwork != "198.51.100.0/24"));
            Assert(router.Context!.Names!.Blocks("tracker.example.net") && !router.Context.Names.Blocks("ads.example.com"));
            Assert(coordinator.Handle(new("apply", new() { Mode = FirewallMode.Lockdown, Blocklists = enabled }, ExpectedRevision: 1)).Success && router.Context!.Names is null);
            Assert(!router.Context.ResolvesSystemDns && backend.Plan.Filters.All(f => !DnsClient(f)));
        });
        check("A downloaded network list that no longer fits stays out and is reported, keeping the plan", () =>
        {
            var lists = new MemoryLists(); var backend = new MemoryBackend();
            using var coordinator = Coordinator(lists, backend, new ServiceSelfTests.FakeRouter([]));
            Assert(coordinator.Handle(new("takeover", new() { Mode = FirewallMode.BlockNew, Blocklists = [new() { CatalogId = "firehol-level1", Name = "FireHOL Level 1" }] })).Success);
            // A network list alone leaves the Windows DNS client to core networking.
            Assert(backend.Plan!.Filters.All(f => !DnsClient(f)));
            lists.Addresses["firehol-level1"] = Enumerable.Range(0, 10_000).Select(i => $"203.{i / 256}.{i % 256}.1/32").ToArray(); lists.Version++;
            coordinator.UpdateBlocklists();
            Assert(backend.Plan!.Filters.All(f => f.Name != "FireHOL Level 1") && coordinator.Handle(new("status")).Status!.Alerts!.Any(a => a.Contains("FireHOL Level 1 is not enforced")));
        });
        check("Any user may ask for a catalog list ahead of enabling it, and only for a catalog list", () =>
        {
            var lists = new MemoryLists(); using var coordinator = Coordinator(lists, new MemoryBackend(), new ServiceSelfTests.FakeRouter([]));
            ServiceResponse Send(ServiceRequest request)
            {
                using var stream = new MemoryStream(); ServiceProtocol.WriteAsync(stream, request, default).GetAwaiter().GetResult();
                var at = stream.Length; stream.Position = 0;
                Assert(ControlPipe.HandleConnectionAsync(coordinator, stream, false, () => false, default).GetAwaiter().GetResult());
                stream.Position = at; return ServiceProtocol.ReadAsync<ServiceResponse>(stream, default).GetAwaiter().GetResult();
            }
            var reply = Send(new("preload-blocklist", BlocklistId: "oisd-small"));
            Assert(reply.Success && lists.Requested.SequenceEqual(["oisd-small"]) && reply.Blocklists?.Count == BlocklistCatalog.Entries.Count);
            Assert(!Send(new("preload-blocklist", BlocklistId: "https://example.com/list.txt")).Success && lists.Requested.Count == 1);
            Assert(Send(new("blocklists")).Blocklists?.Count == BlocklistCatalog.Entries.Count && !Send(new("restore")).Success);
        });
    }

    private static TakeoverCoordinator Coordinator(MemoryLists lists, MemoryBackend backend, ServiceSelfTests.FakeRouter router) =>
        new(new MemoryFirewall(), new MemoryJournal(), () => backend, protections: () => new Dictionary<string, int>(), createRouter: (_, _) => router, blocklists: lists,
            firewallArea: new ServiceSelfTests.FakeFirewallArea([]));

    private static void InTemporary(Action<string> test)
    {
        var root = Path.Combine(Path.GetTempPath(), "darkwire-lists-" + Guid.NewGuid().ToString("N"));
        try { test(root); } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private sealed class MemoryLists : IBlocklistStore
    {
        public readonly Dictionary<string, DomainFilter> Domains = [];
        public readonly Dictionary<string, IReadOnlyList<string>> Addresses = [];
        public readonly List<string> Requested = [];
        public long Version { get; set; }
        public DomainFilter? Names(string catalogId) => Domains.GetValueOrDefault(catalogId);
        public IReadOnlyList<string>? Networks(string catalogId) => Addresses.GetValueOrDefault(catalogId);
        public IReadOnlyList<BlocklistStatus> Status() => BlocklistCatalog.Entries.Select(e =>
            new BlocklistStatus(e.Id, Domains.TryGetValue(e.Id, out var names) ? names.Count : Addresses.GetValueOrDefault(e.Id)?.Count ?? 0, DateTimeOffset.UnixEpoch, false)).ToArray();
        public void Request(string catalogId, TimeSpan maximumAge) => Requested.Add(catalogId);
    }
    private sealed class MemoryBackend : IFilterBackend
    {
        public FilterPlan? Plan;
        public bool LearningEventsReady => true;
        public int FilterCount => Plan?.Filters.Count ?? 0;
        public void Apply(FilterPlan plan) => Plan = plan;
        public void RemoveOwnedFilters() => Plan = null;
        public IReadOnlyList<Connection> DrainBlockedConnections() => [];
        public void Dispose() { }
    }
    private sealed class MemoryFirewall : IWindowsFirewallControl
    {
        public FirewallSnapshot Read() => new([], new() { [1] = true, [2] = true, [4] = true }, []);
        public void Export(string path) { }
        public void SetProfiles(IReadOnlyDictionary<int, bool> profiles) { }
    }
    private sealed class MemoryJournal : IPolicyJournal
    {
        private ServiceJournal state = new();
        public ServiceJournal Read() => state;
        public void Write(ServiceJournal next) => state = next;
        public string BackupPath() => "test-only.wfw";
    }
}
