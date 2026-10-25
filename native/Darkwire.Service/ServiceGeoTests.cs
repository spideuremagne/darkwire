using Darkwire.Core;
using Darkwire.Engine;

namespace Darkwire.Service;

internal static class ServiceGeoTests
{
    public static void Run(Action<string, Action> check)
    {
        const string csv = "network,country,country_name,city,latitude,longitude,asn,organization\n203.0.113.0/24,US,United States,Seattle,47,-122,64496,Example\n";
        static void Assert(bool condition) { if (!condition) throw new Exception("Protected GeoIP invariant failed."); }
        // Takes over with a US restriction on the installed release 2026-09, publishes a weekly release to the shared folder before
        // offering it to the service, as the updater does, then restarts the service on the same files and journal.
        static (string Alert, FilterPlan? Recovered) RestartAfterWeekly(string root, GeoIpDatabase weekly)
        {
            var bundled = Path.Combine(root, "Data", "geoip.dat"); var shared = Path.Combine(root, "Shared", "geoip.dat");
            GeoStore Store() => new(Directory.CreateDirectory(Path.Combine(root, "Service")).FullName, shared, bundled);
            Write(bundled, Compact("2026-09", "203.0.113.0,203.0.113.255"));
            var journal = new MemoryJournal(); string alert;
            using (var coordinator = Coordinator(Store(), new MemoryBackend(), journal))
            {
                Assert(coordinator.Handle(new("takeover", new() { RouteConnections = false, Mode = FirewallMode.BlockNew, BlockedCountries = ["US"] })).Success);
                Write(shared, weekly); coordinator.UpdateGeo(weekly, weekly.Release);
                alert = coordinator.Handle(new("status")).Status!.Alerts!.First();
            }
            var restarted = new MemoryBackend();
            using (var coordinator = Coordinator(Store(), restarted, journal)) coordinator.Recover();
            Assert(journal.Read().Phase == "Active");
            return (alert, restarted.Plan);
        }
        check("Any user may ask the service to check for a GeoIP release now, and status shows the check", () =>
        {
            var updates = new FakeUpdates();
            using var coordinator = new TakeoverCoordinator(new MemoryFirewall(), new MemoryJournal(), () => new MemoryBackend(), protections: () => new Dictionary<string, int>(), geoUpdates: updates,
                firewallArea: new ServiceSelfTests.FakeFirewallArea([]));
            // Through the pipe every user may open.
            using var stream = new MemoryStream(); ServiceProtocol.WriteAsync(stream, new ServiceRequest("refresh-geoip"), default).GetAwaiter().GetResult();
            var at = stream.Length; stream.Position = 0;
            Assert(ControlPipe.HandleConnectionAsync(coordinator, stream, false, () => false, default).GetAwaiter().GetResult());
            stream.Position = at; var reply = ServiceProtocol.ReadAsync<ServiceResponse>(stream, default).GetAwaiter().GetResult();
            Assert(reply.Success && updates.Requests == 1 && reply.Status?.GeoIp is { Checking: true, Release: "2026-10" });
        });
        check("Service GeoIP bytes are validated before committing", () =>
        {
            var store = new MemoryGeo(); using var coordinator = Coordinator(store);
            Assert(coordinator.Handle(new("import-geo", GeoCsv: csv)).Success);
            Assert(store.Database?.Lookup("203.0.113.7")?.Country == "US");
            Assert(!coordinator.Handle(new("import-geo", GeoCsv: "bad,data")).Success);
            Assert(store.Database?.Lookup("203.0.113.7")?.Country == "US");
        });
        check("Service rejects geographic policy without protected data", () =>
        {
            using var coordinator = Coordinator(new MemoryGeo());
            Assert(!coordinator.Handle(new("takeover", new() { RouteConnections = false, Mode = FirewallMode.BlockNew, BlockedCountries = ["US"] })).Success);
        });
        check("Service compiles country restrictions from protected GeoIP", () =>
        {
            var backend = new MemoryBackend(); using var coordinator = Coordinator(new MemoryGeo(), backend);
            Assert(coordinator.Handle(new("import-geo", GeoCsv: csv)).Success);
            Assert(coordinator.Handle(new("takeover", new() { RouteConnections = false, Mode = FirewallMode.BlockNew, BlockedCountries = ["US"] })).Success);
            Assert(backend.Plan?.Filters.Count(f => f.RemoteNetwork == "203.0.113.0/24") == 2);
        });
        check("Service refuses GeoIP replacement while its filters are active", () =>
        {
            using var coordinator = Coordinator(new MemoryGeo());
            Assert(coordinator.Handle(new("takeover", new() { RouteConnections = false, Mode = FirewallMode.BlockNew })).Success);
            Assert(!coordinator.Handle(new("import-geo", GeoCsv: csv)).Success);
        });
        check("Weekly GeoIP data replaces active restriction filters, and never an imported database", () =>
        {
            var backend = new MemoryBackend(); var store = new MemoryGeo { Compact = Compact("2026-09", "203.0.113.0,203.0.113.255") };
            using var coordinator = Coordinator(store, backend);
            var policy = new AppState { RouteConnections = false, Mode = FirewallMode.BlockNew, BlockedCountries = ["US"] };
            Assert(coordinator.Handle(new("takeover", policy)).Success && backend.Plan?.Filters.Count(f => f.RemoteNetwork == "203.0.113.0/24") == 2);
            coordinator.UpdateGeo(Compact("2026-10", "198.51.100.0,198.51.100.255"), "2026-10");
            Assert(backend.Plan?.Filters.Count(f => f.RemoteNetwork == "198.51.100.0/24") == 2 && backend.Plan.Filters.All(f => f.RemoteNetwork != "203.0.113.0/24"));
            Assert(coordinator.Handle(new("restore")).Success && coordinator.Handle(new("import-geo", GeoCsv: csv)).Success);
            coordinator.UpdateGeo(Compact("2026-11", "192.0.2.0,192.0.2.255"), "2026-11");
            Assert(coordinator.Handle(new("takeover", policy)).Success);
            Assert(backend.Plan?.Filters.Any(f => f.RemoteNetwork == "203.0.113.0/24") == true && backend.Plan.Filters.All(f => f.RemoteNetwork != "192.0.2.0/24"));
        });
        check("A restarted service recovers with the GeoIP data it enforced, not a weekly release beyond the filter budget", () => InTemporary(root =>
        {
            var oversized = Compact("2026-10", Enumerable.Range(0, 10_000).Select(i => $"10.{i / 256}.{i % 256}.1,10.{i / 256}.{i % 256}.1").ToArray());
            var (alert, recovered) = RestartAfterWeekly(root, oversized);
            Assert(alert.Contains("2026-10 not applied") && recovered?.Filters.Count(f => f.RemoteNetwork == "203.0.113.0/24") == 2);
        }));
        check("A restarted service recovers with the weekly GeoIP release that applied", () => InTemporary(root =>
        {
            var (alert, recovered) = RestartAfterWeekly(root, Compact("2026-10", "198.51.100.0,198.51.100.255"));
            Assert(alert.Contains("updated to release 2026-10") && recovered?.Filters.Count(f => f.RemoteNetwork == "198.51.100.0/24") == 2 &&
                recovered.Filters.All(f => f.RemoteNetwork != "203.0.113.0/24"));
        }));
        check("Learning never prompts for an address blocked by the protected GeoIP policy", () =>
        {
            var backend = new MemoryBackend(); using var coordinator = Coordinator(new MemoryGeo(), backend);
            Assert(coordinator.Handle(new("import-geo", GeoCsv: csv)).Success);
            Assert(coordinator.Handle(new("takeover", new() { RouteConnections = false, Mode = FirewallMode.Learning, BlockedCountries = ["US"] })).Success);
            backend.Observed.Add(new("Browser", @"C:\Apps\browser.exe", 1, "203.0.113.7", 443, 50000, "TCP", TrafficDirection.Outbound));
            Assert(coordinator.Handle(new("pending")).Pending?.Count == 0);
        });
    }
    private static TakeoverCoordinator Coordinator(IGeoStore geo, MemoryBackend? backend = null, MemoryJournal? journal = null) =>
        new(new MemoryFirewall(), journal ?? new MemoryJournal(), () => backend ?? new(), geo, protections: () => new Dictionary<string, int>(), firewallArea: new ServiceSelfTests.FakeFirewallArea([]));
    /// <summary>A compact database placing each first,last range in the United States.</summary>
    private static GeoIpDatabase Compact(string release, params string[] ranges) =>
        GeoIpDatabase.Build(new StringReader(string.Concat(ranges.Select(r => r + ",US\n"))), new StringReader("192.0.2.0,192.0.2.255,64500,Example\n"), release);
    private static void Write(string path, GeoIpDatabase database)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var stream = File.Create(path); database.Write(stream);
    }
    private static void InTemporary(Action<string> test)
    {
        var root = Path.Combine(Path.GetTempPath(), "darkwire-service-geo-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try { test(root); } finally { Directory.Delete(root, true); }
    }
    private sealed class FakeUpdates : IGeoUpdates
    {
        public int Requests;
        public GeoIpUpdateStatus Status { get; private set; } = new("2026-10", null, false);
        public void Request() { Requests++; Status = Status with { Checking = true }; }
    }
    private sealed class MemoryGeo : IGeoStore
    {
        public GeoDatabase? Database;
        public IGeoLookup? Compact, Kept;
        public bool Imported => Database is not null;
        public IGeoLookup? Read() => Database ?? Kept ?? Compact;
        public GeoDatabase Save(string text) { var parsed = GeoDatabase.Load(new StringReader(text)); Database = parsed; return parsed; }
        public void Keep(GeoIpDatabase database) => Kept = database;
    }
    private sealed class MemoryBackend : IFilterBackend
    {
        public FilterPlan? Plan;
        public List<Connection> Observed = [];
        public bool LearningEventsReady => true;
        public int FilterCount => Plan?.Filters.Count ?? 0;
        public void Apply(FilterPlan plan) => Plan = plan;
        public void RemoveOwnedFilters() => Plan = null;
        public IReadOnlyList<Connection> DrainBlockedConnections() { var result = Observed.ToArray(); Observed.Clear(); return result; }
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
