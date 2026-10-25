using Darkwire.Core;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Darkwire.Service;

internal static class GeoUpdateTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
    private const string Country = "198.51.100.0,198.51.100.255,NL\n", Asn = "198.51.100.0,198.51.100.255,64501,\"Example, B.V.\"\n",
        City = "198.51.100.0,198.51.100.255,EU,NL,\"North Holland\",Amsterdam,52.374,4.88969\n";
    private static void Assert(bool condition, string reason = "GeoIP update invariant failed.") { if (!condition) throw new Exception(reason); }

    public static void Run(Action<string, Action> check)
    {
        check("The weekly GeoIP check falls back to last month's release and publishes it once, with its city data", () => InTemporary(root =>
        {
            var requests = 0; var clock = new Clock(new(2026, 11, 3, 8, 0, 0, TimeSpan.Zero));
            async Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            {
                requests++;
                if (uri.AbsolutePath.Contains("2026-11", StringComparison.Ordinal)) throw new HttpRequestException("Not published yet.", null, HttpStatusCode.NotFound);
                await Gzip(destination, Source(uri));
            }
            var updater = new GeoIpUpdater(Download, Path.Combine(root, "shared"), root, clock, path => Directory.CreateDirectory(path));
            var result = updater.CheckAsync("2026-09", "2026-09", CancellationToken.None).GetAwaiter().GetResult();
            Assert(result?.Release == "2026-10" && result.Lookup("198.51.100.7") is { Country: "NL", Asn: 64501, Organization: "Example, B.V." } && requests == 5);
            Assert(GeoIpUpdater.InstalledRelease(Path.Combine(root, "shared", "geoip.dat")) == "2026-10" && updater.Status.Outcome == "Downloaded DB-IP Lite 2026-10 with city data.");
            Assert(GeoIpCities.Newest([Path.Combine(root, "shared", "geoip-city.dat")]) is { Release: "2026-10" } cities && cities.Lookup("198.51.100.7") is { City: "Amsterdam", Region: "North Holland" },
                "The city data was not published.");
            clock.Now = clock.Now.AddDays(3);
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null && requests == 5, "A check ran before a week passed.");
            clock.Now = clock.Now.AddDays(5);
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null && requests == 7, "The weekly check did not look for the new month.");
        }));
        check("A failed GeoIP check keeps the current data and waits before retrying", () => InTemporary(root =>
        {
            var attempts = 0; var clock = new Clock(new(2026, 11, 20, 0, 0, 0, TimeSpan.Zero));
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation) { attempts++; throw new HttpRequestException("Offline."); }
            var updater = new GeoIpUpdater(Download, Path.Combine(root, "shared"), root, clock, path => Directory.CreateDirectory(path));
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null && attempts == 2);
            clock.Now = clock.Now.AddHours(2);
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null && attempts == 2, "A failed check was retried at once.");
            clock.Now = clock.Now.AddHours(5);
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null && attempts == 4 && !File.Exists(Path.Combine(root, "shared", "geoip.dat")));
        }));
        check("A malformed GeoIP release never replaces the shared data", () => InTemporary(root =>
        {
            var clock = new Clock(new(2026, 11, 20, 0, 0, 0, TimeSpan.Zero));
            Task Download(Uri uri, string destination, long limit, CancellationToken cancellation) => Gzip(destination, "not,a,range\n");
            var updater = new GeoIpUpdater(Download, Path.Combine(root, "shared"), root, clock, path => Directory.CreateDirectory(path));
            Assert(updater.CheckAsync("2026-10", "2026-10", CancellationToken.None).GetAwaiter().GetResult() is null &&
                !File.Exists(Path.Combine(root, "shared", "geoip.dat")) && !File.Exists(Path.Combine(root, "shared", "geoip-city.dat")));
        }));
        check("City data that fails is reported, never holds back the country data, and is tried again at the next weekly check", () => InTemporary(root =>
        {
            var requests = 0; var cityOffline = true; var clock = new Clock(new(2026, 11, 3, 8, 0, 0, TimeSpan.Zero));
            async Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            {
                requests++;
                if (cityOffline && uri.AbsolutePath.Contains("city", StringComparison.Ordinal)) throw new HttpRequestException("City offline.");
                if (uri.AbsolutePath.Contains("2026-11", StringComparison.Ordinal)) throw new HttpRequestException("Not published yet.", null, HttpStatusCode.NotFound);
                await Gzip(destination, Source(uri));
            }
            var shared = Path.Combine(root, "shared");
            var updater = new GeoIpUpdater(Download, shared, root, clock, path => Directory.CreateDirectory(path));
            Assert(updater.CheckAsync("2026-09", "2026-09", CancellationToken.None).GetAwaiter().GetResult()?.Release == "2026-10" && requests == 4);
            Assert(updater.Status is { Failed: true, Release: "2026-10", Outcome: "Downloaded DB-IP Lite 2026-10. The city data failed: City offline." } &&
                File.Exists(Path.Combine(shared, "geoip.dat")) && !File.Exists(Path.Combine(shared, "geoip-city.dat")));
            cityOffline = false; clock.Now = clock.Now.AddHours(7);
            Assert(updater.CheckAsync("2026-10", "2026-09", CancellationToken.None).GetAwaiter().GetResult() is null && requests == 4, "A city failure brought the check forward.");
            clock.Now = clock.Now.AddDays(7);
            Assert(updater.CheckAsync("2026-10", "2026-09", CancellationToken.None).GetAwaiter().GetResult() is null && requests == 7 &&
                updater.Status is { Failed: false, Outcome: "Downloaded DB-IP Lite city data 2026-10." } && GeoIpUpdater.InstalledCities(Path.Combine(shared, "geoip-city.dat")) == "2026-10");
        }));
        check("A requested GeoIP check skips the weekly schedule and the wait after a failure, runs at most once a minute, and reports how it ended", () => InTemporary(root =>
        {
            var requests = 0; var offline = false; var clock = new Clock(new(2026, 11, 3, 8, 0, 0, TimeSpan.Zero));
            async Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
            {
                requests++;
                if (offline) throw new HttpRequestException("Offline.");
                if (uri.AbsolutePath.Contains("2026-11", StringComparison.Ordinal)) throw new HttpRequestException("Not published yet.", null, HttpStatusCode.NotFound);
                await Gzip(destination, Source(uri));
            }
            var updater = new GeoIpUpdater(Download, Path.Combine(root, "shared"), root, clock, path => Directory.CreateDirectory(path));
            GeoIpDatabase? Requested(string installed) => updater.CheckAsync(installed, installed, CancellationToken.None, requested: true).GetAwaiter().GetResult();
            updater.Request();
            Assert(updater.Status.Checking && updater.WaitAsync(TimeSpan.Zero, CancellationToken.None).GetAwaiter().GetResult(), "The request did not wake the update loop.");
            Assert(Requested("2026-09")?.Release == "2026-10" && updater.Status is { Checking: false, Release: "2026-10", Outcome: "Downloaded DB-IP Lite 2026-10 with city data.", Failed: false });
            clock.Now = clock.Now.AddSeconds(30);
            Assert(Requested("2026-10") is null && requests == 5 && updater.Status.Outcome!.StartsWith("Checked less than a minute ago", StringComparison.Ordinal), "A request ran twice within a minute.");
            clock.Now = clock.Now.AddMinutes(2);
            Assert(Requested("2026-10") is null && requests == 7 && updater.Status.Outcome == "DB-IP Lite 2026-10 is the newest release.", "A request waited for the weekly schedule.");
            offline = true; clock.Now = clock.Now.AddMinutes(2);
            Assert(Requested("2026-10") is null && updater.Status is { Failed: true, Outcome: "The check failed: Offline." });
            offline = false; clock.Now = clock.Now.AddMinutes(2);
            Assert(Requested("2026-10") is null && requests == 11 && !updater.Status.Failed, "A request waited six hours after a failure.");
        }));
    }

    private static string Source(Uri uri) => uri.AbsolutePath.Contains("country", StringComparison.Ordinal) ? Country : uri.AbsolutePath.Contains("city", StringComparison.Ordinal) ? City : Asn;
    private static void InTemporary(Action<string> test)
    {
        var root = Path.Combine(Path.GetTempPath(), "darkwire-geo-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try { test(root); } finally { Directory.Delete(root, true); }
    }
    private static async Task Gzip(string destination, string text)
    {
        await using var file = File.Create(destination); await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
        await gzip.WriteAsync(Encoding.UTF8.GetBytes(text));
    }
}
