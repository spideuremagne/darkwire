using Darkwire.Core;
using Darkwire.Engine;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Runtime;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;

namespace Darkwire.Service;

/// <summary>The service's GeoIP update checks, as the control pipe sees them.</summary>
public interface IGeoUpdates
{
    GeoIpUpdateStatus Status { get; }
    /// <summary>Asks for a check now, outside the weekly schedule.</summary>
    void Request();
}

/// <summary>
/// Checks DB-IP once a week for a newer Lite release, which DB-IP publishes monthly, and rebuilds the compact database from it,
/// and the city data the desktop app shows. The results go to a folder every user can read but only SYSTEM and administrators
/// can change, where the desktop app reads them. The desktop app can also ask for a check at once, which runs at most once a minute.
/// </summary>
internal sealed class GeoIpUpdater(Func<Uri, string, long, CancellationToken, Task> download, string sharedDirectory, string stateDirectory, TimeProvider clock,
    Action<string>? prepareShared = null) : IGeoUpdates
{
    public static string SharedDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Darkwire", "Shared");
    public static string SharedPath => Path.Combine(SharedDirectory, "geoip.dat");
    public static string BundledPath => Path.Combine(AppContext.BaseDirectory, "Data", "geoip.dat");
    /// <summary>City data, which only the desktop app reads; the service enforces with the country data.</summary>
    public static string SharedCitiesPath => Path.Combine(SharedDirectory, "geoip-city.dat");
    /// <summary>Installed beside the app, outside the service files whose integrity the service checks every 30 seconds.</summary>
    public static string BundledCitiesPath => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Data", "geoip-city.dat"));
    private static readonly TimeSpan Interval = TimeSpan.FromDays(7), RetryAfterFailure = TimeSpan.FromHours(6), RequestSpacing = TimeSpan.FromMinutes(1);
    // DB-IP's 2026-10 City Lite release is 86 MB, 693 MB expanded.
    private const long MaximumDownload = 64L * 1024 * 1024, MaximumExpanded = 256L * 1024 * 1024, MaximumCityDownload = 256L * 1024 * 1024,
        MaximumCityExpanded = 2L * 1024 * 1024 * 1024;
    private sealed record Schedule(DateTimeOffset? LastCheck, DateTimeOffset? LastFailure);
    private string SchedulePath => Path.Combine(stateDirectory, "geoip-update.json");
    private readonly object gate = new();
    private readonly SemaphoreSlim requests = new(0, 1);
    private GeoIpUpdateStatus status = new(null, null, false);

    public GeoIpUpdateStatus Status { get { lock (gate) return status; } }

    public void Request()
    {
        lock (gate)
        {
            status = status with { Checking = true, Outcome = null, Failed = false };
            if (requests.CurrentCount == 0) requests.Release();
        }
    }

    /// <summary>Waits for the next scheduled look or a request; true when a check was asked for.</summary>
    public Task<bool> WaitAsync(TimeSpan period, CancellationToken cancellation) => requests.WaitAsync(period, cancellation);

    /// <summary>The newest release installed or already downloaded, or null when there is none.</summary>
    public static string? InstalledRelease(params string[] paths) => Installed(GeoIpDatabase.ReadRelease, paths);
    /// <summary>The newest city data release installed or already downloaded, or null when there is none.</summary>
    public static string? InstalledCities(params string[] paths) => Installed(GeoIpCities.ReadRelease, paths);

    private static string? Installed(Func<Stream, string> readRelease, string[] paths)
    {
        string? newest = null;
        foreach (var path in paths.Where(File.Exists))
        {
            try
            {
                using var stream = File.OpenRead(path); var release = readRelease(stream);
                if (newest is null || string.CompareOrdinal(release, newest) > 0) newest = release;
            }
            catch (Exception error) when (error is InvalidDataException or IOException) { }
        }
        return newest;
    }

    /// <summary>
    /// Returns a newer database when one was published; null when no check is due, nothing is newer, or the attempt failed.
    /// Newer city data is published for the app along the way; a city download that fails is reported and tried again at the
    /// next check, without holding back the country data. A requested check skips the weekly schedule and the wait after a
    /// failure, but runs at most once a minute.
    /// </summary>
    public async Task<GeoIpDatabase?> CheckAsync(string? installedRelease, string? installedCities, CancellationToken cancellation, bool requested = false)
    {
        var schedule = ReadSchedule(); var now = clock.GetUtcNow();
        var latest = new[] { schedule.LastCheck, schedule.LastFailure }.Max();
        if (requested && now - latest < RequestSpacing) { Report(installedRelease, schedule.LastCheck, "Checked less than a minute ago. " + Newest(installedRelease)); return null; }
        if (!requested && (schedule.LastCheck is { } checkedAt && now - checkedAt < Interval || schedule.LastFailure is { } failedAt && now - failedAt < RetryAfterFailure)) return null;
        var (outcome, failed) = ("The check stopped early.", true);
        try
        {
            // City data goes first, so nothing comes between publishing country data and handing it to the service.
            string? cities = null, cityFailure = null;
            try { cities = await UpdateCitiesAsync(now, installedCities, cancellation).ConfigureAwait(false); }
            catch (Exception error) when (Failure(error, cancellation)) { cityFailure = error.Message; ServiceHost.Log("GeoIP city update failed: " + error.Message); }
            var result = await NewestAsync(now, installedRelease, FetchAsync, cancellation).ConfigureAwait(false);
            if (result is not null) { Publish("geoip.dat", result.Write); installedRelease = result.Release; }
            WriteSchedule(new(now, null)); schedule = new(now, null);
            (outcome, failed) = cityFailure is null ? (Downloaded(result?.Release, cities) ?? Newest(installedRelease), false)
                : ((result is null ? Newest(installedRelease) : $"Downloaded DB-IP Lite {result.Release}.") + " The city data failed: " + cityFailure, true);
            return result;
        }
        catch (Exception error) when (Failure(error, cancellation))
        {
            WriteSchedule(schedule with { LastFailure = now }); ServiceHost.Log("GeoIP update failed: " + error.Message);
            outcome = "The check failed: " + error.Message;
            return null;
        }
        finally { Report(installedRelease, schedule.LastCheck, outcome, failed); }
    }

    /// <summary>A download or conversion that failed, or timed out; the service stopping is not a failure.</summary>
    private static bool Failure(Exception error, CancellationToken cancellation) =>
        error is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException ||
        error is OperationCanceledException && !cancellation.IsCancellationRequested;

    /// <summary>A month's release appears during that month; until then the previous month's is the newest.</summary>
    private static async Task<T?> NewestAsync<T>(DateTimeOffset now, string? installed, Func<string, CancellationToken, Task<T?>> fetch, CancellationToken cancellation)
        where T : class
    {
        foreach (var month in new[] { now, now.AddMonths(-1) })
        {
            var release = month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            if (installed is not null && string.CompareOrdinal(release, installed) <= 0) break;
            if (await fetch(release, cancellation).ConfigureAwait(false) is { } found) return found;
        }
        return null;
    }

    /// <summary>Publishes newer city data for the app; returns its release, or null when there was none.</summary>
    private async Task<string?> UpdateCitiesAsync(DateTimeOffset now, string? installed, CancellationToken cancellation)
    {
        var cities = await NewestAsync(now, installed, FetchCitiesAsync, cancellation).ConfigureAwait(false);
        if (cities is null) return null;
        Publish("geoip-city.dat", cities.Write);
        var release = cities.Release; cities = null;
        // Building city data holds a few hundred MB for a moment; give that back rather than keep the service's heap at its peak.
        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce; GC.Collect();
        return release;
    }

    private static string? Downloaded(string? release, string? cities) => (release, cities) switch
    {
        (null, null) => null,
        (null, _) => $"Downloaded DB-IP Lite city data {cities}.",
        (_, null) => $"Downloaded DB-IP Lite {release}.",
        _ when release == cities => $"Downloaded DB-IP Lite {release} with city data.",
        _ => $"Downloaded DB-IP Lite {release} and city data {cities}."
    };

    private static string Newest(string? release) => release is null ? "DB-IP published no release Darkwire could use." : $"DB-IP Lite {release} is the newest release.";

    private void Report(string? release, DateTimeOffset? lastCheck, string outcome, bool failed = false)
    {
        lock (gate) status = new(release, lastCheck, false, outcome, failed);
    }

    private async Task<GeoIpDatabase?> FetchAsync(string release, CancellationToken cancellation)
    {
        var country = Path.Combine(stateDirectory, "geoip-country-" + Guid.NewGuid().ToString("N") + ".tmp");
        var asn = Path.Combine(stateDirectory, "geoip-asn-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            try
            {
                await download(new($"https://download.db-ip.com/free/dbip-country-lite-{release}.csv.gz"), country, MaximumDownload, cancellation).ConfigureAwait(false);
                await download(new($"https://download.db-ip.com/free/dbip-asn-lite-{release}.csv.gz"), asn, MaximumDownload, cancellation).ConfigureAwait(false);
            }
            catch (HttpRequestException error) when (error.StatusCode == HttpStatusCode.NotFound) { return null; }
            using var countryReader = Expand(country, MaximumExpanded); using var asnReader = Expand(asn, MaximumExpanded);
            return GeoIpDatabase.Build(countryReader, asnReader, release);
        }
        finally { File.Delete(country); File.Delete(asn); }
    }

    private async Task<GeoIpCities?> FetchCitiesAsync(string release, CancellationToken cancellation)
    {
        var city = Path.Combine(stateDirectory, "geoip-city-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            try { await download(new($"https://download.db-ip.com/free/dbip-city-lite-{release}.csv.gz"), city, MaximumCityDownload, cancellation).ConfigureAwait(false); }
            catch (HttpRequestException error) when (error.StatusCode == HttpStatusCode.NotFound) { return null; }
            using var reader = Expand(city, MaximumCityExpanded);
            return GeoIpCities.Build(reader, release);
        }
        finally { File.Delete(city); }
    }

    private static StreamReader Expand(string path, long limit) =>
        new(new LimitedStream(new GZipStream(File.OpenRead(path), CompressionMode.Decompress), limit), Encoding.UTF8);

    /// <summary>Replaces a shared file in one move, so readers see the old file or the new one.</summary>
    private void Publish(string name, Action<Stream> write)
    {
        (prepareShared ?? PrepareShared)(sharedDirectory);
        var temporary = Path.Combine(sharedDirectory, "geoip-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.WriteThrough))
            { write(stream); stream.Flush(true); }
            File.Move(temporary, Path.Combine(sharedDirectory, name), true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    /// <summary>Readable by every user, writable only by SYSTEM and administrators; an existing folder must already be protected.</summary>
    internal static void PrepareShared(string path)
    {
        var directory = new DirectoryInfo(path);
        ProtectedStorage.CheckParents(directory.Parent!.FullName);
        if (!directory.Exists)
        {
            var security = new DirectorySecurity(); security.SetSecurityDescriptorSddlForm(ServiceSetup.ProgramDirectorySddl);
            directory.Create(security);
            return;
        }
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("The shared data folder is a reparse point.");
        ProtectedStorage.VerifyAcl(directory.GetAccessControl());
    }

    private Schedule ReadSchedule()
    {
        try { return File.Exists(SchedulePath) && new FileInfo(SchedulePath).Length < 4096 ? JsonSerializer.Deserialize<Schedule>(File.ReadAllText(SchedulePath)) ?? new(null, null) : new(null, null); }
        catch (JsonException) { return new(null, null); }
    }
    private void WriteSchedule(Schedule schedule) => File.WriteAllText(SchedulePath, JsonSerializer.Serialize(schedule));
}
