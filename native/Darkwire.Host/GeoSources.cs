using Darkwire.Engine;
using System.Collections.Concurrent;
using System.Globalization;

namespace Darkwire.Host;

public partial class MainWindow
{
    /// <summary>Written weekly by the service; every user can read it.</summary>
    internal static string SharedGeoPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Darkwire", "Shared", "geoip.dat");
    internal static string SharedCitiesPath => Path.Combine(Path.GetDirectoryName(SharedGeoPath)!, "geoip-city.dat");
    /// <summary>Installed with Darkwire, beside the service.</summary>
    internal static string BundledGeoPath => Path.Combine(AppContext.BaseDirectory, "Service", "Data", "geoip.dat");
    /// <summary>Installed beside the app, the only reader of city data.</summary>
    internal static string BundledCitiesPath => Path.Combine(AppContext.BaseDirectory, "Data", "geoip-city.dat");
    private (DateTime Data, DateTime Cities) geoStamp;
    private DateTime lastGeoCheck;
    private TextBlock? geoSource, geoUpdate;

    /// <summary>When the service last wrote each shared file.</summary>
    private static (DateTime Data, DateTime Cities) SharedGeoStamp() =>
        (File.Exists(SharedGeoPath) ? File.GetLastWriteTimeUtc(SharedGeoPath) : default, File.Exists(SharedCitiesPath) ? File.GetLastWriteTimeUtc(SharedCitiesPath) : default);

    /// <summary>
    /// GeoIP for lookups and the map: a database an earlier version imported, otherwise the newer of the service's update and the
    /// copy installed with Darkwire, with the newer of their city data. Loads off the UI thread.
    /// </summary>
    private async Task LoadGeoAsync()
    {
        try
        {
            var custom = state.GeoDatabasePath is { } path && File.Exists(path) ? path : null;
            var stamp = SharedGeoStamp();
            geo = await Task.Run<IGeoLookup?>(() =>
            {
                if (custom is not null) { using var reader = File.OpenText(custom); return GeoDatabase.Load(reader); }
                var database = GeoIpDatabase.Newest([SharedGeoPath, BundledGeoPath]);
                if (database is not null) { database.Locate = CountryPositions.Locate; database.Cities = GeoIpCities.Newest([SharedCitiesPath, BundledCitiesPath]); }
                return database;
            });
            geoStamp = stamp;
            if (geoSource is not null) geoSource.Text = GeoSourceText;
            await RefreshTelemetry();
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException) { ShowToast("GeoIP database: " + error.Message); }
    }

    /// <summary>The database in use, and a button that has the service check DB-IP now instead of at its weekly check.</summary>
    private UIElement GeoCard()
    {
        geoSource = Ui.Text(GeoSourceText, 20, "#E7DFF2", FontWeights.SemiBold);
        geoUpdate = Ui.Text(GeoUpdateText(serviceStatus?.GeoIp), 11, "#A599B3");
        var refresh = Ui.AsyncButton("Refresh", RefreshGeoAsync); refresh.IsEnabled = !demo;
        var buttons = Ui.Row(refresh);
        if (state.GeoDatabasePath is not null && !demo)
        {
            var automatic = Ui.Button("Use the automatic database", () => { state.GeoDatabasePath = null; geo = null; Save(); Navigate("Settings"); _ = LoadGeoAsync(); });
            automatic.Margin = new(10, 0, 0, 0); buttons.Children.Add(automatic);
        }
        return Ui.Card(Ui.Stack(Ui.Label("LOCAL GEOIP & ASN DATABASE"), Ui.Gap(12), geoSource, Ui.Gap(9),
            Ui.Text(state.GeoDatabasePath is null
                ? "Installed with Darkwire and refreshed weekly by the service. Its city data places connections on the map and in Connections. IP geolocation by DB-IP (db-ip.com), licensed CC BY 4.0."
                : "A database imported by an earlier version replaces the automatic one in this app. Service country and ASN restrictions use the automatic one.", 11, "#A599B3"),
            Ui.Gap(6), geoUpdate, Ui.Gap(12), buttons), 23);
    }

    /// <summary>Asks the service to check DB-IP, follows the check until it ends, then loads any release it published.</summary>
    private async Task RefreshGeoAsync()
    {
        if (demo) return;
        var response = await ServiceClient.SendAsync(new("refresh-geoip"));
        if (!response.Success) throw new InvalidOperationException(response.Message);
        for (var waited = 0; response.Status?.GeoIp is { Checking: true } && waited < 180; waited++)
        {
            if (geoUpdate is not null) geoUpdate.Text = GeoUpdateText(response.Status.GeoIp);
            await Task.Delay(1000);
            response = await ServiceClient.SendAsync(new("status"));
        }
        var update = response.Status?.GeoIp;
        if (geoUpdate is not null) geoUpdate.Text = GeoUpdateText(update);
        if (update is null || update.Checking) { ShowToast("DB-IP is still being checked. A new release loads when it is ready."); return; }
        // A check that failed may still have published part of a release, such as the country data without the city data.
        if (SharedGeoStamp() != geoStamp) await LoadGeoAsync();
        ShowToast(update.Outcome ?? "DB-IP was checked.");
    }

    private static string GeoUpdateText(GeoIpUpdateStatus? update) => update switch
    {
        null => "Refresh has the Darkwire service check DB-IP for a newer release now.",
        { Checking: true } => "Checking DB-IP for a newer release…",
        _ => string.Join(" ", new[] { update.Outcome, update.LastCheck is { } at ? $"Last checked {at.ToLocalTime():MMM d, HH:mm}." : null }.OfType<string>())
            is { Length: > 0 } text ? text : "The service checks DB-IP weekly."
    };

    /// <summary>Picks up the service's weekly update without a restart.</summary>
    private void CheckGeoUpdate()
    {
        if (demo || state.GeoDatabasePath is not null || DateTime.UtcNow - lastGeoCheck < TimeSpan.FromMinutes(5)) return;
        lastGeoCheck = DateTime.UtcNow;
        if (SharedGeoStamp() != geoStamp) _ = LoadGeoAsync();
    }

    private string GeoSourceText => geo switch
    {
        GeoIpDatabase { Cities: { } cities } database => $"DB-IP Lite {database.Release} · {database.Count + cities.Count:N0} ranges · {cities.Places:N0} cities" +
            (cities.Release == database.Release ? "" : $" from {cities.Release}"),
        GeoIpDatabase database => $"DB-IP Lite {database.Release} · {database.Count:N0} ranges",
        GeoDatabase database => $"Imported CSV · {database.Count:N0} networks",
        _ => "No database loaded"
    };
}

/// <summary>Map positions for GeoIP country codes, from the bundled Natural Earth label points.</summary>
internal static class CountryPositions
{
    private static readonly Lazy<Dictionary<string, (double Latitude, double Longitude)>> byCode = new(() =>
    {
        var map = new Dictionary<string, (double Latitude, double Longitude)>(StringComparer.Ordinal);
        foreach (var country in WorldMapData.Countries)
        {
            if (country.IsoCode.Length == 3) map.TryAdd(country.IsoCode, (country.LabelLatitude, country.LabelLongitude));
            map.TryAdd(country.SourceCode, (country.LabelLatitude, country.LabelLongitude));
        }
        return map;
    });
    private static readonly ConcurrentDictionary<string, (double Latitude, double Longitude)?> cache = new(StringComparer.Ordinal);

    public static (double Latitude, double Longitude)? Locate(string code) => cache.GetOrAdd(code, static alpha2 =>
    {
        // Natural Earth files Kosovo under its own identifier; RegionInfo knows the others.
        var alpha3 = alpha2 == "XK" ? "KOS" : null;
        if (alpha3 is null) try { alpha3 = new RegionInfo(alpha2).ThreeLetterISORegionName; } catch (ArgumentException) { }
        return alpha3 is not null && byCode.Value.TryGetValue(alpha3, out var position) ? position : null;
    });
}
