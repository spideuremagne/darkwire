using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Darkwire.Host;

/// <summary>Where the map draws this PC, what that place is called, and where that came from.</summary>
public sealed record MapPlace(double Latitude, double Longitude, string Label, string Source);

/// <summary>
/// Places this PC on the map without asking anything online: a position or country set in Settings, else Windows' own
/// "Country or region" setting, narrowed to a city by the time zone in countries that span several.
/// </summary>
public static class MapOrigin
{
    /// <summary>The fallback anchor, used for demos and when Windows names no country.</summary>
    public static readonly MapPlace Default = new(37.77, -122.42, "San Francisco", "default");

    // Windows time zone IDs to a representative city, for countries with several zones; a zone shared by two countries names one city in each.
    private static readonly Dictionary<(string Zone, string Country), (double Latitude, double Longitude, string City)> ZoneCities = new()
    {
        [("Eastern Standard Time", "US")] = (40.71, -74.01, "New York"), [("Eastern Standard Time", "CA")] = (43.65, -79.38, "Toronto"),
        [("US Eastern Standard Time", "US")] = (39.77, -86.16, "Indianapolis"),
        [("Central Standard Time", "US")] = (41.88, -87.63, "Chicago"), [("Central Standard Time", "CA")] = (49.90, -97.14, "Winnipeg"),
        [("Mountain Standard Time", "US")] = (39.74, -104.99, "Denver"), [("Mountain Standard Time", "CA")] = (51.05, -114.07, "Calgary"),
        [("US Mountain Standard Time", "US")] = (33.45, -112.07, "Phoenix"),
        [("Pacific Standard Time", "US")] = (34.05, -118.24, "Los Angeles"), [("Pacific Standard Time", "CA")] = (49.28, -123.12, "Vancouver"),
        [("Alaskan Standard Time", "US")] = (61.22, -149.90, "Anchorage"), [("Hawaiian Standard Time", "US")] = (21.31, -157.86, "Honolulu"),
        [("Atlantic Standard Time", "CA")] = (44.65, -63.58, "Halifax"), [("Newfoundland Standard Time", "CA")] = (47.56, -52.71, "St. John's"),
        [("Canada Central Standard Time", "CA")] = (50.45, -104.62, "Regina"),
        [("AUS Eastern Standard Time", "AU")] = (-33.87, 151.21, "Sydney"), [("E. Australia Standard Time", "AU")] = (-27.47, 153.03, "Brisbane"),
        [("Cen. Australia Standard Time", "AU")] = (-34.93, 138.60, "Adelaide"), [("AUS Central Standard Time", "AU")] = (-12.46, 130.84, "Darwin"),
        [("W. Australia Standard Time", "AU")] = (-31.95, 115.86, "Perth"), [("Tasmania Standard Time", "AU")] = (-42.88, 147.33, "Hobart"),
        [("Kaliningrad Standard Time", "RU")] = (54.71, 20.51, "Kaliningrad"), [("Russian Standard Time", "RU")] = (55.76, 37.62, "Moscow"),
        [("Ekaterinburg Standard Time", "RU")] = (56.84, 60.61, "Yekaterinburg"), [("N. Central Asia Standard Time", "RU")] = (55.01, 82.93, "Novosibirsk"),
        [("North Asia Standard Time", "RU")] = (56.01, 92.85, "Krasnoyarsk"), [("North Asia East Standard Time", "RU")] = (52.29, 104.30, "Irkutsk"),
        [("Vladivostok Standard Time", "RU")] = (43.12, 131.89, "Vladivostok"),
        [("E. South America Standard Time", "BR")] = (-23.55, -46.63, "São Paulo"), [("SA Eastern Standard Time", "BR")] = (-3.73, -38.53, "Fortaleza"),
        [("Central Brazilian Standard Time", "BR")] = (-15.60, -56.10, "Cuiabá"), [("SA Western Standard Time", "BR")] = (-3.12, -60.02, "Manaus"),
        [("Central Standard Time (Mexico)", "MX")] = (19.43, -99.13, "Mexico City"), [("Eastern Standard Time (Mexico)", "MX")] = (21.16, -86.85, "Cancún"),
        [("Mountain Standard Time (Mexico)", "MX")] = (28.63, -106.07, "Chihuahua"), [("Pacific Standard Time (Mexico)", "MX")] = (32.51, -117.04, "Tijuana"),
    };

    /// <param name="windowsCountry">Windows' "Country or region" (ISO 3166 alpha-2); read from the system when not given.</param>
    /// <param name="timeZone">A Windows time zone ID; the local one when not given.</param>
    public static MapPlace Resolve(AppState state, string? windowsCountry = null, string? timeZone = null)
    {
        if (state.MapOriginLatitude is double latitude && state.MapOriginLongitude is double longitude && Valid(latitude, longitude))
        {
            // A city picked in Settings is named with its country; a typed position by its coordinates.
            var label = state.MapOriginCity is { Length: > 0 and <= 200 } city
                ? Country(state.MapOriginCountry) is { } country ? $"{city}, {CountryName(country)}" : city
                : string.Create(CultureInfo.InvariantCulture, $"{latitude:0.###}, {longitude:0.###}");
            return new(latitude, longitude, label, "set in Settings");
        }
        if (Country(state.MapOriginCountry) is { } chosen && CountryPositions.Locate(chosen) is { } position)
            return new(position.Latitude, position.Longitude, CountryName(chosen), "set in Settings");
        if (Country(windowsCountry ?? WindowsCountry()) is not { } region || CountryPositions.Locate(region) is not { } center) return Default;
        if (ZoneCities.TryGetValue((timeZone ?? TimeZoneInfo.Local.Id, region), out var zoneCity))
            return new(zoneCity.Latitude, zoneCity.Longitude, $"{zoneCity.City}, {CountryName(region)}", "Windows region and time zone");
        return new(center.Latitude, center.Longitude, CountryName(region), "Windows region");
    }

    /// <summary>The country map routes start in: the one chosen in Settings, else Windows' region; null when neither names one.</summary>
    public static string? HomeCountry(AppState state, string? windowsCountry = null) => Country(state.MapOriginCountry) ?? Country(windowsCountry ?? WindowsCountry());

    /// <summary>The city the time zone points to in a country spanning several; null elsewhere.</summary>
    public static string? ZoneCity(string country, string? timeZone = null) =>
        ZoneCities.TryGetValue((timeZone ?? TimeZoneInfo.Local.Id, country.ToUpperInvariant()), out var city) ? city.City : null;

    /// <summary>"40.71, -74.01" (or with a semicolon or spaces between), in decimal degrees.</summary>
    public static bool TryParseCoordinates(string text, out double latitude, out double longitude)
    {
        latitude = longitude = double.NaN;
        var parts = text.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 2 && double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out latitude) &&
            double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out longitude) && Valid(latitude, longitude);
    }

    private static bool Valid(double latitude, double longitude) =>
        double.IsFinite(latitude) && double.IsFinite(longitude) && latitude is >= -90 and <= 90 && longitude is >= -180 and <= 180;

    private static string? Country(string? code) => code is { Length: 2 } && code.All(char.IsAsciiLetter) ? code.ToUpperInvariant() : null;

    public static string CountryName(string code)
    {
        try { return new RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return code; }
    }

    /// <summary>Windows' "Country or region" setting, else the region of the user's formats; null when it names no country.</summary>
    private static string? WindowsCountry()
    {
        try
        {
            var name = new StringBuilder(16);
            if (GetUserDefaultGeoName(name, name.Capacity) > 0 && Country(name.ToString()) is { } home) return home;
        }
        catch (EntryPointNotFoundException) { }
        try { return Country(RegionInfo.CurrentRegion.TwoLetterISORegionName); }
        catch (ArgumentException) { return null; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern int GetUserDefaultGeoName(StringBuilder name, int size);
}
