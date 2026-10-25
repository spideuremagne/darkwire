using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace Darkwire.Host;

/// <summary>A city from the bundled GeoNames list. Region is a lettered first-level code (a US state, say), or empty.</summary>
public sealed record CityPlace(string Country, string Name, string Ascii, string Region, double Latitude, double Longitude, int Population)
{
    internal string Key { get; init; } = "";
    internal string AsciiKey { get; init; } = "";
}

/// <summary>
/// GeoNames' cities of 15,000 people or more (CC BY 4.0), bundled so a city typed in Settings places this PC on the map with
/// nothing looked up online. Loaded and validated on first use; each country's cities come most populous first.
/// </summary>
public static class Cities
{
    public const string Attribution = "City data from GeoNames (geonames.org), licensed CC BY 4.0.";
    private const int MaximumCities = 200_000;
    private static readonly Lazy<Dictionary<string, CityPlace[]>> byCountry = new(Load);
    private static readonly Lazy<CityPlace[]> byPopulation = new(() => [.. byCountry.Value.Values.SelectMany(c => c).OrderByDescending(c => c.Population)]);

    public static int Count => byCountry.Value.Values.Sum(c => c.Length);

    /// <summary>Every city, most populous first; the maps name them as they zoom in.</summary>
    public static IReadOnlyList<CityPlace> ByPopulation => byPopulation.Value;

    public static IReadOnlyList<CityPlace> In(string country) => byCountry.Value.GetValueOrDefault(country.ToUpperInvariant()) ?? [];

    /// <summary>The country's cities whose name starts with the text, then those containing it, most populous first; case and accents are ignored.</summary>
    public static IReadOnlyList<CityPlace> Suggest(string country, string text, int limit = 8)
    {
        var key = Fold(text);
        if (key.Length == 0) return [];
        var cities = In(country);
        bool Starts(CityPlace c) => c.Key.StartsWith(key, StringComparison.Ordinal) || c.AsciiKey.StartsWith(key, StringComparison.Ordinal);
        bool Contains(CityPlace c) => c.Key.Contains(key, StringComparison.Ordinal) || c.AsciiKey.Contains(key, StringComparison.Ordinal);
        return [.. cities.Where(Starts).Concat(cities.Where(c => !Starts(c) && Contains(c))).Take(limit)];
    }

    /// <summary>The city nearest a position, by great-circle distance, which names a pin dropped on the map.</summary>
    public static CityPlace Nearest(double latitude, double longitude)
    {
        static double Radians(double degrees) => degrees * Math.PI / 180;
        var (lat, lon) = (Radians(latitude), Radians(longitude));
        // The haversine term alone orders places by distance.
        double Separation(CityPlace city)
        {
            var (cityLat, cityLon) = (Radians(city.Latitude), Radians(city.Longitude));
            var (northSouth, eastWest) = (Math.Sin((cityLat - lat) / 2), Math.Sin((cityLon - lon) / 2));
            return northSouth * northSouth + Math.Cos(lat) * Math.Cos(cityLat) * eastWest * eastWest;
        }
        return ByPopulation.MinBy(Separation) ?? throw new InvalidDataException("The city list is empty.");
    }

    /// <summary>Upper case without accents, so "zurich" finds Zürich and "sao paulo" São Paulo.</summary>
    public static string Fold(string text)
    {
        var folded = new StringBuilder(text.Length);
        foreach (var c in text.Trim().Normalize(NormalizationForm.FormD))
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) folded.Append(char.ToUpperInvariant(c));
        return folded.ToString().Normalize(NormalizationForm.FormC);
    }

    private static Dictionary<string, CityPlace[]> Load()
    {
        using var stream = typeof(Cities).Assembly.GetManifestResourceStream("Darkwire.Cities.tsv.gz") ?? throw new InvalidDataException("The city list is missing.");
        using var reader = new StreamReader(new GZipStream(stream, CompressionMode.Decompress), new UTF8Encoding(false, true));
        if (reader.ReadLine() is not { } header || !header.StartsWith("#darkwire-cities 1\t", StringComparison.Ordinal)) throw new InvalidDataException("Not a Darkwire city list.");
        var cities = new Dictionary<string, List<CityPlace>>(StringComparer.Ordinal);
        var count = 0;
        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0) continue;
            var f = line.Split('\t');
            if (++count > MaximumCities || f.Length != 7 || f[0].Length != 2 || !f[0].All(char.IsAsciiLetterUpper) || f[1].Length is 0 or > 200 ||
                !double.TryParse(f[4], NumberStyles.Float, CultureInfo.InvariantCulture, out var latitude) || !double.TryParse(f[5], NumberStyles.Float, CultureInfo.InvariantCulture, out var longitude) ||
                !int.TryParse(f[6], NumberStyles.None, CultureInfo.InvariantCulture, out var population) || !double.IsFinite(latitude) || !double.IsFinite(longitude) ||
                Math.Abs(latitude) > 90 || Math.Abs(longitude) > 180)
                throw new InvalidDataException($"City list line {count + 1} is malformed.");
            if (!cities.TryGetValue(f[0], out var list)) cities[f[0]] = list = [];
            list.Add(new(f[0], f[1], f[2], f[3], latitude, longitude, population) { Key = Fold(f[1]), AsciiKey = f[2].Length > 0 ? Fold(f[2]) : "" });
        }
        return cities.ToDictionary(p => p.Key, p => p.Value.ToArray(), StringComparer.Ordinal);
    }
}
