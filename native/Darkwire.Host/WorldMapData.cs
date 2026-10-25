using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Darkwire.Host;

/// <summary>Unprojected WGS84 longitude and latitude, in degrees.</summary>
public readonly record struct WorldMapPoint(double Longitude, double Latitude);

public sealed class WorldPolygon
{
    /// <summary>The closed exterior ring followed by any closed interior holes.</summary>
    public IReadOnlyList<IReadOnlyList<WorldMapPoint>> Rings { get; }
    internal WorldPolygon(IReadOnlyList<IReadOnlyList<WorldMapPoint>> rings) => Rings = rings;
}

public sealed class WorldCountry
{
    public string Name { get; }
    /// <summary>ISO alpha-3 code, or an empty string where Natural Earth has no assigned code.</summary>
    public string IsoCode { get; }
    /// <summary>Natural Earth's ADM0_A3 identifier; includes territories without an ISO code.</summary>
    public string SourceCode { get; }
    public double LabelLongitude { get; }
    public double LabelLatitude { get; }
    public int LabelRank { get; }
    /// <summary>Natural Earth's 1..13 political-map palette index; -99 means unassigned.</summary>
    public int MapColor13 { get; }
    public IReadOnlyList<WorldPolygon> Polygons { get; }

    internal WorldCountry(string name, string isoCode, string sourceCode, double labelLongitude,
        double labelLatitude, int labelRank, int mapColor13, IReadOnlyList<WorldPolygon> polygons)
    {
        Name = name; IsoCode = isoCode; SourceCode = sourceCode;
        LabelLongitude = labelLongitude; LabelLatitude = labelLatitude;
        LabelRank = labelRank; MapColor13 = mapColor13; Polygons = polygons;
    }
}

/// <summary>Detailed, offline Natural Earth 1:50m country boundaries, including islands and holes.</summary>
public static class WorldMapData
{
    public const string SourceVersion = "5.1.2";
    public const string SourceSha256 = "3E458FC036AD0A66411F2C1E6CAC49C5D7BFB81CB1123BC513B22511A2B7FDEB";
    private static readonly Lazy<IReadOnlyList<WorldCountry>> countries = new(Load);
    public static IReadOnlyList<WorldCountry> Countries => countries.Value;

    private static IReadOnlyList<WorldCountry> Load()
    {
        using var stream = typeof(WorldMapData).Assembly.GetManifestResourceStream("Darkwire.WorldCountries.json")
            ?? throw new InvalidDataException("The bundled world map is missing.");
        return Read(stream);
    }

    internal static IReadOnlyList<WorldCountry> Read(Stream stream)
    {
        using var document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 16 });
        var root = document.RootElement;
        if (root.GetProperty("schemaVersion").GetInt32() != 1 || root.GetProperty("source").GetString() != "Natural Earth" ||
            root.GetProperty("version").GetString() != SourceVersion || root.GetProperty("sourceSha256").GetString() != SourceSha256)
            throw new InvalidDataException("The bundled world map has unsupported metadata.");
        var features = root.GetProperty("countries");
        if (features.GetArrayLength() is < 1 or > 500) throw new InvalidDataException("Invalid country count.");
        var result = new List<WorldCountry>(features.GetArrayLength());
        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        var totalVertices = 0;
        foreach (var feature in features.EnumerateArray())
        {
            var name = Text(feature, "name"); var isoCode = Text(feature, "isoCode", allowEmpty: true); var sourceCode = Text(feature, "sourceCode");
            if ((isoCode.Length != 0 && (isoCode.Length != 3 || isoCode.Any(c => c is < 'A' or > 'Z'))) || !identifiers.Add(sourceCode))
                throw new InvalidDataException("Invalid country identifier.");
            var labelLongitude = feature.GetProperty("labelLongitude").GetDouble(); var labelLatitude = feature.GetProperty("labelLatitude").GetDouble();
            ValidateCoordinate(labelLongitude, labelLatitude);
            var rank = feature.GetProperty("labelRank").GetInt32(); var color = feature.GetProperty("mapColor13").GetInt32();
            if (rank is < 0 or > 10 || (color != -99 && color is < 1 or > 13)) throw new InvalidDataException("Invalid map styling metadata.");
            var polygonElements = feature.GetProperty("polygons");
            if (polygonElements.GetArrayLength() is < 1 or > 10000) throw new InvalidDataException("Invalid polygon count.");
            var polygons = new List<WorldPolygon>(polygonElements.GetArrayLength());
            foreach (var polygon in polygonElements.EnumerateArray())
            {
                if (polygon.GetArrayLength() is < 1 or > 1000) throw new InvalidDataException("Invalid ring count.");
                var rings = new List<IReadOnlyList<WorldMapPoint>>(polygon.GetArrayLength());
                foreach (var ring in polygon.EnumerateArray())
                {
                    if (ring.GetArrayLength() is < 4 or > 100000) throw new InvalidDataException("Invalid ring size.");
                    totalVertices += ring.GetArrayLength();
                    if (totalVertices > 1_000_000) throw new InvalidDataException("The world map exceeds its coordinate budget.");
                    var points = new List<WorldMapPoint>(ring.GetArrayLength());
                    foreach (var coordinate in ring.EnumerateArray())
                    {
                        if (coordinate.GetArrayLength() != 2) throw new InvalidDataException("Invalid coordinate pair.");
                        var point = new WorldMapPoint(coordinate[0].GetDouble(), coordinate[1].GetDouble());
                        ValidateCoordinate(point.Longitude, point.Latitude);
                        if (points.Count > 0 && Math.Abs(points[^1].Longitude - point.Longitude) > 180 && !PolarEdge(points[^1], point))
                            throw new InvalidDataException("The world map contains an unsplit dateline edge.");
                        points.Add(point);
                    }
                    if (points[0] != points[^1]) throw new InvalidDataException("The world map contains an open ring.");
                    rings.Add(points.AsReadOnly());
                }
                polygons.Add(new(rings.AsReadOnly()));
            }
            result.Add(new(name, isoCode, sourceCode, labelLongitude, labelLatitude, rank, color, polygons.AsReadOnly()));
        }
        return result.AsReadOnly();
    }

    private static bool PolarEdge(WorldMapPoint from, WorldMapPoint to) =>
        from.Latitude == to.Latitude && Math.Abs(from.Latitude) > 89.9 && Math.Abs(from.Longitude) == 180 && Math.Abs(to.Longitude) == 180;

    private static string Text(JsonElement element, string name, bool allowEmpty = false)
    {
        var value = element.GetProperty(name).GetString();
        if (value is null || (!allowEmpty && string.IsNullOrWhiteSpace(value)) || value.Length > 160 || value.Any(char.IsControl))
            throw new InvalidDataException("Invalid country text.");
        return value;
    }

    private static void ValidateCoordinate(double longitude, double latitude)
    {
        if (!double.IsFinite(longitude) || !double.IsFinite(latitude) || longitude is < -180 or > 180 || latitude is < -90 or > 90)
            throw new InvalidDataException("The world map contains an invalid coordinate.");
    }
}
