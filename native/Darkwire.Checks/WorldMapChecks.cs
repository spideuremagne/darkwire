using Darkwire.Host;
using System.Collections;

internal static class WorldMapChecks
{
    internal static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
        static int Vertices(WorldCountry country) => country.Polygons.Sum(p => p.Rings.Sum(r => r.Count));
        static bool Contains(IReadOnlyList<WorldMapPoint> ring, double longitude, double latitude)
        {
            var inside = false;
            for (int i = 0, j = ring.Count - 1; i < ring.Count; j = i++)
                if ((ring[i].Latitude > latitude) != (ring[j].Latitude > latitude) &&
                    longitude < (ring[j].Longitude - ring[i].Longitude) * (latitude - ring[i].Latitude) /
                    (ring[j].Latitude - ring[i].Latitude) + ring[i].Longitude) inside = !inside;
            return inside;
        }

        check("Bundled world map retains all detailed Natural Earth polygons and holes", () =>
        {
            var countries = WorldMapData.Countries; var polygons = countries.SelectMany(c => c.Polygons).ToArray();
            Expect(WorldMapData.SourceVersion == "5.1.2" && countries.Count == 242);
            Expect(polygons.Length == 1620 && polygons.Sum(p => p.Rings.Count) == 1632);
            Expect(polygons.Sum(p => p.Rings.Count - 1) == 12 && countries.Sum(Vertices) == 99613);
            Expect(countries.Select(c => c.SourceCode).Distinct(StringComparer.Ordinal).Count() == countries.Count);
        });
        check("Large-country coastlines retain real detail and country metadata", () =>
        {
            var countries = WorldMapData.Countries;
            Expect(Vertices(countries.Single(c => c.IsoCode == "CAN")) > 11000);
            Expect(Vertices(countries.Single(c => c.IsoCode == "USA")) > 5700);
            Expect(Vertices(countries.Single(c => c.IsoCode == "RUS")) > 7400);
            Expect(countries.Single(c => c.SourceCode == "FRA").IsoCode == "FRA");
            Expect(countries.Single(c => c.SourceCode == "KOS").IsoCode == "", "No unassigned ISO code should be invented");
        });
        check("Japan and Indonesia retain their island polygons", () =>
        {
            var japan = WorldMapData.Countries.Single(c => c.IsoCode == "JPN");
            var indonesia = WorldMapData.Countries.Single(c => c.IsoCode == "IDN");
            Expect(japan.Name == "Japan" && japan.Polygons.Count > 20 && Vertices(japan) > 1000);
            Expect(indonesia.Name == "Indonesia" && indonesia.Polygons.Count > 100 && Vertices(indonesia) > 2000);
            Expect(indonesia.Polygons.SelectMany(p => p.Rings[0]).Any(p => p.Longitude > 140));
        });
        check("South Africa keeps Lesotho as a hole instead of painting over it", () =>
        {
            var southAfrica = WorldMapData.Countries.Single(c => c.IsoCode == "ZAF");
            var lesotho = WorldMapData.Countries.Single(c => c.IsoCode == "LSO");
            Expect(southAfrica.Polygons.SelectMany(p => p.Rings.Skip(1)).Any(r => Contains(r, lesotho.LabelLongitude, lesotho.LabelLatitude)));
            Expect(lesotho.Polygons.Any(p => Contains(p.Rings[0], lesotho.LabelLongitude, lesotho.LabelLatitude)));
        });
        check("World map rings, labels, dateline edges and Antarctica remain valid", () =>
        {
            var antarctica = WorldMapData.Countries.Single(c => c.IsoCode == "ATA");
            Expect(antarctica.Polygons.Count == 108 && Vertices(antarctica) == 4923 && antarctica.MapColor13 == -99);
            Expect(antarctica.Polygons.SelectMany(p => p.Rings).SelectMany(r => r).Min(p => p.Latitude) < -89.9);
            foreach (var country in WorldMapData.Countries)
            {
                Expect(double.IsFinite(country.LabelLongitude) && country.LabelLongitude is >= -180 and <= 180);
                Expect(double.IsFinite(country.LabelLatitude) && country.LabelLatitude is >= -90 and <= 90);
                Expect(country.LabelRank is >= 0 and <= 10 && (country.MapColor13 == -99 || country.MapColor13 is >= 1 and <= 13));
                foreach (var ring in country.Polygons.SelectMany(p => p.Rings))
                {
                    Expect(ring.Count >= 4 && ring[0] == ring[^1], "Ring is not closed");
                    foreach (var point in ring)
                        Expect(double.IsFinite(point.Longitude) && double.IsFinite(point.Latitude) &&
                            point.Longitude is >= -180 and <= 180 && point.Latitude is >= -90 and <= 90);
                    for (var i = 1; i < ring.Count; i++)
                        Expect(Math.Abs(ring[i].Longitude - ring[i - 1].Longitude) <= 180, "The bundled source contains an unsplit dateline edge");
                }
            }
        });
        check("World map loads once and exposes immutable nested collections", () =>
        {
            var countries = WorldMapData.Countries;
            Expect(ReferenceEquals(countries, WorldMapData.Countries));
            IList[] collections = [(IList)countries, (IList)countries[0].Polygons,
                (IList)countries[0].Polygons[0].Rings, (IList)countries[0].Polygons[0].Rings[0]];
            foreach (var collection in collections)
            {
                Expect(collection.IsReadOnly);
                var rejected = false;
                try { collection.Clear(); } catch (NotSupportedException) { rejected = true; }
                Expect(rejected, "Map geometry can be modified by a consumer");
            }
        });
    }
}
