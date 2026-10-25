using Darkwire.Core;
using Darkwire.Host;

/// <summary>Where the maps draw this PC: Settings first, then Windows' region and time zone, never anything online.</summary>
internal static class MapOriginChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Map origin invariant failed.") { if (!value) throw new Exception(reason); }
        check("The map origin follows Windows' region, narrowed by time zone where a country spans several", () =>
        {
            var state = new AppState();
            Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time") is { Latitude: 40.71, Longitude: -74.01, Label: "New York, United States", Source: "Windows region and time zone" });
            Expect(MapOrigin.Resolve(state, "CA", "Eastern Standard Time") is { Label: "Toronto, Canada" });
            var germany = MapOrigin.Resolve(state, "DE", "Eastern Standard Time");
            Expect(germany is { Label: "Germany", Source: "Windows region", Latitude: > 47 and < 55, Longitude: > 5 and < 15 }, "A time zone named another country's city.");
            Expect(MapOrigin.Resolve(state, "us", "Unknown Standard Time") is { Label: "United States", Source: "Windows region" });
            foreach (var unusable in new[] { "", "001", "ZZ", "U5" })
                Expect(MapOrigin.Resolve(state, unusable, "Eastern Standard Time") == MapOrigin.Default, "Unusable region " + unusable);
        });
        check("A country or exact position set in Settings wins, and an invalid position is ignored", () =>
        {
            var state = new AppState { MapOriginCountry = "FR" };
            Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time") is { Label: "France", Source: "set in Settings" });
            state.MapOriginLatitude = 52.37; state.MapOriginLongitude = 4.89;
            Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time") is { Latitude: 52.37, Longitude: 4.89, Label: "52.37, 4.89", Source: "set in Settings" });
            foreach (var (latitude, longitude) in new[] { (double.NaN, 4.89), (91.0, 4.89), (52.37, 181.0) })
            {
                state.MapOriginLatitude = latitude; state.MapOriginLongitude = longitude;
                Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time").Label == "France", "An invalid position was used.");
            }
        });
        check("The bundled GeoNames cities load, and are found by name start, then by contained text, without regard to case or accents", () =>
        {
            Expect(Cities.Count == 31_765 && Cities.In("nl") is { Count: 235 } dutch && dutch.Zip(dutch.Skip(1)).All(p => p.First.Population >= p.Second.Population),
                "The city list is not the bundled one, most populous first: " + Cities.Count);
            Expect(Cities.Suggest("NL", " amst") is [{ Name: "Amsterdam", Latitude: > 52.3 and < 52.4, Longitude: > 4.8 and < 5 }, ..]);
            Expect(Cities.Suggest("CH", "zurich").FirstOrDefault()?.Name == "Zürich" && Cities.Suggest("PL", "lodz").FirstOrDefault()?.Name == "Łódź" &&
                Cities.Suggest("BR", "SAO PAULO").FirstOrDefault()?.Name == "São Paulo", "Accents or case kept a city from being found.");
            var york = Cities.Suggest("US", "york").Select(c => c.Name).ToArray();
            Expect(york is ["York", "Yorkville", "New York City", ..], "Name starts did not come before contained text: " + string.Join(", ", york));
            Expect(Cities.Suggest("US", "springfield", 20).Count(c => c.Name == "Springfield") == 8 && Cities.Suggest("NL", "  ") is [] && Cities.In("ZZ") is []);
        });
        check("A city picked in Settings is named with its country, and the country it is searched in follows Settings, then Windows", () =>
        {
            var state = new AppState { MapOriginCountry = "NL", MapOriginCity = "Amsterdam", MapOriginLatitude = 52.374, MapOriginLongitude = 4.8897 };
            Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time") is { Label: "Amsterdam, Netherlands", Source: "set in Settings", Latitude: 52.374, Longitude: 4.8897 });
            state.MapOriginCity = null;
            Expect(MapOrigin.Resolve(state, "US", "Eastern Standard Time").Label == "52.374, 4.89", "A typed position was named as a city.");
            Expect(MapOrigin.HomeCountry(new AppState(), "de") == "DE" && MapOrigin.HomeCountry(new AppState { MapOriginCountry = "nl" }, "DE") == "NL" && MapOrigin.HomeCountry(new AppState(), "001") is null);
        });
        check("A pin is named after the city nearest it; the time zone suggests a city only where a country spans several", () =>
        {
            foreach (var (country, name) in new[] { ("NL", "Haarlem"), ("US", "Oakland"), ("AU", "Sydney"), ("JP", "Sapporo") })
            {
                var city = Cities.In(country).First(c => c.Name == name);
                Expect(Cities.Nearest(city.Latitude + .002, city.Longitude - .002) == city, name + " was not the city nearest a pin beside it.");
            }
            Expect(MapOrigin.ZoneCity("us", "Pacific Standard Time") == "Los Angeles" && MapOrigin.ZoneCity("CA", "Eastern Standard Time") == "Toronto" &&
                MapOrigin.ZoneCity("NL", "W. Europe Standard Time") is null && MapOrigin.ZoneCity("US", "Unknown Standard Time") is null);
            // Nothing has been asked yet in a new or older settings file.
            Expect(!new AppState().MapOriginAsked && !System.Text.Json.JsonSerializer.Deserialize<AppState>("{\"SchemaVersion\":1}")!.MapOriginAsked);
        });
        check("Map positions parse in decimal degrees, separated by a comma, semicolon or spaces", () =>
        {
            Expect(MapOrigin.TryParseCoordinates("40.71, -74.01", out var latitude, out var longitude) && latitude == 40.71 && longitude == -74.01);
            Expect(MapOrigin.TryParseCoordinates("-33.87;151.21", out _, out _) && MapOrigin.TryParseCoordinates(" 0 0 ", out _, out _));
            foreach (var bad in new[] { "", "40.71", "40,71 -74,01", "91, 0", "0, 181", "a, b", "1, 2, 3", "NaN, 0" })
                Expect(!MapOrigin.TryParseCoordinates(bad, out _, out _), "Accepted " + bad);
        });
    }
}
