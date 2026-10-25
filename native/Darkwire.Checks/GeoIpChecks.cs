using Darkwire.Core;

internal static class GeoIpChecks
{
    private const string Countries = "0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n1.0.4.0,1.0.7.255,AU\n8.8.8.0,8.8.8.255,US\n" +
        "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE\n";
    private const string Asns = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n8.8.8.0,8.8.8.255,15169,Google LLC\n2001:db8::,2001:db8::ffff,64500,\"Example \"\"Quoted\"\" Org\"\n";
    // DB-IP City Lite rows: reserved space, one place with two positions (the majority's wins), a quoted name with a comma,
    // a range naming no place, gaps, and IPv6 ranges starting inside a /64 (the last of them takes the next /64).
    private const string Cities = "0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0\n" +
        "1.0.0.0,1.0.0.255,OC,AU,Queensland,\"South Brisbane\",-27.4767,153.017\n1.0.1.0,1.0.1.255,OC,AU,Queensland,\"South Brisbane\",-27.48,153.02\n" +
        "1.0.2.0,1.0.3.255,AS,CN,Fujian,Wenquan,26.0998,119.297\n1.0.4.0,1.0.7.255,OC,AU,Queensland,\"South Brisbane\",-27.4767,153.017\n" +
        "8.8.4.0,8.8.4.255,NA,US,\"District of Columbia\",\"Washington, D.C.\",38.9072,-77.0369\n" +
        "8.8.8.0,8.8.8.255,NA,US,California,\"Mountain View\",37.4223,-122.085\n8.8.9.0,8.8.9.255,NA,US,,,37.751,-97.822\n" +
        "2001:db8::,2001:db8::ffff,EU,DE,Hesse,\"Frankfurt am Main\",50.1109,8.68213\n2001:db8::1:0,2001:db8::1:ffff,EU,DE,Bavaria,Munich,48.1374,11.5755\n" +
        "2001:db8::2:0,2001:db8:0:5:ffff:ffff:ffff:ffff,EU,DE,Berlin,Berlin,52.52,13.405\n2001:db8:0:6::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,EU,DE,Hamburg,Hamburg,53.5511,9.99371\n";
    private static void Expect(bool value, string message = "GeoIP invariant failed.") { if (!value) throw new Exception(message); }
    private static GeoIpDatabase Build(string countries = Countries, string asns = Asns) => GeoIpDatabase.Build(new StringReader(countries), new StringReader(asns), "2026-10");
    private static GeoIpCities BuildCities(string cities = Cities) => GeoIpCities.Build(new StringReader(cities), "2026-10");
    private static bool Near(double value, double expected) => Math.Abs(value - expected) < 1e-4;

    public static void Run(Action<string, Action> check)
    {
        check("DB-IP ranges resolve countries and ASNs, with gaps and reserved space unknown", () =>
        {
            var db = Build();
            Expect(db.Lookup("1.0.0.1") is { Country: "AU", Asn: 13335, Organization: "Cloudflare, Inc." } au && au.CountryName == "Australia");
            Expect(db.Lookup("1.0.2.3") is { Country: "CN", Asn: 0 });
            Expect(db.Lookup("8.8.8.8") is { Country: "US", Asn: 15169 } && db.Lookup("::ffff:8.8.8.8")?.Country == "US");
            Expect(db.Lookup("2001:db8::1") is { Country: "DE", Asn: 64500, Organization: "Example \"Quoted\" Org" } && db.Lookup("2001:db8:1::1") is { Country: "DE", Asn: 0 });
            Expect(db.Lookup("1.0.8.1") is null && db.Lookup("0.0.0.5") is null && db.Lookup("255.255.255.255") is null && db.Lookup("not an address") is null);
            Expect(double.IsNaN(db.Lookup("1.0.0.1")!.Latitude), "Coordinates appeared without a locator.");
            db.Locate = code => code == "AU" ? (-25, 134) : null;
            Expect(db.Lookup("1.0.0.1") is { Latitude: -25, Longitude: 134 } && double.IsNaN(db.Lookup("8.8.8.8")!.Latitude));
        });
        check("GeoIP database files round-trip and reject damage", () =>
        {
            using var stream = new MemoryStream(); Build().Write(stream);
            stream.Position = 0; Expect(GeoIpDatabase.ReadRelease(stream) == "2026-10");
            stream.Position = 0; var read = GeoIpDatabase.Read(stream);
            Expect(read.Release == "2026-10" && read.Count == Build().Count && read.Lookup("8.8.8.8")?.Organization == "Google LLC");
            var bytes = stream.ToArray();
            static void Rejects(byte[] data) { try { GeoIpDatabase.Read(new MemoryStream(data)); throw new Exception("Damaged GeoIP data accepted."); } catch (Exception e) when (e is InvalidDataException or EndOfStreamException) { } }
            Rejects(bytes[..^3]); Rejects([.. bytes, 0]); var magic = (byte[])bytes.Clone(); magic[0] ^= 0xFF; Rejects(magic);
        });
        check("GeoIP sources must be sorted, disjoint and well formed", () =>
        {
            static void Rejects(string countries, string asns = "8.8.8.0,8.8.8.255,15169,Google\n")
            { try { Build(countries, asns); throw new Exception("Malformed GeoIP source accepted."); } catch (InvalidDataException) { } }
            Rejects("8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n");
            Rejects("1.0.0.0,1.0.0.255,AU\n1.0.0.128,1.0.1.255,CN\n");
            Rejects("1.0.0.0,1.0.0.255,A1\n"); Rejects("1.0.0.0,1.0.0.255\n"); Rejects("1.0.0.0,2001:db8::,AU\n");
            Rejects("1.0.0.0,1.0.0.255,AU\n", "8.8.8.0,8.8.8.255,0,Nobody\n");
            try { GeoIpDatabase.Build(new StringReader(Countries), new StringReader(Asns), "October"); throw new Exception("A bad release name was accepted."); } catch (InvalidDataException) { }
        });
        check("GeoIP restrictions expand to exact, merged CIDRs within the budget", () =>
        {
            var db = Build();
            Expect(db.RestrictedNetworks(["AU"], []).SequenceEqual(["1.0.0.0/24", "1.0.4.0/22"]));
            Expect(db.RestrictedNetworks(["cn"], []).SequenceEqual(["1.0.1.0/24", "1.0.2.0/23"]));
            Expect(db.RestrictedNetworks([], [15169]).SequenceEqual(["8.8.8.0/24"]));
            Expect(db.RestrictedNetworks(["AU", "CN"], [13335]).SequenceEqual(["1.0.0.0/21"]), "Adjacent and overlapping restrictions were not merged.");
            Expect(db.RestrictedNetworks(["DE"], []).SequenceEqual(["2001:db8::/32"]));
            Expect(db.RestrictedNetworks(["AU", "CN", "US"], [], 2).Count == 2);
            try { db.RestrictedNetworks(["AU", "CN", "US"], [], 1); throw new Exception("The filter budget was exceeded."); } catch (InvalidDataException) { }
            var everything = GeoIpDatabase.Build(new StringReader("0.0.0.0,255.255.255.255,US\n::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,US\n"), new StringReader("1.2.3.4,1.2.3.5,64500,Pair\n"), "2026-10");
            Expect(everything.RestrictedNetworks(["US"], []).SequenceEqual(["0.0.0.0/0", "::/0"]) && everything.RestrictedNetworks([], [64500]).SequenceEqual(["1.2.3.4/31"]));
        });
        check("DB-IP city ranges resolve places, with gaps, reserved space and unnamed ranges placeless and IPv6 kept per /64", () =>
        {
            var cities = BuildCities();
            Expect(cities.Lookup("1.0.0.1") is { Country: "AU", Region: "Queensland", City: "South Brisbane" } brisbane && Near(brisbane.Latitude, -27.4767) && Near(brisbane.Longitude, 153.017));
            Expect(cities.Lookup("1.0.1.200") is { City: "South Brisbane", Latitude: var latitude } && Near(latitude, -27.4767), "A place did not keep the position most of its ranges give.");
            Expect(cities.Lookup("1.0.3.255") is { Country: "CN", City: "Wenquan" } && cities.Lookup("1.0.6.7")?.City == "South Brisbane");
            Expect(cities.Lookup("8.8.4.4") is { Region: "District of Columbia", City: "Washington, D.C." } && cities.Lookup("::ffff:8.8.8.8") is { City: "Mountain View" });
            Expect(cities.Lookup("0.0.0.5") is null && cities.Lookup("1.0.8.1") is null && cities.Lookup("8.8.5.1") is null && cities.Lookup("8.8.9.9") is null &&
                cities.Lookup("8.8.10.1") is null && cities.Lookup("255.255.255.255") is null && cities.Lookup("not an address") is null);
            Expect(cities.Lookup("2001:db8::5") is { City: "Frankfurt am Main" } && cities.Lookup("2001:db8::2:7")?.City == "Frankfurt am Main", "A /64 did not keep its first address's place.");
            Expect(cities.Lookup("2001:db8:0:1::5")?.City == "Berlin" && cities.Lookup("2001:db8:0:5:ffff::")?.City == "Berlin" && cities.Lookup("2001:db8:0:6::1")?.City == "Hamburg");
            Expect(cities.Lookup("2001:db8:ffff::1")?.City == "Hamburg" && cities.Lookup("2001:db9::1") is null && cities.Lookup("2001:db7::1") is null);
            Expect(cities.Places == 7, "A place no range keeps stayed in the table.");
        });
        check("GeoIP city files round-trip and reject damage", () =>
        {
            using var stream = new MemoryStream(); BuildCities().Write(stream);
            stream.Position = 0; Expect(GeoIpCities.ReadRelease(stream) == "2026-10");
            stream.Position = 0; var read = GeoIpCities.Read(stream);
            Expect(read.Release == "2026-10" && read.Count == BuildCities().Count && read.Places == 7 && read.Lookup("8.8.4.4")?.City == "Washington, D.C." && read.Lookup("2001:db8:0:3::")?.City == "Berlin");
            var bytes = stream.ToArray();
            static void Rejects(byte[] data) { try { GeoIpCities.Read(new MemoryStream(data)); throw new Exception("Damaged city data accepted."); } catch (Exception e) when (e is InvalidDataException or EndOfStreamException) { } }
            Rejects(bytes[..^3]); Rejects([.. bytes, 0]); var magic = (byte[])bytes.Clone(); magic[0] ^= 0xFF; Rejects(magic);
            var place = (byte[])bytes.Clone(); place[^1] = 0x7F; Rejects(place);
            try { GeoIpDatabase.Read(new MemoryStream(bytes)); throw new Exception("City data read as a country database."); } catch (InvalidDataException) { }
        });
        check("GeoIP city sources must be sorted, disjoint and well formed", () =>
        {
            static void Rejects(string cities, string release = "2026-10")
            { try { GeoIpCities.Build(new StringReader(cities), release); throw new Exception("Malformed city source accepted."); } catch (InvalidDataException) { } }
            Rejects("8.8.8.0,8.8.8.255,NA,US,California,Mountain View,37.4,-122.1\n1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27.5,153\n");
            Rejects("1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27.5,153\n1.0.0.128,1.0.1.255,OC,AU,Queensland,Brisbane,-27.5,153\n");
            Rejects("1.0.0.0,1.0.0.255,OC,A1,Queensland,Brisbane,-27.5,153\n"); Rejects("1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27.5\n");
            Rejects("1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-91,153\n"); Rejects("1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27.5,east\n");
            Rejects("1.0.0.0,1.0.0.255,OC,AU,Queensland,\"Bris\u0007bane\",-27.5,153\n"); Rejects("1.0.0.0,2001:db8::,OC,AU,Queensland,Brisbane,-27.5,153\n");
            Rejects(Cities, "October");
        });
        check("GeoIP lookups take a city only where it names the same country", () =>
        {
            var db = Build(); db.Cities = BuildCities(); db.Locate = code => code == "CN" ? (35, 103) : null;
            Expect(db.Lookup("1.0.0.1") is { Country: "AU", City: "South Brisbane", Region: "Queensland", Asn: 13335 } au && Near(au.Latitude, -27.4767));
            Expect(db.Lookup("1.0.1.9") is { Country: "CN", City: "", Region: "", Latitude: 35, Longitude: 103 }, "A city in another country was used.");
            Expect(db.Lookup("1.0.2.3") is { Country: "CN", City: "Wenquan" } wenquan && Near(wenquan.Longitude, 119.297));
            Expect(db.Lookup("8.8.8.8") is { Country: "US", City: "Mountain View", Asn: 15169 } && db.Lookup("2001:db8::1") is { Country: "DE", City: "Frankfurt am Main" });
            Expect(db.Lookup("8.8.4.4") is null, "City data alone resolved an address the country data does not cover.");
        });
    }
}
