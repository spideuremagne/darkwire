using Darkwire.Core;
using System.Text.Json;

internal static class AtlasProjectionChecks
{
    internal static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
        static bool Near(double a, double b) => Math.Abs(a - b) < 1e-10;
        static void Reject(Action action)
        {
            try { action(); } catch (ArgumentOutOfRangeException) { return; }
            throw new Exception("Invalid coordinate or sampling parameter was accepted");
        }
        static void WithinMap(AtlasPoint p) => Expect(double.IsFinite(p.X) && double.IsFinite(p.Y) &&
            p.X is >= -2 and <= 2 && p.Y is >= -1 and <= 1, "Point is outside the flat map");

        check("The map opens flat until the user picks a view, even where earlier versions saved their globe default", () =>
        {
            var legacy = JsonSerializer.Deserialize<AppState>("{\"SchemaVersion\":1,\"Theme\":\"Amethyst\",\"BackgroundPreset\":\"Clouds\"}")!;
            Expect(legacy.MapProjection == "Flat" && legacy.Theme == "Amethyst" && legacy.BackgroundPreset == "Clouds");
            var saved = StateStore.Upgrade(JsonSerializer.Deserialize<AppState>("{\"SchemaVersion\":1,\"MapProjection\":\"Globe\"}")!);
            Expect(saved.MapProjection == "Flat", "An unchosen globe default survived.");
            var chosen = StateStore.Upgrade(JsonSerializer.Deserialize<AppState>("{\"SchemaVersion\":1,\"MapProjection\":\"Globe\",\"MapProjectionChosen\":true}")!);
            Expect(chosen.MapProjection == "Globe", "A chosen globe was replaced.");
        });
        check("A point on the flat map, on any of its copies, is the place projected there; beyond the poles is no place", () =>
        {
            foreach (var (latitude, longitude) in new[] { (48.8566, 2.3522), (-33.8688, 151.2093), (64.15, -21.94), (0.0, -180.0), (90.0, 0.0), (-90.0, 179.999) })
            {
                var point = AtlasProjection.Project(latitude, longitude);
                foreach (var copy in new[] { -4.0, 0, 4 })
                    Expect(AtlasProjection.Unproject(point with { X = point.X + copy }) is { } place && Near(place.Latitude, latitude) && Near(place.Longitude, longitude),
                        $"{latitude}, {longitude} did not come back from copy {copy}.");
            }
            Expect(AtlasProjection.Unproject(new(0, 1.0001)) is null && AtlasProjection.Unproject(new(0, -1.5)) is null && AtlasProjection.Unproject(new(double.NaN, 0)) is null);
        });
        check("Zooming the flat map toward a point keeps the place under it, wrapping east and west and stopping at the poles", () =>
        {
            // A pixel spans .01 map units before and .005 after: the point 100 right of and 50 below the middle stays put.
            var (x, y) = AtlasProjection.ZoomToward(0, 0, 100, 50, .01, .005);
            Expect(Near(x + 100 * .005, 0 + 100 * .01) && Near(y - 50 * .005, 0 - 50 * .01), "The place under the point moved.");
            // Across the date line the view wraps back toward the middle copy; north it stops where the map's pan does.
            Expect(Near(AtlasProjection.ZoomToward(1.9, 0, 40, 0, .01, .005).X, 2.1 - 4) && Near(AtlasProjection.ZoomToward(0, .9, 0, -400, .01, .005).Y, AtlasProjection.MaximumPanY));
        });
        check("Saved flat map preference retains theme and space settings", () =>
        {
            var state = new AppState { MapProjection = "Flat", Theme = "Glacier", BackgroundPreset = "Space", SpaceSunMoon = true, SpaceUfos = true };
            var restored = JsonSerializer.Deserialize<AppState>(JsonSerializer.Serialize(state))!;
            Expect(restored.MapProjection == "Flat" && restored.Theme == "Glacier" && restored.BackgroundPreset == "Space" && restored.SpaceSunMoon && restored.SpaceUfos);
        });
        check("The flat map opens centered on this PC's place, east to west exactly and north to south as far as the map fills the view", () =>
        {
            // The Overview's wide card shows the whole width but only about 51 degrees either side of the equator.
            var halfHeight = 4.0 / 3.5 / 2;
            var losAngeles = AtlasProjection.Project(34.05, -118.24);
            Expect(AtlasProjection.Home(losAngeles, halfHeight) == (losAngeles.X, losAngeles.Y), "Los Angeles was not in the middle of the view.");
            // Farther north, the view stops where the map's top edge would come into view.
            var (x, y) = AtlasProjection.Home(AtlasProjection.Project(64.15, -21.94), halfHeight);
            Expect(Near(x, -21.94 / 90) && Near(y, 1 - halfHeight), "Reykjavik's view showed past the map's edge.");
            // A view taller than the map keeps it centered; the dateline is one place, at the west edge of the middle copy.
            Expect(AtlasProjection.Home(AtlasProjection.Project(-36.85, 174.76), 1.2).Y == 0);
            Expect(AtlasProjection.Home(AtlasProjection.Project(0, 180), .5).X == -2 && AtlasProjection.Home(AtlasProjection.Project(0, -180), .5).X == -2);
        });
        check("Panning the flat map wraps around the world: every copy east or west is the same place", () =>
        {
            foreach (var x in new[] { -2, -1.3, 0, 1.99 })
                for (var turns = -3; turns <= 3; turns++) Expect(Near(AtlasProjection.Wrap(x + 4 * turns), x), $"{x} panned {turns} worlds came back elsewhere.");
            Expect(AtlasProjection.Wrap(2) == -2 && AtlasProjection.Wrap(5.5) == 1.5 && AtlasProjection.Wrap(-2.5) == 1.5);
        });
        check("The globe's orbit faces a place through the globe's own turn and tilt, its pitch within the orbit's limits", () =>
        {
            Expect(AtlasProjection.Facing(0, 0, 0, 0) is (0, 0) && Near(AtlasProjection.Facing(0, 90, 0, 0).Yaw, 90) && Near(AtlasProjection.Facing(45, 0, 0, 0).Pitch, 45));
            // Turning the globe moves a place along the equator by as much; tilting its top toward the viewer lowers the front.
            Expect(Near(AtlasProjection.Facing(0, 10, 32, 0).Yaw, 42) && Near(AtlasProjection.Facing(0, 0, 0, 11).Pitch, -11));
            Expect(AtlasProjection.Facing(89, 0, 0, 0).Pitch == 80 && AtlasProjection.Facing(-89, 0, 0, 0).Pitch == -80, "The pitch left the orbit's limits.");
        });
        check("Flat atlas projects geographic limits and equator correctly", () =>
        {
            Expect(AtlasProjection.Project(0, 0) == new AtlasPoint(0, 0));
            Expect(AtlasProjection.Project(90, 180) == new AtlasPoint(2, 1));
            Expect(AtlasProjection.Project(-90, -180) == new AtlasPoint(-2, -1));
            var london = AtlasProjection.Project(51.5074, -.1278);
            Expect(london.Y > 0 && london.X < 0 && Math.Abs(london.X) < .002);
        });
        check("Flat atlas rejects nonfinite and out-of-range coordinates", () =>
        {
            foreach (var latitude in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity, -90.001, 90.001 })
                Reject(() => AtlasProjection.Project(latitude, 0));
            foreach (var longitude in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity, -180.001, 180.001 })
                Reject(() => AtlasProjection.CreateRoute(0, 0, 0, longitude));
        });
        check("Eastward dateline route meets the same latitude on opposite edges", () =>
        {
            var route = AtlasProjection.CreateRoute(10, 170, 30, -170);
            Expect(route.Segments.Count == 2);
            var exit = route.Segments[0][^1]; var entry = route.Segments[1][0];
            Expect(exit.X == 2 && entry.X == -2 && Near(exit.Y, entry.Y));
            Expect(route.PointAt(.49).X > 1.9 && route.PointAt(.51).X < -1.9);
            Expect(Near(exit.Y, route.PointAt(.5).Y));
        });
        check("Westward dateline route meets the same latitude on opposite edges", () =>
        {
            var route = AtlasProjection.CreateRoute(-20, -175, 50, 165);
            Expect(route.Segments.Count == 2);
            var exit = route.Segments[0][^1]; var entry = route.Segments[1][0];
            Expect(exit.X == -2 && entry.X == 2 && Near(exit.Y, entry.Y));
            Expect(Near(exit.Y, route.PointAt(.25).Y));
            Expect(route.PointAt(.24).X < -1.9 && route.PointAt(.26).X > 1.9);
        });
        check("Dateline splits are exact even between sampled vertices", () =>
        {
            var route = AtlasProjection.CreateRoute(5, 179, 22, -172, samples: 5);
            var crossing = 1d / 9;
            Expect(route.Segments.Count == 2 && Near(route.Segments[0][^1].Y, route.PointAt(crossing).Y));
            Expect(route.Segments[0][^1].X == 2 && route.Segments[1][0].X == -2);
        });
        check("Flat routes do not draw long lines through the map at the dateline", () =>
        {
            foreach (var (from, to) in new[] { (170d, -170d), (-175d, 165d), (179d, -179d), (-180d, 179d), (180d, -179d) })
            {
                var route = AtlasProjection.CreateRoute(-30, from, 40, to);
                foreach (var segment in route.Segments)
                {
                    Expect(segment.Count >= 2);
                    foreach (var point in segment) WithinMap(point);
                    for (var i = 1; i < segment.Count; i++) Expect(Math.Abs(segment[i].X - segment[i - 1].X) < .04);
                }
            }
        });
        check("Ordinary continental routes remain a single arc with exact endpoints", () =>
        {
            var route = AtlasProjection.CreateRoute(47.6062, -122.3321, 51.5074, -.1278);
            Expect(route.Segments.Count == 1);
            Expect(route.PointAt(0) == AtlasProjection.Project(47.6062, -122.3321));
            Expect(route.PointAt(1) == AtlasProjection.Project(51.5074, -.1278));
            Expect(route.Segments[0][0] == route.PointAt(0) && route.Segments[0][^1] == route.PointAt(1));
            var linearMidpointY = (route.PointAt(0).Y + route.PointAt(1).Y) / 2;
            Expect(route.PointAt(.5).Y > linearMidpointY, "Arc lost its curvature");
        });
        check("Inbound reversal follows the same flat arc in the opposite direction", () =>
        {
            foreach (var (aLat, aLon, bLat, bLon) in new[] { (47.6, -122.3, 35.7, 139.7), (-33.9, 151.2, 51.5, -.1), (20d, -90d, -10d, 90d) })
            {
                var outbound = AtlasProjection.CreateRoute(aLat, aLon, bLat, bLon);
                var inbound = AtlasProjection.CreateRoute(bLat, bLon, aLat, aLon);
                for (var i = 0; i <= 100; i++)
                {
                    var point = outbound.PointAt(i / 100d); var reversed = inbound.PointAt(1 - i / 100d);
                    Expect(Near(point.Y, reversed.Y) && (Near(point.X, reversed.X) || Near(Math.Abs(point.X - reversed.X), 4)));
                }
            }
        });
        check("Pole routes stay finite and inside latitude bounds", () =>
        {
            foreach (var (aLat, aLon, bLat, bLon) in new[] { (90d, 0d, -90d, 180d), (89.9, 170d, 89.9, -170d), (-90d, -180d, -89d, 170d) })
            {
                var route = AtlasProjection.CreateRoute(aLat, aLon, bLat, bLon, curvature: 1);
                foreach (var point in route.Segments.SelectMany(s => s)) WithinMap(point);
                for (var i = 0; i <= 100; i++) WithinMap(route.PointAt(i / 100d));
            }
        });
        check("Identical locations produce no degenerate route geometry", () =>
        {
            var route = AtlasProjection.CreateRoute(47, -122, 47, -122);
            Expect(route.Segments.Count == 0 && route.PointAt(.5) == AtlasProjection.Project(47, -122));
            var seam = AtlasProjection.CreateRoute(0, 180, 0, -180);
            Expect(seam.Segments.Count == 0 && seam.PointAt(.5).Y == 0);
        });
        check("Routes starting or ending on the dateline avoid empty clipped segments", () =>
        {
            foreach (var (from, to) in new[] { (180d, -170d), (-180d, 170d), (170d, -180d), (-170d, 180d) })
            {
                var route = AtlasProjection.CreateRoute(0, from, 10, to);
                Expect(route.Segments.Count == 1 && route.Segments[0].Count >= 2);
                foreach (var point in route.Segments[0]) WithinMap(point);
                Expect(route.Segments[0].Max(p => p.X) - route.Segments[0].Min(p => p.X) < .12);
            }
        });
        check("Flat route sampling rejects invalid progress and unbounded allocations", () =>
        {
            foreach (var count in new[] { -1, 0, 1, 4097, int.MaxValue })
                Reject(() => AtlasProjection.CreateRoute(0, 0, 20, 20, samples: count));
            foreach (var curvature in new[] { double.NaN, double.PositiveInfinity, -.1, 1.1 })
                Reject(() => AtlasProjection.CreateRoute(0, 0, 20, 20, curvature: curvature));
            var route = AtlasProjection.CreateRoute(0, 0, 20, 20);
            foreach (var progress in new[] { double.NaN, double.NegativeInfinity, -.001, 1.001 }) Reject(() => route.PointAt(progress));
        });
    }
}
