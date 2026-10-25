using System.Threading;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Darkwire.Host;

/// <summary>
/// Part of the world to draw: its longitudes, which may run past 180° either way where the world repeats, its latitudes, the
/// bitmap's size in device pixels, and how many of those make one device-independent pixel.
/// </summary>
internal sealed record MapDetailRequest(string Theme, bool Light, double West, double East, double South, double North, int PixelWidth, int PixelHeight, double PixelsPerDip)
{
    public double PixelsPerDegree => PixelHeight / (North - South);
}

/// <summary>
/// Draws part of the world at the resolution a view shows it, for maps zoomed in past the shared artwork's texture: the same
/// borders and colors, with pens and lettering at a fixed size on screen, more names as the view nears them, and the bundled
/// GeoNames cities. Works on any STA thread; the bitmap comes back frozen.
/// </summary>
internal static class WorldMapDetail
{
    /// <summary>The longest side and the most pixels drawn, so a view's detail stays within a few dozen megabytes however large it is.</summary>
    public const int MaximumSide = 4096, MaximumPixels = 6_000_000;

    public static BitmapSource Render(MapDetailRequest request)
    {
        var (theme, light, west, east, south, north, width, height, scale) = request;
        var classic = theme == "Classic";
        // Pixels per degree east to west and north to south; they differ only on the globe, away from the middle latitude.
        var sx = width / (east - west); var sy = height / (north - south);
        Point Place(double longitude, double latitude) => new((longitude - west) * sx, (north - latitude) * sy);
        // The world repeats every 360°; each copy reaching the view is drawn a whole turn over.
        var copies = Enumerable.Range((int)Math.Floor((west + 180) / 360), (int)Math.Floor((east + 180) / 360) - (int)Math.Floor((west + 180) / 360) + 1).ToArray();
        var bounds = new Rect(0, 0, width, height);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushClip(new RectangleGeometry(bounds));
            dc.DrawRectangle(WorldMapArtwork.Ocean(theme, light), null, bounds);
            foreach (var (name, longitude, latitude) in WorldMapArtwork.Oceans)
                foreach (var copy in copies)
                {
                    var text = WorldMapArtwork.Text(name, 15 * scale, WorldMapArtwork.OceanInk(light), classic, true);
                    var at = Place(longitude + 360 * copy, latitude);
                    if (bounds.Contains(at)) dc.DrawText(text, new(at.X - text.Width / 2, at.Y - text.Height / 2));
                }
            var border = new Pen(WorldMapArtwork.Border(theme, light), (classic ? 1.15 : 1) * scale); border.Freeze();
            foreach (var copy in copies)
            {
                // Artwork space is 10 units to a degree east of 180°W and south of 90°N.
                var placement = new MatrixTransform(sx / 10, 0, 0, sy / 10, (360 * copy - 180 - west) * sx, (north - 90) * sy); placement.Freeze();
                var reach = new Rect(new Point((Math.Max(west - 360 * copy, -180) + 180) * 10, (90 - north) * 10),
                    new Point((Math.Min(east - 360 * copy, 180) + 180) * 10, (90 - south) * 10));
                foreach (var (country, shape, extent) in WorldMapArtwork.Shapes)
                {
                    if (!extent.IntersectsWith(reach)) continue;
                    // Moving the geometry rather than the drawing keeps the pen's width in pixels.
                    var placed = new GeometryGroup { FillRule = FillRule.EvenOdd, Transform = placement }; placed.Children.Add(shape);
                    dc.DrawGeometry(WorldMapArtwork.Land(country, theme, light), border, placed);
                }
            }
            DrawGraticule(dc, theme, light, west, east, south, north, Place, bounds, scale);
            var used = new List<Rect>();
            DrawCountryNames(dc, classic, light, copies, Place, bounds, sx, sy, scale, used);
            DrawCities(dc, classic, light, copies, Place, bounds, sx / scale, scale, used);
            dc.Pop();
        }
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual); bitmap.Freeze();
        return bitmap;
    }

    private static void DrawGraticule(DrawingContext dc, string theme, bool light, double west, double east, double south, double north, Func<double, double, Point> place, Rect bounds, double scale)
    {
        // The artwork's 30° lines, closer together as the view narrows so there is always one to read movement against.
        var span = east - west;
        var step = span > 120 ? 30 : span > 40 ? 10 : span > 16 ? 5 : span > 6 ? 2 : 1;
        var grid = new Pen(WorldMapArtwork.Graticule(theme, light), scale); grid.Freeze();
        for (var longitude = Math.Ceiling(west / step) * step; longitude <= east; longitude += step)
        {
            var x = place(longitude, 0).X; dc.DrawLine(grid, new(x, 0), new(x, bounds.Height));
        }
        for (var latitude = Math.Ceiling(south / step) * step; latitude <= north; latitude += step)
        {
            if (Math.Abs(latitude) >= 90) continue;
            var y = place(0, latitude).Y;
            dc.DrawLine(latitude == 0 ? new Pen(WorldMapArtwork.Equator(theme, light), 1.4 * scale) : grid, new(0, y), new(bounds.Width, y));
        }
    }

    private static void DrawCountryNames(DrawingContext dc, bool classic, bool light, int[] copies, Func<double, double, Point> place, Rect bounds, double sx, double sy, double scale, List<Rect> used)
    {
        var halo = new Pen(Ui.RawBrush(WorldMapArtwork.LabelHalo(light)), 2.6 * scale) { LineJoin = PenLineJoin.Round }; halo.Freeze();
        var ink = Ui.RawBrush(WorldMapArtwork.CountryInk(light));
        foreach (var (country, _, extent) in WorldMapArtwork.Shapes.OrderBy(s => s.Country.LabelRank).ThenBy(s => s.Country.Name, StringComparer.Ordinal))
        {
            // A country is named once it shows a few dozen pixels across.
            if (extent.Width / 10 * sx < 36 * scale && extent.Height / 10 * sy < 24 * scale) continue;
            foreach (var copy in copies)
            {
                var at = place(country.LabelLongitude + 360 * copy, country.LabelLatitude);
                if (!bounds.Contains(at)) continue;
                var text = WorldMapArtwork.Text(WorldMapArtwork.LabelName(country), (country.LabelRank <= 2 ? 16 : country.LabelRank <= 4 ? 13.5 : 12) * scale,
                    WorldMapArtwork.CountryInk(light), classic);
                var rect = new Rect(at.X - text.Width / 2, at.Y - text.Height / 2, text.Width, text.Height);
                var space = rect; space.Inflate(6 * scale, 3 * scale);
                if (!bounds.Contains(rect) || used.Any(space.IntersectsWith)) continue;
                var glyphs = text.BuildGeometry(rect.TopLeft);
                dc.DrawGeometry(null, halo, glyphs); dc.DrawGeometry(ink, null, glyphs);
                used.Add(space);
            }
        }
    }

    private static void DrawCities(DrawingContext dc, bool classic, bool light, int[] copies, Func<double, double, Point> place, Rect bounds, double dipsPerDegree, double scale, List<Rect> used)
    {
        // The largest cities first, smaller ones as the view comes closer; a name that would cover another is left out with its dot.
        var least = dipsPerDegree < 18 ? 2_000_000 : dipsPerDegree < 36 ? 600_000 : dipsPerDegree < 72 ? 200_000 : dipsPerDegree < 140 ? 60_000 : 0;
        var dot = Ui.RawBrush(light ? "#244C65" : "#EDE8FF");
        var ring = new Pen(Ui.RawBrush(light ? "#F6FBFF" : "#0D1927"), 1.2 * scale); ring.Freeze();
        var halo = new Pen(Ui.RawBrush(WorldMapArtwork.LabelHalo(light)), 2.4 * scale) { LineJoin = PenLineJoin.Round }; halo.Freeze();
        var ink = Ui.RawBrush(WorldMapArtwork.CityInk(light));
        var named = 0;
        foreach (var city in Cities.ByPopulation)
        {
            if (city.Population < least || named >= 600) break;
            foreach (var copy in copies)
            {
                var at = place(city.Longitude + 360 * copy, city.Latitude);
                if (!bounds.Contains(at)) continue;
                var radius = (city.Population >= 1_000_000 ? 3.2 : 2.5) * scale;
                var mark = new Rect(at.X - radius, at.Y - radius, radius * 2, radius * 2); mark.Inflate(2 * scale, 2 * scale);
                var text = new FormattedText(city.Name, System.Globalization.CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    new Typeface(new FontFamily(classic ? "Georgia" : "Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                    11.5 * scale, ink, 1);
                var gap = radius + 3 * scale;
                // The name goes right of its dot, or left where that is taken.
                Rect? label = null;
                foreach (var candidate in new[] { new Rect(at.X + gap, at.Y - text.Height / 2, text.Width, text.Height), new Rect(at.X - gap - text.Width, at.Y - text.Height / 2, text.Width, text.Height) })
                {
                    var space = candidate; space.Inflate(3 * scale, 1 * scale);
                    if (bounds.Contains(candidate) && !used.Any(u => u.IntersectsWith(space) || u.IntersectsWith(mark))) { label = space; break; }
                }
                if (label is not { } taken) continue;
                dc.DrawEllipse(dot, ring, at, radius, radius);
                var glyphs = text.BuildGeometry(new(taken.X + 3 * scale, taken.Y + 1 * scale));
                dc.DrawGeometry(null, halo, glyphs); dc.DrawGeometry(ink, null, glyphs);
                used.Add(taken); used.Add(mark); named++;
            }
        }
    }
}

/// <summary>One background STA thread that draws map detail, so panning and zooming never wait on it.</summary>
internal static class MapDetailWorker
{
    private static readonly Lazy<Dispatcher> worker = new(() =>
    {
        Dispatcher? dispatcher = null;
        using var started = new ManualResetEventSlim();
        var thread = new Thread(() => { dispatcher = Dispatcher.CurrentDispatcher; started.Set(); Dispatcher.Run(); }) { IsBackground = true, Name = "Darkwire map detail" };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); started.Wait();
        return dispatcher!;
    });

    /// <summary>Draws the request on the worker, then hands the bitmap, or null if it could not be drawn, back on the caller's dispatcher.</summary>
    public static void Render(MapDetailRequest request, Dispatcher reply, Action<BitmapSource?> done) => worker.Value.InvokeAsync(() =>
    {
        BitmapSource? bitmap;
        try { bitmap = WorldMapDetail.Render(request); }
        catch (Exception) { bitmap = null; }
        reply.InvokeAsync(() => done(bitmap));
    });
}
