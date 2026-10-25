using System.Globalization;
using System.Windows.Media.Imaging;

namespace Darkwire.Host;

/// <summary>Offline country cartography shared by the flat atlas and the globe's surface.</summary>
internal static class WorldMapArtwork
{
    private const double Width = 3600, Height = 1800;
    /// <summary>The texture's width in pixels; the flat map's 4 units and the globe's 360 degrees span it.</summary>
    public const int TextureWidth = 4096;
    private static readonly Dictionary<(string Theme, bool Light, int Detail, bool Frame), ImageBrush> cache = [];
    private static readonly Lazy<IReadOnlyList<(WorldCountry Country, StreamGeometry Shape, Rect Extent)>> countries = new(() =>
        WorldMapData.Countries.Select(country => { var shape = Geometry(country); return (country, shape, shape.Bounds); }).ToArray());
    private static readonly string[] politicalColors =
    ["#E8BE83", "#BCD39E", "#ECC2B6", "#B6C8DC", "#E5D69B", "#C9BBDD", "#A8CEBF",
     "#E4AD94", "#D2D9A4", "#E3BBD1", "#B4CFDB", "#D5BF9F", "#C4C4E2"];

    /// <summary>Each country's frozen outline in artwork space, 10 units to a degree east of 180°W and south of 90°N, and the box around it.</summary>
    public static IReadOnlyList<(WorldCountry Country, StreamGeometry Shape, Rect Extent)> Shapes => countries.Value;
    // All palette inputs are values captured by the UI. These helpers also run on the detail worker and never read
    // Application resources, SystemParameters, or mutable appearance state.
    public static SolidColorBrush Ocean(string theme, bool light) => Ui.RawBrush(light ? "#E6F1F7" : "#0C1627");
    public static Brush Land(WorldCountry country, string theme, bool light)
    {
        if (theme == "Classic")
        {
            var political = (Color)ColorConverter.ConvertFromString(country.MapColor13 is >= 1 and <= 13 ? politicalColors[country.MapColor13 - 1] : "#DCE5E5");
            return Frozen(light ? Mix(political, Color.FromRgb(247, 251, 253), .32) : Shade(political, .25));
        }
        return light ? Frozen(Mix(Color.FromRgb(249, 252, 255), Accent(theme, true), .13 + country.MapColor13 % 4 * .018))
            : Frozen(Shade(Accent(theme, false), .25 + country.MapColor13 % 4 * .018));
    }
    public static Brush Border(string theme, bool light) => light ? Frozen(Mix(Color.FromRgb(150, 174, 190), Accent(theme, true), .17))
        : theme == "Classic" ? Ui.RawBrush("#65768B") : Frozen(Shade(Accent(theme, false), .65));
    public static Brush Graticule(string theme, bool light) => Ui.RawBrush(light ? "#507D9AAE" : "#283D536B");
    public static Brush Equator(string theme, bool light) => Ui.RawBrush(light ? "#95AEBE" : "#46596F");
    public static string CountryInk(bool light) => light ? "#2A4051" : "#B7C3D5";
    public static string CityInk(bool light) => light ? "#233E50" : "#D4DAE6";
    public static string OceanInk(bool light) => light ? "#5C7B8E" : "#637B92";
    public static string LabelHalo(bool light) => light ? "#D9F6FBFF" : "#D90D1927";
    public static (string Name, double Longitude, double Latitude)[] Oceans { get; } =
        [("PACIFIC\nOCEAN", -133, -8), ("ATLANTIC\nOCEAN", -35, 8), ("INDIAN\nOCEAN", 77, -29), ("ARCTIC OCEAN", 5, 82)];
    public static Color Accent(string theme, bool light) => (theme, light) switch
    {
        ("Glacier", true) => Color.FromRgb(22, 100, 145), ("Verdant", true) => Color.FromRgb(26, 110, 83),
        ("Classic", true) => Color.FromRgb(54, 75, 153), (_, true) => Color.FromRgb(102, 75, 165),
        ("Glacier", false) => Color.FromRgb(125, 212, 255), ("Verdant", false) => Color.FromRgb(100, 232, 187),
        ("Classic", false) => Color.FromRgb(157, 190, 251), _ => Color.FromRgb(182, 153, 255)
    };
    private static SolidColorBrush Frozen(Color color) { var brush = new SolidColorBrush(color); brush.Freeze(); return brush; }

    public static ImageBrush Create(string theme, bool light, int detail = 0, bool frame = true)
    {
        var key = (theme, light, Math.Clamp(detail, -1, 2), frame);
        if (cache.TryGetValue(key, out var cached)) return cached;
        var classic = theme == "Classic";
        var drawing = new DrawingGroup();
        using (var dc = drawing.Open())
        {
            var bounds = new Rect(0, 0, Width, Height);
            dc.PushClip(new RectangleGeometry(bounds));
            dc.DrawRectangle(Ocean(theme, light), null, bounds);
            if (detail >= 0) DrawOceans(dc, classic, light);
            var border = new Pen(Border(theme, light), classic ? 1.9 : 1.6);
            foreach (var (country, shape, _) in countries.Value) dc.DrawGeometry(Land(country, theme, light), border, shape);
            var grid = new Pen(Graticule(theme, light), 1.25);
            // The dateline's meridian is drawn half at each edge, so it is whole where the flat map and the globe join them.
            for (var x = 0; x <= Width; x += 300) dc.DrawLine(grid, new(x, 0), new(x, Height));
            for (var y = 300; y < Height; y += 300) dc.DrawLine(grid, new(0, y), new(Width, y));
            dc.DrawLine(new Pen(Equator(theme, light), 1.5), new(0, Height / 2), new(Width, Height / 2));
            if (detail >= 0) DrawLabels(dc, classic, light, key.Item3);
            if (frame)
            {
                dc.DrawRectangle(null, new Pen(Ui.RawBrush(light ? "#D1E1EA" : "#39475B"), 12), new Rect(6, 6, Width - 12, Height - 12));
                dc.DrawRectangle(null, new Pen(Ui.RawBrush(light ? "#91ACBC" : "#728198"), 1.5), new Rect(13, 13, Width - 26, Height - 26));
                var ticks = new Pen(Ui.RawBrush(light ? "#7896A9" : "#728198"), 1.5);
                for (var x = 100; x < Width; x += 100)
                {
                    var length = x % 300 == 0 ? 16 : 8;
                    dc.DrawLine(ticks, new(x, 13), new(x, 13 + length));
                    dc.DrawLine(ticks, new(x, Height - 13), new(x, Height - 13 - length));
                }
            }
            dc.Pop();
        }
        drawing.Freeze();
        // Give D3D a fixed high-resolution texture; an automatically rasterized DrawingBrush
        // can retain a low-resolution cache when the camera subsequently zooms in.
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushTransform(new ScaleTransform(TextureWidth / Width, TextureWidth / 2 / Height));
            dc.DrawDrawing(drawing); dc.Pop();
        }
        var bitmap = new RenderTargetBitmap(TextureWidth, TextureWidth / 2, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual); bitmap.Freeze();
        var brush = new ImageBrush(bitmap) { Stretch = Stretch.Fill }; brush.Freeze();
        // A bounded cache avoids retaining every theme/zoom combination at 32 MiB each.
        if (cache.Count >= 4) cache.Remove(cache.Keys.First());
        cache[key] = brush; return brush;
    }

    private static StreamGeometry Geometry(WorldCountry country)
    {
        var result = new StreamGeometry { FillRule = FillRule.EvenOdd };
        using (var path = result.Open())
            foreach (var polygon in country.Polygons)
                foreach (var ring in polygon.Rings)
                {
                    path.BeginFigure(At(ring[0].Longitude, ring[0].Latitude), true, true);
                    path.PolyLineTo(ring.Skip(1).Select(p => At(p.Longitude, p.Latitude)).ToArray(), true, false);
                }
        result.Freeze(); return result;
    }

    private static void DrawOceans(DrawingContext dc, bool classic, bool light)
    {
        foreach (var (name, lon, lat) in Oceans)
        {
            var text = Text(name, classic ? 45 : 36, OceanInk(light), classic, true);
            var at = At(lon, lat); dc.DrawText(text, new(at.X - text.Width / 2, at.Y - text.Height / 2));
        }
    }

    public static string LabelName(WorldCountry country) => country.Name switch
    {
        "United States of America" => "UNITED STATES",
        "Democratic Republic of the Congo" => "D.R. CONGO",
        "Republic of the Congo" => "CONGO",
        "United Republic of Tanzania" => "TANZANIA",
        "People's Republic of China" => "CHINA",
        "Republic of Serbia" => "SERBIA",
        _ => country.Name.ToUpperInvariant()
    };

    private static void DrawLabels(DrawingContext dc, bool classic, bool light, int detail)
    {
        var used = new List<Rect>();
        foreach (var (country, _, _) in countries.Value.OrderBy(item => item.Country.LabelRank).ThenBy(item => item.Country.Name, StringComparer.Ordinal))
        {
            if (country.LabelRank > (detail == 0 ? 5 : detail == 1 ? 7 : 10)) continue;
            if (Area(country) < (detail == 0 ? 50 : detail == 1 ? 12 : 2)) continue;
            // Keep lettering legible at each zoom level, with collision checks rather than overlapping names.
            var size = (country.LabelRank <= 2 ? 41d : 32d) / (detail == 0 ? 1 : detail == 1 ? 1.5 : 2.2);
            var text = Text(LabelName(country), size, CountryInk(light), classic);
            var at = At(country.LabelLongitude, country.LabelLatitude);
            var rect = new Rect(at.X - text.Width / 2, at.Y - text.Height / 2, text.Width, text.Height);
            var space = rect; space.Inflate(10d / (detail + 1), 7d / (detail + 1));
            if (rect.Left < 18 || rect.Right > Width - 18 || rect.Top < 20 || rect.Bottom > Height - 20 || used.Any(other => other.IntersectsWith(space))) continue;
            // A subtle halo keeps names readable across borders and graticules.
            var glyphs = text.BuildGeometry(rect.TopLeft);
            dc.DrawGeometry(null,
                new Pen(Ui.RawBrush(LabelHalo(light)), detail == 0 ? 2.5 : 1.5), glyphs);
            dc.DrawGeometry(Ui.RawBrush(CountryInk(light)), null, glyphs);
            used.Add(space);
        }
    }

    public static FormattedText Text(string value, double size, string color, bool classic, bool ocean = false) =>
        new(value, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            new Typeface(new FontFamily(classic ? "Georgia" : "Segoe UI"), ocean ? FontStyles.Italic : FontStyles.Normal,
                classic || ocean ? FontWeights.Normal : FontWeights.SemiBold, FontStretches.Normal), size, Ui.RawBrush(color), 1)
        { TextAlignment = TextAlignment.Left };
    private static Point At(double longitude, double latitude) => new((longitude + 180) * 10, (90 - latitude) * 10);
    private static Color Shade(Color c, double amount) => Color.FromRgb((byte)(c.R * amount), (byte)(c.G * amount), (byte)(c.B * amount));
    private static Color Mix(Color a, Color b, double amount) => Color.FromRgb((byte)(a.R + (b.R - a.R) * amount),
        (byte)(a.G + (b.G - a.G) * amount), (byte)(a.B + (b.B - a.B) * amount));
    private static double Area(WorldCountry country) => country.Polygons.Sum(polygon =>
    {
        var ring = polygon.Rings[0]; double area = 0;
        for (var i = 1; i < ring.Count; i++) area += ring[i - 1].Longitude * ring[i].Latitude - ring[i].Longitude * ring[i - 1].Latitude;
        return Math.Abs(area) / 2;
    });
}
