using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;

namespace Darkwire.Host;

/// <summary>
/// Past the artwork texture's own resolution, both views lay a patch of detail drawn for the view over it: a bitmap of the
/// part of the world in sight and a margin around it, at the screen's resolution, drawn on a background thread. Until a new
/// patch arrives the last one pans and zooms with the map, and the texture shows beyond it.
/// </summary>
public sealed partial class GlobeView
{
    private GeometryModel3D? detailModel;
    private MapDetailRequest? detailShown, detailDrawing;
    private int detailGeneration;
    private bool detailEngaged, detailFailed;

    /// <summary>The detail the current view wants, with the part of the world it shows, or null while the texture is sharp enough.</summary>
    private (MapDetailRequest Request, double West, double East, double South, double North)? WantedDetail()
    {
        double width = viewport.ActualWidth, height = viewport.ActualHeight;
        if (width < 8 || height < 8 || detailFailed) return null;
        var scale = VisualTreeHelper.GetDpi(this).DpiScaleX;
        if (Projection == "Flat")
        {
            var units = flatCamera.Width; var unitsHigh = units * height / width;
            var perUnit = width * scale / units;
            // The texture spans one world's 4 units.
            if (!Engage(perUnit / (WorldMapArtwork.TextureWidth / 4d))) return null;
            var (x, y) = (flatCamera.Position.X, flatCamera.Position.Y);
            // A quarter of the view on every side keeps a short pan sharp; whole pixels of margin keep the patch's pixels on the screen's.
            var marginX = Math.Round(units / 4 * perUnit) / perUnit; var marginY = Math.Round(unitsHigh / 4 * perUnit) / perUnit;
            var (left, right) = (x - units / 2 - marginX, x + units / 2 + marginX);
            var (bottom, top) = (Math.Max(-1, y - unitsHigh / 2 - marginY), Math.Min(1, y + unitsHigh / 2 + marginY));
            var (pixelWidth, pixelHeight) = Bounded((right - left) * perUnit, (top - bottom) * perUnit);
            return (new(Theme, IsLightAtlas, left * 90, right * 90, bottom * 90, top * 90, pixelWidth, pixelHeight, scale),
                (x - units / 2) * 90, (x + units / 2) * 90, Math.Max(-90, (y - unitsHigh / 2) * 90), Math.Min(90, (y + unitsHigh / 2) * 90));
        }
        var distance = ((Vector3D)camera.Position).Length;
        var tangent = Math.Tan(camera.FieldOfView * Math.PI / 360);
        // Pixels per degree of the ground under the camera, against the texture's.
        var perDegree = width * scale / 2 / tangent * Math.PI / 180 / (distance - 1);
        if (!Engage(perDegree / (WorldMapArtwork.TextureWidth / 360d))) return null;
        // The globe turns and tilts its patch against the screen's pixels, so it is drawn a quarter finer to stay sharp.
        (perDegree, scale) = (perDegree * 1.25, scale * 1.25);
        var inverse = world.Transform.Value; inverse.Invert();
        var under = (Vector3D)inverse.Transform(camera.Position); under.Normalize();
        var latitude = Math.Asin(Math.Clamp(under.Y, -1, 1)) * 180 / Math.PI; var longitude = Math.Atan2(under.X, under.Z) * 180 / Math.PI;
        // The view's corners reach farthest from that point, or the horizon where they miss the globe.
        var corner = Math.Atan(tangent * Math.Sqrt(1 + height * height / (width * width)));
        var reach = (distance * Math.Sin(corner) < 1 ? Math.Asin(distance * Math.Sin(corner)) - corner : Math.Acos(1 / distance)) * 180 / Math.PI;
        var view = Cap(latitude, longitude, reach);
        var (west, east, south, north) = Cap(latitude, longitude, Math.Min(90, reach * 1.35));
        var (patchWidth, patchHeight) = Bounded((east - west) * perDegree * Math.Cos(latitude * Math.PI / 180), (north - south) * perDegree);
        return (new(Theme, IsLightAtlas, west, east, south, north, patchWidth, patchHeight, scale), view.West, view.East, view.South, view.North);
    }

    /// <summary>The longitudes and latitudes around a circle on the globe; one around a pole takes every longitude.</summary>
    private static (double West, double East, double South, double North) Cap(double latitude, double longitude, double radius)
    {
        var (south, north) = (latitude - radius, latitude + radius);
        if (south <= -90 || north >= 90) return (longitude - 180, longitude + 180, Math.Max(-90, south), Math.Min(90, north));
        var spread = Math.Asin(Math.Min(1, Math.Sin(radius * Math.PI / 180) / Math.Cos(latitude * Math.PI / 180))) * 180 / Math.PI;
        return (longitude - spread, longitude + spread, south, north);
    }

    private static (int Width, int Height) Bounded(double width, double height)
    {
        var shrink = Math.Min(1, Math.Min(WorldMapDetail.MaximumSide / Math.Max(width, height), Math.Sqrt(WorldMapDetail.MaximumPixels / (width * height))));
        return (Math.Max(1, (int)Math.Round(width * shrink)), Math.Max(1, (int)Math.Round(height * shrink)));
    }

    // Detail takes over once the texture would show larger than its own pixels, and gives way again a little below that, so a
    // zoom that stops near the threshold does not flicker between the two.
    private bool Engage(double magnification) => detailEngaged = magnification > (detailEngaged ? .85 : 1);

    /// <summary>Whether a patch, shown or being drawn, serves the wanted view: same theme, covering it, at nearly its resolution.</summary>
    private static bool Serves(MapDetailRequest? patch, (MapDetailRequest Request, double West, double East, double South, double North) wanted)
    {
        if (patch is null || patch.Theme != wanted.Request.Theme || patch.Light != wanted.Request.Light || patch.South > wanted.South || patch.North < wanted.North) return false;
        var ratio = patch.PixelsPerDegree / wanted.Request.PixelsPerDegree;
        if (ratio is < .92 or > 1.09) return false;
        if (patch.East - patch.West >= 360) return true;
        return new[] { -360d, 0, 360 }.Any(turn => patch.West + turn <= wanted.West && wanted.East <= patch.East + turn);
    }

    private void UpdateDetail()
    {
        if (disposed) return;
        if (WantedDetail() is not { } wanted) { ClearDetail(); return; }
        // One patch at a time: a view that moves on while one is drawn asks again when it arrives.
        if (Serves(detailShown, wanted) || detailDrawing is not null) return;
        var (request, generation) = (wanted.Request, detailGeneration);
        detailDrawing = request;
        MapDetailWorker.Render(request, Dispatcher, bitmap => ShowDetail(generation, request, bitmap));
    }

    private void ShowDetail(int generation, MapDetailRequest request, BitmapSource? bitmap)
    {
        // A rebuilt or zoomed-out view has moved on; its patch is dropped.
        if (generation != detailGeneration || disposed) return;
        detailDrawing = null;
        if (bitmap is null) { detailFailed = true; ClearDetail(); return; }
        var brush = new ImageBrush(bitmap) { Stretch = Stretch.Fill }; brush.Freeze();
        var flat = Projection == "Flat";
        Material material;
        if (flat) material = new DiffuseMaterial(brush);
        else
        {
            material = SurfaceMaterial(brush, request.Light);
        }
        material.Freeze();
        if (detailModel is null) { detailModel = new(); world.Children.Insert(Math.Min(1, world.Children.Count), detailModel); }
        detailModel.Geometry = flat ? FlatPatch(request) : SpherePatch(request, GlobeAltitude);
        detailModel.Material = material; detailModel.BackMaterial = flat ? material : null;
        detailShown = request;
        UpdateDetail();
    }

    private void ClearDetail()
    {
        if (detailModel is null && detailDrawing is null && detailShown is null) return;
        detailGeneration++; detailDrawing = detailShown = null;
        if (detailModel is not null) { world.Children.Remove(detailModel); detailModel = null; }
    }

    /// <summary>Forgets the patch when the scene is rebuilt; the next camera fit asks for a new one.</summary>
    private void ResetDetail()
    {
        detailGeneration++; detailDrawing = detailShown = null; detailModel = null; detailEngaged = false;
    }

    // Just above the flat map, under its routes.
    private static MeshGeometry3D FlatPatch(MapDetailRequest request)
    {
        var (left, right, bottom, top) = (request.West / 90, request.East / 90, request.South / 90, request.North / 90);
        var mesh = new MeshGeometry3D
        {
            Positions = new([new(left, bottom, .002), new(right, bottom, .002), new(right, top, .002), new(left, top, .002)]),
            TextureCoordinates = new([new(0, 1), new(1, 1), new(1, 0), new(0, 0)]),
            Normals = new([new(0, 0, 1), new(0, 0, 1), new(0, 0, 1), new(0, 0, 1)])
        };
        Triangle(mesh, 0, 1, 2); Triangle(mesh, 0, 2, 3); mesh.Freeze();
        return mesh;
    }

    // A shell just above the globe, raised in step with the camera's height so it never meets the globe's own facets, and
    // always below the routes, which rise in the same step.
    private static MeshGeometry3D SpherePatch(MapDetailRequest request, double altitude)
    {
        var radius = 1 + Math.Clamp(altitude * .004, .0003, .006);
        var columns = Math.Clamp((int)Math.Ceiling((request.East - request.West) / 1.5), 8, 96);
        var rows = Math.Clamp((int)Math.Ceiling((request.North - request.South) / 1.5), 8, 64);
        var mesh = new MeshGeometry3D();
        for (var i = 0; i <= rows; i++)
            for (var j = 0; j <= columns; j++)
            {
                var (u, v) = ((double)j / columns, (double)i / rows);
                var p = Position(request.North - v * (request.North - request.South), request.West + u * (request.East - request.West), radius);
                mesh.Positions.Add(p); mesh.Normals.Add((Vector3D)p); mesh.TextureCoordinates.Add(new(u, v));
            }
        for (var i = 0; i < rows; i++)
            for (var j = 0; j < columns; j++)
            {
                var a = i * (columns + 1) + j;
                Triangle(mesh, a, a + columns + 1, a + 1);
                Triangle(mesh, a + 1, a + columns + 1, a + columns + 2);
            }
        mesh.Freeze();
        return mesh;
    }

    /// <summary>Whether the view shows a patch of detail; for captures.</summary>
    internal bool ShowsDetail => detailModel is not null;

    /// <summary>Waits until the patch the view wants is showing, or it wants none; for captures. Whether a patch shows.</summary>
    internal async Task<bool> DetailSettled()
    {
        for (var waited = 0; waited < 15_000; waited += 25)
        {
            if (detailDrawing is null && (WantedDetail() is { } wanted ? Serves(detailShown, wanted) : detailModel is null)) break;
            await Task.Delay(25);
        }
        return ShowsDetail;
    }
}
