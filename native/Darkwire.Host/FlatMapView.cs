using System.Windows.Media.Media3D;
using System.Windows.Shapes;

namespace Darkwire.Host;

public sealed partial class GlobeView
{
    private readonly OrthographicCamera flatCamera = new(new(0, 0, 8), new(0, 0, -1), new(0, 1, 0), 4.3);
    private Ellipse? halo;
    private double flatPanX, flatPanY, flatZoom = 1;
    // The closest zoom shows about four degrees of longitude across a wide card: a city and its neighbors.
    private const double MinimumFlatZoom = .012;
    // Until the user pans or zooms the flat map, its view stays centered on this PC's place as the card's size settles.
    private bool homeFlat = true;
    // The world repeats east and west, so panning never reaches an edge. Pans stay within half a world of the center, so
    // the widest view, 1.8 worlds across at the farthest zoom out, needs one copy on each side.
    private static readonly double[] FlatCopies = [-4, 0, 4];
    private GeometryModel3D? flatSurface;
    private int flatLabelDetail;
    private int FlatLabelDetail => (4 * viewport.ActualWidth / flatCamera.Width) switch
    {
        < 420 => -1,
        > 2000 => 2,
        > 1200 => 1,
        _ => 0
    };
    private bool showBackground = true;
    public string Projection { get; private set; } = "Globe";
    public event EventHandler? ProjectionChanged;
    internal Size SurfaceSize => new(viewport.ActualWidth, viewport.ActualHeight);
    public static string NormalizeProjection(string? value) => value == "Flat" ? "Flat" : "Globe";

    private static List<MapRoute> ValidPoints(IEnumerable<MapRoute> points) => points
        .Where(p => double.IsFinite(p.Lat) && double.IsFinite(p.Lon) && p.Lat is >= -90 and <= 90 && p.Lon is >= -180 and <= 180)
        .Distinct().ToList();

    public void SetProjection(string value)
    {
        var next = NormalizeProjection(value);
        if (Projection == next) return;
        Projection = next; drag = null; ReleaseMouseCapture();
        Build(); FitCamera(); ProjectionChanged?.Invoke(this, EventArgs.Empty);
    }

    private void ConfigureProjection()
    {
        var flat = Projection == "Flat";
        viewport.Camera = flat ? flatCamera : camera;
        viewport.Margin = new Thickness(0);
        Background = flat ? WorldMapArtwork.Ocean(Theme, IsLightAtlas) : Brushes.Transparent;
        if (environment is not null)
        {
            environment.Visibility = !flat && showBackground ? Visibility.Visible : Visibility.Hidden;
            environment.Animate = !flat && Animate;
        }
        UpdateAtmosphere();
        UpdateHint();
    }

    private void FitFlatCamera()
    {
        // Cover the full card without distorting geography. The user can pan to cropped regions, around the world east and
        // west, or zoom out to see all of it; space beyond the poles remains the map's ocean color.
        flatCamera.Width = Math.Min(4, 2 * Math.Max(1, ActualWidth) / Math.Max(1, ActualHeight)) * flatZoom;
        if (homeFlat)
        {
            var halfHeight = flatCamera.Width / 2 * Math.Max(1, viewport.ActualHeight) / Math.Max(1, viewport.ActualWidth);
            (flatPanX, flatPanY) = AtlasProjection.Home(AtlasProjection.Project(Origin.Latitude, Origin.Longitude), halfHeight);
        }
        flatCamera.Position = new(flatPanX, flatPanY, 8);
        flatCamera.LookDirection = new(0, 0, -1);
        if (flatSurface is not null && flatLabelDetail != FlatLabelDetail)
        {
            flatLabelDetail = FlatLabelDetail;
            var material = new DiffuseMaterial(WorldMapArtwork.Create(Theme, IsLightAtlas, flatLabelDetail, frame: false)); material.Freeze();
            flatSurface.Material = material; flatSurface.BackMaterial = material;
        }
    }

    /// <summary>How far a drag must go to pan the flat map once around the world; for captures.</summary>
    internal double PixelsPerWorld => 4 * Math.Max(1, viewport.ActualWidth) / flatCamera.Width;

    /// <summary>The place under a point of the map: on the flat map where it lies, on the globe where a ray through it meets the ground; null off the map.</summary>
    internal (double Latitude, double Longitude)? PlaceAt(Point point)
    {
        if (viewport.ActualWidth <= 0 || viewport.ActualHeight <= 0) return null;
        if (Projection != "Flat") return GlobePlaceAt(point);
        var unitsPerPixel = flatCamera.Width / viewport.ActualWidth;
        return AtlasProjection.Unproject(new(flatCamera.Position.X + (point.X - viewport.ActualWidth / 2) * unitsPerPixel,
            flatCamera.Position.Y - (point.Y - viewport.ActualHeight / 2) * unitsPerPixel));
    }

    /// <summary>
    /// Zooms in twice as close on the place under a point, as a double-click does: the flat map keeps that place under the
    /// pointer, and the globe turns to face it.
    /// </summary>
    internal void ZoomInAt(Point point)
    {
        if (Projection == "Flat")
        {
            var before = flatCamera.Width / Math.Max(1, viewport.ActualWidth);
            flatZoom = Math.Max(MinimumFlatZoom, flatZoom / 2); homeFlat = false;
            // The camera's width follows the card's shape and the zoom, as FitFlatCamera sets it.
            var after = Math.Min(4, 2 * Math.Max(1, ActualWidth) / Math.Max(1, ActualHeight)) * flatZoom / Math.Max(1, viewport.ActualWidth);
            (flatPanX, flatPanY) = AtlasProjection.ZoomToward(flatPanX, flatPanY, point.X - viewport.ActualWidth / 2, point.Y - viewport.ActualHeight / 2, before, after);
        }
        else
        {
            if (GlobePlaceAt(point) is { } place) (orbitYaw, orbitPitch) = AtlasProjection.Facing(place.Latitude, place.Longitude, GlobeTurn, GlobeTilt);
            zoom = Math.Max(MinimumGlobeZoom, zoom / 2);
        }
        FitCamera();
    }

    private Action<double, double>? picked;
    /// <summary>Told the place clicked on the flat map, to choose a position by it; a drag still pans. Null leaves clicks alone.</summary>
    public Action<double, double>? Picked { get => picked; set { picked = value; UpdateHint(); } }

    private void UpdateHint()
    {
        var flat = Projection == "Flat";
        hint.Visibility = ActualWidth < 400 || ActualHeight < 180 ? Visibility.Collapsed : Visibility.Visible;
        hint.Margin = new(12, 0, 58, 16);
        hint.TextWrapping = TextWrapping.Wrap;
        hint.TextAlignment = TextAlignment.Center;
        hint.MaxWidth = Math.Max(1, ActualWidth - 80);
        hint.Text = flat ? (picked is null ? "DRAG TO PAN   ·   SCROLL OR DOUBLE-CLICK TO ZOOM" : "CLICK TO DROP A PIN   ·   DRAG TO PAN   ·   SCROLL OR DOUBLE-CLICK TO ZOOM")
            : "DRAG TO ORBIT   ·   SCROLL OR DOUBLE-CLICK TO ZOOM";
        // Runs with every camera move, so the brushes are made once rather than a new one each frame.
        hint.Foreground = IsLightAtlas ? DayHint : NightHint;
    }
    private static readonly Brush DayHint = Ui.RawBrush("#3E6076"), NightHint = Ui.RawBrush("#A0ACC0");

    private void PanFlat(double dx, double dy)
    {
        var unitsPerPixel = flatCamera.Width / Math.Max(1, viewport.ActualWidth);
        // Crossing a copy's edge looks the same as staying on its neighbor, so the pan wraps back toward the center.
        flatPanX = AtlasProjection.Wrap(flatPanX - dx * unitsPerPixel);
        flatPanY = Math.Clamp(flatPanY + dy * unitsPerPixel, -AtlasProjection.MaximumPanY, AtlasProjection.MaximumPanY);
        homeFlat = false;
    }

    internal void ShowBackgroundForCapture(bool show)
    {
        showBackground = show;
        Build(); FitCamera();
    }

    private void BuildFlat()
    {
        world.Transform = Transform3D.Identity;
        flatSurface = FlatSurface(); flatLabelDetail = FlatLabelDetail; world.Children.Add(flatSurface);
        world.Children.Add(routeModels); BuildRoutes();
        var root = new Model3DGroup(); root.Children.Add(new AmbientLight(Colors.White));
        // Each copy shares the one world, so routes, markers and moving traffic stay the same on all of them.
        foreach (var offset in FlatCopies) root.Children.Add(new Model3DGroup { Children = { world }, Transform = new TranslateTransform3D(offset, 0, 0) });
        viewport.Children.Add(new ModelVisual3D { Content = root });
        UpdateParticles();
    }

    private GeometryModel3D FlatSurface()
    {
        var brush = WorldMapArtwork.Create(Theme, IsLightAtlas, FlatLabelDetail, frame: false);
        var mesh = new MeshGeometry3D
        {
            Positions = new([new(-2, -1, 0), new(2, -1, 0), new(2, 1, 0), new(-2, 1, 0)]),
            TextureCoordinates = new([new(0, 1), new(1, 1), new(1, 0), new(0, 0)]),
            Normals = new([new(0, 0, 1), new(0, 0, 1), new(0, 0, 1), new(0, 0, 1)])
        };
        Triangle(mesh, 0, 1, 2); Triangle(mesh, 0, 2, 3); mesh.Freeze();
        var material = new DiffuseMaterial(brush); material.Freeze();
        return new(mesh, material) { BackMaterial = material };
    }

    private void BuildFlatRoutes()
    {
        var routes = endpoints.GroupBy(p => p.Direction).SelectMany(g => g.Take(10)).Take(32);
        var s = routeScale;
        foreach (var endpoint in routes)
        {
            var route = AtlasProjection.CreateRoute(Origin.Latitude, Origin.Longitude, endpoint.Lat, endpoint.Lon, curvature: AttackView ? .24 : .14);
            var color = RouteColor(endpoint);
            var glow = new MeshGeometry3D(); var line = new MeshGeometry3D();
            foreach (var segment in route.Segments)
            {
                AddPlanarLine(glow, segment.Select(p => new Point3D(p.X, p.Y, .013)).ToArray(), .009 * s);
                AddPlanarLine(line, segment.Select(p => new Point3D(p.X, p.Y, .016)).ToArray(), .0023 * s);
            }
            if (atmosphereGlow && DecorativeEffects)
                overlays.Add(FlatModel(glow, Color.FromArgb((byte)(12 + effectIntensity * 32), color.R, color.G, color.B)));
            routeModels.Children.Add(FlatModel(line, color));
            var target = FlatPosition(endpoint.Lat, endpoint.Lon, .025);
            AddFlatMarker(target, color, .012 * s);
            AddEndpointWave(target, color, endpoint.Blocked, flat: true);
            if (routeParticles && DecorativeEffects && endpoint.Direction is TrafficDirection.Inbound or TrafficDirection.Outbound && route.Segments.Count > 0)
            {
                var moving = FlatModel(Sphere((.006 + effectIntensity * .007) * s, 6, 8), color);
                var translation = new TranslateTransform3D(); moving.Transform = translation; routeModels.Children.Add(moving);
                particles.Add((translation, t =>
                {
                    var p = route.PointAt(endpoint.Direction == TrafficDirection.Inbound ? 1 - t : t);
                    return new(p.X, p.Y, .04);
                }, particles.Count * .123));
            }
        }
        // This PC's place is marked whether or not any route starts there.
        AddFlatMarker(FlatPosition(Origin.Latitude, Origin.Longitude, .035), IsLightAtlas ? Color.FromRgb(34, 67, 91) : Color.FromRgb(236, 231, 255), .016 * s);
    }

    private void AddFlatMarker(Point3D center, Color color, double radius)
    {
        var dot = new MeshGeometry3D(); AddPlanarDot(dot, center, radius); routeModels.Children.Add(FlatModel(dot, color));
        var ring = new MeshGeometry3D();
        AddPlanarLine(ring, Enumerable.Range(0, 33).Select(i => new Point3D(center.X + radius * 2.4 * Math.Cos(i * Math.PI / 16),
            center.Y + radius * 2.4 * Math.Sin(i * Math.PI / 16), center.Z)).ToArray(), .0012 * routeScale);
        routeModels.Children.Add(FlatModel(ring, color));
    }

    private static Point3D FlatPosition(double latitude, double longitude, double z)
    { var point = AtlasProjection.Project(latitude, longitude); return new(point.X, point.Y, z); }
    private static GeometryModel3D FlatModel(MeshGeometry3D mesh, Color color)
    {
        mesh.Freeze(); var material = new DiffuseMaterial(new SolidColorBrush(color)); material.Freeze();
        return new(mesh, material) { BackMaterial = material };
    }

    private static void AddPlanarDot(MeshGeometry3D mesh, Point3D center, double radius)
    {
        var start = mesh.Positions.Count;
        mesh.Positions.Add(center + new Vector3D(radius, 0, 0)); mesh.Positions.Add(center + new Vector3D(0, radius, 0));
        mesh.Positions.Add(center - new Vector3D(radius, 0, 0)); mesh.Positions.Add(center - new Vector3D(0, radius, 0));
        Triangle(mesh, start, start + 1, start + 2); Triangle(mesh, start, start + 2, start + 3);
    }

    private static void AddPlanarLine(MeshGeometry3D mesh, Point3D[] path, double radius)
    {
        for (var i = 0; i < path.Length - 1; i++)
        {
            var direction = path[i + 1] - path[i]; var side = new Vector3D(-direction.Y, direction.X, 0);
            if (side.LengthSquared < 1e-16) continue;
            side.Normalize(); side *= radius; var index = mesh.Positions.Count;
            mesh.Positions.Add(path[i] - side); mesh.Positions.Add(path[i] + side);
            mesh.Positions.Add(path[i + 1] + side); mesh.Positions.Add(path[i + 1] - side);
            Triangle(mesh, index, index + 1, index + 2); Triangle(mesh, index, index + 2, index + 3);
        }
    }
}
