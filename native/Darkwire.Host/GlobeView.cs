using System.Windows.Media.Media3D;
using System.Windows.Shapes;
using System.Diagnostics;

namespace Darkwire.Host;

public sealed record MapRoute(double Lat, double Lon, bool Blocked, TrafficDirection Direction);

/// <summary>A native WPF/Direct3D scene. No browser, tile server, or remote map request.</summary>
public sealed partial class GlobeView : Grid, IDisposable
{
    private readonly Viewport3D viewport = new();
    private readonly Model3DGroup world = new();
    private readonly Model3DGroup routeModels = new();
    // The globe's fixed turn about its axis and tilt toward the viewer; facing a place has to undo both.
    private const double GlobeTurn = 32, GlobeTilt = 11;
    private readonly AxisAngleRotation3D rotation = new(new(0, 1, 0), GlobeTurn);
    private readonly AxisAngleRotation3D tilt = new(new(1, 0, 0), GlobeTilt);
    private readonly PerspectiveCamera camera = new(new(0, 0, 3.4), new(0, 0, -3.4), new(0, 1, 0), 40);
    private readonly List<(TranslateTransform3D Transform, Func<double, Point3D> Position, double Offset)> particles = [];
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private StackPanel? navigationControls;
    private List<MapRoute> endpoints;
    private Point? drag, pressed;
    private bool disposed, attached, animate = true;
    private double orbitYaw, orbitPitch, sceneTime;
    private AtlasBackground? environment;
    // The globe's zoom scales the camera's height above the ground; 1 is the starting view.
    private double zoom = 1;
    // The size routes and markers were last built at; see RouteScale.
    private double routeScale = 1;
    public bool Animate { get => animate; set { animate = value; if (environment is not null) environment.Animate = value && Projection != "Flat"; UpdateSubscription(); } }
    public bool AttackView { get; private set; }
    public string Theme { get; private set; } = "Amethyst";
    public bool IsLightAtlas { get; private set; } = AppearanceTheme.IsLight;
    public static IReadOnlyList<string> Themes { get; } = Array.AsReadOnly(new[] { "Amethyst", "Glacier", "Verdant", "Classic" });
    private Color accent = Color.FromRgb(182, 153, 255);
    private readonly TextBlock hint = new() { Text = "DRAG TO ORBIT   ·   SCROLL TO ZOOM", FontSize = 9, Foreground = Ui.RawBrush("#A0ACC0"), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Bottom, Margin = new(0, 0, 0, 17), IsHitTestVisible = false };

    /// <summary>Where routes start: this PC's place on the map.</summary>
    public MapPlace Origin { get; private set; }

    public GlobeView(IEnumerable<MapRoute>? points = null, string projection = "Globe", MapPlace? origin = null)
    {
        Projection = NormalizeProjection(projection);
        Origin = origin ?? MapOrigin.Default;
        accent = WorldMapArtwork.Accent(Theme, IsLightAtlas);
        // Both views open on this PC's place: the globe faces it, and the flat map keeps it in sight.
        (orbitYaw, orbitPitch) = AtlasProjection.Facing(Origin.Latitude, Origin.Longitude, GlobeTurn, GlobeTilt);
        endpoints = ValidPoints(points ?? []);
        ClipToBounds = true; Background = Brushes.Transparent;
        halo = new Ellipse { Width = 440, Height = 440, IsHitTestVisible = false, Opacity = .22,
            Fill = new RadialGradientBrush(Color.FromRgb(103, 62, 161), Colors.Transparent) { GradientOrigin = new(.5, .5), RadiusX = .5, RadiusY = .5 } };
        atmosphereLayer.Children.Add(halo);
        navigationControls = ViewControls();
        Children.Add(atmosphereLayer); Children.Add(viewport); Children.Add(dust); Children.Add(hint); Children.Add(navigationControls);
        viewport.Camera = camera;
        Build(); FitCamera();
        MouseLeftButtonDown += (_, e) =>
        {
            // A double-click zooms in on the place under the pointer.
            if (e.ClickCount == 2) { ZoomInAt(e.GetPosition(this)); e.Handled = true; return; }
            drag = pressed = e.GetPosition(this); CaptureMouse();
        };
        MouseLeftButtonUp += (_, e) =>
        {
            // A click, rather than a drag, picks the place under it.
            var released = e.GetPosition(this);
            if (picked is { } pick && pressed is Point start && (released - start).Length < 4 && PlaceAt(released) is { } place) pick(place.Latitude, place.Longitude);
            drag = pressed = null; ReleaseMouseCapture();
        };
        LostMouseCapture += (_, _) => drag = pressed = null;
        MouseMove += (_, e) => { if (drag is not Point p) return; var q = e.GetPosition(this); OrbitBy(q.X - p.X, q.Y - p.Y); drag = q; };
        SizeChanged += (_, _) => FitCamera();
        viewport.SizeChanged += (_, _) => FitCamera();
        MouseWheel += (_, e) => { ZoomBy(e.Delta); e.Handled = true; };
        Loaded += (_, _) => UpdateSubscription();
        Unloaded += (_, _) => Detach();
        IsVisibleChanged += (_, _) => UpdateSubscription();
    }
    public void SetEnvironment(AtlasBackground value) { environment = value; environment.Animate = Animate; environment.SetCamera(camera); Build(); FitCamera(); }
    public void SetTheme(string name, bool attack)
    {
        Theme = Themes.Contains(name) ? name : "Amethyst"; AttackView = attack;
        accent = WorldMapArtwork.Accent(Theme, IsLightAtlas);
        Build(); FitCamera();
    }
    /// <summary>Refreshes both projections after a resolved app-theme change, preserving cameras, routes and preferences.</summary>
    public void RefreshAppearance()
    {
        Dispatcher.VerifyAccess(); environment?.RefreshAppearance();
        if (disposed || IsLightAtlas == AppearanceTheme.IsLight) return;
        IsLightAtlas = AppearanceTheme.IsLight;
        accent = WorldMapArtwork.Accent(Theme, IsLightAtlas);
        dust.SetAppearance(IsLightAtlas);
        UpdateNavigationAppearance(); Build(); FitCamera();
    }
    public void SetPoints(IEnumerable<MapRoute> points)
    {
        var next = ValidPoints(points);
        if (endpoints.SequenceEqual(next)) return;
        endpoints = next; BuildRoutes(); UpdateParticles();
    }
    // The camera's distance from the globe's center at the starting zoom, farther for wide cards so the whole globe shows.
    private double GlobeReach => (observatory ? 3.65 : AttackView ? 4.5 : 3.9) * Math.Max(1, ActualWidth / Math.Max(1, ActualHeight));
    // The closest the camera comes, an eighth of the globe's radius above the ground: a few degrees across, about a city and its neighbors.
    private double MinimumGlobeZoom => .12 / (GlobeReach - 1);
    private double GlobeAltitude => (GlobeReach - 1) * Math.Max(zoom, MinimumGlobeZoom);
    // Routes and markers grow with the map as it zooms in, until here; closer than this they keep their size on screen.
    private double RouteScale => Projection == "Flat" ? Math.Min(1, flatZoom / .6) : Math.Min(1, GlobeAltitude / 1.75);
    private void FitCamera()
    {
        if (Projection == "Flat") FitFlatCamera();
        else
        {
            var distance = 1 + GlobeAltitude;
            var yaw = orbitYaw * Math.PI / 180; var pitch = orbitPitch * Math.PI / 180;
            camera.Position = new(distance * Math.Sin(yaw) * Math.Cos(pitch), distance * Math.Sin(pitch), distance * Math.Cos(yaw) * Math.Cos(pitch));
            camera.LookDirection = -(Vector3D)camera.Position; camera.NearPlaneDistance = Math.Min(.125, GlobeAltitude / 2);
            environment?.CameraChanged();
        }
        if (Math.Abs(RouteScale - routeScale) > 1e-3) { BuildRoutes(); UpdateParticles(); }
        UpdateAtmosphere();
        UpdateHint();
        if (navigationControls is not null) navigationControls.Visibility = ActualHeight < 180 ? Visibility.Collapsed : Visibility.Visible;
        UpdateDetail();
    }
    internal void OrbitBy(double dx, double dy)
    {
        if (Projection == "Flat") PanFlat(dx, dy);
        else
        {
            // Up close a drag carries the ground with the pointer; farther out it turns the globe faster than that, as it always has.
            var ground = GlobeAltitude * 2 * Math.Tan(camera.FieldOfView * Math.PI / 360) / Math.Max(1, viewport.ActualWidth) * 180 / Math.PI;
            var rate = Math.Min(.25, ground * (1 + 1.5 * Math.Min(1, GlobeAltitude / 2.9)));
            orbitYaw = (orbitYaw - dx * rate) % 360; orbitPitch = Math.Clamp(orbitPitch + dy * rate, -80, 80);
        }
        FitCamera();
    }
    internal void ZoomBy(double delta)
    {
        // Each wheel notch zooms by the same ratio, from the whole world down to a city and its neighbors.
        if (Projection == "Flat") { flatZoom = Math.Clamp(flatZoom * Math.Exp(-delta * .0012), MinimumFlatZoom, 1.8); homeFlat = false; }
        else zoom = Math.Clamp(zoom * Math.Exp(-delta * .0012), MinimumGlobeZoom, 1.9);
        FitCamera();
    }
    /// <summary>Centers the flat map on a place, or turns the globe to face it; a flat map closest in when asked.</summary>
    internal void LookAt(double latitude, double longitude, bool closest = false)
    {
        if (Projection == "Flat")
        {
            var point = AtlasProjection.Project(latitude, longitude);
            (flatPanX, flatPanY, homeFlat) = (AtlasProjection.Wrap(point.X), Math.Clamp(point.Y, -AtlasProjection.MaximumPanY, AtlasProjection.MaximumPanY), false);
            if (closest) flatZoom = MinimumFlatZoom;
        }
        else (orbitYaw, orbitPitch) = AtlasProjection.Facing(latitude, longitude, GlobeTurn, GlobeTilt);
        FitCamera();
    }
    /// <summary>Moves this PC's place and its marker, and the routes that start there; the view stays where it is.</summary>
    public void MoveOrigin(MapPlace place) { Origin = place; BuildRoutes(); UpdateParticles(); }
    /// <summary>Returns the view to its starting zoom, back on this PC's place.</summary>
    public void ResetOrbit()
    {
        if (Projection == "Flat") { flatZoom = 1; homeFlat = true; }
        else { (orbitYaw, orbitPitch) = AtlasProjection.Facing(Origin.Latitude, Origin.Longitude, GlobeTurn, GlobeTilt); zoom = 1; }
        FitCamera();
    }
    /// <summary>Whether the globe's camera looks straight at this PC's place, by WPF's own rotation of the globe; for captures.</summary>
    internal bool FacesOrigin()
    {
        var turned = new Transform3DGroup(); turned.Children.Add(new RotateTransform3D(rotation)); turned.Children.Add(new RotateTransform3D(tilt));
        var place = (Vector3D)turned.Transform(Position(Origin.Latitude, Origin.Longitude, 1)); place.Normalize();
        var look = (Vector3D)camera.Position; look.Normalize();
        return Vector3D.DotProduct(place, look) > .9999 || Math.Abs(orbitPitch) >= 80;
    }
    /// <summary>The globe's zoom, 1 at the starting view and halving with each double-click; for captures.</summary>
    internal double GlobeZoom => zoom;
    /// <summary>
    /// The place on the globe under a point: where a ray from the camera through it first meets the unit sphere, turned back
    /// by the globe's turn and tilt; null when the ray misses the globe.
    /// </summary>
    private (double Latitude, double Longitude)? GlobePlaceAt(Point point)
    {
        var forward = camera.LookDirection; forward.Normalize();
        var right = Vector3D.CrossProduct(forward, camera.UpDirection); right.Normalize();
        var up = Vector3D.CrossProduct(right, forward);
        // WPF's field of view spans the viewport's width.
        var half = Math.Tan(camera.FieldOfView * Math.PI / 360);
        var ray = forward + right * ((2 * point.X / viewport.ActualWidth - 1) * half) + up * ((1 - 2 * point.Y / viewport.ActualHeight) * half * viewport.ActualHeight / viewport.ActualWidth);
        ray.Normalize();
        var from = (Vector3D)camera.Position;
        var along = Vector3D.DotProduct(from, ray); var discriminant = along * along - (from.LengthSquared - 1);
        if (discriminant < 0 || -along - Math.Sqrt(discriminant) < 0) return null;
        var turned = new Transform3DGroup(); turned.Children.Add(new RotateTransform3D(rotation)); turned.Children.Add(new RotateTransform3D(tilt));
        if (turned.Inverse is not { } back) return null;
        var ground = back.Transform(camera.Position + ray * (-along - Math.Sqrt(discriminant)));
        return (Math.Asin(Math.Clamp(ground.Y, -1, 1)) * 180 / Math.PI, Math.Atan2(ground.X, ground.Z) * 180 / Math.PI);
    }
    /// <summary>Whether the flat map's view is centered east to west on this PC's place, and has it in its middle half north to south; for captures.</summary>
    internal bool CentersOriginFlat()
    {
        var point = AtlasProjection.Project(Origin.Latitude, Origin.Longitude);
        var halfHeight = flatCamera.Width / 2 * Math.Max(1, viewport.ActualHeight) / Math.Max(1, viewport.ActualWidth);
        return Math.Abs(AtlasProjection.Wrap(point.X - flatCamera.Position.X)) < 1e-9 && Math.Abs(point.Y - flatCamera.Position.Y) <= halfHeight / 2;
    }
    /// <summary>Zoom and reset buttons in the bottom-right corner, for when no scroll wheel is at hand. Each zoom step is two wheel notches.</summary>
    private StackPanel ViewControls()
    {
        var panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Bottom, Margin = new(0, 0, 14, 14) };
        foreach (var (glyph, name, action) in new (string, string, Action)[] { ("", "Zoom in", () => ZoomBy(240)), ("", "Zoom out", () => ZoomBy(-240)), ("", "Reset view", ResetOrbit) })
        {
            var button = new Button
            {
                Content = new TextBlock { Text = glyph, FontFamily = new FontFamily("Segoe Fluent Icons"), FontSize = 14 }, ToolTip = name,
                Width = 34, Height = 34, Padding = new(0), Margin = new(0, 6, 0, 0),
                Background = Ui.RawBrush(IsLightAtlas ? "#F2F8FCFF" : "#E0101927"), BorderBrush = Ui.RawBrush(IsLightAtlas ? "#94AEBF" : "#41506A"), Foreground = Ui.RawBrush(IsLightAtlas ? "#294B63" : "#E6EDF8")
            };
            System.Windows.Automation.AutomationProperties.SetName(button, name);
            button.Click += (_, _) => action();
            panel.Children.Add(button);
        }
        return panel;
    }
    private void UpdateNavigationAppearance()
    {
        if (navigationControls is null) return;
        foreach (var button in navigationControls.Children.OfType<Button>())
        {
            button.Background = Ui.RawBrush(IsLightAtlas ? "#F2F8FCFF" : "#E0101927");
            button.BorderBrush = Ui.RawBrush(IsLightAtlas ? "#94AEBF" : "#41506A");
            button.Foreground = Ui.RawBrush(IsLightAtlas ? "#294B63" : "#E6EDF8");
        }
    }
    private void Build()
    {
        particles.Clear(); waves.Clear(); viewport.Children.Clear(); world.Children.Clear(); ResetDetail();
        ConfigureProjection();
        if (Projection == "Flat") { BuildFlat(); return; }
        var transform = new Transform3DGroup(); transform.Children.Add(new RotateTransform3D(rotation)); transform.Children.Add(new RotateTransform3D(tilt)); world.Transform = transform;
        var root = new Model3DGroup();
        root.Children.Add(new AmbientLight(IsLightAtlas ? Color.FromRgb(196, 206, 218) : Color.FromRgb(180, 175, 200)));
        root.Children.Add(new DirectionalLight(IsLightAtlas ? Color.FromRgb(55, 58, 65) : Color.FromRgb(90, 85, 110), new(-2, -1, -3)));
        if (environment is not null && showBackground) root.Children.Add(environment.Bodies);
        world.Children.Add(GlobeSurface());
        world.Children.Add(routeModels); BuildRoutes();
        root.Children.Add(world); viewport.Children.Add(new ModelVisual3D { Content = root });
        UpdateParticles();
    }
    private void BuildRoutes()
    {
        particles.Clear(); waves.Clear(); overlays.Clear(); routeModels.Children.Clear(); routeScale = RouteScale;
        if (Projection == "Flat") { BuildFlatRoutes(); AddOverlays(); return; }
        // Reserve space for each observed direction so a busy outbound set cannot hide inbound traffic.
        var routes = endpoints.GroupBy(p => p.Direction).SelectMany(g => g.Take(10)).Take(32).ToList();
        var s = routeScale; var lift = 1 + .018 * s;
        if (routes.Count > 0)
        {
            // Routes start where Settings or Windows' region places this PC; nothing is looked up online.
            var origin = Position(Origin.Latitude, Origin.Longitude, lift);
            foreach (var endpoint in routes)
            {
                var target = Position(endpoint.Lat, endpoint.Lon, lift); var path = new Point3D[65];
                // Up close an arc rises with the ground it spans, so one to a nearby place stays in view.
                var span = Vector3D.AngleBetween((Vector3D)origin, (Vector3D)target) / 90;
                var rise = (AttackView ? .22 : .14) * Math.Min(1, span);
                var bendAxis = Vector3D.CrossProduct((Vector3D)origin, (Vector3D)target);
                if (bendAxis.Length < 1e-8) bendAxis = Vector3D.CrossProduct((Vector3D)origin,
                    Math.Abs(origin.Y) > .95 ? new(1, 0, 0) : new(0, 1, 0));
                bendAxis.Normalize();
                var bend = .14 * Math.Min(1, span);
                for (var i = 0; i < path.Length; i++)
                {
                    var t = i / 64.0; var v = (Vector3D)origin * (1 - t) + (Vector3D)target * t;
                    if (v.Length < .01) v += new Vector3D(0, .01, 0);
                    v.Normalize();
                    // A restrained lateral bend keeps schematic routes distinguishable when the camera faces their
                    // shared origin. Endpoints remain exact; these curves are not claims about a packet's geography.
                    v += bendAxis * (Math.Sin(Math.PI * t) * bend); v.Normalize();
                    path[i] = (Point3D)(v * (1 + .02 * s + Math.Sin(Math.PI * t) * rise));
                }
                var color = RouteColor(endpoint);
                if (atmosphereGlow && DecorativeEffects)
                {
                    var trail = new MeshGeometry3D(); AddTube(trail, path, (.0046 + effectIntensity * .002) * s);
                    overlays.Add(Model(trail, Color.FromArgb((byte)(10 + effectIntensity * 18), color.R, color.G, color.B)));
                }
                var arc = new MeshGeometry3D(); AddTube(arc, path, .0032 * s); routeModels.Children.Add(Model(arc, color));
                var dot = new MeshGeometry3D(); AddDot(dot, target, .013 * s); routeModels.Children.Add(Model(dot, color));
                if (routeParticles && DecorativeEffects && endpoint.Direction is TrafficDirection.Inbound or TrafficDirection.Outbound)
                {
                    if (endpoint.Direction == TrafficDirection.Inbound) Array.Reverse(path);
                    var moving = Model(Sphere((.007 + effectIntensity * .007) * s, 6, 8), color); var translation = new TranslateTransform3D(); moving.Transform = translation; routeModels.Children.Add(moving);
                    particles.Add((translation, t => SamplePath(path, t), particles.Count * .123));
                }
                var ring = new MeshGeometry3D(); var n = (Vector3D)target; n.Normalize(); var tangent = Vector3D.CrossProduct(n, Math.Abs(n.Y) > .95 ? new(1, 0, 0) : new(0, 1, 0)); tangent.Normalize(); var bitangent = Vector3D.CrossProduct(n, tangent);
                AddTube(ring, Enumerable.Range(0, 33).Select(j => target + tangent * (.027 * s * Math.Cos(j * Math.PI / 16)) + bitangent * (.027 * s * Math.Sin(j * Math.PI / 16))).ToArray(), .0011 * s);
                routeModels.Children.Add(Model(ring, color));
                AddEndpointWave(target, color, endpoint.Blocked, flat: false);
            }
        }
        // This PC's place is marked whether or not any route starts there.
        var home = new MeshGeometry3D(); AddDot(home, Position(Origin.Latitude, Origin.Longitude, lift), .016 * s);
        routeModels.Children.Add(Model(home, IsLightAtlas ? Color.FromRgb(34, 67, 91) : Color.FromRgb(236, 231, 255)));
        AddOverlays();
    }
    private TimeSpan lastFrame;
    private void UpdateSubscription()
    {
        if (!disposed && Animate && IsLoaded && IsVisible)
        {
            if (attached) return; lastFrame = clock.Elapsed; CompositionTarget.Rendering += Frame; attached = true;
        }
        else Detach();
    }
    private void Detach() { if (!attached) return; CompositionTarget.Rendering -= Frame; attached = false; }
    private void Frame(object? sender, EventArgs e)
    {
        var elapsed = clock.Elapsed; if (e is RenderingEventArgs && elapsed - lastFrame < TimeSpan.FromMilliseconds(32)) return;
        var dt = Math.Min((elapsed - lastFrame).TotalSeconds, .1); lastFrame = elapsed;
        if (!Animate || !IsVisible) return;
        sceneTime += dt; environment?.Advance(dt);
        // The globe's slow turn slows further up close, so it does not carry a place out of a narrow view.
        if (autoRotate && drag is null && Projection != "Flat") { orbitYaw -= dt * .6 * Math.Min(1, GlobeAltitude / 1.75); FitCamera(); }
        UpdateParticles();
    }
    internal void SampleAt(double seconds) { sceneTime = seconds; environment?.SampleAt(seconds); UpdateParticles(); }
    internal void ShowEarthForCapture(bool show)
    {
        if (viewport.Children[0] is not ModelVisual3D { Content: Model3DGroup root }) return;
        if (show && !root.Children.Contains(world)) root.Children.Add(world);
        else if (!show) root.Children.Remove(world);
    }
    private void UpdateParticles()
    {
        foreach (var (transform, position, offset) in particles)
        {
            var t = (sceneTime * .15 + offset) % 1;
            var p = position(t);
            transform.OffsetX = p.X; transform.OffsetY = p.Y; transform.OffsetZ = p.Z;
        }
        UpdateWaves();
        dust.SampleAt(sceneTime);
    }
    private static Point3D SamplePath(Point3D[] path, double t)
    {
        var segment = t * (path.Length - 1); var index = Math.Min(path.Length - 2, (int)segment);
        return path[index] + (path[index + 1] - path[index]) * (segment - index);
    }
    public void Dispose() { if (disposed) return; disposed = true; Detach(); ResetDetail(); environment = null; ProjectionChanged = null; viewport.Children.Clear(); }
    private static Point3D Position(double lat, double lon, double radius) { lat *= Math.PI / 180; lon *= Math.PI / 180; return new(radius * Math.Cos(lat) * Math.Sin(lon), radius * Math.Sin(lat), radius * Math.Cos(lat) * Math.Cos(lon)); }
    private GeometryModel3D Model(MeshGeometry3D mesh, Color color)
    {
        mesh.Freeze();
        // Diffuse ribbons preserve semantic hues without additive saturation; the scene supplies even ambient light.
        var brush = new SolidColorBrush(Color.FromRgb(color.R, color.G, color.B)) { Opacity = color.A / 255d };
        Material material = new DiffuseMaterial(brush);
        material.Freeze(); return new(mesh, material) { BackMaterial = material };
    }
    private static MeshGeometry3D Sphere(double radius, int stacks, int slices)
    {
        var mesh = new MeshGeometry3D();
        for (var i = 0; i <= stacks; i++) for (var j = 0; j <= slices; j++) { var p = Position(i * 180.0 / stacks - 90, j * 360.0 / slices, radius); mesh.Positions.Add(p); var n = (Vector3D)p; n.Normalize(); mesh.Normals.Add(n); mesh.TextureCoordinates.Add(new(j / (double)slices, i / (double)stacks)); }
        for (var i = 0; i < stacks; i++) for (var j = 0; j < slices; j++) { var a = i * (slices + 1) + j; Triangle(mesh, a, a + 1, a + slices + 1); Triangle(mesh, a + 1, a + slices + 2, a + slices + 1); }
        return mesh;
    }
    private static void Triangle(MeshGeometry3D m, int a, int b, int c) { m.TriangleIndices.Add(a); m.TriangleIndices.Add(b); m.TriangleIndices.Add(c); }
    private static void AddDot(MeshGeometry3D mesh, Point3D center, double radius)
    {
        var n = (Vector3D)center; n.Normalize(); var u = Vector3D.CrossProduct(n, Math.Abs(n.Y) > .95 ? new(1, 0, 0) : new(0, 1, 0)); u.Normalize(); var v = Vector3D.CrossProduct(n, u); var start = mesh.Positions.Count;
        mesh.Positions.Add(center + u * radius); mesh.Positions.Add(center + v * radius); mesh.Positions.Add(center - u * radius); mesh.Positions.Add(center - v * radius); Triangle(mesh, start, start + 1, start + 2); Triangle(mesh, start, start + 2, start + 3);
        AddQuadTexture(mesh);
    }
    private static void AddTube(MeshGeometry3D mesh, Point3D[] points, double radius)
    {
        for (var i = 0; i < points.Length - 1; i++)
        {
            var direction = points[i + 1] - points[i]; var side = Vector3D.CrossProduct(direction, (Vector3D)points[i]);
            if (side.Length < 1e-8) continue; side.Normalize(); side *= radius; var index = mesh.Positions.Count;
            mesh.Positions.Add(points[i] - side); mesh.Positions.Add(points[i] + side); mesh.Positions.Add(points[i + 1] + side); mesh.Positions.Add(points[i + 1] - side);
            AddQuadTexture(mesh);
            Triangle(mesh, index, index + 1, index + 2); Triangle(mesh, index, index + 2, index + 3);
        }
    }
    private static void AddQuadTexture(MeshGeometry3D mesh)
    {
        mesh.TextureCoordinates.Add(new(0, 0)); mesh.TextureCoordinates.Add(new(1, 0));
        mesh.TextureCoordinates.Add(new(1, 1)); mesh.TextureCoordinates.Add(new(0, 1));
    }
}

public sealed class Sparkline : FrameworkElement
{
    public List<double> Values { get; set; } = [];
    public Color Color { get; set; } = Color.FromRgb(183, 160, 255);
    /// <summary>The value at the top of the chart, so lines drawn over one another share a scale; unset, a fifth above the highest.</summary>
    public double? Scale { get; set; }
    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc); if (Values.Count < 2 || ActualHeight <= 0) return;
        var max = Scale ?? Math.Max(1, Values.Max() * 1.2); var geometry = new StreamGeometry(); var fill = new StreamGeometry();
        Point At(int i) => new(i * ActualWidth / (Values.Count - 1), ActualHeight - Values[i] / max * (ActualHeight - 7));
        using (var c = geometry.Open()) { c.BeginFigure(At(0), false, false); c.PolyLineTo(Enumerable.Range(1, Values.Count - 1).Select(At).ToArray(), true, false); }
        using (var c = fill.Open()) { c.BeginFigure(new(0, ActualHeight), true, true); c.PolyLineTo(Enumerable.Range(0, Values.Count).Select(At).Append(new Point(ActualWidth, ActualHeight)).ToArray(), true, false); }
        dc.DrawGeometry(new LinearGradientBrush(Color.FromArgb(40, Color.R, Color.G, Color.B), Colors.Transparent, 90), null, fill);
        dc.DrawGeometry(null, new Pen(new SolidColorBrush(Color), 1.7), geometry);
    }
}
