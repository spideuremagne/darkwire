using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;

namespace Darkwire.Host;

/// <summary>Earth-centered environment, driven by the globe's camera and frame clock.</summary>
public sealed class AtlasBackground : FrameworkElement, IDisposable
{
    public static readonly string[] Presets = ["Space", "Clouds"];
    public static readonly string[] CloudDirections = ["Left", "Right", "Up", "Down"];
    public Model3DGroup Bodies { get; } = new();
    private readonly Model3DGroup solar = new(), ships = new();
    private readonly GeometryModel3D cloudShell, moon;
    private readonly List<(GeometryModel3D Model, string Dark, string Light, double Gloss, bool Emissive)> themedModels = [];
    private readonly AxisAngleRotation3D cloudScroll = new(new(0, 1, 0), 0);
    private readonly TranslateTransform3D moonPosition = new();
    private readonly AxisAngleRotation3D moonRotation = new(new(0, 1, 0), 0);
    private readonly List<(TranslateTransform3D Position, AxisAngleRotation3D Bank, AxisAngleRotation3D Spin)> flights = [];
    private readonly Star[] stars;
    private PerspectiveCamera? camera;
    private bool disposed, sunMoon = true, ufos, observatory, atmosphereGlow = true;
    private bool lightAppearance, highContrast, appearanceReady;
    private Color systemBackground, systemForeground;
    private Brush contrastBackground = Brushes.Transparent;
    private double effectIntensity = .45;
    private double sceneTime, cloudTime;
    private string preset, cloudDirection;
    private static readonly Point3D SunPosition = new(-9, 5, -34);
    private static readonly Brush Space = FrozenBrush("#080B16"), DaySpace = Daylight(), White = FrozenBrush("#D8DFFB"), DayStar = FrozenBrush("#64859E");
    private static readonly Brush StarGlow = Glow("#A7BCFF", 80), SunGlow = Glow("#FFB65A", 165);
    private static readonly Brush ObservatoryBlue = Glow("#356A99", 58), ObservatoryViolet = Glow("#665390", 32);
    private static readonly Brush DaySunGlow = Glow("#C69A46", 65), DayObservatoryBlue = Glow("#73ACC9", 38), DayObservatoryViolet = Glow("#A5ACD4", 24);
    private static readonly Lazy<ImageBrush> MoonTexture = new(() => CreateMoonTexture(false)), DayMoonTexture = new(() => CreateMoonTexture(true));
    private static readonly Lazy<ImageBrush> CloudTexture = new(() => CreateCloudTexture(false)), DayCloudTexture = new(() => CreateCloudTexture(true));
    private readonly record struct Star(Point3D Position, double Radius, double Phase);

    public AtlasBackground(string preset = "Space", string direction = "Left", bool animate = true, bool sunMoon = true, bool ufos = false)
    {
        this.preset = NormalizePreset(preset); cloudDirection = NormalizeDirection(direction);
        lightAppearance = AppearanceTheme.IsLight;
        Animate = animate; this.sunMoon = sunMoon; this.ufos = ufos;
        IsHitTestVisible = false; ClipToBounds = true; Focusable = false;
        var random = new Random(44017);
        stars = Enumerable.Range(0, 4200).Select(_ =>
        {
            var y = random.NextDouble() * 2 - 1; var angle = random.NextDouble() * Math.Tau;
            var radius = 180 + random.NextDouble() * 240; var ring = Math.Sqrt(1 - y * y);
            return new Star(new(radius * ring * Math.Cos(angle), radius * y, radius * ring * Math.Sin(angle)),
                .4 + Math.Pow(random.NextDouble(), 6) * 1.65, random.NextDouble() * Math.Tau);
        }).ToArray();
        var sun = ThemedSolid(AtlasGeometry.Sphere(1.3), "#FFE6AE", "#BF913F", emissive: true);
        sun.Transform = new TranslateTransform3D((Vector3D)SunPosition); solar.Children.Add(sun);
        moon = AtlasGeometry.Solid(AtlasGeometry.Sphere(.27), lightAppearance ? DayMoonTexture.Value : MoonTexture.Value, 0);
        var moonTransform = new Transform3DGroup(); moonTransform.Children.Add(new RotateTransform3D(moonRotation)); moonTransform.Children.Add(moonPosition);
        moon.Transform = moonTransform; solar.Children.Add(moon);
        BuildShip(.17); BuildShip(.12);
        cloudShell = AtlasGeometry.Solid(AtlasGeometry.Sphere(800, 40, 80), lightAppearance ? DayCloudTexture.Value : CloudTexture.Value, emissive: true);
        cloudShell.Transform = new RotateTransform3D(cloudScroll);
        RefreshAppearance(); RefreshBodies(); UpdateMotion();
    }

    public string Preset { get => preset; set { preset = NormalizePreset(value); RefreshBodies(); } }
    public string CloudDirection { get => cloudDirection; set { cloudDirection = NormalizeDirection(value); cloudTime = 0; UpdateMotion(); } }
    public bool SunMoon { get => sunMoon; set { sunMoon = value; RefreshBodies(); } }
    public bool Ufos { get => ufos; set { ufos = value; RefreshBodies(); } }
    public bool Animate { get; set; }
    /// <summary>Recolors the existing environment without replacing its camera, orbit, clock or saved options.</summary>
    public void RefreshAppearance()
    {
        Dispatcher.VerifyAccess();
        if (disposed) return;
        var light = AppearanceTheme.IsLight; var contrast = SystemParameters.HighContrast;
        var background = SystemColors.WindowColor; var foreground = SystemColors.WindowTextColor;
        if (appearanceReady && lightAppearance == light && highContrast == contrast &&
            (!contrast || systemBackground == background && systemForeground == foreground)) return;
        appearanceReady = true; lightAppearance = light; highContrast = contrast;
        systemBackground = background; systemForeground = foreground;
        contrastBackground = FrozenBrush(background.ToString());
        foreach (var (model, dark, day, gloss, emissive) in themedModels)
            SetMaterial(model, FrozenBrush(contrast ? foreground.ToString() : light ? day : dark), gloss, emissive);
        SetMaterial(moon, contrast ? FrozenBrush(foreground.ToString()) : light ? DayMoonTexture.Value : MoonTexture.Value);
        SetMaterial(cloudShell, contrast ? contrastBackground : light ? DayCloudTexture.Value : CloudTexture.Value, emissive: true);
        InvalidateVisual();
    }
    public void ConfigureEffects(AppState state)
    {
        observatory = state.AtlasPresentation == "Observatory"; atmosphereGlow = state.AtmosphereGlow;
        effectIntensity = Math.Clamp(state.EffectIntensity, 0, 100) / 100d;
        InvalidateVisual();
    }
    public static string NormalizePreset(string? value) => value == "Clouds" ? "Clouds" : "Space";
    public static string NormalizeDirection(string? value) => CloudDirections.Contains(value, StringComparer.Ordinal) ? value! : "Left";
    public static void NormalizeSettings(AppState state)
    {
        // Retain the previous four-preset preferences when upgrading to two environments.
        if (state.BackgroundPreset == "Stars") { state.SpaceSunMoon = false; state.SpaceUfos = false; }
        else if (state.BackgroundPreset == "Solar system") { state.SpaceSunMoon = true; state.SpaceUfos = false; }
        else if (state.BackgroundPreset == "UFOs") { state.SpaceSunMoon = false; state.SpaceUfos = true; }
        state.BackgroundPreset = NormalizePreset(state.BackgroundPreset);
        state.CloudDirection = NormalizeDirection(state.CloudDirection);
    }

    internal void SetCamera(PerspectiveCamera value) { camera = value; InvalidateVisual(); }
    internal void CameraChanged() => InvalidateVisual();
    internal void Advance(double seconds)
    {
        if (disposed || !Animate) return;
        sceneTime += seconds; cloudTime += seconds; UpdateMotion(); InvalidateVisual();
    }
    // Deterministic capture samples independent motion without depending on machine rendering speed.
    internal void SampleAt(double seconds) { sceneTime = cloudTime = seconds; UpdateMotion(); InvalidateVisual(); }

    private void RefreshBodies()
    {
        Bodies.Children.Clear();
        if (!disposed)
        {
            if (preset == "Clouds") Bodies.Children.Add(cloudShell);
            else { if (sunMoon) Bodies.Children.Add(solar); if (ufos) Bodies.Children.Add(ships); }
        }
        InvalidateVisual();
    }

    private void UpdateMotion()
    {
        var phase = .32 + sceneTime * .075;
        moonPosition.OffsetX = Math.Cos(phase) * 1.95;
        moonPosition.OffsetY = .25 + Math.Sin(phase) * .7;
        moonPosition.OffsetZ = -Math.Sin(phase) * 1.95;
        moonRotation.Angle = -phase * 180 / Math.PI;
        for (var i = 0; i < flights.Count; i++)
        {
            var (position, bank, spin) = flights[i]; var t = sceneTime * (.2 - i * .04) + 2.65 + i * Math.PI;
            var radius = 1.65 + i * .25; var inclination = (22 + i * 13) * Math.PI / 180;
            // Circular, inclined orbits keep the entire hull clear of Earth. Shared depth testing
            // naturally hides a craft on the far side; no screen-space wrapping or fake occlusion.
            position.OffsetX = Math.Cos(t) * radius;
            position.OffsetY = Math.Sin(t) * Math.Sin(inclination) * radius;
            position.OffsetZ = Math.Sin(t) * Math.Cos(inclination) * radius;
            bank.Angle = -10 + Math.Sin(t) * 10; spin.Angle = sceneTime * 24 + i * 70;
        }
        cloudScroll.Axis = cloudDirection is "Up" or "Down" ? new(1, 0, 0) : new(0, 1, 0);
        cloudScroll.Angle = cloudTime * (cloudDirection is "Right" or "Down" ? -.9 : .9);
    }

    private void BuildShip(double scale)
    {
        var ship = new Model3DGroup();
        ship.Children.Add(ThemedSolid(AtlasGeometry.Lathe(new(0, -.16), new(.15, -.14), new(.36, -.065), new(.48, -.015), new(.49, .025), new(.42, .06), new(.25, .13), new(.13, .15), new(0, .15)), "#536378", "#647C8E", 100));
        ship.Children.Add(ThemedSolid(AtlasGeometry.Torus(.467, .015, .005), "#6CDCCD", "#287D84", emissive: true));
        ship.Children.Add(ThemedSolid(AtlasGeometry.Torus(.24, .008, .13), "#CBD3E0", "#DCE4E9", 80));
        ship.Children.Add(ThemedSolid(AtlasGeometry.Torus(.17, .015, -.12), "#68D6FA", "#287B9D", emissive: true));
        var dome = ThemedSolid(AtlasGeometry.Sphere(.195, 20, 40), "#233C5B", "#385B75", 130);
        var domeTransform = new Transform3DGroup(); domeTransform.Children.Add(new ScaleTransform3D(1, .82, 1)); domeTransform.Children.Add(new TranslateTransform3D(0, .13, 0)); dome.Transform = domeTransform; ship.Children.Add(dome);
        for (var i = 0; i < 12; i++)
        {
            var angle = i * Math.Tau / 12; var lamp = ThemedSolid(AtlasGeometry.Sphere(.019, 6, 8), i % 3 == 0 ? "#FFB885" : "#B7FFF0", i % 3 == 0 ? "#A47438" : "#227D79", emissive: true);
            lamp.Transform = new TranslateTransform3D(Math.Cos(angle) * .4, .066, Math.Sin(angle) * .4); ship.Children.Add(lamp);
        }
        var spin = new AxisAngleRotation3D(new(0, 1, 0), 0); var bank = new AxisAngleRotation3D(new(0, 0, 1), 0); var translation = new TranslateTransform3D();
        var transform = new Transform3DGroup(); transform.Children.Add(new ScaleTransform3D(scale, scale, scale));
        transform.Children.Add(new RotateTransform3D(spin)); transform.Children.Add(new RotateTransform3D(new AxisAngleRotation3D(new(1, 0, 0), 18)));
        transform.Children.Add(new RotateTransform3D(bank)); transform.Children.Add(translation); ship.Transform = transform;
        ships.Children.Add(ship); flights.Add((translation, bank, spin));
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc); var w = ActualWidth; var h = ActualHeight;
        if (disposed || w <= 0 || h <= 0) return;
        dc.DrawRectangle(highContrast ? contrastBackground : lightAppearance ? DaySpace : Space, null, new(0, 0, w, h));
        if (highContrast || preset != "Space" || camera is null) return;
        if (observatory && atmosphereGlow && effectIntensity > 0)
        {
            dc.PushOpacity(.3 + effectIntensity * .7);
            dc.DrawEllipse(lightAppearance ? DayObservatoryBlue : ObservatoryBlue, null, new(w * .38, h * .22), w * .65, h * .85);
            dc.DrawEllipse(lightAppearance ? DayObservatoryViolet : ObservatoryViolet, null, new(w * .82, h * .78), w * .46, h * .65);
            dc.Pop();
        }
        var forward = camera.LookDirection; forward.Normalize();
        var right = Vector3D.CrossProduct(forward, camera.UpDirection); right.Normalize(); var up = Vector3D.CrossProduct(right, forward);
        var focal = w / (2 * Math.Tan(camera.FieldOfView * Math.PI / 360));
        bool Project(Point3D point, out Point screen, out double depth)
        {
            var v = point - camera.Position; depth = Vector3D.DotProduct(v, forward);
            if (depth <= .1) { screen = default; return false; }
            screen = new(w / 2 + focal * Vector3D.DotProduct(v, right) / depth, h / 2 - focal * Vector3D.DotProduct(v, up) / depth); return true;
        }
        foreach (var star in stars)
        {
            if (lightAppearance && star.Phase < Math.PI * 1.25) continue;
            if (!Project(star.Position, out var center, out _) || center.X < -8 || center.X > w + 8 || center.Y < -8 || center.Y > h + 8) continue;
            var twinkle = .5 + .5 * Math.Sin(sceneTime * 1.1 + star.Phase);
            dc.PushOpacity(lightAppearance ? .16 + .16 * twinkle : .38 + .35 * twinkle);
            if (!lightAppearance && star.Radius > 1.45) dc.DrawEllipse(StarGlow, null, center, 6, 6);
            var radius = lightAppearance ? Math.Min(star.Radius, 1.15) : star.Radius;
            dc.DrawEllipse(lightAppearance ? DayStar : White, null, center, radius, radius); dc.Pop();
        }
        if (sunMoon && Project(SunPosition, out var sun, out var distance))
        {
            var radius = focal * 1.3 / distance;
            dc.DrawEllipse(lightAppearance ? DaySunGlow : SunGlow, null, sun, radius * (lightAppearance ? 3.4 : 4.8), radius * (lightAppearance ? 3.4 : 4.8));
        }
    }

    private static ImageBrush CreateCloudTexture(bool light)
    {
        const int w = 2048, h = 1024;
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawRectangle(FrozenBrush(light ? "#E4EDF3" : "#101629"), null, new(0, 0, w, h));
            var random = new Random(7151); var colors = light ? new[] { "#FFFFFF", "#C4DAE7", "#D6E5EC", "#BFD6E1", "#EAF4F7" } : new[] { "#6854AE", "#326282", "#854D88", "#38676F", "#553E80" };
            for (var i = 0; i < 420; i++)
            {
                var x = random.NextDouble() * w; var y = random.NextDouble() * h;
                var radius = 35 + random.NextDouble() * 100; var brush = Glow(colors[i % colors.Length], 125);
                // Longitude repeats; pole-adjacent clouds remain smooth on the inside of the sky sphere.
                for (var tile = -1; tile <= 1; tile++) dc.DrawEllipse(brush, null, new(x + tile * w, y), radius, radius * .6);
            }
        }
        return Texture(visual, w, h);
    }
    private static ImageBrush CreateMoonTexture(bool light)
    {
        const int w = 768, h = 384; var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawRectangle(FrozenBrush(light ? "#9AACB8" : "#B8BBC9"), null, new(0, 0, w, h));
            var random = new Random(1997);
            for (var i = 0; i < 370; i++)
            {
                var center = new Point(random.NextDouble() * w, random.NextDouble() * h); var radius = 2 + Math.Pow(random.NextDouble(), 3) * 45;
                dc.DrawEllipse(Glow(light ? "#647887" : "#4B5266", light ? (byte)65 : (byte)95), null, center, radius * 1.6, radius);
                dc.DrawEllipse(null, new Pen(FrozenBrush("#35E4E7EF"), 1), center, radius, radius * .65);
            }
        }
        return Texture(visual, w, h);
    }
    private static ImageBrush Texture(DrawingVisual visual, int width, int height)
    {
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual); bitmap.Freeze();
        var brush = new ImageBrush(bitmap); brush.Freeze(); return brush;
    }
    private static Brush FrozenBrush(string color) { var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)); brush.Freeze(); return brush; }
    private static Brush Daylight()
    {
        var brush = new LinearGradientBrush((Color)ColorConverter.ConvertFromString("#F5FAFC"), (Color)ColorConverter.ConvertFromString("#DFEAF3"), 90);
        brush.Freeze(); return brush;
    }
    private GeometryModel3D ThemedSolid(MeshGeometry3D mesh, string dark, string light, double gloss = 0, bool emissive = false)
    {
        var model = AtlasGeometry.Solid(mesh, FrozenBrush(lightAppearance ? light : dark), gloss, emissive);
        themedModels.Add((model, dark, light, gloss, emissive)); return model;
    }
    private static void SetMaterial(GeometryModel3D model, Brush brush, double gloss = 0, bool emissive = false)
    {
        var material = new MaterialGroup();
        material.Children.Add(emissive ? new EmissiveMaterial(brush) : new DiffuseMaterial(brush));
        if (gloss > 0) material.Children.Add(new SpecularMaterial(Brushes.White, gloss));
        material.Freeze(); model.Material = model.BackMaterial = material;
    }
    private static Brush Glow(string color, byte alpha)
    {
        var tint = (Color)ColorConverter.ConvertFromString(color); tint.A = alpha;
        var brush = new RadialGradientBrush(tint, Color.FromArgb(0, tint.R, tint.G, tint.B));
        brush.GradientStops.Insert(1, new(Color.FromArgb((byte)(alpha / 3), tint.R, tint.G, tint.B), .48)); brush.Freeze(); return brush;
    }
    public void Dispose() { if (disposed) return; disposed = true; camera = null; Bodies.Children.Clear(); }
}
