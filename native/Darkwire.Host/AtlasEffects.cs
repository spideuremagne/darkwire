using System.Windows.Media.Media3D;

namespace Darkwire.Host;

public sealed partial class GlobeView
{
    private bool observatory, routeParticles = true, endpointRipples = true, policyShockwaves = true, atmosphereGlow = true, autoRotate = true;
    private double effectIntensity = .45;
    private Color? atmosphereColor;
    private readonly List<AtlasWave> waves = [];
    // Translucent glow and rings, added after every opaque route part: WPF draws 3D models in order and each writes depth,
    // so one drawn first hides whatever comes later behind it, as a trail on its arc's own path cut the arc into dashes.
    private readonly List<Model3D> overlays = [];
    private readonly AtlasDust dust = new();
    private readonly Canvas atmosphereLayer = new() { IsHitTestVisible = false, ClipToBounds = true };
    private sealed record AtlasWave(ScaleTransform3D Scale, SolidColorBrush Brush, double Offset, bool Policy);

    /// <summary>Applies the saved visual preferences to either projection without moving the user's camera.</summary>
    public void ConfigureEffects(AppState state)
    {
        var next = (state.AtlasPresentation == "Observatory", state.RouteParticles, state.EndpointRipples,
            state.PolicyShockwaves, state.AtmosphereGlow, state.AutoRotateGlobe, Math.Clamp(state.EffectIntensity, 0, 100) / 100d);
        var previous = (observatory, routeParticles, endpointRipples, policyShockwaves, atmosphereGlow, autoRotate, effectIntensity);
        (observatory, routeParticles, endpointRipples, policyShockwaves, atmosphereGlow, autoRotate, effectIntensity) = next;
        Animate = Ui.MotionEnabled(state);
        environment?.ConfigureEffects(state);
        dust.Configure(state.AmbientParticles, effectIntensity, observatory);
        dust.SetAppearance(IsLightAtlas);
        if (previous != next) { BuildRoutes(); UpdateParticles(); FitCamera(); }
        UpdateAtmosphere();
    }

    private bool DecorativeEffects => effectIntensity > 0;
    internal (int Particles, int Ripples, int Shockwaves) EffectCounts =>
        (particles.Count, waves.Count(w => !w.Policy), waves.Count(w => w.Policy));
    internal bool AtmosphereVisible => halo?.Visibility == Visibility.Visible && halo.Opacity > 0;

    private void UpdateAtmosphere()
    {
        if (halo is null) return;
        halo.Visibility = Projection == "Flat" || !atmosphereGlow || !DecorativeEffects ? Visibility.Collapsed : Visibility.Visible;
        if (halo.Visibility != Visibility.Visible) return;
        var reach = ((Vector3D)camera.Position).Length;
        var focal = Math.Max(1, viewport.ActualWidth) / (2 * Math.Tan(camera.FieldOfView * Math.PI / 360));
        var radius = focal / Math.Sqrt(Math.Max(.01, reach * reach - 1));
        // The luminous edge sits just beyond the actual globe silhouette at every zoom and card size.
        halo.Width = halo.Height = Math.Min(9000, radius * 2.42);
        Canvas.SetLeft(halo, (ActualWidth - halo.Width) / 2);
        Canvas.SetTop(halo, (ActualHeight - halo.Height) / 2);
        halo.Opacity = (.25 + effectIntensity * .65) * (observatory ? 1 : .65) * (IsLightAtlas ? .3 : 1);
        var color = IsLightAtlas ? Color.FromRgb(67, 133, 170) : observatory ? Color.FromRgb(117, 195, 242) : accent;
        if (atmosphereColor == color) return;
        atmosphereColor = color;
        var glow = new RadialGradientBrush { Center = new(.5, .5), GradientOrigin = new(.5, .5), RadiusX = .5, RadiusY = .5 };
        glow.GradientStops.Add(new(Color.FromArgb(0, color.R, color.G, color.B), 0));
        glow.GradientStops.Add(new(Color.FromArgb(0, color.R, color.G, color.B), .75));
        glow.GradientStops.Add(new(Color.FromArgb(145, color.R, color.G, color.B), .826));
        glow.GradientStops.Add(new(Color.FromArgb(30, color.R, color.G, color.B), .90));
        glow.GradientStops.Add(new(Color.FromArgb(0, color.R, color.G, color.B), 1));
        glow.Freeze(); halo.Fill = glow;
    }

    private void AddEndpointWave(Point3D center, Color color, bool policy, bool flat)
    {
        if (!DecorativeEffects || (policy ? !policyShockwaves : !endpointRipples)) return;
        var s = routeScale;
        var mesh = new MeshGeometry3D();
        var radius = (policy ? .042 : .028) * s;
        if (flat)
        {
            center.Z += .003;
            AddPlanarLine(mesh, Enumerable.Range(0, 49).Select(i => center + new Vector3D(
                radius * Math.Cos(i * Math.Tau / 48), radius * Math.Sin(i * Math.Tau / 48), 0)).ToArray(), .0012 * s);
        }
        else
        {
            var normal = (Vector3D)center; normal.Normalize();
            center += normal * .002;
            var tangent = Vector3D.CrossProduct(normal, Math.Abs(normal.Y) > .95 ? new(1, 0, 0) : new(0, 1, 0)); tangent.Normalize();
            var bitangent = Vector3D.CrossProduct(normal, tangent);
            AddTube(mesh, Enumerable.Range(0, 49).Select(i => center + tangent * (radius * Math.Cos(i * Math.Tau / 48))
                + bitangent * (radius * Math.Sin(i * Math.Tau / 48))).ToArray(), .0012 * s);
        }
        mesh.Freeze();
        var brush = new SolidColorBrush(color);
        Material material = new DiffuseMaterial(brush);
        var scale = new ScaleTransform3D(1, 1, 1, center.X, center.Y, center.Z);
        overlays.Add(new GeometryModel3D(mesh, material) { BackMaterial = material, Transform = scale });
        waves.Add(new(scale, brush, waves.Count * .173, policy));
    }

    private void AddOverlays()
    {
        foreach (var overlay in overlays) routeModels.Children.Add(overlay);
        overlays.Clear();
    }

    private void UpdateWaves()
    {
        foreach (var wave in waves)
        {
            // These are visual markers for currently shown routes, not a count or time of policy events.
            var phase = (sceneTime / (wave.Policy ? 5.6 : 4.5) + wave.Offset) % 1;
            var progress = Math.Min(1, phase / .82);
            var scale = .55 + progress * (wave.Policy ? 3.2 : 2.2);
            wave.Scale.ScaleX = wave.Scale.ScaleY = wave.Scale.ScaleZ = scale;
            wave.Brush.Opacity = Math.Pow(1 - progress, 1.8) * (.12 + effectIntensity * .68);
        }
    }

    /// <summary>Decorative suspended dust. It never encodes a connection, a direction, or an event.</summary>
    private sealed class AtlasDust : FrameworkElement
    {
        private readonly (double X, double Y, double Radius, double Phase)[] specks;
        private Brush tint = Ui.RawBrush("#BED8EF");
        private bool enabled;
        private double intensity, time;
        private int count;

        internal AtlasDust()
        {
            IsHitTestVisible = false; Focusable = false; ClipToBounds = true;
            var random = new Random(18951);
            specks = Enumerable.Range(0, 52).Select(_ => (random.NextDouble(), random.NextDouble(),
                .45 + random.NextDouble() * 1.1, random.NextDouble() * Math.Tau)).ToArray();
        }
        internal void Configure(bool show, double strength, bool cinematic)
        {
            enabled = show && strength > 0; intensity = strength; count = cinematic ? 52 : 28;
            Visibility = enabled ? Visibility.Visible : Visibility.Collapsed; InvalidateVisual();
        }
        internal void SetAppearance(bool light) { tint = Ui.RawBrush(light ? "#3D6B8C" : "#BED8EF"); InvalidateVisual(); }
        internal void SampleAt(double seconds) { time = seconds; if (enabled) InvalidateVisual(); }
        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);
            if (!enabled || ActualWidth <= 0 || ActualHeight <= 0) return;
            for (var i = 0; i < count; i++)
            {
                var speck = specks[i];
                var x = (speck.X + time * .0018 * (1 + i % 3)) % 1;
                var y = (speck.Y + time * .0008 + .004 * Math.Sin(time * .17 + speck.Phase)) % 1;
                if (y < 0) y += 1;
                dc.PushOpacity((.045 + intensity * .14) * (.65 + .35 * Math.Sin(time * .3 + speck.Phase)));
                dc.DrawEllipse(tint, null, new(x * ActualWidth, y *ActualHeight), speck.Radius, speck.Radius); dc.Pop();
            }
        }
    }
}
