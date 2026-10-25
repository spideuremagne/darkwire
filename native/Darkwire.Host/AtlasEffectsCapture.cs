using System.Text.Json;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    /// <summary>Deterministic checks of independent visual effects on real WPF render surfaces.</summary>
    private async Task VerifyAtlasEffects(string output)
    {
        if (activeGlobe is not { } globe || activeAtlasBackground is not { } background) return;
        var projection = globe.Projection;
        var checks = new Dictionary<string, bool>();
        var settings = new AppState
        {
            AtlasPresentation = "Observatory", RouteParticles = true, EndpointRipples = true,
            PolicyShockwaves = true, AmbientParticles = true, AtmosphereGlow = true,
            EffectIntensity = 70, AutoRotateGlobe = false
        };
        MapRoute[] routes = [new(51.5, -.12, false, TrafficDirection.Outbound),
            new(40.7, -74, true, TrafficDirection.Inbound), new(35.7, 139.7, false, TrafficDirection.Unknown)];
        async Task<byte[]> Frame()
        {
            await globe.DetailSettled();
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
            var width = (int)globe.ActualWidth; var height = (int)globe.ActualHeight;
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(globe);
            var pixels = new byte[width * height * 4]; bitmap.CopyPixels(pixels, width * 4, 0); return pixels;
        }
        static bool Equal(byte[] a, byte[] b) => a.AsSpan().SequenceEqual(b);
        try
        {
            background.Preset = "Space"; background.SunMoon = background.Ufos = false;
            foreach (var view in new[] { "Globe", "Flat" })
            {
                globe.SetProjection(view); globe.ResetOrbit(); globe.SetPoints(routes);
                settings.RouteParticles = settings.EndpointRipples = settings.PolicyShockwaves = settings.AtmosphereGlow = true;
                settings.EffectIntensity = 70; settings.ReducedMotion = false;
                globe.ConfigureEffects(settings); globe.Animate = false; globe.SampleAt(0);
                checks[view + "OnlyKnownDirectionsHaveParticles"] = globe.EffectCounts == (2, 2, 1);
                checks[view + "AtmosphereUsesGlobeOnly"] = globe.AtmosphereVisible == (view == "Globe");
                var first = await Frame(); globe.SampleAt(1.25);
                checks[view + "EffectsMoveWithoutCameraRotation"] = !Equal(first, await Frame());
                checks[view + "CameraRemainsAtOrigin"] = view == "Flat" ? globe.CentersOriginFlat() : globe.FacesOrigin();
                SaveAtlasFrame(Path.Combine(output, "Atlas-Observatory-" + view + ".png"));

                settings.RouteParticles = false; globe.ConfigureEffects(settings); globe.Animate = false;
                checks[view + "ParticlesToggleIndependently"] = globe.EffectCounts == (0, 2, 1);
                settings.EndpointRipples = false; globe.ConfigureEffects(settings); globe.Animate = false;
                checks[view + "RipplesToggleIndependently"] = globe.EffectCounts == (0, 0, 1);
                settings.PolicyShockwaves = false; globe.ConfigureEffects(settings); globe.Animate = false;
                checks[view + "ShockwavesToggleIndependently"] = globe.EffectCounts == (0, 0, 0);
                settings.AtmosphereGlow = false; globe.ConfigureEffects(settings); globe.Animate = false;
                checks[view + "AtmosphereCanBeDisabled"] = !globe.AtmosphereVisible;

                settings.RouteParticles = settings.EndpointRipples = settings.PolicyShockwaves = settings.AtmosphereGlow = true;
                settings.EffectIntensity = 0; globe.ConfigureEffects(settings); globe.Animate = false;
                checks[view + "ZeroIntensityRemovesDecoration"] = globe.EffectCounts == (0, 0, 0) && !globe.AtmosphereVisible;
                settings.EffectIntensity = 100; settings.ReducedMotion = true; globe.ConfigureEffects(settings);
                checks[view + "ReducedMotionDisablesFrameClock"] = !globe.Animate;
                var frozen = await Frame(); await Task.Delay(160);
                checks[view + "ReducedMotionFreezesAllEffects"] = Equal(frozen, await Frame());

                // Glow may tint a route but never cut it: a translucent trail drawn before the arc on its own path hid the
                // arc wherever the depth test fell its way, leaving the globe's arcs dashed.
                settings.RouteParticles = settings.EndpointRipples = settings.PolicyShockwaves = settings.AtmosphereGlow = false;
                globe.ConfigureEffects(settings); globe.SampleAt(0);
                var bare = RedPixels(await Frame());
                settings.AtmosphereGlow = true; globe.ConfigureEffects(settings); globe.SampleAt(0);
                checks[view + "GlowKeepsRoutesWhole"] = bare > 0 && RedPixels(await Frame()) >= bare;
            }
        }
        finally
        {
            globe.SetProjection(projection); globe.ConfigureEffects(state); globe.SetPoints(MapPoints());
            background.Preset = state.BackgroundPreset; background.SunMoon = state.SpaceSunMoon; background.Ufos = state.SpaceUfos;
        }
        File.WriteAllText(Path.Combine(output, "atlas-effects-check.json"), JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
        if (checks.Values.Any(passed => !passed)) throw new InvalidOperationException("Atlas effects failed: " + string.Join(", ", checks.Where(c => !c.Value).Select(c => c.Key)));
        await VerifyAtlasPalette(output);
    }

    private async Task VerifyAtlasPalette(string output)
    {
        if (activeGlobe is not { } globe || activeAtlasBackground is not { } background) return;
        var checks = new Dictionary<string, bool>();
        var savedProjection = globe.Projection; var savedTheme = globe.Theme;
        var savedPreset = background.Preset; var savedSun = background.SunMoon; var savedUfos = background.Ufos;
        var settings = new AppState { ReducedMotion = true, RouteParticles = false, EndpointRipples = false,
            PolicyShockwaves = false, AmbientParticles = false, AtmosphereGlow = false, AutoRotateGlobe = false };
        static byte[] Pixels(BitmapSource bitmap)
        {
            var pixels = new byte[bitmap.PixelWidth * bitmap.PixelHeight * 4]; bitmap.CopyPixels(pixels, bitmap.PixelWidth * 4, 0); return pixels;
        }
        async Task<byte[]> Frame()
        {
            await globe.DetailSettled(); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
            var bitmap = new RenderTargetBitmap((int)globe.ActualWidth, (int)globe.ActualHeight, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(globe); return Pixels(bitmap);
        }
        static byte[] OceanSample(ImageBrush image)
        {
            var pixel = new byte[4]; ((BitmapSource)image.ImageSource).CopyPixels(new Int32Rect(100, 1009, 1, 1), pixel, 4, 0); return pixel;
        }
        async Task<BitmapSource?> Detail(bool light)
        {
            var completion = new TaskCompletionSource<BitmapSource?>(TaskCreationOptions.RunContinuationsAsynchronously);
            MapDetailWorker.Render(new("Amethyst", light, -126, -116, 33, 43, 480, 480, 1), Dispatcher, image => completion.TrySetResult(image));
            return await completion.Task;
        }
        static double Mean(byte[] pixels)
        {
            double total = 0;
            for (var i = 0; i < pixels.Length; i += 4) total += (pixels[i] + pixels[i + 1] + pixels[i + 2]) / 3d;
            return total / (pixels.Length / 4);
        }
        try
        {
            foreach (var theme in GlobeView.Themes)
            {
                var dark = OceanSample(WorldMapArtwork.Create(theme, false));
                var light = OceanSample(WorldMapArtwork.Create(theme, true));
                var darkAgain = OceanSample(WorldMapArtwork.Create(theme, false));
                checks[theme + "ArtworkHasLightAndDarkOcean"] = light[0] > dark[0] + 100 && light[1] > dark[1] + 100 && light[2] > dark[2] + 100;
                checks[theme + "ArtworkCacheSeparatesAppearance"] = dark.AsSpan().SequenceEqual(darkAgain);
            }
            // Explicit requests must render differently even though the app's global appearance stays dark.
            AppearanceTheme.Apply("Dark");
            var darkDetail = await Detail(false); var lightDetail = await Detail(true);
            checks["WorkerDetailUsesCapturedAppearance"] = darkDetail is not null && lightDetail is not null
                && Mean(Pixels(lightDetail)) > Mean(Pixels(darkDetail)) + 70;
            background.Preset = "Space"; background.SunMoon = background.Ufos = false;
            globe.SetTheme("Amethyst", true); globe.ConfigureEffects(settings);
            foreach (var appearance in new[] { "Dark", "Light" })
            {
                AppearanceTheme.Apply(appearance); globe.RefreshAppearance();
                foreach (var projection in new[] { "Globe", "Flat" })
                {
                    globe.SetProjection(projection); globe.ResetOrbit(); globe.SetPoints([]); globe.SampleAt(0);
                    var baseline = RedPixels(await Frame());
                    globe.SetPoints([new(40.7, -74, true, TrafficDirection.Inbound)]);
                    checks[appearance + projection + "DeniedRoutesRetainRedHue"] = RedPixels(await Frame()) > baseline + 4;
                }
            }
        }
        finally
        {
            AppearanceTheme.Apply(state.AppAppearance); globe.RefreshAppearance(); globe.SetTheme(savedTheme, true);
            globe.SetProjection(savedProjection); globe.ConfigureEffects(state); globe.SetPoints(MapPoints()); globe.ResetOrbit();
            background.Preset = savedPreset; background.SunMoon = savedSun; background.Ufos = savedUfos;
        }
        File.WriteAllText(Path.Combine(output, "atlas-palette-check.json"), JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
        if (checks.Values.Any(passed => !passed)) throw new InvalidOperationException("Atlas palette failed: " + string.Join(", ", checks.Where(c => !c.Value).Select(c => c.Key)));
    }

    /// <summary>Pixels of a BGRA frame red enough to be a denied route's.</summary>
    private static int RedPixels(byte[] pixels)
    {
        var count = 0;
        for (var i = 0; i < pixels.Length; i += 4)
            if (pixels[i + 2] > 40 && pixels[i + 2] > pixels[i + 1] * 1.3 && pixels[i + 2] > pixels[i] * 1.1) count++;
        return count;
    }
}
