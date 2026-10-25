using System.Text.Json;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    private async Task CaptureFlatAtlas(string output)
    {
        if (!capture) return;
        var savedPage = currentPage;
        var savedProjection = state.MapProjection;
        var savedTheme = state.Theme;
        var savedReducedMotion = state.ReducedMotion;
        var savedPreset = state.BackgroundPreset;
        var savedDirection = state.CloudDirection;
        var savedSunMoon = state.SpaceSunMoon;
        var savedUfos = state.SpaceUfos;
        var savedEffects = (state.AtlasPresentation, state.MapEffectPreset, state.RouteParticles, state.EndpointRipples,
            state.PolicyShockwaves, state.AtmosphereGlow, state.AmbientParticles, state.AutoRotateGlobe, state.EffectIntensity);
        var savedWidth = Width;
        var savedHeight = Height;
        var checks = new Dictionary<string, bool>();

        async Task Settle()
        {
            UpdateLayout();
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            // Detail is drawn in the background; waiting for it keeps every frame reproducible.
            if (activeGlobe is { } globe) await globe.DetailSettled();
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
        }
        async Task<byte[]> Frame(FrameworkElement element)
        {
            await Settle();
            var width = (int)Math.Ceiling(element.ActualWidth);
            var height = (int)Math.Ceiling(element.ActualHeight);
            if (width <= 0 || height <= 0) throw new InvalidOperationException("The flat atlas has no render surface.");
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(element);
            var pixels = new byte[width * height * 4];
            bitmap.CopyPixels(pixels, width * 4, 0);
            return pixels;
        }
        static bool Equal(byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right);

        try
        {
            state.MapProjection = "Flat";
            state.AtlasPresentation = "Standard";
            AppearancePreferences.ApplyEffectPreset(state, "Balanced");
            state.Theme = "Amethyst";
            state.ReducedMotion = true;
            state.BackgroundPreset = "Space";
            state.SpaceSunMoon = true;
            state.SpaceUfos = true;
            try
            {
                Width = MinWidth;
                Height = MinHeight;
                Navigate("Overview");
                if (activeGlobe is null) throw new InvalidOperationException("The compact flat atlas was not attached.");
                activeGlobe.Animate = false;
                activeGlobe.ResetOrbit();
                activeGlobe.SampleAt(0);
                await Settle();
                // Window resizing also passes through the native window layout queue.
                await Task.Delay(100);
                await Settle();
                var surface = activeGlobe.SurfaceSize;
                checks["compactOverviewHasUsableMapSurface"] =
                    double.IsFinite(surface.Width) && double.IsFinite(surface.Height) &&
                    surface.Width >= 320 && surface.Height >= 64;
                checks["compactOverviewMapFillsCard"] =
                    Math.Abs(surface.Width - activeGlobe.ActualWidth) < 1 &&
                    Math.Abs(surface.Height - activeGlobe.ActualHeight) < 1;
                checks["compactOverviewCentersOrigin"] = activeGlobe.CentersOriginFlat();
                SaveAtlasFrame(Path.Combine(output, "Overview-flat-compact.png"));
            }
            finally
            {
                Width = savedWidth;
                Height = savedHeight;
                await Settle();
            }
            foreach (var page in new[] { "Overview", "Map" })
            {
                Navigate(page);
                if (activeGlobe is null) throw new InvalidOperationException("The flat atlas was not attached.");
                checks[page.ToLowerInvariant() + "UsesSavedProjection"] = activeGlobe.Projection == "Flat";
                activeGlobe.Animate = false;
                activeGlobe.ResetOrbit();
                activeGlobe.SampleAt(0);
                await Settle();
                var surface = activeGlobe.SurfaceSize;
                checks[page.ToLowerInvariant() + "MapFillsCard"] =
                    Math.Abs(surface.Width - activeGlobe.ActualWidth) < 1 &&
                    Math.Abs(surface.Height - activeGlobe.ActualHeight) < 1;
                checks[page.ToLowerInvariant() + "CentersOrigin"] = activeGlobe.CentersOriginFlat();
                SaveAtlasFrame(Path.Combine(output, page + "-flat.png"));
            }

            var atlas = activeGlobe!;
            var background = activeAtlasBackground ?? throw new InvalidOperationException("The atlas background was not attached.");
            // A click picks the place under it: the middle of a view centered on a place is that place, and a pixel off is a pixel's worth off.
            atlas.LookAt(48.8566, 2.3522); await Settle();
            var middle = new Point(atlas.SurfaceSize.Width / 2, atlas.SurfaceSize.Height / 2);
            var degreesPerPixel = 360 / atlas.PixelsPerWorld;
            checks["flatClickPicksPlace"] = atlas.PlaceAt(middle) is { } paris && Math.Abs(paris.Latitude - 48.8566) < 1e-6 && Math.Abs(paris.Longitude - 2.3522) < 1e-6 &&
                atlas.PlaceAt(middle + new Vector(100, 50)) is { } off && Math.Abs(off.Latitude - (48.8566 - 50 * degreesPerPixel)) < 1e-6 && Math.Abs(off.Longitude - (2.3522 + 100 * degreesPerPixel)) < 1e-6;
            // A double-click zooms in twice as close and keeps the place under the pointer there.
            var pointer = middle + new Vector(120, -60);
            var under = atlas.PlaceAt(pointer); var spread = atlas.PixelsPerWorld;
            atlas.ZoomInAt(pointer);
            checks["flatDoubleClickZoomsAtPointer"] = under is { } was && atlas.PlaceAt(pointer) is { } still && Math.Abs(still.Latitude - was.Latitude) < 1e-6 &&
                Math.Abs(still.Longitude - was.Longitude) < 1e-6 && Math.Abs(atlas.PixelsPerWorld / spread - 2) < 1e-9;
            atlas.ResetOrbit(); await Settle();
            // The map wraps around: half a world's pan from home shows the far side of the world, and a whole world's the same view.
            var home = await Frame(atlas);
            atlas.OrbitBy(-atlas.PixelsPerWorld / 2, 0);
            await Settle();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-far-side.png"));
            atlas.OrbitBy(-atlas.PixelsPerWorld / 2, 0);
            checks["wholeWorldPanShowsSameView"] = Equal(home, await Frame(atlas));
            atlas.ResetOrbit();
            atlas.ZoomBy(240);
            atlas.OrbitBy(80, -35);
            await Settle();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-pan-zoom.png"));
            // Past the artwork's own pixels the view draws its part of the world afresh: sharp borders, names at a fixed
            // size, and cities, down to a city and its neighbors.
            atlas.LookAt(40.71, -74.01);
            atlas.ZoomBy(2880);
            checks["closeZoomDrawsDetail"] = await atlas.DetailSettled();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-close.png"));
            atlas.ZoomBy(6000);
            checks["closestZoomDrawsDetail"] = await atlas.DetailSettled();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-closest.png"));
            atlas.ResetOrbit();
            checks["resetDropsDetail"] = !await atlas.DetailSettled();

            state.Theme = "Classic";
            foreach (var page in new[] { "Overview", "Map" })
            {
                Navigate(page);
                atlas = activeGlobe!;
                atlas.Animate = false;
                atlas.ResetOrbit();
                atlas.SampleAt(0);
                checks[page.ToLowerInvariant() + "RetainsClassicPreference"] =
                    atlas.Theme == "Classic" && atlas.Projection == "Flat";
                await Settle();
                SaveAtlasFrame(Path.Combine(output, page + "-flat-Classic.png"));
            }
            // Move the closer view toward Europe to inspect country boundaries and small coastlines.
            atlas.ZoomBy(600);
            atlas.OrbitBy(-80, 250);
            await Settle();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-Classic-zoom.png"));
            atlas.LookAt(50.1, 8.7);
            atlas.ZoomBy(1680);
            checks["classicCloseZoomDrawsDetail"] = await atlas.DetailSettled();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-Classic-close.png"));

            state.MapProjection = "Globe";
            Navigate("Map");
            atlas = activeGlobe!;
            atlas.Animate = false;
            atlas.SampleAt(0);
            checks["projectionChangeRetainsClassicPreference"] = atlas.Theme == "Classic" && atlas.Projection == "Globe";
            await Settle();
            SaveAtlasFrame(Path.Combine(output, "Globe-Classic.png"));
            atlas.LookAt(50.1, 8.7);
            atlas.ZoomBy(1680);
            checks["globeCloseZoomDrawsDetail"] = await atlas.DetailSettled();
            SaveAtlasFrame(Path.Combine(output, "Globe-Classic-close.png"));
            atlas.ZoomBy(6000);
            checks["globeClosestZoomDrawsDetail"] = await atlas.DetailSettled();
            SaveAtlasFrame(Path.Combine(output, "Globe-Classic-closest.png"));
            atlas.ResetOrbit();
            checks["globeResetDropsDetail"] = !await atlas.DetailSettled();

            state.MapProjection = "Flat";
            state.Theme = "Glacier";
            Navigate("Map");
            atlas = activeGlobe!;
            atlas.Animate = false;
            atlas.SampleAt(0);
            await Settle();
            SaveAtlasFrame(Path.Combine(output, "Map-flat-Glacier.png"));

            state.Theme = "Amethyst";
            state.BackgroundPreset = "Clouds";
            Navigate("Map");
            atlas = activeGlobe!;
            background = activeAtlasBackground!;
            atlas.Animate = false;
            atlas.SampleAt(0);
            await Settle();

            // Keep the globe environment out of the projection round-trip comparisons.
            atlas.ShowBackgroundForCapture(false);
            MapRoute[] routes =
            [
                new(51.51, -.13, false, TrafficDirection.Outbound),
                new(35.68, 139.69, false, TrafficDirection.Inbound),
                new(-33.87, 151.21, true, TrafficDirection.Outbound)
            ];
            atlas.SetPoints(routes);
            atlas.ResetOrbit();
            atlas.SampleAt(0);
            var baseline = await Frame(atlas);
            await Task.Delay(200);
            checks["reducedMotionStable"] = Equal(baseline, await Frame(atlas));

            atlas.SampleAt(2);
            checks["trafficParticlesMoveWithStationaryCamera"] = !Equal(baseline, await Frame(atlas));
            atlas.SampleAt(0);
            checks["timeSampleIsDeterministic"] = Equal(baseline, await Frame(atlas));

            // The on-screen controls zoom like the wheel, and reset returns to the same view.
            var controls = atlas.Children.OfType<StackPanel>().SelectMany(p => p.Children.OfType<Button>())
                .ToDictionary(b => System.Windows.Automation.AutomationProperties.GetName(b));
            void Press(string name) => controls[name].RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Press("Zoom in");
            checks["zoomButtonChangesView"] = !Equal(baseline, await Frame(atlas));
            Press("Reset view");
            checks["resetButtonRestoresView"] = Equal(baseline, await Frame(atlas));

            atlas.ZoomBy(240);
            var zoomed = await Frame(atlas);
            checks["zoomChangesView"] = !Equal(baseline, zoomed);
            atlas.OrbitBy(80, -35);
            var panned = await Frame(atlas);
            checks["panChangesView"] = !Equal(zoomed, panned);

            atlas.SetTheme("Classic", atlas.AttackView);
            checks["classicThemeChangesMap"] = !Equal(panned, await Frame(atlas));
            atlas.SetTheme("Amethyst", atlas.AttackView);
            checks["classicThemeRoundTripPreservesPanAndZoom"] = Equal(panned, await Frame(atlas));

            atlas.SetProjection("Globe");
            atlas.ResetOrbit();
            checks["globeResetFacesOrigin"] = atlas.FacesOrigin();
            // On the globe the middle of the view is the place it faces, and a double-click turns to face the place under the
            // pointer from twice as close.
            var face = new Point(atlas.SurfaceSize.Width / 2, atlas.SurfaceSize.Height / 2);
            atlas.LookAt(35.6762, 139.6503);
            checks["globeClickPicksPlace"] = atlas.PlaceAt(face) is { } tokyo && Math.Abs(tokyo.Latitude - 35.6762) < 1e-6 && Math.Abs(tokyo.Longitude - 139.6503) < 1e-6 &&
                atlas.PlaceAt(new(2, 2)) is null;
            var aside = atlas.PlaceAt(face + new Vector(70, 40)); var closer = atlas.GlobeZoom / 2;
            atlas.ZoomInAt(face + new Vector(70, 40));
            checks["globeDoubleClickFacesPlace"] = aside is { } target && atlas.PlaceAt(face) is { } faced && Math.Abs(faced.Latitude - target.Latitude) < 1e-6 &&
                Math.Abs(faced.Longitude - target.Longitude) < 1e-6 && Math.Abs(atlas.GlobeZoom - closer) < 1e-12;
            atlas.ResetOrbit();
            atlas.OrbitBy(45, 18);
            atlas.ZoomBy(120);
            atlas.SampleAt(0);
            var globeView = await Frame(atlas);
            checks["globeAndFlatDiffer"] = !Equal(panned, globeView);
            atlas.SetProjection("Flat");
            atlas.SampleAt(0);
            checks["flatViewSurvivesModeRoundTrip"] = Equal(panned, await Frame(atlas));
            atlas.ResetOrbit();
            checks["resetRestoresFlatView"] = Equal(baseline, await Frame(atlas));
            atlas.SetProjection("Globe");
            atlas.SampleAt(0);
            checks["flatResetPreservesGlobeView"] = Equal(globeView, await Frame(atlas));
            atlas.SetProjection("Flat");
            atlas.SampleAt(0);

            atlas.SetTheme("Glacier", atlas.AttackView);
            checks["themeChangesMap"] = !Equal(baseline, await Frame(atlas));
            atlas.SetTheme("Amethyst", atlas.AttackView);
            checks["themeRoundTripPreservesMap"] = Equal(baseline, await Frame(atlas));
            atlas.SetPoints([]);
            checks["connectionUpdatesChangeMap"] = !Equal(baseline, await Frame(atlas));
            atlas.SetPoints(routes);
            atlas.SampleAt(0);
            checks["connectionRoundTripPreservesMap"] = Equal(baseline, await Frame(atlas));

            atlas.Animate = true;
            var liveStart = await Frame(atlas);
            await Task.Delay(400);
            checks["liveFrameClockMovesTraffic"] = !Equal(liveStart, await Frame(atlas));
            atlas.Animate = false;
            var frozen = await Frame(atlas);
            await Task.Delay(200);
            checks["stoppingAnimationFreezesTraffic"] = Equal(frozen, await Frame(atlas));

            atlas.ShowBackgroundForCapture(true);
            atlas.SetPoints([]);
            background.Preset = "Space";
            background.SunMoon = background.Ufos = false;
            atlas.SampleAt(0);
            var plainMap = await Frame(atlas);
            checks["flatHidesEnvironment"] = background.Visibility != Visibility.Visible;
            background.Preset = "Clouds";
            foreach (var direction in AtlasBackground.CloudDirections)
            {
                background.CloudDirection = direction;
                atlas.SampleAt(0);
                var unchanged = Equal(plainMap, await Frame(atlas));
                atlas.SampleAt(4);
                checks["flatIgnoresClouds" + direction] = unchanged && Equal(plainMap, await Frame(atlas));
            }

            background.Preset = "Space";
            var ignoresDecorations = true;
            foreach (var (sunMoon, ufos) in new[] { (false, false), (true, false), (false, true), (true, true) })
            {
                background.SunMoon = sunMoon;
                background.Ufos = ufos;
                atlas.SampleAt(0);
                ignoresDecorations &= Equal(plainMap, await Frame(atlas));
            }
            checks["flatIgnoresSpaceDecorations"] = ignoresDecorations;
            atlas.SampleAt(4);
            checks["flatIgnoresEnvironmentAnimation"] = Equal(plainMap, await Frame(atlas));

            atlas.SetProjection("Globe");
            await Settle();
            checks["globeRestoresEnvironmentPreferences"] = background.Visibility == Visibility.Visible &&
                background.Preset == "Space" && background.SunMoon && background.Ufos;
            atlas.ShowEarthForCapture(false);
            background.Preset = "Clouds";
            atlas.SampleAt(0);
            var globeClouds = await Frame(atlas);
            atlas.SampleAt(4);
            checks["globeEnvironmentAnimatesAfterFlat"] = !Equal(globeClouds, await Frame(atlas));
            atlas.ShowEarthForCapture(true);

            File.WriteAllText(Path.Combine(output, "flat-atlas-check.json"),
                JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
            if (checks.Values.Any(passed => !passed))
                throw new InvalidOperationException("Flat atlas capture failed: " +
                    string.Join(", ", checks.Where(check => !check.Value).Select(check => check.Key)));
        }
        finally
        {
            state.MapProjection = savedProjection;
            state.Theme = savedTheme;
            state.ReducedMotion = savedReducedMotion;
            state.BackgroundPreset = savedPreset;
            state.CloudDirection = savedDirection;
            state.SpaceSunMoon = savedSunMoon;
            state.SpaceUfos = savedUfos;
            (state.AtlasPresentation, state.MapEffectPreset, state.RouteParticles, state.EndpointRipples,
                state.PolicyShockwaves, state.AtmosphereGlow, state.AmbientParticles, state.AutoRotateGlobe, state.EffectIntensity) = savedEffects;
            Width = savedWidth;
            Height = savedHeight;
            Navigate(savedPage);
        }
    }
}
