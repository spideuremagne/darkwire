using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Text.Json;

namespace Darkwire.Host;

public partial class MainWindow
{
    private AtlasBackground? activeAtlasBackground;
    private AtlasBackground CreateAtlasBackground()
    {
        DisposeAtlasBackground();
        AtlasBackground.NormalizeSettings(state);
        state.MapProjection = GlobeView.NormalizeProjection(state.MapProjection);
        activeAtlasBackground = new(state.BackgroundPreset, state.CloudDirection, Ui.MotionEnabled(state), state.SpaceSunMoon, state.SpaceUfos);
        activeAtlasBackground.ConfigureEffects(state);
        return activeAtlasBackground;
    }
    private void DisposeAtlasBackground() { activeAtlasBackground?.Dispose(); activeAtlasBackground = null; }
    private void UpdateAtlasMotion()
    {
        if (activeAtlasBackground is not null) { activeAtlasBackground.Animate = Ui.MotionEnabled(state); activeAtlasBackground.ConfigureEffects(state); }
        activeGlobe?.ConfigureEffects(state);
        Shield.Pulse = Ui.MotionEnabled(state) && !capture;
    }

    private sealed record ProjectionOption(string Value, string Label)
    { public override string ToString() => Label; }
    private ComboBox AtlasProjectionSelector()
    {
        ProjectionOption[] choices = [new("Globe", "Globe"), new("Flat", "Flat map")];
        var picker = new ComboBox { ItemsSource = choices, SelectedItem = choices.First(p => p.Value == state.MapProjection), MinWidth = 130 };
        System.Windows.Automation.AutomationProperties.SetName(picker, "Map view");
        picker.SelectionChanged += (_, _) =>
        {
            if (picker.SelectedItem is not ProjectionOption option) return;
            state.MapProjection = option.Value; state.MapProjectionChosen = true; activeGlobe?.SetProjection(option.Value); Save();
        };
        return picker;
    }

    /// <summary>
    /// Where the maps draw this PC: Windows' region by default, or a country, a city in it from the bundled GeoNames list, or an
    /// exact position chosen here.
    /// </summary>
    private UIElement MapOriginCard()
    {
        var place = Origin;
        CountryOption automatic = new("", "Automatic, from Windows region");
        CountryOption[] options = [automatic, .. CountryOptions()];
        var country = new ComboBox { ItemsSource = options, DisplayMemberPath = nameof(CountryOption.Display), Width = 300, HorizontalAlignment = HorizontalAlignment.Left,
            SelectedItem = options.FirstOrDefault(o => o.Code.Length > 0 && o.Code == state.MapOriginCountry) ?? automatic };
        System.Windows.Automation.AutomationProperties.SetName(country, "Map origin country");
        country.SelectionChanged += (_, _) =>
        {
            if (country.SelectedItem is not CountryOption choice) return;
            // A country chosen here replaces a city or position set earlier.
            state.MapOriginCountry = choice.Code.Length == 0 ? null : choice.Code;
            state.MapOriginCity = null; state.MapOriginLatitude = state.MapOriginLongitude = null; Save(); Navigate("Settings");
        };
        var home = MapOrigin.HomeCountry(state, demo ? Demo.Region : null);
        var homeName = home is null ? null : MapOrigin.CountryName(home);
        var input = Ui.Input(state.MapOriginCity ?? (state.MapOriginLatitude is double latitude && state.MapOriginLongitude is double longitude
            ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{latitude}, {longitude}") : ""),
            (homeName is null ? "A city" : "A city in " + homeName) + ", or latitude and longitude as 52.37, 4.89");
        input.Width = 300; input.HorizontalAlignment = HorizontalAlignment.Left; input.Margin = new(0, 5, 0, 4);
        System.Windows.Automation.AutomationProperties.SetName(input, "Map origin city or position");
        var suggestions = Ui.Stack(); suggestions.Width = 300; suggestions.HorizontalAlignment = HorizontalAlignment.Left;
        void Apply(double latitude, double longitude, CityPlace? city)
        {
            if (city is not null) state.MapOriginCountry = city.Country;
            state.MapOriginCity = city?.Name; state.MapOriginLatitude = latitude; state.MapOriginLongitude = longitude;
            Save(); Navigate("Settings"); ShowToast("Map routes now start at " + Origin.Label + ".");
        }
        void Use()
        {
            var text = input.Text.Trim();
            if (MapOrigin.TryParseCoordinates(text, out var lat, out var lon)) Apply(lat, lon, null);
            else if (home is not null && Cities.Suggest(home, text, 1) is [var first]) Apply(first.Latitude, first.Longitude, first);
            else ShowToast((homeName is null ? "Choose a country first" : $"No city in {homeName} matches \"{text}\"; pick one from the list") + ", or enter latitude and longitude, as 52.37, 4.89.");
        }
        input.TextChanged += (_, _) =>
        {
            suggestions.Children.Clear();
            if (home is null || MapOrigin.TryParseCoordinates(input.Text, out _, out _)) return;
            var cities = Cities.In(home);
            foreach (var city in Cities.Suggest(home, input.Text, 6))
            {
                // A name the country has more than once shows its region, where the list has one.
                var region = city.Region.Length > 0 && cities.Count(c => c.Name == city.Name) > 1 ? city.Region + "  ·  " : "";
                var pick = Ui.Button($"{city.Name}  ·  {region}{city.Population:N0} people", () => Apply(city.Latitude, city.Longitude, city));
                pick.HorizontalContentAlignment = HorizontalAlignment.Left; pick.Padding = new(11, 6, 11, 6); pick.Margin = new(0, 0, 0, 3);
                suggestions.Children.Add(pick);
            }
        };
        input.KeyDown += (_, e) => { if (e.Key == Key.Enter) { e.Handled = true; Use(); } };
        var use = Ui.Button("Use this place", Use);
        var clear = Ui.Button("Clear", () => { state.MapOriginCity = null; state.MapOriginLatitude = state.MapOriginLongitude = null; Save(); Navigate("Settings"); }); clear.Margin = new(10, 0, 0, 0);
        // The first run's question, again: a country and city, and a pin on the map for an exact spot.
        var pin = Ui.Button("Pin on the map…", () => LocationDialog(firstRun: false).ShowDialog()); pin.Margin = new(10, 0, 0, 0);
        var source = place.Source switch
        {
            "set in Settings" => state.MapOriginLatitude is double setLatitude && state.MapOriginLongitude is double setLongitude
                ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"Set here, at {setLatitude:0.#####}, {setLongitude:0.#####}.") : "Set here.",
            "default" => demo ? "The demo keeps a fixed anchor." : "Windows names no country, so the default anchor is used.",
            _ => $"From the {place.Source}."
        };
        return Ui.Card(Ui.Stack(Ui.Label("MAP ORIGIN"), Ui.Gap(12), Ui.Text(place.Label, 20, "#E7DFF2", FontWeights.SemiBold), Ui.Gap(6),
            Ui.Text(source + " Routes on the maps start here. Your location never leaves this PC, and nothing is looked up online.", 11, "#A599B3"), Ui.Gap(14),
            Ui.Label("COUNTRY"), Ui.Gap(6), country, Ui.Gap(14), Ui.Label("CITY OR POSITION"), input, suggestions, Ui.Gap(6), Ui.Row(use, clear, pin), Ui.Gap(12),
            Ui.Text("Automatic uses Windows' Country or region setting (Settings › Time & language › Language & region) and, in countries spanning several time zones, the time zone. A city or position chosen here wins over a country. " + Cities.Attribution, 11, "#A599B3")), 23);
    }

    private UIElement AtlasBackgroundControls(bool compact = false)
    {
        var presets = new ComboBox { ItemsSource = AtlasBackground.Presets, SelectedItem = AtlasBackground.NormalizePreset(state.BackgroundPreset) };
        var direction = new ComboBox { ItemsSource = AtlasBackground.CloudDirections, SelectedItem = AtlasBackground.NormalizeDirection(state.CloudDirection) };
        if (!compact) { presets.Width = direction.Width = 240; presets.HorizontalAlignment = direction.HorizontalAlignment = HorizontalAlignment.Left; }
        var directionPanel = Ui.Stack(Ui.Gap(12), Ui.Label("CLOUD DIRECTION"), Ui.Gap(8), direction);
        var sunMoon = new CheckBox { Content = "Sun and Moon", IsChecked = state.SpaceSunMoon };
        var ufos = new CheckBox { Content = "UFOs", IsChecked = state.SpaceUfos };
        var spacePanel = Ui.Stack(Ui.Gap(12), sunMoon, ufos);
        directionPanel.Visibility = presets.SelectedItem as string == "Clouds" ? Visibility.Visible : Visibility.Collapsed;
        spacePanel.Visibility = presets.SelectedItem as string == "Space" ? Visibility.Visible : Visibility.Collapsed;
        presets.SelectionChanged += (_, _) =>
        {
            state.BackgroundPreset = (string)presets.SelectedItem;
            if (activeAtlasBackground is not null) activeAtlasBackground.Preset = state.BackgroundPreset;
            directionPanel.Visibility = state.BackgroundPreset == "Clouds" ? Visibility.Visible : Visibility.Collapsed;
            spacePanel.Visibility = state.BackgroundPreset == "Space" ? Visibility.Visible : Visibility.Collapsed; Save();
        };
        direction.SelectionChanged += (_, _) =>
        {
            state.CloudDirection = (string)direction.SelectedItem;
            if (activeAtlasBackground is not null) activeAtlasBackground.CloudDirection = state.CloudDirection; Save();
        };
        void ChangeSpace(object sender, RoutedEventArgs e)
        {
            state.SpaceSunMoon = sunMoon.IsChecked == true; state.SpaceUfos = ufos.IsChecked == true;
            if (activeAtlasBackground is not null) { activeAtlasBackground.SunMoon = state.SpaceSunMoon; activeAtlasBackground.Ufos = state.SpaceUfos; }
            Save();
        }
        sunMoon.Checked += ChangeSpace; sunMoon.Unchecked += ChangeSpace; ufos.Checked += ChangeSpace; ufos.Unchecked += ChangeSpace;
        var controls = Ui.Stack(Ui.Label("GLOBE BACKGROUND"), Ui.Gap(10), presets, spacePanel, directionPanel);
        return compact ? controls : Ui.Card(controls, 23);
    }
    private async Task CaptureAtlasBackgrounds(string output)
    {
        if (!capture) return;
        var savedPreset = state.BackgroundPreset; var savedSunMoon = state.SpaceSunMoon; var savedUfos = state.SpaceUfos;
        var savedProjection = state.MapProjection; state.MapProjection = "Globe";
        try
        {
            foreach (var (name, preset, sunMoon, ufos) in new[]
            {
                ("Space-stars", "Space", false, false), ("Space-Sun-Moon", "Space", true, false),
                ("Space-UFOs", "Space", false, true), ("Space", "Space", true, true), ("Clouds", "Clouds", false, false)
            })
            {
                state.BackgroundPreset = preset; state.SpaceSunMoon = sunMoon; state.SpaceUfos = ufos; Navigate("Map");
                activeGlobe!.Animate = false; activeGlobe.ResetOrbit(); activeGlobe.SampleAt(0);
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(200); UpdateLayout();
                SaveAtlasFrame(Path.Combine(output, "Atlas-" + name + ".png"));
                if (name is "Space" or "Clouds")
                {
                    activeGlobe.OrbitBy(100, 30);
                    await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
                    SaveAtlasFrame(Path.Combine(output, "Atlas-" + name + "-orbit.png"));
                    activeGlobe.ResetOrbit(); activeGlobe.SampleAt(7);
                    await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
                    SaveAtlasFrame(Path.Combine(output, "Atlas-" + name + "-motion.png"));
                }
            }
            await VerifyAtlasAnimation(output);
            await VerifyAtlasEffects(output);
        }
        finally { state.BackgroundPreset = savedPreset; state.SpaceSunMoon = savedSunMoon; state.SpaceUfos = savedUfos; state.MapProjection = savedProjection; }
    }
    private void SaveAtlasFrame(string path)
    {
        var bitmap = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(this); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path); encoder.Save(file);
    }
    private async Task VerifyAtlasAnimation(string output)
    {
        if (activeAtlasBackground is null || activeGlobe is null) throw new InvalidOperationException("Atlas scene was not attached for capture.");
        var visual = activeAtlasBackground; var globe = activeGlobe;
        static byte[] Pixels(FrameworkElement element)
        {
            var width = (int)element.ActualWidth; var height = (int)element.ActualHeight;
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(element);
            var pixels = new byte[width * height * 4]; bitmap.CopyPixels(pixels, width * 4, 0); return pixels;
        }
        async Task<byte[]> Frame(FrameworkElement element)
        {
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render); return Pixels(element);
        }
        static bool Equal(byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right);
        var checks = new Dictionary<string, bool>();
        globe.Animate = false; globe.SetPoints([]); globe.ShowEarthForCapture(false); globe.ResetOrbit(); visual.Preset = "Space";
        visual.SunMoon = visual.Ufos = false; globe.SampleAt(0); var stars = await Frame(visual);
        globe.SampleAt(2); checks["starsTwinkleWithStationaryCamera"] = !Equal(stars, await Frame(visual));
        globe.SampleAt(0); globe.OrbitBy(100, 30); checks["starsFollowOrbit"] = !Equal(stars, await Frame(visual)); globe.ResetOrbit();
        foreach (var objectName in new[] { "Moon", "UFOs" })
        {
            visual.SunMoon = objectName == "Moon"; visual.Ufos = objectName == "UFOs";
            globe.SampleAt(0); var before = await Frame(globe); globe.SampleAt(4);
            checks[objectName + "MoveWithStationaryCamera"] = !Equal(before, await Frame(globe));
        }
        visual.Preset = "Clouds";
        foreach (var direction in AtlasBackground.CloudDirections)
        {
            visual.CloudDirection = direction; globe.SampleAt(0); var before = await Frame(globe);
            globe.SampleAt(4); checks["cloudsScroll" + direction] = !Equal(before, await Frame(globe));
        }
        var clouds = await Frame(globe); globe.OrbitBy(100, 30);
        checks["cloudsFollowOrbit"] = !Equal(clouds, await Frame(globe));
        globe.Animate = true; var moving = await Frame(globe); await Task.Delay(400);
        checks["liveFrameClock"] = !Equal(moving, await Frame(globe));
        globe.Animate = false; var frozen = await Frame(globe); await Task.Delay(250);
        checks["reducedMotionStable"] = Equal(frozen, await Frame(globe));
        globe.OrbitBy(50, -20); checks["manualOrbitWithReducedMotion"] = !Equal(frozen, await Frame(globe));
        File.WriteAllText(Path.Combine(output, "atlas-animation-check.json"), JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
        globe.ShowEarthForCapture(true);
        if (checks.Values.Any(passed => !passed)) throw new InvalidOperationException("Atlas capture failed: " + string.Join(", ", checks.Where(c => !c.Value).Select(c => c.Key)));
    }
}
