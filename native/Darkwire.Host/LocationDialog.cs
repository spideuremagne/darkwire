using System.Globalization;

namespace Darkwire.Host;

/// <summary>
/// Where this PC is, which the maps start their routes from: asked once on first run, and from Settings whenever wanted. A
/// country, then a city in it from the bundled GeoNames list, and once a city is chosen, a pin dropped on the map for an
/// exact position. Nothing is looked up online, and the answer stays in this PC's settings.
/// </summary>
public partial class MainWindow
{
    /// <summary>What the location dialog starts with: a country, a city in it, and a pinned position.</summary>
    private sealed record LocationChoice(string? Country, CityPlace? City, (double Latitude, double Longitude)? Pin);

    /// <summary>
    /// Asks where this PC is the first time the window shows, unless a place is set already; the question waits while the app
    /// starts in the tray, and is asked once whatever the answer.
    /// </summary>
    private void AskLocationOnce()
    {
        if (demo || startHidden || state.MapOriginAsked || askingLocation) return;
        if (state.MapOriginCountry is not null || state.MapOriginLatitude is not null) { state.MapOriginAsked = true; Save(); return; }
        askingLocation = true;
        try { LocationDialog(firstRun: true).ShowDialog(); }
        finally { askingLocation = false; }
    }
    private bool askingLocation;

    /// <summary>The place set now: its country, the city named, and a position other than that city's own.</summary>
    private LocationChoice CurrentLocation()
    {
        var country = MapOrigin.HomeCountry(state, demo ? Demo.Region : null);
        var city = country is null || state.MapOriginCity is not { } name ? null : Cities.In(country).FirstOrDefault(c => c.Name == name);
        (double, double)? pin = state.MapOriginLatitude is double latitude && state.MapOriginLongitude is double longitude &&
            (city is null || Math.Abs(city.Latitude - latitude) > 1e-6 || Math.Abs(city.Longitude - longitude) > 1e-6) ? (latitude, longitude) : null;
        return new(country, city, pin);
    }

    /// <param name="firstRun">Asked on first run: putting it off is final, and Settings asks again on request.</param>
    /// <param name="initial">What it starts with; the place set now when not given.</param>
    private Window LocationDialog(bool firstRun, LocationChoice? initial = null)
    {
        var start = initial ?? CurrentLocation();
        var countries = CountryOptions();
        var country = new ComboBox { ItemsSource = countries, DisplayMemberPath = nameof(CountryOption.Display), SelectedItem = countries.FirstOrDefault(c => c.Code == start.Country) };
        System.Windows.Automation.AutomationProperties.SetName(country, "Your country");
        var cityInput = Ui.Input(start.City?.Name ?? "", "Your city, or latitude and longitude as 52.37, 4.89");
        cityInput.Margin = new(0, 6, 0, 4);
        System.Windows.Automation.AutomationProperties.SetName(cityInput, "Your city");
        var suggestions = Ui.Stack();
        var placeText = Ui.Text("", 12, "#D9CFEA"); placeText.VerticalAlignment = VerticalAlignment.Center;
        var mapHost = new Border { Height = 250, CornerRadius = new(8), ClipToBounds = true, BorderBrush = Ui.Brush("#34303E"), BorderThickness = new(1) };
        var error = Ui.Text("", 11, "#F2849C");
        CityPlace? city = start.City; (double Latitude, double Longitude)? pin = start.Pin;
        // A pin from coordinates typed in the city box goes when they do; one dropped on the map stays.
        var typedPin = false;
        GlobeView? map = null;
        string? Code() => (country.SelectedItem as CountryOption)?.Code;
        string Coordinates((double Latitude, double Longitude) spot) => string.Create(CultureInfo.InvariantCulture, $"{spot.Latitude:0.00000}, {spot.Longitude:0.00000}");

        var center = Ui.Button("Use the city's center", () => { });
        center.Padding = new(11, 6, 11, 6); center.Margin = new(12, 0, 0, 0);
        var line = new DockPanel(); DockPanel.SetDock(center, Dock.Right); line.Children.Add(center); line.Children.Add(placeText);
        var mapSection = Ui.Stack(Ui.Gap(18), Ui.Label("EXACT SPOT (OPTIONAL)"), Ui.Gap(6),
            Ui.Text("Click the map to drop a pin on your exact spot. Drag to pan, scroll to zoom.", 11, "#A599B3"),
            Ui.Gap(8), mapHost, Ui.Gap(8), line);
        center.Click += (_, _) => { pin = null; typedPin = false; ShowPlace(recenter: true); };

        // The map follows the city, and a pin on it wins over the city's own position.
        void ShowPlace(bool recenter)
        {
            (double Latitude, double Longitude)? at = pin ?? (city is null ? null : (city.Latitude, city.Longitude));
            mapSection.Visibility = at is null ? Visibility.Collapsed : Visibility.Visible;
            center.Visibility = pin is not null && city is not null ? Visibility.Visible : Visibility.Collapsed;
            if (at is not { } spot) return;
            if (map is null)
            {
                map = new GlobeView([], "Flat", new(spot.Latitude, spot.Longitude, "", "pin")) { Animate = false };
                map.SetTheme(state.Theme, false);
                map.Picked = (latitude, longitude) => { pin = (latitude, longitude); typedPin = false; ShowPlace(recenter: false); };
                mapHost.Child = map; recenter = true;
            }
            else map.MoveOrigin(new(spot.Latitude, spot.Longitude, "", "pin"));
            if (recenter) map.LookAt(spot.Latitude, spot.Longitude, closest: true);
            if (pin is null) placeText.Text = $"{city!.Name}, {MapOrigin.CountryName(city.Country)}  ·  {Coordinates(spot)}";
            else
            {
                var near = Cities.Nearest(spot.Latitude, spot.Longitude);
                placeText.Text = $"Pinned at {Coordinates(spot)}, near {near.Name}, {MapOrigin.CountryName(near.Country)}";
            }
        }

        void Choose(CityPlace place)
        {
            city = place; pin = null; typedPin = false; error.Text = "";
            cityInput.Text = place.Name; suggestions.Children.Clear();
            ShowPlace(recenter: true);
        }

        // Until a name is typed, the city the time zone points to comes first, then the country's largest.
        void Suggest()
        {
            suggestions.Children.Clear();
            if (Code() is not { } code || city is not null && cityInput.Text == city.Name) return;
            var text = cityInput.Text.Trim();
            if (MapOrigin.TryParseCoordinates(text, out _, out _)) return;
            var cities = Cities.In(code);
            var zone = MapOrigin.ZoneCity(code, demo ? Demo.TimeZone : null);
            var found = text.Length > 0 ? Cities.Suggest(code, text, 6) : cities.Where(c => c.Name == zone).Take(1).Concat(cities).Distinct().Take(6).ToList();
            foreach (var place in found)
            {
                // A name the country has more than once shows its region, where the list has one.
                var region = place.Region.Length > 0 && cities.Count(c => c.Name == place.Name) > 1 ? place.Region + "  ·  " : "";
                var pick = Ui.Button($"{place.Name}  ·  {region}{place.Population:N0} people", () => Choose(place));
                pick.HorizontalContentAlignment = HorizontalAlignment.Left; pick.Padding = new(11, 6, 11, 6); pick.Margin = new(0, 0, 0, 3);
                suggestions.Children.Add(pick);
            }
        }

        country.SelectionChanged += (_, _) => { city = null; pin = null; typedPin = false; error.Text = ""; cityInput.Text = ""; Suggest(); ShowPlace(recenter: true); };
        cityInput.TextChanged += (_, _) =>
        {
            if (city is not null && cityInput.Text != city.Name) city = null;
            // Coordinates typed in place of a city pin the map there.
            if (MapOrigin.TryParseCoordinates(cityInput.Text.Trim(), out var latitude, out var longitude)) { pin = (latitude, longitude); typedPin = true; ShowPlace(recenter: true); }
            else if (typedPin) { pin = null; typedPin = false; ShowPlace(recenter: true); }
            Suggest();
        };

        var shield = new TextBlock { Text = "", FontFamily = new("Segoe Fluent Icons"), FontSize = 20, Foreground = Ui.Brush("#B7A0FF"), Margin = new(0, 1, 14, 0), VerticalAlignment = VerticalAlignment.Top };
        DockPanel.SetDock(shield, Dock.Left);
        var privacy = new Border
        {
            Background = Ui.Brush("#1B1926"), BorderBrush = Ui.Brush("#3B3452"), BorderThickness = new(1), CornerRadius = new(8), Padding = new(16, 13, 16, 13),
            Child = new DockPanel { Children = { shield, Ui.Stack(Ui.Text("Private by design", 13, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(4),
                Ui.Text("Darkwire never collects any information. There are no accounts, no telemetry and no analytics, and nothing is looked up online to place you: " +
                    "your location only draws the map, stays in Darkwire's settings on this PC and never leaves it. You're in full control, and can change or clear it in Settings at any time.", 11, "#B8ADC9")) } }
        };
        var panel = Ui.Stack(Ui.Text("Where are you?", 24, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(8),
            Ui.Text("Darkwire draws your connections on a map, starting from where this PC is. Choose your country and city; then, if you like, drop a pin on the map for your exact spot.", 12, "#A99DBA"),
            Ui.Gap(16), privacy, Ui.Gap(18), Where(), mapSection, Ui.Gap(10), error);
        // The country beside the city, which lists its suggestions under it.
        UIElement Where()
        {
            var columns = Ui.Columns(0, 0);
            var left = Ui.Stack(Ui.Label("COUNTRY"), Ui.Gap(6), country); left.Margin = new(0, 0, 16, 0);
            Ui.Add(columns, left, 0); Ui.Add(columns, Ui.Stack(Ui.Label("CITY"), cityInput, suggestions), 1);
            return columns;
        }
        var window = Dialog("Where are you?", panel, 740);
        var saved = false;
        var save = Ui.Button("Save", () =>
        {
            if (pin is { } spot)
            {
                // A pin is named after the city nearest it, wherever that is.
                var near = Cities.Nearest(spot.Latitude, spot.Longitude);
                (state.MapOriginCountry, state.MapOriginCity, state.MapOriginLatitude, state.MapOriginLongitude) = (near.Country, near.Name, spot.Latitude, spot.Longitude);
            }
            else
            {
                if (Code() is not { } code) { error.Text = "Choose your country first."; return; }
                var typed = cityInput.Text.Trim();
                if (city is null && typed.Length > 0)
                {
                    if (Cities.Suggest(code, typed, 1) is [var first]) city = first;
                    else { error.Text = $"No city in {MapOrigin.CountryName(code)} matches \"{typed}\". Pick one from the list, or leave the city empty to use the country alone."; return; }
                }
                if (city is not null) (state.MapOriginCountry, state.MapOriginCity, state.MapOriginLatitude, state.MapOriginLongitude) = (city.Country, city.Name, city.Latitude, city.Longitude);
                else { state.MapOriginCountry = code; state.MapOriginCity = null; state.MapOriginLatitude = state.MapOriginLongitude = null; }
            }
            state.MapOriginAsked = true; Save(); saved = true; window.Close();
            Navigate(currentPage); ShowToast("Your maps now start at " + Origin.Label + ".");
        }, true);
        var later = Ui.Button(firstRun ? "Not now" : "Cancel", window.Close); later.Margin = new(10, 0, 0, 0);
        panel.Children.Add(Ui.Gap(14)); panel.Children.Add(Ui.Row(save, later));
        if (firstRun) panel.Children.Add(Ui.Text("Not now keeps Windows' region setting as your place on the map; Settings › Map origin asks again whenever you like.", 11, "#8E8399"));
        window.Closed += (_, _) =>
        {
            map?.Dispose();
            if (firstRun && !saved) { state.MapOriginAsked = true; Save(); }
        };
        Suggest(); ShowPlace(recenter: true);
        return window;
    }
}
