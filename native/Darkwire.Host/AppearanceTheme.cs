using Microsoft.Win32;
using System.ComponentModel;
using System.Windows.Data;

namespace Darkwire.Host;

/// <summary>Shared semantic brushes keep every page and open dialog in the same palette.</summary>
public static class AppearanceTheme
{
    private static readonly Dictionary<string, SolidColorBrush> brushes = new(StringComparer.Ordinal);
    private static readonly Dictionary<string, ColorValue> colors = new(StringComparer.Ordinal);
    // A bound brush cannot be frozen when WPF seals a style. Existing direct Ui.Brush references, as well as
    // dynamic resources and any WPF-created binding clones, keep observing this same per-role source.
    private sealed class ColorValue(Color initial) : INotifyPropertyChanged
    {
        private Color value = initial;
        public event PropertyChangedEventHandler? PropertyChanged;
        public Color Value
        {
            get => value;
            set
            {
                if (this.value == value) return;
                this.value = value; PropertyChanged?.Invoke(this, new(nameof(Value)));
            }
        }
    }
    private static readonly Dictionary<string, string> legacyRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["#0C0D13"]="Background", ["#101119"]="Panel", ["#101118"]="Panel", ["#14151E"]="Panel",
        ["#151620"]="Panel", ["#15161F"]="Panel", ["#191A24"]="Header", ["#1C1D29"]="PanelRaised",
        ["#20212D"]="PanelRaised", ["#1A1924"]="Panel", ["#211F2B"]="PanelRaised",
        ["#292735"]="Stroke", ["#292A38"]="Stroke", ["#23242F"]="Stroke", ["#34303E"]="Stroke",
        ["#383948"]="Stroke", ["#464252"]="Stroke", ["#58516B"]="Stroke", ["#6B4E2E"]="WarningStroke",
        ["#282234"]="Selected", ["#292238"]="Selected", ["#3B2F50"]="Selected", ["#342D49"]="Selected",
        ["#1A1826"]="Selected", ["#211D30"]="Selected", ["#2B2739"]="Selected", ["#30273F"]="Selected",
        ["#16302A"]="SuccessPanel", ["#2A2118"]="WarningPanel", ["#2E2418"]="WarningPanel",
        ["#33192A"]="DangerPanel", ["#30212C"]="DangerPanel", ["#191321"]="OnAccent",
        ["#0D2A20"]="OnStatus", ["#3B2A0C"]="OnStatus", ["#3D0D19"]="OnStatus",
        ["#A58ACD"]="Accent", ["#84749D"]="Accent", ["#67517E"]="Accent",
        ["#69568E"]="Selection", ["#51485E"]="Thumb", ["#6C607F"]="ThumbHover", ["#8E7FAA"]="Accent",
        ["#1B1C27"]="PanelRaised", ["#48405E"]="Selected", ["#6F6680"]="Muted",
        // The peach of warning details and of servers without DNSSEC, which the hues below would read as text.
        ["#E8C9A8"]="Warning"
    };
    private static readonly (string Key, string Dark, string Light)[] palette =
    [
        ("Background", "#090D14", "#EDF2F5"), ("Panel", "#101620", "#FFFFFF"),
        ("PanelRaised", "#19212F", "#F3F7F9"), ("Header", "#141D2A", "#F1F6F8"),
        ("Stroke", "#2B3545", "#CCD9E1"), ("Text", "#EDF2FA", "#192C3B"),
        ("Muted", "#A5B1C5", "#536978"), ("Accent", "#BAAAFF", "#126D8C"),
        ("OnAccent", "#171322", "#FFFFFF"), ("Selected", "#28263E", "#E0EFF5"),
        ("Selection", "#635781", "#ABD6E5"), ("SelectionText", "#EDF2FA", "#192C3B"),
        ("OnStatus", "#121A23", "#FFFFFF"), ("Disabled", "#A5B1C5", "#536978"), ("Green", "#84DDBB", "#207054"),
        ("Red", "#FFA0B0", "#AA304A"), ("Warning", "#EEC893", "#875514"),
        ("WarningPanel", "#282016", "#FFF4DF"), ("WarningStroke", "#705532", "#DAC49B"),
        ("SuccessPanel", "#152D28", "#E5F4ED"), ("DangerPanel", "#30202C", "#FCE9EE"),
        ("Thumb", "#65748E", "#6B8392"), ("ThumbHover", "#7F8FA7", "#526F80"),
        ("AtlasBackground", "#0B111D", "#EAF2F7"), ("AtlasOverlay", "#ED101826", "#EDF8FBFD"),
        ("AtlasText", "#E6EEF8", "#263D4D"), ("AtlasMuted", "#B5C6DA", "#526A7C")
    ];
    public static bool IsLight { get; private set; }
    public static bool WindowsUsesLight()
    {
        try { return Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is not int value || value != 0; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return true; }
    }

    public static void Apply(string choice)
    {
        // Shared live brush sources belong to the UI dispatcher, including those already used by open dialogs.
        Application.Current?.Dispatcher.VerifyAccess();
        IsLight = AppearancePreferences.IsLight(choice, WindowsUsesLight());
        foreach (var (key, dark, light) in palette)
        {
            var color = (Color)ColorConverter.ConvertFromString(IsLight ? light : dark);
            if (!brushes.TryGetValue(key, out var brush))
            {
                var source = new ColorValue(color); colors.Add(key, source);
                brush = new SolidColorBrush();
                BindingOperations.SetBinding(brush, SolidColorBrush.ColorProperty, new Binding(nameof(ColorValue.Value)) { Source = source, Mode = BindingMode.OneWay });
                brushes.Add(key, brush);
            }
            else colors[key].Value = color;
            if (Application.Current is { } app) app.Resources[key] = brush;
        }
        // Windows high contrast is an accessibility preference, even with an explicit app palette.
        if (SystemParameters.HighContrast)
        {
            // Use matched Windows foreground/background pairs throughout, including status fills and disabled controls.
            foreach (var key in new[] { "Background", "Panel", "PanelRaised", "Header", "Selected", "WarningPanel", "SuccessPanel", "DangerPanel", "OnStatus", "AtlasBackground", "AtlasOverlay" })
                Override(key, SystemColors.WindowColor);
            foreach (var key in new[] { "Text", "Muted", "Stroke", "Green", "Red", "Warning", "WarningStroke", "Thumb", "AtlasText", "AtlasMuted" })
                Override(key, SystemColors.WindowTextColor);
            Override("Accent", SystemColors.HighlightColor); Override("ThumbHover", SystemColors.HighlightColor);
            Override("OnAccent", SystemColors.HighlightTextColor); Override("Selection", SystemColors.HighlightColor);
            Override("SelectionText", SystemColors.HighlightTextColor); Override("Disabled", SystemColors.GrayTextColor);
        }
        if (Application.Current is { } current)
        {
            current.Resources["HoverOpacity"] = SystemParameters.HighContrast ? 1d : .94d;
            current.Resources["DisabledOpacity"] = SystemParameters.HighContrast ? 1d : .45d;
        }
    }
    private static void Override(string key, Color color) { colors[key].Value = color; }
    public static SolidColorBrush Token(string key)
    {
        if (brushes.Count == 0) Apply("Dark");
        return brushes[key];
    }
    public static SolidColorBrush Brush(string hex)
    {
        var color = (Color)ColorConverter.ConvertFromString(hex);
        return color.A != 255 ? Ui.RawBrush(hex) : Token(Role(hex));
    }
    /// <summary>The role an opaque page color plays.</summary>
    public static string Role(string hex)
    {
        if (legacyRoles.TryGetValue(hex, out var known)) return known;
        var color = (Color)ColorConverter.ConvertFromString(hex);
        var high = Math.Max(color.R, Math.Max(color.G, color.B));
        var low = Math.Min(color.R, Math.Min(color.G, color.B));
        // Existing page colors resolve to roles, rather than a dark color leaking into Glacier.
        string role;
        if (high < 75) role = high < 25 ? "Background" : high < 44 ? "PanelRaised" : "Stroke";
        else if (color.R > color.G * 1.22 && color.G > color.B * 1.15) role = "Warning";
        else if (color.R > color.G * 1.22 && color.R > color.B * 1.08) role = "Red";
        else if (color.G > color.R * 1.15 && color.G >= color.B * .85) role = "Green";
        else if (high > 210 && low > 190) role = "Text";
        // Only a saturated violet is an accent. The greyed lavenders of secondary text (#A99DBA, #B8AAC8) are muted;
        // as accents they read as links, teal in Glacier.
        else if (color.B > color.G * 1.14 && high > 180 && high - low >= high * .2) role = "Accent";
        else role = high > 210 ? "Text" : "Muted";
        legacyRoles[hex] = role;
        return role;
    }
}
