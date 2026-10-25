using System.Windows.Data;

namespace Darkwire.Host;

public static class Ui
{
    public static SolidColorBrush Brush(string hex) => AppearanceTheme.Brush(hex);
    public static SolidColorBrush RawBrush(string hex) { var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); b.Freeze(); return b; }
    public static bool MotionEnabled(AppState state) => !state.ReducedMotion && SystemParameters.ClientAreaAnimation && !SystemParameters.HighContrast;
    public static TextBlock Text(string text, double size = 13, string color = "#F0EFF9", FontWeight? weight = null) => new() { Text = text, FontSize = Math.Max(11, size), Foreground = Brush(color), FontWeight = weight ?? FontWeights.Normal, TextWrapping = TextWrapping.Wrap };
    public static TextBlock Label(string text) => Text(text.ToUpperInvariant(), 11, "#8E859F", FontWeights.Medium);
    public static StackPanel Stack(params UIElement[] children) { var p = new StackPanel(); foreach (var c in children) p.Children.Add(c); return p; }
    public static StackPanel Row(params UIElement[] children) { var p = Stack(children); p.Orientation = Orientation.Horizontal; return p; }
    public static Border Card(UIElement content, double padding = 20) => new() { Background = Brush("#14151E"), BorderBrush = Brush("#292735"), BorderThickness = new(1), CornerRadius = new(12), Padding = new(padding), Child = content };
    public static Button Button(string text, Action action, bool primary = false) { var b = new Button { Content = text }; if (primary) b.Style = (Style)Application.Current.FindResource("Primary"); b.Click += (_, _) => action(); return b; }
    public static Button AsyncButton(string text, Func<Task> action, bool primary = false)
    {
        var b = new Button { Content = text }; if (primary) b.Style = (Style)Application.Current.FindResource("Primary");
        b.Click += async (_, _) => { b.IsEnabled = false; try { await action(); } catch (Exception ex) { MessageBox.Show(ex.Message, "Darkwire"); } finally { b.IsEnabled = true; } }; return b;
    }
    public static Border Pill(string text, string color = "#B7A0FF", string background = "#292238") => new() { Background = Brush(background), CornerRadius = new(4), Padding = new(9, 4, 9, 4), VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Left, Child = Text(text, 10, color) };
    public static FrameworkElement Gap(double height = 16) => new Border { Height = height };
    public static Grid Columns(params double[] widths) { var grid = new Grid(); foreach (var w in widths) grid.ColumnDefinitions.Add(new() { Width = w == 0 ? new(1, GridUnitType.Star) : new(w) }); return grid; }
    public static void Add(Grid grid, UIElement child, int column, int row = 0) { Grid.SetColumn(child, column); Grid.SetRow(child, row); grid.Children.Add(child); }
    public static ScrollViewer Scroll(UIElement element) => new() { Content = element, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new(0, 0, 6, 0) };
    public static TextBox Input(string value, string? tooltip = null) => new() { Text = value, ToolTip = tooltip, Margin = new(0, 5, 0, 12), MinWidth = 100 };
    public static DataGridTextColumn Column(string title, string property, double width = 150, bool readOnly = true) => new() { Header = title, Binding = new Binding(property) { Mode = readOnly ? BindingMode.OneWay : BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.LostFocus }, Width = width, IsReadOnly = readOnly, SortMemberPath = property };
    public static string Rate(double value) => value >= 1_000_000 ? $"{value / 1_000_000:F1} MB/s" : value >= 1000 ? $"{value / 1000:F0} KB/s" : $"{value:F0} B/s";
}
