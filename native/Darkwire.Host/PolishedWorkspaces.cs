using System.Windows.Data;

namespace Darkwire.Host;

public partial class MainWindow
{
    private UIElement OverviewWorkspace()
    {
        var root = new Grid();
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new(1.35, GridUnitType.Star), MinHeight = 120 });
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star), MinHeight = 135 });
        root.Children.Add(Ui.Stack(SetupBanner(), ModeSelector(), Ui.Gap(15)));
        var map = new Grid { ClipToBounds = true, Background = AppearanceTheme.Token("AtlasBackground") };
        map.Children.Add(CreateAtlasBackground());
        activeGlobe = new(MapPoints(), state.MapProjection, Origin) { Animate = Ui.MotionEnabled(state) };
        activeGlobe.SetEnvironment(activeAtlasBackground!); activeGlobe.SetTheme(state.Theme, false); activeGlobe.ConfigureEffects(state);
        map.Children.Add(activeGlobe);
        var label = Ui.Text("CONNECTION ATLAS", 11); label.Foreground = AppearanceTheme.Token("AtlasText");
        var caption = new Border { Child = label, Background = AppearanceTheme.Token("AtlasOverlay"), CornerRadius = new(6), Padding = new(10, 6, 10, 6), Margin = new(15, 12, 0, 0), HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, IsHitTestVisible = false };
        map.Children.Add(caption);
        var explore = Ui.Button("Explore map  ↗", () => Navigate("Map")); explore.Padding = new(12, 7, 12, 7); explore.Margin = new(8, 0, 0, 0);
        var tools = Ui.Row(AtlasProjectionSelector(), explore); tools.HorizontalAlignment = HorizontalAlignment.Right; tools.VerticalAlignment = VerticalAlignment.Top; tools.Margin = new(0, 12, 15, 0); map.Children.Add(tools);
        var mapCard = Ui.Card(map, 0); mapCard.ClipToBounds = true; Grid.SetRow(mapCard, 1); root.Children.Add(mapCard);
        var band = Ui.Columns(0, 0, 0, 0, 0, 0); band.Margin = new(0, 14, 0, 14);
        UIElement Item(string title, out TextBlock value, string detail, bool first = false)
        {
            value = Ui.Text("0", 25, "#F0EFF9", FontWeights.Medium);
            return new Border { BorderBrush = AppearanceTheme.Token("Stroke"), BorderThickness = new(first ? 0 : 1, 0, 0, 0), Padding = new(first ? 0 : 18, 0, 8, 0), ToolTip = detail,
                Child = Ui.Stack(Ui.Text(title, 12, "#989AAE"), Ui.Gap(6), value) };
        }
        Ui.Add(band, Item("Connections", out connectionCount, "Observed endpoints", true), 0);
        Ui.Add(band, Item("Applications", out appCount, "Using the network"), 1);
        Ui.Add(band, Item("Countries", out countryCount, "Known destinations"), 2);
        Ui.Add(band, Item("List blocks", out listBlockCount, "Since service start"), 3);
        Ui.Add(band, Item("↓ Download", out downloadText, "Current rate"), 4);
        Ui.Add(band, Item("↑ Upload", out uploadText, "Current rate"), 5);
        Grid.SetRow(band, 2); root.Children.Add(band);
        var bottom = new Grid(); bottom.RowDefinitions.Add(new() { Height = new(43) }); bottom.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        var title = Ui.Text("Recent connections", 15, "#F0EFF9", FontWeights.Medium); title.Margin = new(16, 11, 0, 0); bottom.Children.Add(title);
        var actions = Ui.Row(Ui.Button("Rules  →", () => Navigate("Rules")), Ui.Button("View all  →", () => Navigate("Connections")));
        actions.HorizontalAlignment = HorizontalAlignment.Right; actions.Margin = new(0, 3, 10, 3);
        foreach (Button b in actions.Children) { b.Background = Brushes.Transparent; b.BorderThickness = new(0); b.Padding = new(12, 4, 12, 4); }
        bottom.Children.Add(actions);
        var table = ConnectionTable(5);
        // The overview is deliberately compact. Every field remains in Connections and its inspector.
        foreach (var column in table.Columns.Where(c => c.SortMemberPath is "Protocol" or "Port" or "Direction")) column.Visibility = Visibility.Collapsed;
        Grid.SetRow(table, 1); bottom.Children.Add(table); var recent = Ui.Card(bottom, 0); Grid.SetRow(recent, 3); root.Children.Add(recent);
        return root;
    }

    private UIElement ConnectionWorkspace()
    {
        var root = new DockPanel();
        var search = Ui.Input(connectionSearch, "Search applications, names, addresses, location or route"); search.Width = 360; search.HorizontalAlignment = HorizontalAlignment.Left;
        var table = ConnectionTable(); var view = new ListCollectionView(connections); table.ItemsSource = view;
        void Filter() { connectionSearch = search.Text; view.Filter = item => item is ConnectionRow row && $"{row.Application} {row.Destination} {row.Connection.RemoteAddress} {row.Place} {row.Route}".Contains(connectionSearch, StringComparison.OrdinalIgnoreCase); }
        search.TextChanged += (_, _) => Filter(); Filter();
        var inspector = Ui.Stack();
        var body = Ui.Columns(0, 290); var inspectorCard = Ui.Card(Ui.Scroll(inspector), 18); inspectorCard.Margin = new(18, 0, 0, 0);
        Ui.Add(body, Ui.Card(table, 0), 0); Ui.Add(body, inspectorCard, 1);
        var allColumns = new CheckBox { Content = "All columns", VerticalAlignment = VerticalAlignment.Center, Margin = new(20, 0, 20, 0) };
        void Columns()
        {
            var full = allColumns.IsChecked == true;
            foreach (var column in table.Columns)
            {
                column.Visibility = full || column.SortMemberPath is "Application" or "Destination" or "Decision" ? Visibility.Visible : Visibility.Collapsed;
                if (column.SortMemberPath == "Destination") { column.Width = full ? new(280) : new(1, DataGridLengthUnitType.Star); column.MinWidth = 180; }
            }
            inspectorCard.Visibility = full ? Visibility.Collapsed : Visibility.Visible; body.ColumnDefinitions[1].Width = new(full ? 0 : 290);
        }
        allColumns.Checked += (_, _) => Columns(); allColumns.Unchecked += (_, _) => Columns(); Columns();
        var tools = new DockPanel { Margin = new(0, 0, 0, 8) }; var export = Ui.Button("Export CSV", ExportConnections); export.VerticalAlignment = VerticalAlignment.Center;
        DockPanel.SetDock(export, Dock.Right); tools.Children.Add(export); DockPanel.SetDock(allColumns, Dock.Right); tools.Children.Add(allColumns); tools.Children.Add(Ui.Stack(Ui.Label("Search connections"), search));
        DockPanel.SetDock(tools, Dock.Top); root.Children.Add(tools);
        void Inspect(ConnectionRow? row)
        {
            inspector.Children.Clear(); inspector.Children.Add(Ui.Label("Selected connection")); inspector.Children.Add(Ui.Gap(17));
            if (row is null) { inspector.Children.Add(Ui.Text("Select a connection to inspect its route and policy.", 13, "#989AAE")); return; }
            var icon = ApplicationIcons.Image(row.Connection.Path, 32); icon.Margin = new(0, 0, 12, 0);
            var identity = new DockPanel(); DockPanel.SetDock(icon, Dock.Left); identity.Children.Add(icon);
            identity.Children.Add(Ui.Text(row.Application, 16, "#F0EFF9", FontWeights.Medium)); inspector.Children.Add(identity);
            inspector.Children.Add(Ui.Gap(18));
            foreach (var (name, property) in new[] { ("Destination", nameof(ConnectionRow.Destination)), ("Location", nameof(ConnectionRow.Place)), ("Protocol / port", nameof(ConnectionRow.Protocol)), ("Direction", nameof(ConnectionRow.Direction)), ("Route", nameof(ConnectionRow.Route)), ("Policy preview", nameof(ConnectionRow.Decision)), ("Reason", nameof(ConnectionRow.Reason)) })
            {
                var value = Ui.Text("", 13);
                value.SetBinding(TextBlock.TextProperty, new Binding(property) { Source = row, StringFormat = property == nameof(ConnectionRow.Protocol) ? "{0} / " + row.Port : null });
                inspector.Children.Add(Ui.Label(name)); inspector.Children.Add(Ui.Gap(4)); inspector.Children.Add(value); inspector.Children.Add(Ui.Gap(15));
            }
            inspector.Children.Add(Ui.Button("Details & rule actions  ↗", () => ConnectionDetails(row)));
        }
        table.SelectionChanged += (_, _) => Inspect(table.SelectedItem as ConnectionRow);
        if (view.Count > 0) table.SelectedIndex = 0;
        Inspect(table.SelectedItem as ConnectionRow);
        var note = Ui.Text("Select a connection to inspect it. Use All columns for the full sortable table; double-click for rule actions.", 11, "#989AAE"); note.Margin = new(0, 13, 0, 0); DockPanel.SetDock(note, Dock.Bottom); root.Children.Add(note);
        root.Children.Add(body); return root;
    }

    private UIElement ObservatoryWorkspace()
    {
        var canvas = new Grid { ClipToBounds = true, Background = AppearanceTheme.Token("AtlasBackground") };
        canvas.Children.Add(CreateAtlasBackground());
        activeGlobe = new(MapPoints(), state.MapProjection, Origin) { Animate = Ui.MotionEnabled(state) };
        activeGlobe.SetEnvironment(activeAtlasBackground!); activeGlobe.SetTheme(state.Theme, true); activeGlobe.ConfigureEffects(state); canvas.Children.Add(activeGlobe);
        var controls = Ui.Row(AtlasProjectionSelector(), Ui.Button("Appearance & motion", () => Navigate("Settings")), Ui.Button("Reset view", () => activeGlobe?.ResetOrbit()));
        foreach (FrameworkElement element in controls.Children) element.Margin = new(6, 0, 0, 0);
        controls.HorizontalAlignment = HorizontalAlignment.Right; controls.VerticalAlignment = VerticalAlignment.Top; controls.Margin = new(18); canvas.Children.Add(controls);
        var origin = Ui.Text("CONNECTION ATLAS\n\n" + Origin.Label, 13); origin.Foreground = AppearanceTheme.Token("AtlasText");
        canvas.Children.Add(new Border { Child = origin, Background = AppearanceTheme.Token("AtlasOverlay"), CornerRadius = new(8), Padding = new(14), Margin = new(18), VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Left, MaxWidth = 300, IsHitTestVisible = false });
        var dock = Ui.Columns(0, 0, 0, 0);
        FrameworkElement Count(string label, out TextBlock text)
        {
            text = Ui.Text("0", 28); text.Foreground = AppearanceTheme.Token("AtlasText"); var caption = Ui.Text(label, 11); caption.Foreground = AppearanceTheme.Token("AtlasMuted");
            return Ui.Stack(text, Ui.Gap(5), caption);
        }
        Ui.Add(dock, Count("CONNECTIONS", out connectionCount), 0); Ui.Add(dock, Count("COUNTRIES", out countryCount), 1);
        Ui.Add(dock, Count("↓ DOWNLOAD", out downloadText), 2); Ui.Add(dock, Count("↑ UPLOAD", out uploadText), 3);
        var meaning = Ui.Text(RefusedFlows is null ? "↑ Outbound   ↓ Inbound   · Unknown   /   Red: would be blocked" : "↑ Outbound   ↓ Inbound   · Unknown   /   Red: blocked attempts", 11);
        meaning.Foreground = AppearanceTheme.Token("AtlasMuted");
        var attribution = Ui.Text("Approximate locations · Map: Natural Earth · Cities: GeoNames (CC BY 4.0)", 11); attribution.Foreground = AppearanceTheme.Token("AtlasMuted");
        canvas.Children.Add(new Border { Child = Ui.Stack(dock, Ui.Gap(14), meaning, Ui.Gap(6), attribution), Background = AppearanceTheme.Token("AtlasOverlay"), CornerRadius = new(10), Padding = new(18), Margin = new(18, 0, 76, 44), VerticalAlignment = VerticalAlignment.Bottom, IsHitTestVisible = false });
        return Ui.Card(canvas, 0);
    }
}
