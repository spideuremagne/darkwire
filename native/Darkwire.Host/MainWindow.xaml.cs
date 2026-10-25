using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Text.Json;
using System.Threading;
using Forms = System.Windows.Forms;

namespace Darkwire.Host;

public partial class MainWindow : Window
{
    private readonly bool demo = App.Arguments.Contains("--demo") || App.Arguments.Contains("--capture");
    private readonly bool capture = App.Arguments.Contains("--capture");
    private readonly PolicyEngine engine = new();
    private readonly OwnConnections ownConnections = new(OwnConnections.InstalledServiceDirectory);
    private readonly DispatcherTimer telemetryTimer = new() { Interval = TimeSpan.FromSeconds(3) };
    private readonly DispatcherTimer toastTimer = new() { Interval = TimeSpan.FromSeconds(7) };
    private AppState state;
    private string settingsPath = AppPaths.State;
    private readonly ObservableCollection<ConnectionRow> connections = [];
    private readonly ObservableCollection<ConnectionRow> recentConnections = [];
    private readonly ReverseDnsResolver reverseDns = new();
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource? reverseLookupCancellation;
    private Task reverseLookupTask = Task.CompletedTask;
    private readonly ObservableCollection<FirewallRule> rules;
    private IGeoLookup? geo;
    private GlobeView? activeGlobe;
    private Forms.NotifyIcon? tray;
    private bool quitting, refreshing;
    // Started at sign-in into the tray: the window loaded off screen and is centered when first shown.
    private bool startHidden;
    private string currentPage = "Overview";
    private readonly List<double> downloadHistory = [], uploadHistory = [];
    private (long Received, long Sent) previousBytes;
    private DateTime previousSample = DateTime.UtcNow;
    private TextBlock? connectionCount, appCount, countryCount, listBlockCount, downloadText, uploadText;
    private string connectionSearch = "";
    private DataGrid? ruleGrid;
    private readonly Dictionary<FirewallMode, Button> modeButtons = [];
    private StackPanel? mapRegions;
    private TextBlock? mapDirections;
    // The Map page's legend and note, drawn again whenever whose red its arcs show changes.
    private Action? followMapService;
    // A capture shows the map without the service's refusals too, as a window that has not heard from the service yet does.
    private bool previewOnly;

    public MainWindow()
    {
        InitializeComponent();
        try { state = demo ? Demo.State() : StateStore.Read(AppPaths.State); }
        catch (Exception ex) { state = new(); settingsPath = AppPaths.State + ".recovered.json"; Loaded += (_, _) => ShowToast("Original settings retained. New changes will use settings.json.recovered.json: " + ex.Message); }
        AtlasBackground.NormalizeSettings(state);
        rules = new(state.Rules);
        InitializeAppearance();
        if (!demo) { _ = LoadGeoAsync(); installedBuild = new(AppContext.BaseDirectory); }
        try { var icon = new BitmapImage(new Uri("pack://application:,,,/Assets/darkwire.png")); TitleIcon.Source = icon; Icon = icon; } catch (IOException) { }
        DeviceLabel.Text = demo ? Demo.DeviceName : Environment.MachineName;
        if (typeof(MainWindow).Assembly.GetName().Version is { } version) VersionLabel.Text = "DARKWIRE / " + version.ToString(3);
        SourceLabel.Text = demo ? "DEMO DATA" : "LOCAL TELEMETRY";
        // The shield pulses while nothing is filtered, unless motion is reduced; a demo shows the monitor-only state it runs in.
        Shield.Pulse = Ui.MotionEnabled(state) && !capture;
        if (demo) { Shield.State = ShieldState.Inactive; Shield.ToolTip = AuthorityTitle.Text + "\n" + AuthorityDetail.Text; }
        // A demo's captures leave out the graphics of the PC they are taken on.
        RenderStatus.Text = demo ? "NATIVE .NET" : $"NATIVE .NET  /  D3D TIER {RenderCapability.Tier >> 16}";
        toastTimer.Tick += (_, _) => { Toast.Visibility = Visibility.Collapsed; toastTimer.Stop(); };
        telemetryTimer.Tick += async (_, _) => { await RefreshTelemetry(); await RefreshService(); CheckGeoUpdate(); CheckForUpdate(); };
        Closing += OnClosing;
        SourceInitialized += (_, _) => AcceptFileDrops();
        Loaded += async (_, _) =>
        {
            if (startHidden) { Hide(); ShowInTaskbar = true; }
            await RefreshTelemetry(); Navigate(StartPage());
            if (capture) { await CaptureViews(); return; }
            // Until the service answers, the banner says the routed VPN profiles are being established.
            SetupTray(); telemetryTimer.Start(); UpdateTunnelsBanner(); await RefreshService();
            // First run asks where this PC is, for the maps; started in the tray, it asks once the window shows.
            AskLocationOnce();
            // Restarted as administrator to set up: open setup straight away.
            if (App.Arguments.Contains("--setup") && Elevated) ShowSetupDialog();
        };
    }
    /// <summary>The first page: --manage opens Settings, --vpn the VPN page, and --page the one named, as a restart into an update reopens the page shown.</summary>
    private static string StartPage()
    {
        var named = Array.IndexOf(App.Arguments, "--page");
        if (named >= 0 && named + 1 < App.Arguments.Length && App.Arguments[named + 1] is "Overview" or "Connections" or "Map" or "Rules" or "VPN" or "Blocklists" or "Regions" or "Settings") return App.Arguments[named + 1];
        return App.Arguments.Contains("--manage") ? "Settings" : App.Arguments.Contains("--vpn") ? "VPN" : "Overview";
    }
    private void TitleDrag(object sender, MouseButtonEventArgs e) { if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; else if (e.LeftButton == MouseButtonState.Pressed) DragMove(); }
    private void MinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaximizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void CloseClick(object sender, RoutedEventArgs e) => Close();
    private void NavigateClick(object sender, RoutedEventArgs e) => Navigate((string)((Button)sender).Tag, keepScroll: false);
    private async void RefreshClick(object sender, RoutedEventArgs e) { await RefreshTelemetry(); ShowToast(demo ? "Demo data refreshed." : "Connection snapshot refreshed."); }
    /// <param name="keepScroll">
    /// Building the page shown again, as a change made on it does, keeps it scrolled where it was; a click on the sidebar
    /// opens a page at its top.
    /// </param>
    private void Navigate(string page, bool keepScroll = true)
    {
        var offsets = keepScroll && page == currentPage && PageContent.Content is DependencyObject shown ? PageScrollers(shown).Select(v => (v.HorizontalOffset, v.VerticalOffset)).ToList() : [];
        if (currentPage == "Rules") SaveColumns();
        activeGlobe?.Dispose(); activeGlobe = null; DisposeAtlasBackground(); currentPage = page;
        mapRegions = null; mapDirections = null; followMapService = null;
        connectionCount = appCount = countryCount = listBlockCount = downloadText = uploadText = null;
        RefreshNavigationSelection();
        var headings = page switch
        {
            "Overview" => ("NETWORK AT A GLANCE", "Network overview", "Connections, bandwidth, and policy status."),
            "Connections" => ("TRAFFIC INSPECTOR", "Connections", "Observed TCP endpoints, the route each takes, and their policy preview."),
            "Map" => ("GLOBAL PERSPECTIVE", "Connection map", "Local GeoIP resolution. No remote map queries."),
            "Rules" => ("POLICY WORKSPACE", "Firewall rules", "Double-click to edit. Drag headers to reorder. Click to sort."),
            "VPN" => ("PRIVATE ROUTES", "VPN profiles", "Route applications through WireGuard tunnels, and see each tunnel's state."),
            "Blocklists" => ("NETWORK FILTERS", "Blocklists & DNS", "Choose who answers lookups, and block ads, trackers and threats with curated DNS and IP lists."),
            "Regions" => ("GEOGRAPHIC POLICIES", "Regions & ASN", "Define country and autonomous system restrictions."),
            _ => ("PREFERENCES", "Settings", "Appearance, local data, and integration status.")
        };
        PageEyebrow.Text = headings.Item1; PageTitle.Text = headings.Item2; PageDescription.Text = headings.Item3;
        PageContent.Content = page switch { "Overview" => Overview(), "Connections" => ConnectionsPage(), "Map" => MapPage(), "Rules" => RulesPage(), "VPN" => VpnPage(), "Blocklists" => BlocklistsPage(), "Regions" => RegionsPage(), _ => SettingsPage() };
        if (offsets.Count > 0) RestoreScroll(offsets);
        UpdateMetrics();
    }

    /// <summary>The page's own scroll viewers and its tables', in the visual tree's order; those inside text boxes and lists are their own.</summary>
    private static IEnumerable<ScrollViewer> PageScrollers(DependencyObject root)
    {
        if (root is ScrollViewer { TemplatedParent: null or DataGrid } viewer) yield return viewer;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            foreach (var inner in PageScrollers(VisualTreeHelper.GetChild(root, i))) yield return inner;
    }

    /// <summary>
    /// Scrolls the page just built back to where the one it replaces was: at once, laid out first, so it is never drawn at
    /// its top, and again once what the page fills in later has its height.
    /// </summary>
    private void RestoreScroll(IReadOnlyList<(double Horizontal, double Vertical)> offsets)
    {
        var built = PageContent.Content;
        void Apply()
        {
            if (!ReferenceEquals(PageContent.Content, built) || built is not DependencyObject page) return;
            var viewers = PageScrollers(page).ToList();
            for (var i = 0; i < Math.Min(viewers.Count, offsets.Count); i++) { viewers[i].ScrollToHorizontalOffset(offsets[i].Horizontal); viewers[i].ScrollToVerticalOffset(offsets[i].Vertical); }
        }
        PageContent.UpdateLayout(); Apply();
        Dispatcher.BeginInvoke(Apply, DispatcherPriority.ContextIdle);
    }
    /// <summary>Where the maps draw this PC; demos keep the fixed anchor so captures stay comparable.</summary>
    private MapPlace Origin => demo ? MapOrigin.Default : MapOrigin.Resolve(state);
    private void Save()
    {
        state.Rules = rules.ToList();
        if (!demo) StateStore.Write(settingsPath, state);
    }
    private void ShowToast(string message) { ToastText.Text = message; Toast.Visibility = Visibility.Visible; toastTimer.Stop(); toastTimer.Start(); }
    private void SetupTray()
    {
        tray = new Forms.NotifyIcon { Text = "Darkwire — monitor only", Visible = true };
        try { var resource = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/darkwire.ico")); if (resource is not null) tray.Icon = new System.Drawing.Icon(resource.Stream); }
        catch (Exception) { }
        tray.Icon ??= System.Drawing.SystemIcons.Shield;
        tray.DoubleClick += (_, _) => Dispatcher.Invoke(ShowMain);
        var menu = new Forms.ContextMenuStrip(); menu.Items.Add("Open Darkwire", null, (_, _) => Dispatcher.Invoke(ShowMain)); menu.Items.Add(new Forms.ToolStripSeparator());
        foreach (var mode in Enum.GetValues<FirewallMode>())
        { var item = menu.Items.Add($"Preview: {ModeName(mode)}"); item.Click += (_, _) => Dispatcher.Invoke(() => SetMode(mode)); }
        menu.Items.Add(new Forms.ToolStripSeparator()); menu.Items.Add("Exit", null, (_, _) => Dispatcher.Invoke(() => { quitting = true; Close(); })); tray.ContextMenuStrip = menu;
    }
    private void ShowMain()
    {
        if (startHidden)
        {
            var area = SystemParameters.WorkArea; startHidden = false;
            Left = area.Left + Math.Max(0, (area.Width - Width) / 2); Top = area.Top + Math.Max(0, (area.Height - Height) / 2);
        }
        Show(); WindowState = WindowState.Normal; Activate();
        if (!state.MapOriginAsked) Dispatcher.BeginInvoke(AskLocationOnce, DispatcherPriority.ApplicationIdle);
    }

    /// <summary>
    /// Started at sign-in: the window loads off screen and goes to the tray, its prompts and alerts working as usual; without
    /// the tray it waits minimized on the taskbar.
    /// </summary>
    internal void StartInTray()
    {
        if (!state.CloseToTray) { WindowState = WindowState.Minimized; Show(); return; }
        startHidden = true; ShowInTaskbar = false; ShowActivated = false;
        WindowStartupLocation = WindowStartupLocation.Manual; Left = -32000; Top = -32000;
        Show();
    }
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!quitting && state.CloseToTray && tray is not null) { e.Cancel = true; Hide(); return; }
        SaveColumns(); Save(); lifetime.Cancel(); reverseLookupCancellation?.Cancel(); telemetryTimer.Stop(); toastTimer.Stop(); activeGlobe?.Dispose(); DisposeAtlasBackground(); tray?.Dispose(); Application.Current.Shutdown();
    }
    private async Task RefreshTelemetry()
    {
        if (refreshing) return; refreshing = true;
        try
        {
            var reading = demo ? Task.FromResult(Demo.Connections()) : Task.Run(WindowsTelemetry.Snapshot);
            var routes = await ConnectionRoutesAsync();
            // The router's relay sockets are how routed connections travel, not connections of their own.
            var snapshot = demo ? await reading : ownConnections.Made(await reading);
            var existing = connections.ToDictionary(r => ConnectionDisplay.Key(r.Connection), StringComparer.Ordinal);
            var nextRows = new List<ConnectionRow>();
            var observedAt = DateTimeOffset.UtcNow;
            foreach (var original in snapshot)
            {
                var location = demo ? Demo.LocationFor(original) : geo?.Lookup(original.RemoteAddress);
                var c = location is null ? original : original with { Country = location.Country, Asn = location.Asn };
                var decision = Preview(c);
                existing.TryGetValue(ConnectionDisplay.Key(c), out var old);
                var row = old is not null && old.Connection == c && old.Geo == location ? old : new(c, decision, location, old?.FirstSeen ?? observedAt);
                row.Update(decision); row.SetRoute(routes.Of(c));
                row.SetReverseHostname(state.ReverseDnsEnabled && reverseDns.TryGet(c.RemoteAddress, out var name) ? name : null);
                nextRows.Add(row);
            }
            Reconcile(connections, nextRows);
            Reconcile(recentConnections, connections.OrderByDescending(r => r.FirstSeen).Take(5).ToList());
            activeGlobe?.SetPoints(MapPoints()); UpdateMapRegions(); followMapService?.Invoke();
            StartReverseLookups();
            if (demo) { downloadHistory.AddRange(Demo.Download); uploadHistory.AddRange(Demo.Upload); }
            else
            {
                var bytes = await Task.Run(WindowsTelemetry.Bytes); var now = DateTime.UtcNow; var seconds = (now - previousSample).TotalSeconds;
                if (previousBytes != default && seconds > 0) { downloadHistory.Add(Math.Max(0, bytes.Received - previousBytes.Received) / seconds); uploadHistory.Add(Math.Max(0, bytes.Sent - previousBytes.Sent) / seconds); }
                previousBytes = bytes; previousSample = now;
            }
            if (downloadHistory.Count > 60) downloadHistory.RemoveRange(0, downloadHistory.Count - 60);
            if (uploadHistory.Count > 60) uploadHistory.RemoveRange(0, uploadHistory.Count - 60);
            UpdateMetrics();
            FooterStatus.Text = demo ? "Demo data  •  Policy simulation  •  No traffic is filtered" :
                serviceStatus?.Active == true ? $"Updated {DateTime.Now:HH:mm:ss}  •  Service: {ModeName(serviceStatus.Mode)}  •  Editor changes are drafts until applied" :
                $"Updated {DateTime.Now:HH:mm:ss}  •  Desktop policy preview  •  See Settings for enforcement status";
        }
        catch (Exception ex) { ShowToast("Could not read network telemetry: " + ex.Message); }
        finally { refreshing = false; }
    }
    /// <summary>The draft's decision on a connection; Darkwire's own programs need no rule while connections are routed.</summary>
    private PolicyDecision Preview(Connection connection) => ownConnections.Own(connection) ? engine.EvaluateOwn(state, connection) : engine.Evaluate(state, connection);
    private ConnectionRoutes connectionRoutes = ConnectionRoutes.None;
    /// <summary>
    /// Where the connections go: while Darkwire enforces, as its router reports them, the last report standing in for one
    /// that fails; otherwise they all take the Windows route.
    /// </summary>
    private async Task<ConnectionRoutes> ConnectionRoutesAsync()
    {
        if (demo) return new(Demo.Routed(state), Demo.Status(state).Tunnels ?? [], ProfileName);
        if (serviceStatus is not { Active: true } status) return connectionRoutes = ConnectionRoutes.None;
        try
        {
            // The connections wait for this read, so a busy service costs them a few seconds at most.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            if ((await Darkwire.Engine.ServiceClient.SendAsync(new("routed-connections"), timeout.Token)).Routed is { } routed) connectionRoutes = new(routed, status.Tunnels ?? [], ProfileName);
        }
        catch (Exception error) when (error is not OutOfMemoryException) { }
        return connectionRoutes;
    }
    private string ProfileName(Guid id) => state.VpnProfiles.FirstOrDefault(p => p.Id == id)?.Name ?? "VPN profile";
    private static void Reconcile(ObservableCollection<ConnectionRow> target, IReadOnlyList<ConnectionRow> next)
    {
        for (var i = 0; i < next.Count; i++)
        {
            if (i < target.Count && ReferenceEquals(target[i], next[i])) continue;
            var currentIndex = target.IndexOf(next[i]);
            if (currentIndex >= 0) target.Move(currentIndex, i);
            else target.Insert(i, next[i]);
        }
        while (target.Count > next.Count) target.RemoveAt(target.Count - 1);
    }
    private void StartReverseLookups()
    {
        if (demo || !state.ReverseDnsEnabled || !reverseLookupTask.IsCompleted || lifetime.IsCancellationRequested) return;
        reverseLookupCancellation?.Dispose();
        reverseLookupCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        var token = reverseLookupCancellation.Token;
        var addresses = connections.Where(r => string.IsNullOrWhiteSpace(r.Connection.Hostname))
            .Select(r => r.Connection.RemoteAddress).Distinct().Where(address => !reverseDns.TryGet(address, out _)).Take(32).ToArray();
        reverseLookupTask = Task.WhenAll(addresses.Select(async address =>
        {
            var hostname = await reverseDns.ResolveAsync(address, token);
            if (token.IsCancellationRequested || !state.ReverseDnsEnabled) return;
            foreach (var row in connections.Where(r => r.Connection.RemoteAddress == address)) row.SetReverseHostname(hostname);
        }));
    }
    private void SetReverseDns(bool enabled)
    {
        state.ReverseDnsEnabled = enabled; Save();
        if (!enabled)
        {
            reverseLookupCancellation?.Cancel();
            foreach (var row in connections) row.SetReverseHostname(null);
        }
        else StartReverseLookups();
    }
    private void UpdateMetrics()
    {
        if (connectionCount != null) connectionCount.Text = connections.Count.ToString("N0");
        if (appCount != null) appCount.Text = connections.Select(c => c.Connection.Path.Length == 0 ? c.Application : c.Connection.Path).Distinct().Count().ToString();
        if (countryCount != null) countryCount.Text = connections.Where(c => c.Connection.Country.Length > 0).Select(c => c.Connection.Country).Distinct().Count().ToString();
        // What every blocklist blocked since the service started.
        if (listBlockCount != null) listBlockCount.Text = (ListHits?.Total ?? 0).ToString("N0");
        if (downloadText != null) downloadText.Text = Ui.Rate(downloadHistory.LastOrDefault());
        if (uploadText != null) uploadText.Text = Ui.Rate(uploadHistory.LastOrDefault());
    }
    private static string ModeName(FirewallMode mode) => Modes.Name(mode);
    private void SetMode(FirewallMode mode)
    {
        state.Mode = mode; Save();
        foreach (var item in modeButtons) { item.Value.Background = Ui.Brush(item.Key == mode ? "#3B2F50" : "#1A1924"); item.Value.BorderBrush = Ui.Brush(item.Key == mode ? "#A58ACD" : "#34303E"); }
        foreach (var row in connections) row.Update(Preview(row.Connection));
        activeGlobe?.SetPoints(MapPoints());
        ShowToast($"Draft mode: {ModeName(mode)}. Apply the draft in Settings to change enforced policy.");
    }
    private UIElement ModeSelector()
    {
        modeButtons.Clear(); var grid = Ui.Columns(0, 0, 0, 0);
        foreach (var mode in Enum.GetValues<FirewallMode>())
        {
            var descriptions = mode switch { FirewallMode.Open => "All traffic is allowed", FirewallMode.Learning => "Review unmatched connections", FirewallMode.BlockNew => "Only matching allow rules", _ => "Block every connection" };
            var icon = mode switch { FirewallMode.Open => "\uE785", FirewallMode.Learning => "\uE8BD", FirewallMode.BlockNew => "\uE72E", _ => "\uE72E" };
            var content = Ui.Row(new TextBlock { Text = icon, FontFamily = new("Segoe Fluent Icons"), Foreground = Ui.Brush("#C4B1E7"), Margin = new(0, 0, 9, 0) }, Ui.Text(ModeName(mode), 13, "#ECE5F8", FontWeights.SemiBold));
            var button = Ui.Button("", () => SetMode(mode)); button.Content = content; button.ToolTip = descriptions; button.HorizontalContentAlignment = HorizontalAlignment.Left; button.Padding = new(15, 11, 12, 11); button.Margin = new(0, 0, mode == FirewallMode.Lockdown ? 0 : 9, 0);
            System.Windows.Automation.AutomationProperties.SetName(button, ModeName(mode));
            System.Windows.Automation.AutomationProperties.SetHelpText(button, descriptions);
            button.Background = Ui.Brush(state.Mode == mode ? "#3B2F50" : "#1A1924"); button.BorderBrush = Ui.Brush(state.Mode == mode ? "#A58ACD" : "#34303E"); modeButtons[mode] = button; Ui.Add(grid, button, (int)mode);
        }
        return grid;
    }
    private UIElement Overview() => OverviewWorkspace();
    /// <summary>
    /// What the service refused lately, while it enforces policy; a demo shows some. Null leaves the map to the editor's
    /// preview of the connections seen.
    /// </summary>
    private IReadOnlyList<Darkwire.Engine.BlockedFlow>? RefusedFlows => demo ? previewOnly ? null : Demo.Blocked() : serviceStatus is { Active: true, Blocked: { } blocked } ? blocked : null;

    /// <summary>
    /// The map's routes. While Darkwire enforces policy, the connections seen are ones it let through, and red marks what it
    /// refused, from the service; otherwise red marks what the editor's policy would deny of the connections seen.
    /// </summary>
    private IEnumerable<MapRoute> MapPoints()
    {
        if (RefusedFlows is not { } refused)
            return connections.Where(row => row.Geo is not null).Select(row => new MapRoute(row.Geo!.Latitude, row.Geo.Longitude, row.Decision == "Deny", row.Connection.Direction));
        var seen = connections.Where(row => row.Geo is not null).Select(row => new MapRoute(row.Geo!.Latitude, row.Geo.Longitude, false, row.Connection.Direction));
        var blocked = refused.Select(flow => (Flow: flow, Geo: demo ? Demo.LocationFor(new("", "", 0, flow.RemoteAddress, flow.RemotePort, 0, flow.Protocol, flow.Direction, "", Country: Demo.CountryOf(flow.RemoteAddress))) : geo?.Lookup(flow.RemoteAddress)))
            .Where(p => p.Geo is not null).Select(p => new MapRoute(p.Geo!.Latitude, p.Geo.Longitude, true, p.Flow.Direction));
        return [.. seen, .. blocked];
    }
    private DataGrid ConnectionTable(int limit = 0)
    {
        var table = new DataGrid { IsReadOnly = true, RowHeight = limit > 0 ? 38 : 49, ColumnHeaderHeight = 35, ItemsSource = limit > 0 ? recentConnections : connections };
        table.Columns.Add(ApplicationIcons.Column("APPLICATION", "Application", "Connection.Path", 200));
        var destination = Ui.Column("DESTINATION", "Destination", limit > 0 ? 285 : 280); destination.MinWidth = 240;
        if (limit > 0) destination.Width = new DataGridLength(1, DataGridLengthUnitType.Star);
        table.Columns.Add(destination);
        table.Columns.Add(Ui.Column("PROTOCOL", "Protocol", 85)); table.Columns.Add(Ui.Column("DIRECTION", "Direction", 95));
        table.Columns.Add(Ui.Column("LOCATION", "Location", 190)); table.Columns.Add(Ui.Column("PORT", "Port", 60));
        if (limit == 0) table.Columns.Add(Ui.Column("ROUTE", "Route", 150));
        table.Columns.Add(Ui.Column("POLICY PREVIEW", "Decision", 115));
        if (limit == 0) { table.Columns.Add(Ui.Column("PID", "Pid", 72)); table.Columns.Add(Ui.Column("STATE", "State", 120)); }
        table.MouseDoubleClick += (_, _) => { if (table.SelectedItem is ConnectionRow row) ConnectionDetails(row); };
        return table;
    }
    private UIElement ConnectionsPage() => ConnectionWorkspace();
    private void ConnectionDetails(ConnectionRow row)
    {
        var c = row.Connection; var appIcon = ApplicationIcons.Image(c.Path, 36); appIcon.Margin = new(0, 0, 14, 0);
        var panel = Ui.Stack(Ui.Row(appIcon, Ui.Text(c.ProcessDisplay, 24, "#EDE7F8", FontWeights.SemiBold)), Ui.Gap(10), Ui.Text(c.Path.Length > 0 ? c.Path : "Application path unavailable", 12, "#A39AAC"), Ui.Gap(22));
        // Windows filters the services sharing a process together, so a rule for this connection's service reaches them too.
        if (c.SharedServices() is { Length: > 0 } shared)
        { panel.Children.Add(Ui.Label("Shares its process with")); panel.Children.Add(Ui.Text(string.Join(", ", shared) + $", which a rule for {c.Service} also covers")); panel.Children.Add(Ui.Gap(15)); }
        foreach (var (key, value) in new[] { ("Remote endpoint", c.Endpoint), ("Remote name / address", row.Destination), ("Local endpoint", ConnectionDisplay.Endpoint(c.LocalAddress, c.LocalPort)), ("Protocol / direction", $"{c.Protocol} / {c.Direction}"), ("Location", row.Place), ("Country / ASN", $"{c.CountryDisplay} / {(c.Asn == 0 ? "Unresolved" : "AS" + c.Asn)}"), ("Route", row.Route), ("Policy preview", $"{row.Decision} — {row.Reason}") })
        { panel.Children.Add(Ui.Label(key)); panel.Children.Add(Ui.Text(value)); panel.Children.Add(Ui.Gap(15)); }
        var dialog = Dialog("Connection details", panel, 570);
        var allow = Ui.Button("Create allow rule", () => { CreateConnectionRule(c, RuleAction.Allow); dialog.Close(); }, true);
        var deny = Ui.Button("Create deny rule", () => { CreateConnectionRule(c, RuleAction.Deny); dialog.Close(); }); deny.Margin = new(10, 0, 0, 0); panel.Children.Add(Ui.Row(allow, deny)); dialog.ShowDialog();
    }
    private void CreateConnectionRule(Connection c, RuleAction action)
    {
        if (string.IsNullOrEmpty(c.Path)) { ShowToast("The application path is unavailable. Add a rule with its full path in Firewall rules."); return; }
        // A service host's rule names the connection's service when it is known; otherwise it covers the executable.
        rules.Add(new() { ApplicationName = c.Application, Path = c.Path, Service = c.Service.Length > 0 ? c.Service : "*", RemoteAddresses = c.RemoteAddress, RemotePorts = c.RemotePort.ToString(), Protocol = c.Protocol, Direction = c.Direction == TrafficDirection.Unknown ? TrafficDirection.Any : c.Direction, Action = action });
        Save(); ShowToast("Rule saved for policy preview."); foreach (var row in connections) row.Update(Preview(row.Connection));
        activeGlobe?.SetPoints(MapPoints());
    }
    private UIElement MapPage()
    {
        if (state.AtlasPresentation == "Observatory") return ObservatoryWorkspace();
        var root = Ui.Columns(0, 265); var canvas = new Grid();
        canvas.Children.Add(CreateAtlasBackground());
        activeGlobe = new GlobeView(MapPoints(), state.MapProjection, Origin) { Animate = Ui.MotionEnabled(state) }; activeGlobe.SetEnvironment(activeAtlasBackground!); activeGlobe.SetTheme(state.Theme, true); activeGlobe.ConfigureEffects(state); canvas.Children.Add(activeGlobe);
        var legend = Ui.Row();
        Border LegendItem(string text, string role)
        {
            var label = Ui.Text(text, 11); label.Foreground = AppearanceTheme.Token(role);
            return new Border { Child = label, Background = AppearanceTheme.Token("AtlasOverlay"), Padding = new(9, 5, 9, 5), CornerRadius = new(5), Margin = new(0, 0, 5, 0) };
        }
        void UpdateMapLegend()
        {
            legend.Children.Clear();
            legend.Children.Add(LegendItem("●  Outbound", "Accent"));
            legend.Children.Add(LegendItem("●  Inbound", "Green"));
            // Enforcing, red is what Darkwire refused; otherwise it is the editor's preview of what its policy would deny.
            var enforcing = RefusedFlows is not null;
            var red = LegendItem(enforcing ? "●  Blocked" : "●  Would be blocked", "Red");
            red.ToolTip = enforcing ? "Connection attempts Darkwire refused lately, by its router or its kernel filters." : "Connections seen that your edited policy would deny. Darkwire isn't enforcing it yet.";
            legend.Children.Add(red);
        }
        UpdateMapLegend(); legend.Margin = new(20); legend.HorizontalAlignment = HorizontalAlignment.Left; legend.VerticalAlignment = VerticalAlignment.Top; canvas.Children.Add(legend);
        var mapInfo = Ui.Text((demo ? "DEMO ROUTES  /  SAN FRANCISCO ORIGIN" : $"Origin: {Origin.Label} ({Origin.Source})\nEndpoints: " + geo switch
        {
            GeoIpDatabase { Cities: not null } => "IP geolocation by DB-IP, by city",
            GeoIpDatabase => "IP geolocation by DB-IP, by country",
            _ => "imported GeoIP data"
        }) + "\nMap: Natural Earth · 1:50m  ·  Cities: GeoNames (CC BY 4.0)", 11);
        mapInfo.Foreground = AppearanceTheme.Token("AtlasMuted");
        canvas.Children.Add(new Border { Child = mapInfo, Background = AppearanceTheme.Token("AtlasOverlay"), Padding = new(10, 7, 10, 7), CornerRadius = new(6), VerticalAlignment = VerticalAlignment.Bottom, HorizontalAlignment = HorizontalAlignment.Left, Margin = new(18, 0, 65, 42), IsHitTestVisible = false });
        var card = Ui.Card(canvas, 0); card.Margin = new(0, 0, 16, 0); Ui.Add(root, card, 0);
        var mapAtlas = activeGlobe;
        var backgroundControls = Ui.Stack(Ui.Gap(18), AtlasBackgroundControls(true), Ui.Gap(12));
        void UpdateMapPresentation()
        {
            var flat = mapAtlas.Projection == "Flat";
            backgroundControls.Visibility = flat ? Visibility.Collapsed : Visibility.Visible;
        }
        mapAtlas.ProjectionChanged += (_, _) => UpdateMapPresentation(); UpdateMapPresentation();
        var themes = new ComboBox { ItemsSource = GlobeView.Themes, SelectedItem = state.Theme };
        themes.SelectionChanged += (_, _) => { state.Theme = (string)themes.SelectedItem; activeGlobe?.SetTheme(state.Theme, activeGlobe.AttackView); UpdateMapLegend(); UpdateMapPresentation(); Save(); };
        var attack = new CheckBox { Content = "Elevated route arcs", IsChecked = true, Margin = new(0, 17, 0, 10) }; attack.Checked += (_, _) => activeGlobe?.SetTheme(state.Theme, true); attack.Unchecked += (_, _) => activeGlobe?.SetTheme(state.Theme, false);
        var auto = new CheckBox { Content = "Animate scene", IsChecked = !state.ReducedMotion }; auto.Checked += (_, _) => { state.ReducedMotion = false; UpdateAtlasMotion(); Save(); }; auto.Unchecked += (_, _) => { state.ReducedMotion = true; UpdateAtlasMotion(); Save(); };
        mapDirections = Ui.Text("", 11, "#BDB1CB"); mapRegions = Ui.Stack();
        var controls = Ui.Stack(Ui.Label("MAP VIEW"), Ui.Gap(10), AtlasProjectionSelector(), Ui.Gap(18), Ui.Label("MAP APPEARANCE"), Ui.Gap(13), themes, attack, auto, backgroundControls, Ui.Gap(12), Ui.Button("Reset view", () => activeGlobe?.ResetOrbit()), Ui.Gap(26), Ui.Label("CONNECTIONS"), Ui.Gap(12), mapDirections, Ui.Gap(20), Ui.Label("REMOTE REGIONS"), Ui.Gap(12), mapRegions);
        UpdateMapRegions();
        var note = Ui.Text("", 11, "#95899F");
        controls.Children.Add(Ui.Gap(10)); controls.Children.Add(note);
        // The legend and note say whose red the arcs show: the service's refusals once it answers, and the editor's preview until
        // then or while it doesn't, as when a window restarted into an update draws this page before it first hears from it.
        bool? shownEnforcing = null; var shownLocated = false;
        followMapService = () =>
        {
            var enforcing = RefusedFlows is not null; var located = geo is not null || demo;
            if (shownEnforcing == enforcing && shownLocated == located) return;
            var redraw = shownEnforcing is not null;
            shownEnforcing = enforcing; shownLocated = located;
            UpdateMapLegend();
            note.Text = !located ? "No GeoIP database is loaded yet."
                : enforcing ? "GeoIP positions are approximate. Map arcs show the connections seen, and in red the attempts Darkwire refused lately, not detected attacks."
                : "GeoIP positions are approximate. Map arcs show the connections seen; red marks those your edited policy would deny, not detected attacks.";
            // The arcs switch with them, not at the next count of connections.
            if (redraw) activeGlobe?.SetPoints(MapPoints());
        };
        followMapService();
        Ui.Add(root, Ui.Card(Ui.Scroll(controls), 18), 1); return root;
    }
    private void UpdateMapRegions()
    {
        if (mapDirections is not null)
            mapDirections.Text = $"↑ {connections.Count(c => c.Connection.Direction == TrafficDirection.Outbound)} outbound    ↓ {connections.Count(c => c.Connection.Direction == TrafficDirection.Inbound)} inbound\n{connections.Count(c => c.Connection.Direction == TrafficDirection.Unknown)} unknown direction";
        if (mapRegions is null) return;
        mapRegions.Children.Clear();
        foreach (var group in connections.GroupBy(c => c.Country).OrderByDescending(g => g.Count()).Take(8))
        { var row = Ui.Columns(0, 35); Ui.Add(row, Ui.Text(group.Key, 12, "#BCB2CC"), 0); Ui.Add(row, Ui.Text(group.Count().ToString(), 12, "#D2B5FF"), 1); row.Margin = new(0, 0, 0, 14); mapRegions.Children.Add(row); }
    }
    private Window Dialog(string title, UIElement content, double width = 520)
    {
        return new Window { Title = title, Owner = this, Width = width, MaxHeight = Math.Max(600, ActualHeight - 60), SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, Content = new Border { Padding = new(25), Child = Ui.Scroll(content) } };
    }
    private void ExportConnections()
    {
        var picker = new Microsoft.Win32.SaveFileDialog { Filter = "CSV|*.csv", FileName = "darkwire-connections.csv" }; if (picker.ShowDialog(this) != true) return;
        static string Cell(string s) => "\"" + (s.Length > 0 && "=+-@".Contains(s[0]) ? "'" : "") + s.Replace("\"", "\"\"") + "\"";
        File.WriteAllLines(picker.FileName, new[] { "Application,Path,Destination,RemoteAddress,RemotePort,Protocol,Direction,Country,Region,City,ASN,Route,PolicyPreview" }.Concat(connections.Select(r => string.Join(',', new[] { r.Application, r.Connection.Path, r.Destination, r.Connection.RemoteAddress, r.Port, r.Protocol, r.Direction, r.Country, r.Geo?.Region ?? "", r.Geo?.City ?? "", r.Connection.Asn.ToString(), r.Route, r.Decision }.Select(Cell)))));
        ShowToast("Connection snapshot exported.");
    }
    private async Task CaptureViews()
    {
        var index = Array.IndexOf(App.Arguments, "--capture"); var output = index >= 0 && index + 1 < App.Arguments.Length ? App.Arguments[index + 1] : Path.Combine(AppContext.BaseDirectory, "captures"); Directory.CreateDirectory(output);
        File.Delete(Path.Combine(output, "capture-result.json")); File.Delete(Path.Combine(output, "capture-error.txt"));
        try
        {
            // Captures go into the documentation, so they show the demo's PC, never the one they are taken on.
            if (DeviceLabel.Text != Demo.DeviceName) throw new InvalidOperationException("The capture would show this PC's name.");
            foreach (var page in new[] { "Overview", "Map", "Rules", "Connections", "VPN", "Blocklists", "Regions", "Settings" })
            {
                Navigate(page); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout();
                var bitmap = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); bitmap.Render(this); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using var file = File.Create(Path.Combine(output, page + ".png")); encoder.Save(file);
            }
            // The VPN page again, scrolled to its last profile cards.
            Navigate("VPN"); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            if (PageContent.Content is ScrollViewer vpnScroll) { vpnScroll.ScrollToEnd(); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout(); }
            var lower = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); lower.Render(this);
            var lowerEncoder = new PngBitmapEncoder(); lowerEncoder.Frames.Add(BitmapFrame.Create(lower));
            using (var file = File.Create(Path.Combine(output, "VPN-end.png"))) lowerEncoder.Save(file);
            // The blocklists page further down: domain lists with their select-all button, and the names blocked one by one.
            Navigate("Blocklists"); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            if (PageContent.Content is ScrollViewer listScroll)
                foreach (var (name, offset) in new[] { ("Blocklists-names", listScroll.ScrollableHeight * .45), ("Blocklists-end", listScroll.ScrollableHeight) })
                {
                    listScroll.ScrollToVerticalOffset(offset); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout();
                    var shot = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); shot.Render(this);
                    var shotEncoder = new PngBitmapEncoder(); shotEncoder.Frames.Add(BitmapFrame.Create(shot));
                    using var file = File.Create(Path.Combine(output, name + ".png")); shotEncoder.Save(file);
                }
            // Settings at its end, where the Windows integration card sums up how Darkwire works with Windows.
            Navigate("Settings"); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            if (PageContent.Content is ScrollViewer settingsScroll) { settingsScroll.ScrollToEnd(); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout(); }
            var settingsEnd = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); settingsEnd.Render(this);
            var settingsEncoder = new PngBitmapEncoder(); settingsEncoder.Frames.Add(BitmapFrame.Create(settingsEnd));
            using (var file = File.Create(Path.Combine(output, "Settings-end.png"))) settingsEncoder.Save(file);
            // The banner an upgrade brings up while the window is open.
            UpdateBanner.Visibility = Visibility.Visible; Navigate("Overview"); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout();
            var updated = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); updated.Render(this);
            var updatedEncoder = new PngBitmapEncoder(); updatedEncoder.Frames.Add(BitmapFrame.Create(updated));
            using (var file = File.Create(Path.Combine(output, "Update-banner.png"))) updatedEncoder.Save(file);
            UpdateBanner.Visibility = Visibility.Collapsed;
            // The banner while VPN tunnels start and are checked end to end: the demo's first tunnel starting, the others being checked.
            var demoStatus = Demo.Status(state);
            if (VpnState.Establishing(state, demoStatus with { Tunnels = [.. (demoStatus.Tunnels ?? []).Select((t, i) => i == 0 ? t with { State = "Starting" } : t with { State = "Up", Checking = true })] }, false) is { } establishing)
            {
                TunnelsBannerTitle.Text = establishing.Title; TunnelsBannerDetail.Text = establishing.Detail; TunnelsBanner.Visibility = Visibility.Visible;
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(180); UpdateLayout();
                var establishingShot = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); establishingShot.Render(this);
                var establishingEncoder = new PngBitmapEncoder(); establishingEncoder.Frames.Add(BitmapFrame.Create(establishingShot));
                using (var file = File.Create(Path.Combine(output, "Tunnels-banner.png"))) establishingEncoder.Save(file);
                TunnelsBanner.Visibility = Visibility.Collapsed;
            }
            await CaptureScrollBars(output);
            await CaptureAtlasBackgrounds(output);
            await CaptureFlatAtlas(output);
            Connection Edge(TrafficDirection direction) => new("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 4242,
                "203.0.113.42", 443, 52914, "TCP", direction, Hostname: "example.com", LocalAddress: "192.0.2.10");
            // A service sharing its svchost.exe: the rule names it and also covers the services in the same process.
            var service = new Connection("svchost", @"C:\Windows\System32\svchost.exe", 1312, "203.0.113.43", 443, 52915, "TCP", TrafficDirection.Outbound,
                Service: "wuauserv", Hostname: "update.example.com", LocalAddress: "192.0.2.10", HostedServices: "BITS, Schedule, UsoSvc, wuauserv");
            // A window's content on its background, without the frame a dialog has around it.
            async Task CaptureWindow(Window window, string name)
            {
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(150); window.UpdateLayout();
                var content = (FrameworkElement)window.Content; var area = new Rect(0, 0, Math.Ceiling(content.ActualWidth), Math.Ceiling(content.ActualHeight));
                var frame = new DrawingVisual();
                var image = new VisualBrush(content) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top, ViewboxUnits = BrushMappingMode.Absolute, Viewbox = area };
                using (var drawing = frame.RenderOpen()) { drawing.DrawRectangle(window.Background, null, area); drawing.DrawRectangle(image, null, area); }
                var bitmap = new RenderTargetBitmap((int)area.Width, (int)area.Height, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(frame); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                using (var file = File.Create(Path.Combine(output, name + ".png"))) encoder.Save(file);
                window.Close();
            }
            foreach (var (name, flow) in new[] { ("Learning-outbound", Edge(TrafficDirection.Outbound)), ("Learning-inbound", Edge(TrafficDirection.Inbound)), ("Learning-service", service) })
                await CaptureWindow(ShowLearningRequest(new LearningRequest(Guid.NewGuid(), flow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(60), 1), state), name);
            // A port's answer reaches TCP and UDP, and the note under the rule scope follows the choice.
            static IEnumerable<DependencyObject> Tree(DependencyObject parent) => LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>().SelectMany(child => Tree(child).Prepend(child));
            var anyHost = ShowLearningRequest(new LearningRequest(Guid.NewGuid(), Edge(TrafficDirection.Outbound), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(60), 1), state);
            Tree(anyHost).OfType<ComboBox>().First(c => System.Windows.Automation.AutomationProperties.GetName(c) == "Rule scope").SelectedIndex = 1;
            await CaptureWindow(anyHost, "Learning-any-host");
            var setupWindow = SetupDialog(); setupWindow.Show(); await CaptureWindow(setupWindow, "Setup");
            var assignWindow = VpnAppDialog(state.VpnProfiles[0]); assignWindow.Show(); await CaptureWindow(assignWindow, "Vpn-assign");
            var countriesWindow = CountryChooser(CountryOptions(), allowList: true); countriesWindow.Show(); await CaptureWindow(countriesWindow, "Regions-countries");
            var dnsWindow = DnsServerChooser(Demo.DnsCatalog()); dnsWindow.Show(); await CaptureWindow(dnsWindow, "Dns-servers");
            // Where the user is, as first run asks it: a country with its cities to choose from, then a city with a pin dropped across the bay.
            var asked = LocationDialog(firstRun: true, new("US", null, null)); asked.Show(); await CaptureWindow(asked, "Location");
            var pinned = LocationDialog(firstRun: false, new("US", Cities.In("US").First(c => c.Name == "San Francisco"), (37.80444, -122.27083))); pinned.Show(); await CaptureWindow(pinned, "Location-pin");
            await CaptureInteractions(output);
            // The status shield in each of its states, as the sidebar's card shows them.
            var shields = new StackPanel { Orientation = Orientation.Horizontal, Background = Ui.Brush("#1A1826") };
            foreach (var shown in Enum.GetValues<ShieldState>()) shields.Children.Add(new StatusShield { Pulse = false, State = shown, Width = 48, Height = 48, Margin = new(12) });
            shields.Measure(new(double.PositiveInfinity, double.PositiveInfinity)); shields.Arrange(new(shields.DesiredSize)); shields.UpdateLayout();
            var shieldShot = new RenderTargetBitmap((int)Math.Ceiling(shields.ActualWidth), (int)Math.Ceiling(shields.ActualHeight), 96, 96, PixelFormats.Pbgra32); shieldShot.Render(shields);
            var shieldEncoder = new PngBitmapEncoder(); shieldEncoder.Frames.Add(BitmapFrame.Create(shieldShot));
            using (var file = File.Create(Path.Combine(output, "Status-shield.png"))) shieldEncoder.Save(file);
            // The sidebar's shield pulses only while it is red, allowed to pulse and on screen.
            async Task<bool> Pulsing() { UpdateLayout(); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); return Shield.HasAnimatedProperties; }
            Shield.Pulse = true;
            var shieldChecks = new Dictionary<string, bool> { ["pulsesWhenInactive"] = await Pulsing() };
            Shield.Visibility = Visibility.Collapsed; shieldChecks["pausesWhenHidden"] = !await Pulsing();
            Shield.Visibility = Visibility.Visible; shieldChecks["resumesWhenShown"] = await Pulsing();
            Shield.State = ShieldState.Active; shieldChecks["steadyWhenActive"] = !await Pulsing() && Shield.Opacity == 1;
            Shield.State = ShieldState.Inactive; Shield.Pulse = false; shieldChecks["steadyWithReducedMotion"] = !await Pulsing() && Shield.Opacity == 1;
            File.WriteAllText(Path.Combine(output, "shield-check.json"), JsonSerializer.Serialize(shieldChecks, new JsonSerializerOptions { WriteIndented = true }));
            if (shieldChecks.ContainsValue(false)) throw new InvalidOperationException("Status shield check failed: " + string.Join(", ", shieldChecks.Where(c => !c.Value).Select(c => c.Key)));
            await CaptureAppearanceViews(output);
            File.WriteAllText(Path.Combine(output, "capture-result.json"), JsonSerializer.Serialize(new { success = true, views = 8, projections = 2, backgrounds = AtlasBackground.Presets.Length, rules = rules.Count, connections = connections.Count, renderingTier = RenderCapability.Tier >> 16 }));
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(output, "capture-error.txt"), ex.ToString());
            File.WriteAllText(Path.Combine(output, "capture-result.json"), JsonSerializer.Serialize(new { success = false, error = ex.Message }));
        }
        quitting = true; Close();
    }
}

public sealed class ConnectionRow : Observable
{
    public Connection Connection { get; }
    public GeoRecord? Geo { get; }
    public DateTimeOffset FirstSeen { get; }
    private string? reverseHostname;
    private string route = "";
    private PolicyDecision decision;
    public ConnectionRow(Connection connection, PolicyDecision decision, GeoRecord? geo, DateTimeOffset? firstSeen = null) { Connection = connection; this.decision = decision; Geo = geo; FirstSeen = firstSeen ?? DateTimeOffset.UtcNow; }
    public string Application => Connection.ProcessDisplay;
    public string Destination => ConnectionDisplay.Destination(Connection.RemoteAddress, Connection.Hostname, reverseHostname);
    public string Country => Geo?.CountryName ?? Connection.CountryDisplay;
    /// <summary>The city, or the region when the city data names no city, then the country.</summary>
    public string Location => Geo is { } geo && (geo.City.Length > 0 ? geo.City : geo.Region) is { Length: > 0 } place ? $"{place}, {Country}" : Country;
    /// <summary>City, region and country, as far as they are known.</summary>
    public string Place => string.Join(", ", new[] { Geo?.City, Geo?.Region, Country }.Where(part => !string.IsNullOrEmpty(part)));
    public string Port => Connection.RemotePort.ToString();
    public string Protocol => Connection.Protocol;
    public string Direction => Connection.Direction switch { TrafficDirection.Inbound => "↓ Inbound", TrafficDirection.Outbound => "↑ Outbound", _ => "Unknown" };
    public int Pid => Connection.ProcessId;
    public string State => Connection.State;
    public string Decision => decision.Kind == DecisionKind.Prompt ? "Needs review" : decision.Kind.ToString();
    public string Reason => decision.Reason;
    /// <summary>The VPN profile whose tunnel carries the connection, or the Windows route (<see cref="ConnectionRoutes"/>).</summary>
    public string Route => route;
    public void Update(PolicyDecision next) { decision = next; Notify(nameof(Decision)); Notify(nameof(Reason)); }
    public void SetRoute(string next) { if (route == next) return; route = next; Notify(nameof(Route)); }
    public void SetReverseHostname(string? hostname) { if (reverseHostname == hostname) return; reverseHostname = hostname; Notify(nameof(Destination)); }
}
