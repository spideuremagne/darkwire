using Darkwire.Engine;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    private readonly Dictionary<Guid, VpnCardView> vpnCards = [];
    /// <summary>
    /// What a profile's card updates with each status: its state, its throughput with a chart in and out, the buttons that
    /// reconnect and check a tunnel, which only a tunnel can use, and the last check's result.
    /// </summary>
    private sealed record VpnCardView(Border Pill, TextBlock Detail, FrameworkElement Traffic, TextBlock Rates, Sparkline Received, Sparkline Sent,
        Button Reconnect, Button Refresh, TextBlock Checked);
    // Each profile's last check from its card: when, what the service said, and whether the tunnel's DNS server answered.
    private readonly Dictionary<Guid, (DateTimeOffset At, string Text, bool Answered)> vpnChecks = [];
    private Border? vpnBanner;
    private VpnPageAlert? vpnBannerShown;
    // Why the last apply failed, shown until the editor's routes change.
    private string? vpnApplyError, vpnErrorRoutes;
    // An apply runs, and routes changed while it did.
    private bool vpnApplying, vpnApplyAgain;
    // Route changes apply once a burst of them settles.
    private DispatcherTimer? vpnApplyTimer;

    /// <summary>The status the VPN page shows; a demo shows tunnels in each state.</summary>
    private ServiceStatus? VpnStatus => demo ? Demo.Status(state) : serviceStatus;
    /// <summary>Route changes apply as they are made while Darkwire enforces policy and this app may change it.</summary>
    private bool CanApplyNow => !demo && Elevated && serviceStatus is { Active: true };
    private bool VpnApplyPending => vpnApplying || vpnApplyTimer?.IsEnabled == true;

    /// <summary>
    /// The editor's VPN routes changed. While Darkwire enforces policy they apply a moment later, once a burst of edits
    /// settles; otherwise they wait for setup, and the VPN page says so.
    /// </summary>
    private void VpnRoutesChanged(string change)
    {
        Save();
        if (CanApplyNow)
        {
            if (vpnApplyTimer is null)
            {
                vpnApplyTimer = new() { Interval = TimeSpan.FromMilliseconds(600) };
                vpnApplyTimer.Tick += async (_, _) => { vpnApplyTimer.Stop(); await ApplyVpnRoutes(); };
            }
            vpnApplyTimer.Stop(); vpnApplyTimer.Start();
            ShowToast(change + " Applying…");
        }
        else ShowToast(demo ? change : change + (!Elevated ? " Restart Darkwire as administrator to apply it." : " It applies when Darkwire takes over; set it up from the Overview."));
        UpdateVpnStatus();
    }

    private UIElement VpnPage()
    {
        vpnCards.Clear(); vpnBannerShown = null;
        var body = Ui.Stack(); var toolbar = Ui.Row(Ui.Button("+  Import configurations", ImportVpn, true), Ui.AsyncButton("Service storage", ManageStoredVpnProfiles), Ui.Text($"    {state.VpnProfiles.Count} / {VpnAssignments.MaximumProfiles} configurations  ·  or drop WireGuard .conf files here", 12, "#B5A7C5")); toolbar.Margin = new(0, 0, 0, 18); body.Children.Add(toolbar);
        vpnBanner = Warning(new Border()); vpnBanner.Margin = new(0, 0, 0, 16); vpnBanner.Visibility = Visibility.Collapsed; body.Children.Add(vpnBanner);
        var routes = new List<RouteOption> { new(null, "Windows route (includes a system VPN)") };
        routes.AddRange(state.VpnProfiles.Select(p => new RouteOption(p.Id, p.Name + " · " + p.Kind)));
        var defaultRoute = new ComboBox { ItemsSource = routes, DisplayMemberPath = nameof(RouteOption.Label), SelectedItem = routes.FirstOrDefault(p => p.ProfileId == state.DefaultOutboundVpnProfileId) ?? routes[0], Margin = new(0, 8, 0, 0) };
        // The cards say which profile carries every other application, so the page is drawn again once the choice settles.
        defaultRoute.SelectionChanged += (_, _) =>
        {
            var picked = state.VpnProfiles.FirstOrDefault(p => p.Id == ((RouteOption)defaultRoute.SelectedItem).ProfileId);
            state.DefaultOutboundVpnProfileId = picked?.Id;
            VpnRoutesChanged(picked is null ? "Applications without a profile of their own use the Windows route." : $"Applications without a profile of their own go through {picked.Name}.");
            Dispatcher.BeginInvoke(() => Navigate("VPN"), DispatcherPriority.Background);
        };
        // Local traffic staying local is part of the routes, applied with them.
        var local = new CheckBox { Content = "Keep local and internal traffic off VPN tunnels", IsChecked = state.LocalNetworkBypassesVpn, Margin = new(0, 12, 0, 0),
            ToolTip = "Devices on your own networks, such as printers, shares and the router's page, and every private, link-local and unique local address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7) stay reachable directly, under your rules, " +
                "unless a profile's tunnel routes that private network itself, as an office VPN does. Multicast, broadcast and loopback never enter a tunnel. DNS still goes through the tunnel." };
        // The kill switch's description names what stays reachable, so the page is drawn again.
        local.Checked += (_, _) => { state.LocalNetworkBypassesVpn = true; VpnRoutesChanged("Local and internal traffic stays off VPN tunnels."); Dispatcher.BeginInvoke(() => Navigate("VPN"), DispatcherPriority.Background); };
        local.Unchecked += (_, _) => { state.LocalNetworkBypassesVpn = false; VpnRoutesChanged("Local and internal traffic follows the VPN routes."); Dispatcher.BeginInvoke(() => Navigate("VPN"), DispatcherPriority.Background); };
        // A default profile's tunnel carries everything else or nothing does: the router never falls back to the Windows route,
        // and the kernel guards every application around it, whether or not the service runs.
        var defaultProfile = state.VpnProfiles.FirstOrDefault(p => p.Id == state.DefaultOutboundVpnProfileId);
        var killSwitch = Ui.Text(defaultProfile is null
            ? "Kill switch: make a VPN profile the default route, and nothing reaches the internet whenever its tunnel is down."
            : $"Kill switch on: while {defaultProfile.Name} is down or still connecting, applications without a profile of their own reach " +
                (state.LocalNetworkBypassesVpn ? "only your local and internal networks" : "nothing at all") + ": no internet, no DNS. Darkwire never falls back to the Windows route.",
            11, defaultProfile is null ? "#A097B1" : "#7CE3BA");
        killSwitch.Margin = new(0, 10, 0, 0);
        body.Children.Add(Ui.Card(Ui.Stack(Ui.Label("DEFAULT OUTBOUND ROUTE"), defaultRoute, Ui.Gap(8), Ui.Text("Used by applications without a profile of their own.", 11, "#A097B1"), local, killSwitch), 17)); body.Children.Add(Ui.Gap(12));
        body.Children.Add(OwnRouteCard(defaultProfile)); body.Children.Add(Ui.Gap(12));
        body.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Tunnels run in the Darkwire service.", 14, "#CCB7F2", FontWeights.SemiBold), Ui.Gap(6), Ui.Text("Connect a profile to bring its tunnel up, then assign applications or make it the default route. While Darkwire enforces policy, route changes apply as you make them, and Darkwire stores each configuration in its service when it first needs it. Assigned applications use only their tunnel; while it is down their connections are refused.", 12, "#A097B1")), 17)); body.Children.Add(Ui.Gap(20));
        if (state.VpnProfiles.Count == 0) body.Children.Add(Empty("No VPN profiles", "Import a WireGuard .conf configuration.", "Import profile", ImportVpn));
        foreach (var profile in state.VpnProfiles)
        {
            var pill = Ui.Pill(""); pill.HorizontalAlignment = HorizontalAlignment.Right;
            var stored = profile.CredentialsRevision == Guid.Empty ? "not stored in the service yet" : "stored in the service";
            var header = Ui.Columns(0, 130); Ui.Add(header, Ui.Stack(Ui.Label(profile.Kind), Ui.Gap(8), Ui.Text(profile.Name, 22, "#EEE8F7", FontWeights.SemiBold), Ui.Gap(7), Ui.Text(profile.Endpoint + "  ·  " + stored, 12, "#9A90AD")), 0); Ui.Add(header, pill, 1);
            var detail = Ui.Text("", 12, "#B4A9C4"); detail.Margin = new(0, 12, 0, 0);
            // While the tunnel runs: its latest rates, and a chart of the last few minutes with both directions on one scale.
            var rates = Ui.Text("", 12, "#CFC4DF"); rates.VerticalAlignment = VerticalAlignment.Center;
            var received = new Sparkline { Color = AppearanceTheme.Token("Green").Color }; var sent = new Sparkline { Color = AppearanceTheme.Token("Accent").Color };
            var chart = new Grid { Height = 48 }; chart.Children.Add(received); chart.Children.Add(sent);
            var traffic = Ui.Columns(0, 260); Ui.Add(traffic, rates, 0); Ui.Add(traffic, chart, 1); traffic.Margin = new(0, 14, 0, 0); traffic.Visibility = Visibility.Collapsed;
            // The connection's buttons: connect or disconnect, then reconnect and refresh, which act on a running tunnel. An OpenVPN
            // profile from an earlier build can still be disconnected and removed, but nothing more: it never connects.
            var supported = profile.Kind == "WireGuard";
            var running = VpnAssignments.Tunneled(state).Any(p => p.Id == profile.Id);
            var routed = profile.Applications.Count > 0 || profile.Id == state.DefaultOutboundVpnProfileId || VpnAssignments.OwnProfile(state) == profile.Id;
            var connect = running ? Ui.AsyncButton("Disconnect", () => SetConnected(profile, false)) : Ui.AsyncButton("Connect", () => SetConnected(profile, true), primary: true);
            connect.ToolTip = running ? routed ? "Stops the tunnel. What it carries is refused until you connect it again, never sent another way." : "Stops the tunnel."
                : routed ? "Starts the tunnel, and what it carries goes through it again." : "Starts the tunnel now, with nothing routed through it yet.";
            var reconnect = Ui.AsyncButton("Reconnect", () => ReconnectVpn(profile));
            reconnect.ToolTip = "Starts the tunnel again with a new connection to its server. Its connections end, and new ones wait until it is back.";
            var refresh = Ui.AsyncButton("Refresh", () => CheckVpn(profile));
            refresh.ToolTip = "Checks the tunnel now: asks its DNS server a question through it, and reads its state again.";
            reconnect.Margin = refresh.Margin = new(10, 0, 0, 0); reconnect.IsEnabled = refresh.IsEnabled = false; connect.IsEnabled = supported || running;
            var connection = Ui.Row(connect, reconnect, refresh); connection.Margin = new(0, 14, 0, 0);
            var checkedLine = Ui.Text("", 11, "#9A90AD"); checkedLine.Margin = new(0, 8, 0, 0); checkedLine.Visibility = Visibility.Collapsed;
            vpnCards[profile.Id] = new(pill, detail, traffic, rates, received, sent, reconnect, refresh, checkedLine);
            var carries = profile.AppCount + (profile.Id == state.DefaultOutboundVpnProfileId ? " · default route for every other application" : "") +
                (VpnAssignments.OwnProfile(state) == profile.Id ? " · Darkwire's own connections" : "");
            var apps = Ui.Stack(); foreach (var app in profile.Applications) { var line = new DockPanel(); var remove = Ui.Button("×", () => { profile.Applications.Remove(app); Navigate("VPN"); VpnRoutesChanged($"{Path.GetFileName(app)} uses the default route again."); }); DockPanel.SetDock(remove, Dock.Right); line.Children.Add(remove); line.Children.Add(Ui.Text(app, 11, "#B4A9C4")); line.Margin = new(0, 7, 0, 0); apps.Children.Add(line); }
            // The service always fails closed; there is no setting that lets assigned apps fall back to another network.
            var kill = new CheckBox { Content = "Require tunnel for assigned apps", IsChecked = true, IsEnabled = false, Margin = new(0, 15, 0, 8), ToolTip = "Always on: while this tunnel is down, its apps' connections are refused." };
            var actions = Ui.Row();
            var assign = Ui.Button("+  Assign application", () => VpnAppDialog(profile).ShowDialog()); assign.IsEnabled = supported;
            actions.Children.Add(assign);
            var delete = Ui.Button("Remove profile", () =>
            {
                // A profile the routes use, here or in the service, goes from them at once.
                var used = VpnAssignments.Running(state).Any(p => p.Id == profile.Id) || serviceStatus?.Routes?.Any(r => r.ProfileId == profile.Id) == true;
                state.VpnProfiles.Remove(profile); if (state.DefaultOutboundVpnProfileId == profile.Id) state.DefaultOutboundVpnProfileId = null;
                if (state.OwnTraffic == OwnRoute.Profile && state.OwnTrafficProfileId == profile.Id) { state.OwnTraffic = OwnRoute.Default; state.OwnTrafficProfileId = null; }
                Navigate("VPN");
                if (used) VpnRoutesChanged($"Removed {profile.Name}; nothing goes through it now."); else Save();
            });
            delete.Margin = new(10, 0, 0, 0);
            var upload = Ui.AsyncButton("Store in service", () => UploadVpnProfile(profile)); upload.Margin = new(10, 0, 0, 0); upload.IsEnabled = supported;
            actions.Children.Add(delete); actions.Children.Add(upload);
            var card = Ui.Card(Ui.Stack(header, detail, traffic, connection, checkedLine, Ui.Gap(18), Ui.Label(carries), apps, kill, Ui.Gap(12), actions), 23); card.Margin = new(0, 0, 0, 16); body.Children.Add(card);
        }
        UpdateVpnStatus();
        return Ui.Scroll(body);
    }

    private sealed record OwnRouteOption(OwnRoute Route, Guid? ProfileId, string Label)
    { public override string ToString() => Label; }

    /// <summary>
    /// Where Darkwire's own connections go, its downloads and its encrypted DNS: the default route unless chosen otherwise. A
    /// profile carries them only through its tunnel, so while it is down they wait rather than leave another way.
    /// </summary>
    private Border OwnRouteCard(VpnProfile? defaultProfile)
    {
        var options = new List<OwnRouteOption>
        {
            new(OwnRoute.Default, null, "Default route" + (defaultProfile is null ? " (the Windows route now)" : $" (through {defaultProfile.Name} now)")),
            new(OwnRoute.Windows, null, "Windows route (includes a system VPN)")
        };
        options.AddRange(state.VpnProfiles.Select(p => new OwnRouteOption(OwnRoute.Profile, p.Id, p.Name + " · " + p.Kind)));
        var selected = options.FirstOrDefault(o => o.Route == state.OwnTraffic && (o.Route != OwnRoute.Profile || o.ProfileId == state.OwnTrafficProfileId)) ?? options[0];
        var own = new ComboBox { ItemsSource = options, DisplayMemberPath = nameof(OwnRouteOption.Label), SelectedItem = selected, Margin = new(0, 8, 0, 0) };
        System.Windows.Automation.AutomationProperties.SetName(own, "Route for Darkwire's own connections");
        own.SelectionChanged += (_, _) =>
        {
            var picked = (OwnRouteOption)own.SelectedItem;
            state.OwnTraffic = picked.Route; state.OwnTrafficProfileId = picked.ProfileId;
            VpnRoutesChanged(picked.Route switch
            {
                OwnRoute.Windows => "Darkwire's own connections use the Windows route.",
                OwnRoute.Profile => $"Darkwire's own connections go through {picked.Label.Split(" · ")[0]}.",
                _ => "Darkwire's own connections follow the default route."
            });
            Dispatcher.BeginInvoke(() => Navigate("VPN"), DispatcherPriority.Background);
        };
        var through = VpnAssignments.OwnProfile(state) is { } id ? state.VpnProfiles.FirstOrDefault(p => p.Id == id) : null;
        var note = Ui.Text(through is null
            ? "Its downloads (GeoIP data, blocklists, the resolver list) and its encrypted DNS leave through the Windows route."
            : $"Its downloads and its encrypted DNS go only through {through.Name}; while that tunnel is down they wait, and never leave another way.", 11, through is null ? "#A097B1" : "#7CE3BA");
        note.Margin = new(0, 10, 0, 0);
        return Ui.Card(Ui.Stack(Ui.Label("DARKWIRE'S OWN CONNECTIONS"), own, note), 17);
    }

    /// <summary>Draws each card's tunnel state and the page's alert from the service's last answer.</summary>
    private void UpdateVpnStatus()
    {
        if (currentPage != "VPN" || vpnBanner is null) return;
        var status = VpnStatus; var offline = !demo && serviceWatch.Offline; var now = DateTimeOffset.Now;
        foreach (var profile in state.VpnProfiles)
        {
            if (!vpnCards.TryGetValue(profile.Id, out var card)) continue;
            var view = VpnState.Describe(profile, state, status, offline, now, VpnApplyPending);
            var (color, background) = view.Tone switch
            {
                VpnTone.Good => ("#7CE3BA", "#16302A"),
                VpnTone.Busy => ("#C9B4EF", "#292238"),
                VpnTone.Warn => ("#E8B07A", "#2E2418"),
                VpnTone.Bad => ("#F2849C", "#33192A"),
                _ => ("#A99DBA", "#211F2B")
            };
            card.Pill.Background = Ui.Brush(background);
            if (card.Pill.Child is TextBlock text) { text.Text = view.Pill; text.Foreground = Ui.Brush(color); }
            card.Detail.Text = view.Detail; card.Detail.Foreground = Ui.Brush(view.Tone switch { VpnTone.Bad => "#F2849C", VpnTone.Warn => "#E8C9A8", _ => "#B4A9C4" });
            var tunnel = status?.Tunnels?.FirstOrDefault(t => t.ProfileId == profile.Id);
            // Reconnect starts a tunnel that is up or failed again; Refresh checks one that is up.
            var live = demo || CanApplyNow;
            card.Reconnect.IsEnabled = live && tunnel?.State is "Up" or "Failed";
            card.Refresh.IsEnabled = live && tunnel?.State == "Up";
            if (vpnChecks.TryGetValue(profile.Id, out var check))
            {
                card.Checked.Text = $"Checked at {check.At:HH:mm:ss}: {check.Text}";
                card.Checked.Foreground = Ui.Brush(check.Answered ? "#7CE3BA" : "#F2849C"); card.Checked.Visibility = Visibility.Visible;
            }
            if (tunnel is not null && VpnState.Throughput(tunnel) is { } throughput)
            {
                card.Rates.Inlines.Clear();
                card.Rates.Inlines.Add(new System.Windows.Documents.Run(throughput.Received) { Foreground = Ui.Brush("#7CE3BA") });
                card.Rates.Inlines.Add(new System.Windows.Documents.Run("    " + throughput.Sent) { Foreground = Ui.Brush("#C4A9FF") });
                card.Rates.Inlines.Add(new System.Windows.Documents.Run("\n" + throughput.Peak) { Foreground = Ui.Brush("#9A90AD"), FontSize = 11 });
                var top = Math.Max(1, Math.Max(tunnel.InRates!.Max(), tunnel.OutRates!.Max()) * 1.2);
                card.Received.Values = [.. tunnel.InRates!.Select(r => (double)r)]; card.Sent.Values = [.. tunnel.OutRates!.Select(r => (double)r)];
                card.Received.Scale = card.Sent.Scale = top; card.Received.InvalidateVisual(); card.Sent.InvalidateVisual();
                card.Traffic.Visibility = Visibility.Visible;
            }
            else card.Traffic.Visibility = Visibility.Collapsed;
        }
        var alert = demo ? null : VpnState.Alert(state, status, offline, Elevated, VpnApplyPending);
        if (vpnApplyError is not null && RoutesKey() != vpnErrorRoutes) vpnApplyError = vpnErrorRoutes = null;
        if (alert is not null && vpnApplyError is { } error) alert = alert with { Title = "VPN routes weren't applied", Detail = error };
        if (alert == vpnBannerShown && (alert is null) == (vpnBanner.Visibility == Visibility.Collapsed)) return;
        vpnBannerShown = alert;
        vpnBanner.Visibility = alert is null ? Visibility.Collapsed : Visibility.Visible;
        if (alert is null) return;
        var button = alert.Action switch
        {
            VpnPageAction.Apply => Ui.AsyncButton("Apply VPN routes", ApplyVpnRoutes, true),
            VpnPageAction.SetUp => Ui.Button("Set up Darkwire", ShowSetupDialog, true),
            VpnPageAction.RestartElevated => Ui.Button("Restart as administrator", () => RestartElevated("--vpn"), true),
            _ => Ui.AsyncButton("Check again", () => RefreshService(true), true)
        };
        button.VerticalAlignment = VerticalAlignment.Center;
        var row = new DockPanel(); DockPanel.SetDock(button, Dock.Right); row.Children.Add(button);
        var words = Ui.Stack(Ui.Text(alert.Title, 13, "#E8B07A", FontWeights.SemiBold), Ui.Gap(3), Ui.Text(alert.Detail, 11, "#E8C9A8"));
        words.Margin = new(0, 0, 16, 0); row.Children.Add(words);
        vpnBanner.Child = row;
    }

    /// <summary>
    /// Stores the configurations the editor's routes need, then applies those routes alone to the enforced policy. The
    /// rest of the draft stays a draft, still current if it was.
    /// </summary>
    private async Task ApplyVpnRoutes()
    {
        if (demo) return;
        // Routes changed while an apply runs go in the next one.
        if (vpnApplying) { vpnApplyAgain = true; return; }
        if (!Elevated) { ShowToast("Restart Darkwire as administrator to apply VPN routes."); return; }
        vpnApplyTimer?.Stop();
        // Edits that came back to what the service runs leave nothing to apply.
        if (vpnApplyError is null && serviceStatus is { Active: true } current && VpnState.Applied(state, current)) { UpdateVpnStatus(); return; }
        vpnApplying = true; vpnApplyAgain = false; Save(); vpnApplyError = vpnErrorRoutes = null;
        UpdateVpnStatus();
        try
        {
            await StoreVpnCredentials();
            var response = await ServiceClient.SendAsync(new("apply-vpn", Routes: new(state.VpnProfiles, state.DefaultOutboundVpnProfileId, state.LocalNetworkBypassesVpn, state.OwnTraffic, state.OwnTrafficProfileId)));
            if (!response.Success) throw new InvalidOperationException(response.Message + ErrorList(response));
            // Routes edited meanwhile stay as edited, for the next apply.
            if (response.Policy is { } policy) AdoptVpnRoutes(policy, response.Status?.PolicyRevision, routes: !vpnApplyAgain);
            ShowToast(response.Message);
        }
        catch (Exception error) when (error is not OutOfMemoryException) { vpnApplyError = error.Message; vpnErrorRoutes = RoutesKey(); }
        finally { vpnApplying = false; }
        await RefreshService(true);
        if (vpnApplyAgain) { await ApplyVpnRoutes(); return; }
        if (currentPage == "VPN") Navigate("VPN");
    }

    /// <summary>The editor's VPN routes as text, to tell whether they changed since an apply failed.</summary>
    private string RoutesKey() => System.Text.Json.JsonSerializer.Serialize(new { Routes = VpnState.Draft(state), state.LocalNetworkBypassesVpn, state.OwnTraffic, state.OwnTrafficProfileId });

    /// <summary>
    /// Connects a profile, so its tunnel runs whether or not anything routes through it, or disconnects it, so its tunnel stops
    /// and what it carries is refused until it is connected again; while Darkwire enforces policy and runs as administrator
    /// the change applies at once. Disconnecting the default route asks first, since nothing else reaches the internet then.
    /// </summary>
    private async Task SetConnected(VpnProfile profile, bool connect)
    {
        var routed = profile.Applications.Count > 0 || profile.Id == state.DefaultOutboundVpnProfileId || VpnAssignments.OwnProfile(state) == profile.Id;
        if (!connect && profile.Id == state.DefaultOutboundVpnProfileId && MessageBox.Show(this,
                $"{profile.Name} is the default route: while it is disconnected, applications without a profile of their own reach nothing beyond your local networks. " +
                "To go without it, choose the Windows route as the default instead.\n\nDisconnect it?", "Disconnect the default route?", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        profile.KeepConnected = connect; profile.Disconnected = !connect && routed; Save();
        if (CanApplyNow) { await ApplyVpnRoutes(); return; }
        Navigate("VPN");
        if (!demo) ShowToast(!Elevated ? "Saved. Restart Darkwire as administrator to connect or disconnect tunnels."
            : $"Saved. {(connect ? "The tunnel connects" : "This applies")} once Darkwire enforces policy; set it up from the Overview.");
    }

    /// <summary>Starts a profile's tunnel again at once with a new connection to its server, as its card's Reconnect asks.</summary>
    private async Task ReconnectVpn(VpnProfile profile)
    {
        if (demo) { ShowToast($"Reconnecting {profile.Name}: its tunnel starts again with a new connection, and its applications wait meanwhile."); return; }
        var response = await ServiceClient.SendAsync(new("reconnect-vpn", VpnProfileId: profile.Id));
        ShowToast(response.Message);
        await RefreshService(true);
    }

    /// <summary>
    /// Checks a profile's tunnel now, as its card's Refresh asks: the service asks the tunnel's DNS server a question through
    /// it, and the card shows the answer and the state read again.
    /// </summary>
    private async Task CheckVpn(VpnProfile profile)
    {
        var response = demo ? new ServiceResponse(true, $"{profile.Name}'s DNS server 10.64.0.1 answered through the tunnel in 31 ms.", Check: new(profile.Id, true, "10.64.0.1", 31))
            : await ServiceClient.SendAsync(new("check-vpn", VpnProfileId: profile.Id));
        vpnChecks[profile.Id] = (DateTimeOffset.Now, response.Message, response.Success && response.Check?.Answered == true);
        ShowToast(response.Message);
        if (!demo) await RefreshService(true);
        UpdateVpnStatus();
    }

    /// <summary>
    /// Stores each configuration the editor routes through that the service doesn't hold as the editor last stored it. One
    /// the enforced policy already routes through keeps the credentials the service has, which can't change under it.
    /// </summary>
    private async Task StoreVpnCredentials()
    {
        // A disconnected profile starts no tunnel, so the service needs no credentials for it.
        var needed = VpnAssignments.Tunneled(state).ToList();
        if (needed.Count == 0) return;
        var listing = await ServiceClient.SendAsync(new("vpn-profiles"));
        if (!listing.Success) throw new InvalidOperationException(listing.Message);
        var held = (listing.VpnProfiles ?? []).ToDictionary(p => p.Id);
        var enforced = serviceStatus?.Routes?.Select(r => r.ProfileId).ToHashSet() ?? [];
        try
        {
            foreach (var profile in needed)
            {
                if (held.TryGetValue(profile.Id, out var stored) && (stored.Revision == profile.CredentialsRevision || enforced.Contains(profile.Id) || profile.EncryptedConfig.Length == 0))
                { profile.CredentialsRevision = stored.Revision; profile.Kind = stored.Kind; profile.Endpoint = stored.Endpoint; continue; }
                if (profile.EncryptedConfig.Length == 0) throw new InvalidOperationException($"{profile.Name}'s configuration is neither on this computer nor in the service. Import it again.");
                await StoreVpnProfile(profile);
            }
        }
        finally { Save(); }
    }

    /// <summary>
    /// Takes the VPN routes the service now enforces into the editor, keeping each configuration's local copy, unless they
    /// were edited again meanwhile. A draft based on the revision just before this change differed from the service only in
    /// its own edits, so it still does; with no revision given, the change was more than the routes.
    /// </summary>
    private void AdoptVpnRoutes(AppState policy, long? revision, bool routes = true)
    {
        if (routes)
        {
            var localSecrets = state.VpnProfiles.ToDictionary(p => p.Id, p => p.EncryptedConfig);
            foreach (var profile in policy.VpnProfiles) profile.EncryptedConfig = localSecrets.GetValueOrDefault(profile.Id, "");
            state.VpnProfiles = policy.VpnProfiles; state.DefaultOutboundVpnProfileId = policy.DefaultOutboundVpnProfileId;
            state.LocalNetworkBypassesVpn = policy.LocalNetworkBypassesVpn;
            state.OwnTraffic = policy.OwnTraffic; state.OwnTrafficProfileId = policy.OwnTrafficProfileId;
        }
        if (revision is { } now && draftPolicyRevision == now - 1) draftPolicyRevision = now;
        Save();
    }

    /// <summary>Picks an application for a profile from those seen connecting or named in rules, or any program on disk.</summary>
    private Window VpnAppDialog(VpnProfile profile)
    {
        var choices = VpnState.Choices(profile, state, connections.Select(r => r.Connection), rules, AppContext.BaseDirectory);
        var panel = Ui.Stack(Ui.Label("ASSIGN APPLICATION"), Ui.Gap(10), Ui.Text("Route an application through " + profile.Name, 21, "#EAE3F7", FontWeights.SemiBold), Ui.Gap(6),
            Ui.Text("It will use only this tunnel, and while the tunnel is down its connections are refused. Each application has one route, so assigning it here moves it from any other profile.", 11, "#A599B3"), Ui.Gap(14));
        var search = Ui.Input("", "Search by name or path"); search.Margin = new(0, 0, 0, 10); panel.Children.Add(search);
        System.Windows.Automation.AutomationProperties.SetName(search, "Search applications");
        var list = Ui.Stack(); panel.Children.Add(new ScrollViewer { Content = list, MaxHeight = 330, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        var error = Ui.Text("", 11, "#F2849C"); panel.Children.Add(error);
        var window = Dialog("Assign application", panel, 560);
        void Assign(string path)
        {
            VpnAssignments.Assign(state, profile.Id, path); window.Close(); Navigate("VPN");
            VpnRoutesChanged($"{Path.GetFileName(path)} now routes through {profile.Name}.");
        }
        void Fill()
        {
            list.Children.Clear();
            var query = search.Text.Trim(); string? group = null;
            var shown = choices.Where(c => c.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) || c.Path.Contains(query, StringComparison.OrdinalIgnoreCase)).Take(200).ToList();
            foreach (var choice in shown)
            {
                if (choice.Source != group) { group = choice.Source; var heading = Ui.Label(group); heading.Margin = new(0, list.Children.Count == 0 ? 0 : 10, 0, 6); list.Children.Add(heading); }
                var name = Ui.Text(choice.Name + (choice.CurrentProfile is { } current ? "  ·  now " + current : ""), 13, "#ECE4F7");
                var where = Ui.Text(choice.Path, 10, "#A99DBA"); where.TextTrimming = TextTrimming.CharacterEllipsis; where.TextWrapping = TextWrapping.NoWrap;
                var row = new Button { Content = Ui.Stack(name, Ui.Gap(2), where), HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new(12, 8, 12, 8), Margin = new(0, 0, 0, 6), ToolTip = choice.Path };
                row.Click += (_, _) => Assign(choice.Path); list.Children.Add(row);
            }
            if (shown.Count == 0) list.Children.Add(Ui.Text(choices.Count == 0 ? "No applications seen yet. Browse for one instead." : "Nothing matches.", 12, "#A99DBA"));
        }
        search.TextChanged += (_, _) => Fill(); Fill();
        var browse = Ui.Button("Browse…", () =>
        {
            var picker = new Microsoft.Win32.OpenFileDialog { Filter = "Application|*.exe" };
            if (picker.ShowDialog(window) != true) return;
            if (VpnState.Routable(picker.FileName) is { } full) Assign(full);
            else error.Text = Path.GetFileName(picker.FileName).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
                ? "svchost.exe runs many Windows services, and they would all go through the tunnel. Make the profile the default route instead."
                : "Choose a program (.exe).";
        }, true);
        var cancel = Ui.Button("Cancel", window.Close); cancel.Margin = new(8, 0, 0, 0);
        panel.Children.Add(Ui.Gap(12)); panel.Children.Add(Ui.Row(browse, cancel));
        return window;
    }

    private void ImportVpn()
    {
        var picker = new Microsoft.Win32.OpenFileDialog { Filter = "WireGuard configuration|*.conf", Multiselect = true }; if (picker.ShowDialog(this) != true) return;
        ImportVpnFiles(picker.FileNames);
    }

    /// <summary>Whether a file is a VPN configuration Darkwire imports: a WireGuard .conf.</summary>
    private static bool VpnConfigurationFile(string path) => Path.GetExtension(path).Equals(".conf", StringComparison.OrdinalIgnoreCase);

    /// <summary>Imports VPN configurations as encrypted profiles, picked or dropped: all of them, or none when one cannot be read.</summary>
    /// <param name="others">Dropped files that are no VPN configuration, which the message names.</param>
    private void ImportVpnFiles(IReadOnlyList<string> files, int others = 0)
    {
        var otherNote = others > 0 ? $" Left out {others} file{(others == 1 ? " that is not a WireGuard .conf" : "s that are not WireGuard .conf files")}." : "";
        if (state.VpnProfiles.Count + files.Count > VpnAssignments.MaximumProfiles) { ShowToast("Darkwire supports 100 saved VPN configurations. Remove one before importing more."); return; }
        var imported = new List<VpnProfile>();
        try
        {
            foreach (var file in files)
            {
                if (new FileInfo(file).Length > 2_000_000) throw new InvalidDataException("Configuration exceeds 2 MB: " + Path.GetFileName(file));
                // An OpenVPN profile picked anyway is refused by name.
                var text = File.ReadAllText(file); var kind = Path.GetExtension(file).Equals(".ovpn", StringComparison.OrdinalIgnoreCase) ? "OpenVPN" : "WireGuard";
                var parsed = Darkwire.Vpn.VpnConfiguration.Parse(kind, text);
                imported.Add(new() { Name = Path.GetFileNameWithoutExtension(file), Kind = kind, Endpoint = parsed.Endpoint, EncryptedConfig = SecureConfig.Protect(text) });
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException) { ShowToast("No configurations imported: " + ex.Message + otherNote); return; }
        if (imported.Count == 0) { ShowToast("No configurations imported." + otherNote); return; }
        state.VpnProfiles.AddRange(imported); Save(); Navigate("VPN");
        ShowToast($"Imported {imported.Count} encrypted configuration(s). Connect a profile or assign applications to it." + otherNote);
    }
}
