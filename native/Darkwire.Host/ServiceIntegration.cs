using Darkwire.Engine;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows.Media.Animation;

namespace Darkwire.Host;

public partial class MainWindow
{
    private readonly ServiceWatch serviceWatch = new();
    private ServiceStatus? serviceStatus => serviceWatch.Status;
    private long? draftPolicyRevision;
    private DateTimeOffset lastServiceRead = DateTimeOffset.MinValue;
    private bool serviceReading, serviceReadQueued, learningDialogOpen;
    private readonly HashSet<Guid> shownRequests = [];
    // The learning prompt on screen, and the request it answers.
    private Window? learningPrompt;
    private Guid learningPromptRequest;
    private TextBlock? serviceSummary, setupTitle;
    private readonly Setup setup = new(request => ServiceClient.SendAsync(request));
    private StackPanel? setupSteps;
    private Button? setupButton, setupClose;
    private Border? setupBanner;
    private SetupAlert? setupBannerShown;
    private bool setupBannerDrawn;

    private static bool Elevated
    {
        get { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
    }
    private UIElement ServicePanel()
    {
        serviceSummary = Ui.Text(ServiceSummaryText(serviceStatus), 12, "#BBB0C9");
        var body = Ui.Stack(Ui.Label("FILTERING SERVICE"), Ui.Gap(12), serviceSummary, Ui.Gap(15));
        if (demo)
        {
            body.Children.Add(Ui.Text("Demo session. Service controls are disabled.", 12, "#9F93AE"));
            return Ui.Card(body, 23);
        }
        var buttons = new WrapPanel();
        foreach (var button in new[]
        {
            Ui.AsyncButton("Check service", async () => await RefreshService(true)),
            Ui.AsyncButton("Load active policy", LoadServicePolicy),
            Ui.AsyncButton("Import service GeoIP", ImportServiceGeo),
            Ui.AsyncButton("Validate draft", async () => await ServiceAction("preflight", true)),
            Ui.AsyncButton("Apply draft", async () => await ServiceAction("apply", true)),
            Ui.AsyncButton("Review takeover", ReviewTakeover),
            Ui.AsyncButton("Restore Windows Firewall", async () => await ServiceAction("restore", false))
        }) { button.Margin = new(0, 0, 8, 8); buttons.Children.Add(button); }
        body.Children.Add(buttons);
        if (!Elevated)
        {
            body.Children.Add(Ui.Button("Open administrator controls", OpenAdministratorControls));
            body.Children.Add(Ui.Gap(10));
        }
        var core = new CheckBox { Content = "Keep DHCP, DNS client and IPv6 discovery open", IsChecked = state.CoreNetworking, Margin = new(0, 4, 0, 6) };
        core.Checked += (_, _) => { state.CoreNetworking = true; Save(); }; core.Unchecked += (_, _) => { state.CoreNetworking = false; Save(); };
        body.Children.Add(core);
        var route = new CheckBox { Content = "Route connections through Darkwire and hold new ones for a decision", IsChecked = state.RouteConnections, Margin = new(0, 0, 0, 6) };
        route.Checked += (_, _) => { state.RouteConnections = true; Save(); }; route.Unchecked += (_, _) => { state.RouteConnections = false; Save(); };
        body.Children.Add(route);
        body.Children.Add(Ui.Text("Loopback is never filtered. Edits are a local draft until applied. Takeover inherits every Windows rule. Rules Darkwire can't express are left out or reduced, never widened; only a broader block asks for consent.", 11, "#9F93AE"));
        return Ui.Card(body, 23);
    }

    private static Border Warning(UIElement content) =>
        new() { Background = Ui.Brush("#2A2118"), BorderBrush = Ui.Brush("#6B4E2E"), BorderThickness = new(1), CornerRadius = new(8), Padding = new(16, 12, 16, 12), Child = content };

    /// <summary>
    /// The Overview's alert while Darkwire does not enforce, or cannot tell whether it does, with a button that sets it up
    /// (restarting Darkwire as administrator first when needed) or reads the service again.
    /// </summary>
    private UIElement SetupBanner()
    {
        setupBanner = Warning(new Border()); setupBanner.Margin = new(0, 0, 0, 16); setupBannerDrawn = false;
        UpdateSetupBanner();
        return setupBanner;
    }

    private void UpdateSetupBanner()
    {
        if (setupBanner is null) return;
        var alert = SetupAlert.For(serviceWatch, Elevated, demo);
        if (setupBannerDrawn && alert == setupBannerShown) return;
        setupBannerDrawn = true; setupBannerShown = alert;
        setupBanner.Visibility = alert is null ? Visibility.Collapsed : Visibility.Visible;
        if (alert is null) return;
        var button = alert.Action switch
        {
            SetupAction.SetUp => Ui.Button("Set up Darkwire", ShowSetupDialog, true),
            SetupAction.RestartElevated => Ui.Button("Restart as administrator", () => RestartElevated("--setup"), true),
            _ => Ui.AsyncButton("Check again", () => RefreshService(true), true)
        };
        button.IsEnabled = !demo; button.VerticalAlignment = VerticalAlignment.Center;
        var row = new DockPanel(); DockPanel.SetDock(button, Dock.Right); row.Children.Add(button);
        var text = Ui.Stack(Ui.Text(alert.Title, 13, "#E8B07A", FontWeights.SemiBold), Ui.Gap(3), Ui.Text(alert.Detail, 11, "#E8C9A8"));
        text.Margin = new(0, 0, 16, 0); row.Children.Add(text);
        setupBanner.Child = row;
    }

    /// <summary>Setup in a dialog: checks the service, loads the policy, validates it, reviews the takeover and takes over when nothing needs the user.</summary>
    private void ShowSetupDialog() => SetupDialog().ShowDialog();

    private Window SetupDialog()
    {
        setupTitle = Ui.Text("", 22, "#EAE3F7", FontWeights.SemiBold);
        var panel = Ui.Stack(Ui.Label("SET UP DARKWIRE"), Ui.Gap(10), setupTitle, Ui.Gap(6),
            Ui.Text("Checks the service, loads the policy, validates it and reviews the takeover. When nothing needs your consent and every enabled rule comes from Windows, Darkwire takes over at once; otherwise the review opens for you.", 11, "#A599B3"), Ui.Gap(16));
        // A demo shows the dialog as the installed app, always run as administrator, has it.
        if (!Elevated && !demo)
        {
            var restart = Ui.Button("Restart as administrator", () => RestartElevated("--setup")); restart.HorizontalAlignment = HorizontalAlignment.Left; restart.IsEnabled = !demo;
            panel.Children.Add(Warning(Ui.Stack(Ui.Text("Not running as administrator", 13, "#E8B07A", FontWeights.SemiBold), Ui.Gap(4),
                Ui.Text("Setup can check the service, but loading the policy, validating it and taking over need administrator rights.", 11, "#E8C9A8"), Ui.Gap(10), restart)));
            panel.Children.Add(Ui.Gap(16));
        }
        setupSteps = Ui.Stack(); panel.Children.Add(setupSteps); panel.Children.Add(Ui.Gap(6));
        var window = Dialog("Set up Darkwire", panel, 560);
        setupButton = Ui.AsyncButton("", RunSetup, true);
        setupClose = Ui.Button("Close", window.Close); setupClose.Margin = new(8, 0, 0, 0);
        panel.Children.Add(Ui.Row(setupButton, setupClose));
        setup.Changed -= RenderSetup; setup.Changed += RenderSetup; RenderSetup();
        // A running setup finishes before the dialog closes, so its review and result stay in view.
        window.Closing += (_, e) => e.Cancel = setup.Running;
        window.Closed += (_, _) => { setup.Changed -= RenderSetup; setupSteps = null; setupButton = setupClose = null; setupTitle = null; };
        return window;
    }

    private async Task RunSetup()
    {
        if (demo || setup.Running) return;
        Save();
        // A takeover routes only through configurations the service holds. One that can't be stored is reported by validation.
        if (Elevated && serviceStatus is { Active: false })
        {
            try { await StoreVpnCredentials(); }
            catch (Exception error) when (error is not OutOfMemoryException) { AppPaths.Log("VPN configurations were not stored for setup: " + error.Message); }
        }
        var outcome = await setup.RunAsync(state, Elevated, (policy, revision) => { AdoptPolicy(policy, revision); return state; });
        if (outcome == SetupOutcome.NeedsReview && setup.PendingReview is { } review) setup.Reviewed(ShowTakeoverReview(review));
        await RefreshService(true);
    }

    /// <summary>The setup dialog's title and buttons, and the Overview's alert, follow whether Darkwire already enforces policy.</summary>
    private void UpdateSetupHeader()
    {
        var active = serviceStatus?.Active == true;
        if (setupTitle is not null) setupTitle.Text = active ? "Darkwire is enforcing " + ModeName(serviceStatus!.Mode) : "Take over Windows Firewall";
        if (setupButton is not null) { setupButton.Content = active ? "Check setup" : "Set up and take over"; setupButton.IsEnabled = !demo && !setup.Running; }
        if (setupClose is not null) setupClose.IsEnabled = !setup.Running;
        UpdateSetupBanner();
    }

    /// <summary>Shows each step's progress.</summary>
    private void RenderSetup()
    {
        UpdateSetupHeader();
        if (setupSteps is null) return;
        setupSteps.Children.Clear();
        for (var i = 0; i < setup.Steps.Count; i++)
        {
            var step = setup.Steps[i];
            var (mark, color) = step.State switch
            {
                SetupState.Running => ("…", "#B699FF"),
                SetupState.Done => ("✓", "#77D7C7"),
                SetupState.NeedsYou => ("!", "#E8B07A"),
                SetupState.Failed => ("✕", "#F2849C"),
                SetupState.Skipped => ("–", "#6F6680"),
                _ => ((i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "#8E859F")
            };
            var badge = new Border
            {
                Width = 22, Height = 22, CornerRadius = new(11), BorderThickness = new(1), BorderBrush = Ui.Brush(color), VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock { Text = mark, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Ui.Brush(color), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }
            };
            var text = Ui.Stack(Ui.Text(step.Title, 13, step.State is SetupState.Waiting or SetupState.Skipped ? "#A99DBA" : "#ECE4F7", FontWeights.SemiBold));
            if (step.Detail.Length > 0) text.Children.Add(Ui.Text(step.Detail, 11, step.State switch { SetupState.Failed => "#F2849C", SetupState.NeedsYou => "#E8B07A", _ => "#A99DBA" }));
            text.Margin = new(0, 2, 0, 0);
            var row = Ui.Columns(34, 0); row.Margin = new(0, 0, 0, 10); Ui.Add(row, badge, 0); Ui.Add(row, text, 1); setupSteps.Children.Add(row);
        }
    }

    /// <summary>Preflights the draft against a fresh Windows import, then shows the takeover review.</summary>
    private async Task ReviewTakeover()
    {
        if (demo) return;
        if (!Elevated) { ShowToast("Open administrator controls to take over Windows Firewall."); return; }
        Save();
        var (review, first) = await TakeoverReview.PrepareAsync(state, request => ServiceClient.SendAsync(request));
        if (review is null) { MessageBox.Show(this, first.Message + ErrorList(first), "Takeover review", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        ShowTakeoverReview(review);
    }

    /// <summary>
    /// Shows what is out of scope or not from Windows and the blocks that need consent, then takes over once the user agrees.
    /// Returns the service's answer when Darkwire took over, else null.
    /// </summary>
    private ServiceResponse? ShowTakeoverReview(TakeoverReview takeover)
    {
        var candidate = takeover.Candidate; var final = takeover.Final; var review = takeover.Consent;
        var imported = takeover.Imported; var outOfScope = takeover.OutOfScope; var added = takeover.Added;
        var panel = Ui.Stack(Ui.Text("Take over Windows Firewall", 23, "#EAE3F7", FontWeights.SemiBold), Ui.Gap(6),
            Ui.Text($"{ModeName(candidate.Mode)} · {imported.Count:N0} Windows rules inherited", 12, "#A99DBA"), Ui.Gap(16));
        var summary = Ui.Stack(Ui.Text($"{imported.Count(r => r.Import == ImportOutcome.Exact):N0} translate exactly", 13),
            Ui.Text($"{imported.Count(r => r.Import == ImportOutcome.Inert):N0} disabled rules stay disabled", 13),
            Ui.Text($"{outOfScope.Count:N0} out of scope: left out or reduced, never widened", 13),
            Ui.Text($"{added.Count:N0} enabled rules of your own", 13, added.Count > 0 ? "#E3B3FF" : "#F0EFF9"));
        if (review.Count > 0) summary.Children.Add(Ui.Text($"{review.Count:N0} broader blocks need your consent", 13, "#E3B3FF"));
        if (DefaultChange(takeover.Defaults, candidate.Mode) is { } change) { summary.Children.Add(Ui.Gap(10)); summary.Children.Add(Ui.Text(change, 12, "#C9BCD8")); }
        summary.Children.Add(Ui.Gap(6));
        summary.Children.Add(Ui.Text(candidate.CoreNetworking ? "Loopback, DHCP, DNS client and IPv6 discovery stay open." : "Loopback stays open. DHCP, DNS and IPv6 discovery follow your rules.", 12, "#C9BCD8"));
        summary.Children.Add(Ui.Text(candidate.ShowFirewallWarnings ? "Windows Security keeps its firewall page, which will say the firewall is off."
            : "Windows Security's firewall page is hidden while Darkwire enforces, so it doesn't say the firewall is off.", 12, "#C9BCD8"));
        summary.Children.Add(Ui.Text(candidate.RouteConnections
            ? candidate.Mode == FirewallMode.Learning ? "Outbound connections pass through Darkwire's tunnel router; new ones wait for your answer." : "Outbound connections pass through Darkwire's tunnel router."
            : "Kernel filters only: unmatched connections are blocked, not held.", 12, "#C9BCD8"));
        panel.Children.Add(Ui.Card(summary, 16)); panel.Children.Add(Ui.Gap(14));

        if (outOfScope.Count > 0)
        {
            panel.Children.Add(Ui.Label("OUT OF SCOPE · NOTHING EXTRA IS ALLOWED")); panel.Children.Add(Ui.Gap(6));
            panel.Children.Add(Ui.Text("Windows allows this traffic only to peers or tunnels it identifies itself. Darkwire can't evaluate those conditions, so it doesn't allow the traffic: it stays blocked, or asks in Learning. These features won't work until you add a rule of your own.", 11, "#B8AAC8"));
            panel.Children.Add(Ui.Gap(8));
            var groups = Ui.Stack();
            foreach (var group in outOfScope.GroupBy(r => ScopeFeature(r.ImportWarning)).OrderBy(g => g.Key, StringComparer.CurrentCulture))
            {
                var names = group.Select(r => r.ApplicationName).Distinct(StringComparer.CurrentCultureIgnoreCase).ToList();
                var reduced = group.Count(r => r.Import == ImportOutcome.Narrowed);
                var row = Ui.Stack(Ui.Text($"{group.Key} · {group.Count()} {(reduced == group.Count() ? "reduced" : reduced > 0 ? "not enforced or reduced" : "not enforced")}", 13, "#ECE4F7", FontWeights.SemiBold),
                    Ui.Text(string.Join(", ", names.Take(4)) + (names.Count > 4 ? $" and {names.Count - 4} more" : ""), 11, "#B8AAC8"));
                row.Margin = new(0, 0, 0, 10); groups.Children.Add(row);
            }
            panel.Children.Add(new ScrollViewer { Content = groups, MaxHeight = 200, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        }
        if (added.Count > 0)
        {
            panel.Children.Add(Ui.Gap(10)); panel.Children.Add(Ui.Label("YOUR RULES · NOT FROM WINDOWS")); panel.Children.Add(Ui.Gap(6));
            var list = Ui.Stack();
            foreach (var rule in added.OrderBy(r => r.Action == RuleAction.Allow ? 0 : 1).ThenBy(r => r.ApplicationName, StringComparer.CurrentCultureIgnoreCase))
            {
                var row = Ui.Stack(Ui.Text($"{rule.Action} · {rule.ApplicationName}", 13, rule.Action == RuleAction.Allow ? "#ECE4F7" : "#B8AAC8", FontWeights.SemiBold),
                    Ui.Text($"{rule.Direction} · {rule.Protocol} · {rule.Path} · remote {rule.RemoteAddresses} port {rule.RemotePorts}", 11, "#B8AAC8"));
                row.Margin = new(0, 0, 0, 8); list.Children.Add(row);
            }
            panel.Children.Add(new ScrollViewer { Content = list, MaxHeight = 160, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        }
        CheckBox? accept = null;
        if (review.Count > 0)
        {
            panel.Children.Add(Ui.Gap(10)); panel.Children.Add(Ui.Label("BROADER BLOCKS · NEED CONSENT")); panel.Children.Add(Ui.Gap(8));
            var list = Ui.Stack();
            foreach (var rule in review.OrderBy(r => r.ApplicationName, StringComparer.CurrentCultureIgnoreCase))
            {
                var row = Ui.Stack(Ui.Text(rule.ApplicationName, 13, "#ECE4F7", FontWeights.SemiBold), Ui.Text(rule.ImportWarning ?? "", 11, "#B8AAC8"));
                row.Margin = new(0, 0, 0, 10); list.Children.Add(row);
            }
            panel.Children.Add(new ScrollViewer { Content = list, MaxHeight = 200, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
            accept = new CheckBox { Content = "Enforce these blocks as listed. They can block traffic Windows allowed.", Margin = new(0, 10, 0, 4) };
            panel.Children.Add(accept);
        }
        if (!final.Success)
        {
            panel.Children.Add(Ui.Gap(10)); panel.Children.Add(Ui.Label("RESOLVE FIRST"));
            panel.Children.Add(Ui.Text(final.Message + ErrorList(final), 11, "#F2849C"));
        }
        var error = Ui.Text("", 11, "#F2849C"); panel.Children.Add(error);
        var window = Dialog("Takeover review", panel, 600);
        ServiceResponse? taken = null;
        var takeOver = Ui.AsyncButton("Take over", async () =>
        {
            var result = await ServiceClient.SendAsync(new("takeover", candidate));
            if (!result.Success) { error.Text = result.Message + ErrorList(result); return; }
            taken = result;
            if (result.Policy is not null) AdoptPolicy(result.Policy, result.Status?.PolicyRevision);
            window.Close(); ShowToast(result.Message); await RefreshService(true);
        }, true);
        takeOver.IsEnabled = final.Success && accept is null;
        if (accept is not null) { accept.Checked += (_, _) => takeOver.IsEnabled = final.Success; accept.Unchecked += (_, _) => takeOver.IsEnabled = false; }
        var cancel = Ui.Button("Cancel", window.Close); cancel.Margin = new(8, 0, 0, 0);
        panel.Children.Add(Ui.Gap(14)); panel.Children.Add(Ui.Row(takeOver, cancel));
        window.ShowDialog();
        return taken;
    }

    private static string ErrorList(ServiceResponse response) => response.Errors is { Count: > 0 } errors ? "\n\n" + string.Join("\n", errors.Take(12)) : "";

    /// <summary>The Windows feature behind a condition Darkwire can't evaluate, for grouping the takeover review.</summary>
    private static string ScopeFeature(string? warning) => warning switch
    {
        null => "Other conditions",
        _ when warning.Contains("Play To", StringComparison.Ordinal) => "Cast to Device (Play To)",
        _ when warning.Contains("Wi-Fi Direct", StringComparison.Ordinal) => "Wireless Display and Wi-Fi Direct",
        _ when warning.Contains("UPnP", StringComparison.Ordinal) => "UPnP discovery over Teredo",
        _ when warning.Contains("proximity", StringComparison.OrdinalIgnoreCase) => "Nearby sharing",
        _ when warning.Contains("Teredo", StringComparison.Ordinal) || warning.Contains("IP-HTTPS", StringComparison.Ordinal) || warning.Contains("IP-TLS", StringComparison.Ordinal) => "IPv6 transition tunnels (Teredo, IP-HTTPS)",
        _ when warning.Contains("edge traversal", StringComparison.Ordinal) => "Edge traversal decided by the app",
        _ => warning.Replace("Not translatable: ", "", StringComparison.Ordinal).TrimEnd('.')
    };

    /// <summary>Describes how unmatched traffic changes from Windows' current defaults.</summary>
    private static string? DefaultChange(WindowsDefaults? defaults, FirewallMode mode)
    {
        if (defaults is null) return null;
        static string Profiles(Dictionary<int, bool> allowed) => string.Join(", ", new[] { (1, "Domain"), (2, "Private"), (4, "Public") }.Where(p => allowed.GetValueOrDefault(p.Item1)).Select(p => p.Item2));
        var outbound = Profiles(defaults.OutboundAllowed); var inbound = Profiles(defaults.InboundAllowed);
        if (outbound.Length == 0 && inbound.Length == 0) return null;
        var effect = mode switch { FirewallMode.Learning => "Darkwire blocks it and asks", FirewallMode.Lockdown => "Lockdown blocks it", _ => "Darkwire blocks it" };
        var allowed = string.Join("; ", new[] { outbound.Length > 0 ? "outbound on " + outbound : "", inbound.Length > 0 ? "inbound on " + inbound : "" }.Where(s => s.Length > 0));
        return $"Windows allows unmatched {allowed}. {effect}.";
    }

    private async Task RefreshService(bool force = false)
    {
        if (demo) return;
        // A forced read asked for during another runs right after it, so a takeover's outcome is never read too early.
        if (serviceReading) { serviceReadQueued |= force; return; }
        // Learning prompts, tunnels coming up or being checked, and the VPN page's and blocklists' states are read every couple of seconds.
        var interval = serviceStatus is { Active: true, Mode: FirewallMode.Learning } || currentPage is "VPN" or "Blocklists" || VpnState.Establishing(state, serviceStatus, false) is not null ? 2 : 10;
        if (!force && DateTimeOffset.UtcNow - lastServiceRead < TimeSpan.FromSeconds(interval)) return;
        serviceReading = true;
        try
        {
            do
            {
                serviceReadQueued = false; lastServiceRead = DateTimeOffset.UtcNow;
                await ReadServiceAsync(force);
            }
            while (serviceReadQueued);
        }
        finally { serviceReading = false; UpdateSetupHeader(); UpdateVpnStatus(); UpdateTunnelsBanner(); followMapService?.Invoke(); if (currentPage == "Blocklists") ApplyBlocklistStatus(); }
    }

    // Whether this start of the app has asked the service to check its tunnels end to end.
    private bool tunnelsCheckAsked;

    /// <summary>
    /// Once each time the app starts, an update's restart included: the service checks every running tunnel end to end again,
    /// restarting any that carries nothing back, and the banner shows until each has answered.
    /// </summary>
    private async Task CheckTunnelsOnceAsync(ServiceStatus? status)
    {
        if (tunnelsCheckAsked || !Elevated || status is not { Active: true, Tunnels.Count: > 0 }) return;
        tunnelsCheckAsked = true;
        try
        {
            var checking = await ServiceClient.SendAsync(new("check-tunnels"));
            if (checking.Status is { } now) serviceWatch.Answered(now);
        }
        catch (Exception error) when (error is not OutOfMemoryException) { AppPaths.Log("The VPN tunnels were not checked at start: " + error.Message); }
    }

    /// <summary>The banner shown while VPN tunnels are starting or being checked, from the service's last answer.</summary>
    private void UpdateTunnelsBanner()
    {
        var establishing = demo ? null : VpnState.Establishing(state, serviceStatus, serviceWatch.Offline);
        TunnelsBanner.Visibility = establishing is null ? Visibility.Collapsed : Visibility.Visible;
        if (establishing is null) return;
        TunnelsBannerTitle.Text = establishing.Title; TunnelsBannerDetail.Text = establishing.Detail;
    }

    private async Task ReadServiceAsync(bool force)
    {
        try
        {
            // The reply carries the service's state even when the service reports a failure of its own.
            var response = await ServiceClient.SendAsync(new("status"));
            serviceWatch.Answered(response.Status ?? throw new InvalidOperationException(response.Message));
            await CheckTunnelsOnceAsync(response.Status);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            serviceWatch.Missed(ex.Message);
            if (force) ShowToast("Service unavailable: " + ex.Message);
        }
        var status = serviceStatus;
        var recovering = status is { Active: false, Phase: not "Inactive" };
        if (serviceSummary is not null) serviceSummary.Text = status is null && serviceWatch.Offline ? "Service unavailable: " + serviceWatch.Error : ServiceSummaryText(status);
        // While the startup lock holds, nothing reaches the internet until the service has restored its policy and VPN tunnels.
        AuthorityTitle.Text = status is null ? "SERVICE OFFLINE" : status.StartupLocked ? "STARTING UP" : status.Active ? "FILTERING ACTIVE" : recovering ? "RECOVERY REQUIRED" : "MONITOR ONLY";
        AuthorityDetail.Text = status is null ? "Filtering status unavailable." : status.StartupLocked ? "Internet blocked until Darkwire restores its policy and VPN tunnels."
            : status.Active ? ModeName(status.Mode) + " · Service enforced" : recovering ? status.Message : "Windows Firewall unchanged.";
        Shield.State = status is null ? ShieldState.Inactive : status.StartupLocked ? ShieldState.Starting : status.Active ? ShieldState.Active : ShieldState.Inactive;
        Shield.ToolTip = AuthorityTitle.Text + "\n" + AuthorityDetail.Text;
        if (tray is not null) tray.Text = status is null ? "Darkwire — filtering status unavailable" : status.StartupLocked ? "Darkwire — starting; internet blocked"
            : status.Active ? "Darkwire — " + ModeName(status.Mode) : recovering ? "Darkwire — recovery required" : "Darkwire — monitor only";
        if (status is { Active: true, PendingCount: > 0 }) await ShowPendingAsync();
        // Nothing waits any more, so neither does a prompt still on screen.
        else if (status is not null) learningPrompt?.Close();
    }

    /// <summary>
    /// Shows the next learning request, after closing a prompt whose request no longer waits: another decision answered it,
    /// such as a broader one for the same application, or it expired. A failure here says nothing about whether Darkwire
    /// enforces; the next read tries again.
    /// </summary>
    private async Task ShowPendingAsync()
    {
        try
        {
            var pending = await ServiceClient.SendAsync(new("pending"));
            if (pending.Pending is { } waiting && learningPrompt is { } open && waiting.All(p => p.Id != learningPromptRequest)) open.Close();
            shownRequests.IntersectWith(pending.Pending?.Select(p => p.Id) ?? []);
            // Why an answer failed matters only while its request still waits.
            foreach (var gone in learningRetries.Keys.Where(id => pending.Pending?.Any(p => p.Id == id) != true).ToArray()) learningRetries.Remove(gone);
            // An application whose answer is still being applied waits: the answer may settle its other requests.
            var request = pending.Pending?.FirstOrDefault(p => !shownRequests.Contains(p.Id) && !deciding.ContainsKey(p.Connection.Path));
            if (request is null || learningDialogOpen) return;
            var authoritative = await ServiceClient.SendAsync(new("policy"));
            if (!authoritative.Success || authoritative.Policy is null) return;
            // A request that cannot be drawn stays marked as shown, and the next one may still open.
            try { ShowLearningRequest(request, authoritative.Policy); }
            catch { learningDialogOpen = false; throw; }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { AppPaths.Log("A learning request was not shown: " + ex); }
    }

    private static string ServiceSummaryText(ServiceStatus? status) => status is null ? "Service is not connected." :
        status.Message + (status.Active ? $"\n{status.FilterCount:N0} runtime filters · {status.BootFilterCount} boot guards" : "") +
        (status.Alerts is { Count: > 0 } alerts ? "\n\nAlerts\n" + string.Join("\n", alerts.Take(3)) : "");

    private async Task ServiceAction(string command, bool includePolicy)
    {
        if (demo) return;
        if (!Elevated) { ShowToast("Open administrator controls to change service policy."); return; }
        Save();
        if (command == "apply" && draftPolicyRevision is null) { ShowToast("Load the active policy before editing and applying a service draft."); return; }
        var response = await ServiceClient.SendAsync(new(command, includePolicy ? state : null, ExpectedRevision: command == "apply" ? draftPolicyRevision : null));
        var detail = response.Message + (response.Errors?.Count > 0 ? "\n\n" + string.Join("\n", response.Errors.Take(20)) : "");
        MessageBox.Show(this, detail, response.Success ? "Darkwire" : "Policy was not applied", MessageBoxButton.OK,
            response.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        if (response.Success && response.Policy is not null && command is "takeover" or "apply") AdoptPolicy(response.Policy, response.Status?.PolicyRevision);
        await RefreshService(true);
    }

    private async Task LoadServicePolicy()
    {
        if (demo) return;
        var response = await ServiceClient.SendAsync(new("policy"));
        if (!response.Success || response.Policy is null) throw new InvalidOperationException(response.Message);
        AdoptPolicy(response.Policy, response.Status?.PolicyRevision); ShowToast("Loaded the service policy into the editor.");
    }
    private async Task ImportServiceGeo()
    {
        if (demo) return;
        if (!Elevated) { ShowToast("Open administrator controls to import service data."); return; }
        var picker = new Microsoft.Win32.OpenFileDialog { Filter = "Normalized GeoIP CSV|*.csv" };
        if (picker.ShowDialog(this) != true) return;
        if (new FileInfo(picker.FileName).Length > 4 * 1024 * 1024) throw new InvalidDataException("Service uploads support up to 4 MB of normalized GeoIP CSV.");
        var csv = await File.ReadAllTextAsync(picker.FileName);
        var response = await ServiceClient.SendAsync(new("import-geo", GeoCsv: csv));
        if (!response.Success) throw new InvalidOperationException(response.Message);
        ShowToast(response.Message);
    }
    private void AdoptPolicy(AppState policy, long? revision)
    {
        draftPolicyRevision = revision;
        var localSecrets = state.VpnProfiles.ToDictionary(p => p.Id, p => p.EncryptedConfig);
        foreach (var profile in policy.VpnProfiles)
            profile.EncryptedConfig = localSecrets.GetValueOrDefault(profile.Id, "");
        // Desktop preferences stay local; enforcement fields come from the authoritative service.
        state.Mode = policy.Mode; state.Rules = policy.Rules; state.Blocklists = policy.Blocklists;
        state.VpnProfiles = policy.VpnProfiles; state.BlockedCountries = policy.BlockedCountries; state.BlockedAsns = policy.BlockedAsns;
        state.DefaultOutboundVpnProfileId = policy.DefaultOutboundVpnProfileId; state.LocalNetworkBypassesVpn = policy.LocalNetworkBypassesVpn;
        state.OwnTraffic = policy.OwnTraffic; state.OwnTrafficProfileId = policy.OwnTrafficProfileId; state.DnsServers = policy.DnsServers; state.BlockedNames = policy.BlockedNames;
        state.InternalNetworks = policy.InternalNetworks; state.CountryAllowList = policy.CountryAllowList; state.AllowedCountries = policy.AllowedCountries; state.StartupLock = policy.StartupLock;
        state.ShowFirewallWarnings = policy.ShowFirewallWarnings;
        rules.Clear(); foreach (var rule in state.Rules) rules.Add(rule);
        Save(); Navigate(currentPage);
    }
    private async Task UploadVpnProfile(VpnProfile profile)
    {
        if (demo) return;
        if (!Elevated) { ShowToast("Open administrator controls to upload VPN credentials."); return; }
        var message = await StoreVpnProfile(profile);
        Navigate("VPN");
        // A profile the routes use runs on the configuration just stored once they apply again.
        if (VpnAssignments.Running(state).Any(p => p.Id == profile.Id)) VpnRoutesChanged($"Stored {profile.Name} in the service.");
        else { Save(); ShowToast(message); }
    }
    /// <summary>Sends a configuration to the service's protected storage and records the revision it stored.</summary>
    private static async Task<string> StoreVpnProfile(VpnProfile profile)
    {
        if (string.IsNullOrEmpty(profile.EncryptedConfig)) throw new InvalidOperationException("Import this configuration locally before uploading credentials.");
        var response = await ServiceClient.SendAsync(new("import-vpn", VpnConfiguration: new(profile.Id, profile.Kind, SecureConfig.Unprotect(profile.EncryptedConfig))));
        if (!response.Success) throw new InvalidOperationException(response.Message);
        var stored = response.VpnProfiles?.Single() ?? throw new InvalidDataException("The service returned no configuration metadata.");
        profile.CredentialsRevision = stored.Revision; profile.Endpoint = stored.Endpoint;
        return response.Message;
    }
    private sealed record RouteOption(Guid? ProfileId, string Label)
    { public override string ToString() => Label; }
    private sealed record ScopeOption(LearningScope Scope, string Label)
    { public override string ToString() => Label; }

    /// <summary>"A", "A and B", "A, B and C", or the first three and how many more.</summary>
    private static string Listing(IReadOnlyList<string> names) => names.Count switch
    {
        1 => names[0],
        <= 4 => string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1],
        _ => string.Join(", ", names.Take(3)) + $" and {names.Count - 3} more"
    };

    /// <summary>What a decision can cover, worded for the request's direction: an inbound rule keeps the local port the peer reached.</summary>
    private static ScopeOption[] ScopeOptions(Connection flow)
    {
        var host = flow.Destination;
        if (flow.Direction == TrafficDirection.Inbound)
            return [new(LearningScope.Exact, $"From {host} to port {flow.LocalPort}"), new(LearningScope.AnyHost, $"From any host to port {flow.LocalPort}"),
                new(LearningScope.AnyPort, $"From {host} to any port"), new(LearningScope.AnyHostAndPort, "From any host to any port")];
        return [new(LearningScope.Exact, $"{host} on port {flow.RemotePort}"), new(LearningScope.AnyHost, $"Any host on port {flow.RemotePort}"),
            new(LearningScope.AnyPort, $"{host} on any port"), new(LearningScope.AnyHostAndPort, "Any host on any port")];
    }
    private async Task ManageStoredVpnProfiles()
    {
        if (demo) { ShowToast("Service storage is unavailable in demo mode."); return; }
        var response = await ServiceClient.SendAsync(new("vpn-profiles"));
        if (!response.Success) throw new InvalidOperationException(response.Message);
        var panel = Ui.Stack(Ui.Text("Service VPN storage", 23, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(12),
            Ui.Text("Protected configurations used by the filtering service.", 12, "#A99DBA"), Ui.Gap(14));
        var entries = Ui.Stack(); panel.Children.Add(new ScrollViewer { Content = entries, MaxHeight = 360, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        var error = Ui.Text("", 11, "#F2849C"); panel.Children.Add(error);
        var window = Dialog("Service VPN storage", panel);
        foreach (var stored in response.VpnProfiles ?? [])
        {
            var local = state.VpnProfiles.FirstOrDefault(p => p.Id == stored.Id);
            var row = Ui.Stack(Ui.Text(local?.Name ?? stored.Kind + " · " + stored.Id.ToString("N")[..8], 14),
                Ui.Text(stored.Endpoint, 11, "#A99DBA"));
            var card = Ui.Card(row, 12); card.Margin = new(0, 0, 0, 8);
            var remove = Ui.AsyncButton("Remove stored credentials", async () =>
            {
                try
                {
                    var result = await ServiceClient.SendAsync(new("remove-vpn", VpnProfileId: stored.Id));
                    if (!result.Success) { error.Text = result.Message; return; }
                    if (local is not null) local.CredentialsRevision = Guid.Empty;
                    Save(); entries.Children.Remove(card); error.Text = "";
                    if (entries.Children.Count == 0) entries.Children.Add(Ui.Text("No configurations in service storage.", 12, "#A99DBA"));
                }
                catch (Exception e) { error.Text = e.Message; }
            });
            remove.IsEnabled = Elevated; row.Children.Add(Ui.Gap(7)); row.Children.Add(remove); entries.Children.Add(card);
        }
        if (entries.Children.Count == 0) entries.Children.Add(Ui.Text("No configurations in service storage.", 12, "#A99DBA"));
        if (!Elevated) panel.Children.Add(Ui.Text("Open administrator controls to remove credentials.", 11, "#A99DBA"));
        panel.Children.Add(Ui.Gap(12)); panel.Children.Add(Ui.Button("Close", window.Close)); window.ShowDialog();
    }
    // Why an answer did not apply, for the request it answered, shown on the request's prompt when it comes back.
    private readonly Dictionary<Guid, string> learningRetries = [];
    // Applications whose answers are being applied, by path, and how many.
    private readonly Dictionary<string, int> deciding = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A connection request as a compact notification above the taskbar. Allow and Block close it at once and apply the
    /// decision in the background, so it never waits on the service; an answer the service could not apply brings the request
    /// back, with why, while it still waits. A bar empties as the time to decide runs out, and the notification goes when it does.
    /// </summary>
    private Window ShowLearningRequest(LearningRequest request, AppState activePolicy)
    {
        learningDialogOpen = true; shownRequests.Add(request.Id); learningPromptRequest = request.Id;
        var flow = request.Connection;
        // Routed connections wait in Darkwire's router; others were blocked and their applications must retry.
        var held = flow.State == "Held";
        var path = Ui.Text(flow.Path, 10, "#A99DBA"); path.MaxHeight = 32; path.ToolTip = flow.Path;
        var countdown = Ui.Text(held ? "Held until you decide" : "Blocked pending a decision", 10, "#A99DBA");
        var title = string.IsNullOrEmpty(flow.Service) ? flow.Application : flow.Application + " · " + flow.Service;
        var body = Ui.Stack(Ui.Label("DARKWIRE · CONNECTION REQUEST"));
        if (learningRetries.Remove(request.Id, out var retry))
        {
            var why = Ui.Text("Your last answer was not applied: " + retry.TrimEnd('.') + ". Choose again.", 11, "#F2849C"); why.Margin = new(0, 8, 0, 0); why.MaxHeight = 54;
            body.Children.Add(why);
        }
        var appIcon = ApplicationIcons.Image(flow.Path, 36); appIcon.Margin = new(0, 1, 12, 0); appIcon.VerticalAlignment = VerticalAlignment.Top;
        var identity = new DockPanel(); DockPanel.SetDock(appIcon, Dock.Left); identity.Children.Add(appIcon);
        identity.Children.Add(Ui.Stack(Ui.Text(title, 19, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(4), path));
        body.Children.Add(Ui.Stack(Ui.Gap(14), identity,
            Ui.Gap(16), Ui.Text(flow.Destination + ":" + flow.RemotePort, 13),
            Ui.Gap(5), Ui.Text($"{flow.Protocol} · {flow.Direction} · Local port {flow.LocalPort}", 11, "#B8AAC8"), Ui.Gap(12)));
        // Allow and Block both install a rule for this application over this protocol; the scope picks its hosts and ports.
        var scopes = ScopeOptions(flow);
        var scope = new ComboBox { ItemsSource = scopes, DisplayMemberPath = nameof(ScopeOption.Label), SelectedItem = scopes[0], Margin = new(0, 5, 0, 6), MinHeight = 31 };
        System.Windows.Automation.AutomationProperties.SetName(scope, "Rule scope");
        body.Children.Add(Ui.Label("RULE")); body.Children.Add(scope);
        // A service host whose service could not be identified gets a rule for every service it runs; one sharing its process
        // with other services gets a rule WFP applies to them too.
        var unknownService = flow.Service.Length == 0 && Path.GetFileName(flow.Path).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
        var shared = flow.SharedServices();
        // An exact answer keeps the protocol asked about; one for a port takes TCP and UDP, one for any port every protocol.
        string Protocols() => ((ScopeOption)scope.SelectedItem).Scope switch { LearningScope.Exact => flow.Protocol, LearningScope.AnyHost => "TCP and UDP", _ => "every protocol" };
        string Reach() => unknownService ? $"The service could not be identified, so Allow or Block applies to every service svchost.exe runs, over {Protocols()}."
            : shared.Length > 0 ? $"Allow or Block applies to {flow.Service} over {Protocols()}. Windows filters the services sharing its process together, so it also covers {Listing(shared)}."
            : $"Allow or Block applies to {(flow.Service.Length > 0 ? flow.Service : flow.Application)} over {Protocols()}.";
        var reachNote = Ui.Text(Reach(), 10, unknownService || shared.Length > 0 ? "#E8B07A" : "#A99DBA");
        scope.SelectionChanged += (_, _) => reachNote.Text = Reach();
        body.Children.Add(reachNote);
        body.Children.Add(Ui.Gap(12));
        var defaultName = activePolicy.VpnProfiles.FirstOrDefault(p => p.Id == activePolicy.DefaultOutboundVpnProfileId)?.Name ?? "Windows route";
        var options = new List<RouteOption> { new(null, "Default · " + defaultName) };
        options.AddRange(activePolicy.VpnProfiles.Select(p => new RouteOption(p.Id, p.Name + " · " + p.Kind)));
        var selected = activePolicy.VpnProfiles.FirstOrDefault(p => p.Applications.Any(a => a.Equals(flow.Path, StringComparison.OrdinalIgnoreCase)))?.Id;
        var route = new ComboBox { ItemsSource = options, DisplayMemberPath = nameof(RouteOption.Label), SelectedItem = options.First(o => o.ProfileId == selected),
            Margin = new(0, 5, 0, 6), MinHeight = 31 };
        // A profile carries a whole program, and Windows services share svchost.exe, so they keep the default route. A service
        // running alone in a program of its own, outside Windows, can take a route: everything that program sends is the service's.
        var service = flow.Service.Length > 0 || flow.HostedServices.Length > 0;
        var routable = service ? VpnAssignments.CarriableService(flow.Path, flow.HostedServices) : VpnAssignments.Carriable(flow.Path);
        if (flow.Direction == TrafficDirection.Outbound)
        {
            body.Children.Add(Ui.Label("APP ROUTE"));
            if (routable)
            {
                body.Children.Add(route);
                body.Children.Add(Ui.Text($"The route carries everything {(service && flow.Service.Length > 0 ? flow.Service : Path.GetFileName(flow.Path))} sends, and replaces any route it had.", 10, "#A99DBA"));
            }
            else body.Children.Add(Ui.Text(VpnAssignments.Carriable(flow.Path)
                ? $"Default · {defaultName}. {(flow.Service.Length > 0 ? flow.Service : "This service")} is part of Windows or shares its program with other services, so it follows the default route."
                : $"Default · {defaultName}. Windows services share svchost.exe, so they follow the default route; a VPN profile can carry only a program of its own.", 10, "#A99DBA"));
            body.Children.Add(Ui.Gap(12));
        }
        var card = Ui.Card(body, 22);
        var dialog = new Window
        {
            Title = "Darkwire connection request", Width = 430, SizeToContent = SizeToContent.Height, WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize, AllowsTransparency = true, Background = Brushes.Transparent, Content = card,
            ShowInTaskbar = false, ShowActivated = false, Topmost = true, UseLayoutRounding = true,
            WindowStartupLocation = WindowStartupLocation.Manual
        };
        void PositionNotification() { var area = SystemParameters.WorkArea; dialog.Left = Math.Max(area.Left, area.Right - dialog.ActualWidth - 16); dialog.Top = Math.Max(area.Top, area.Bottom - dialog.ActualHeight - 16); }
        dialog.Loaded += (_, _) => PositionNotification(); dialog.SizeChanged += (_, _) => PositionNotification();
        var decided = false;
        async Task Decide(RuleAction action)
        {
            if (decided) return;
            decided = true;
            // Read before the notification goes; nothing here can throw, so it always goes.
            var choice = action == RuleAction.Allow && flow.Direction == TrafficDirection.Outbound && routable && route.SelectedItem is RouteOption picked
                ? new LearningRouteChoice(picked.ProfileId) : null;
            var reach = (scope.SelectedItem as ScopeOption)?.Scope ?? LearningScope.Exact;
            dialog.Close();
            if (demo) { ShowToast("Demo session: answers are not sent to a service."); return; }
            deciding[flow.Path] = deciding.GetValueOrDefault(flow.Path) + 1;
            try
            {
                if (!Elevated)
                {
                    var executable = Path.Combine(AppContext.BaseDirectory, "Darkwire.exe");
                    if (!File.Exists(executable)) throw new IOException("Run the packaged Darkwire.exe to approve connections.");
                    var routeArgument = choice is null ? "unchanged" : choice.VpnProfileId?.ToString("N") ?? "default";
                    using var helper = Process.Start(new ProcessStartInfo(executable, $"--learning-decision {request.Id:N} {action} {routeArgument} {reach}")
                    { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = AppContext.BaseDirectory })
                        ?? throw new IOException("Administrator approval did not start.");
                    await helper.WaitForExitAsync();
                    if (helper.ExitCode != 0) { Retry("The decision was not applied, and traffic remains blocked"); return; }
                    lastServiceRead = DateTimeOffset.MinValue; return;
                }
                var result = await ServiceClient.SendAsync(new("resolve", RequestId: request.Id, Action: action, LearningRoute: choice, Scope: reach));
                if (!result.Success) { Retry(result.Message); return; }
                // The route chosen here joins the editor's routes, so routes changed later keep it. The rule added makes the
                // draft's rules older than the service's, so its revision stays.
                if (choice is not null && result.Policy is { } enforced) { AdoptVpnRoutes(enforced, null); if (currentPage == "VPN") Navigate("VPN"); }
                // Preserve any unsaved draft. Its older revision makes the service reject a stale apply.
                ShowToast(result.Message + " Load the active policy before further edits."); lastServiceRead = DateTimeOffset.MinValue;
            }
            // A pipe that stayed busy never took the answer; a reply that never came may still be on its way.
            catch (TimeoutException) { Retry("Darkwire's service was busy and did not take it"); }
            catch (OperationCanceledException) { Retry("Darkwire's service did not answer in time, though it may still apply it"); }
            catch (Exception error) when (error is not OutOfMemoryException) { Retry(error.Message); }
            finally
            {
                if (--deciding[flow.Path] == 0) deciding.Remove(flow.Path);
                // What is left waiting shows at the next status read.
                lastServiceRead = DateTimeOffset.MinValue;
            }
        }
        // An answer that did not apply: the request comes back at the next status read, with why, while it still waits; one
        // that expired or another answer settled does not.
        void Retry(string why)
        {
            learningRetries[request.Id] = why; shownRequests.Remove(request.Id); lastServiceRead = DateTimeOffset.MinValue;
            ShowToast($"Your answer for {title} was not applied: {why.TrimEnd('.')}.");
        }
        // Equal-width targets fill the card with explicit gutters; labels remain centered at every DPI.
        var decisions = Ui.Columns(0, 10, 0, 10, 0); decisions.Margin = new(0, 4, 0, 0);
        var allow = Ui.Button("Allow", () => _ = Decide(RuleAction.Allow), true);
        var block = Ui.Button("Block", () => _ = Decide(RuleAction.Deny));
        var dismiss = Ui.Button("Dismiss", dialog.Close);
        foreach (var button in new[] { allow, block, dismiss })
        { button.MinHeight = 44; button.Padding = new(12, 10, 12, 10); button.HorizontalContentAlignment = HorizontalAlignment.Center; button.VerticalContentAlignment = VerticalAlignment.Center; }
        Ui.Add(decisions, allow, 0); Ui.Add(decisions, block, 2); Ui.Add(decisions, dismiss, 4); body.Children.Add(decisions);
        // The time left to decide: a bar that empties from full as the request runs out, amber for its last ten seconds.
        var bar = new Border { Background = Ui.Brush("#B7A0FF"), CornerRadius = new(2), RenderTransformOrigin = new(0, .5), RenderTransform = new ScaleTransform(1, 1) };
        var track = new Border { Height = 4, CornerRadius = new(2), Background = Ui.Brush("#2B2739"), Margin = new(0, 14, 0, 6), Child = bar };
        System.Windows.Automation.AutomationProperties.SetName(track, "Time left to decide");
        body.Children.Add(track); body.Children.Add(countdown);
        if (!Elevated && !demo) body.Children.Add(Ui.Text("Windows will request administrator approval.", 10, "#A99DBA"));
        var left = request.ExpiresAt - DateTimeOffset.UtcNow;
        if (left > TimeSpan.Zero && !capture) bar.RenderTransform.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(1, 0, left));
        var timeout = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timeout.Tick += (_, _) =>
        {
            var remaining = request.ExpiresAt - DateTimeOffset.UtcNow; var seconds = Math.Max(0, (int)Math.Ceiling(remaining.TotalSeconds));
            countdown.Text = held ? $"Held · {seconds}s to decide · Allowing lets it continue if the app is still waiting" : $"Blocked · {seconds}s to decide · App must retry";
            if (remaining <= TimeSpan.FromSeconds(10)) bar.Background = Ui.Brush("#F2C46D");
            if (remaining <= TimeSpan.Zero) dialog.Close();
        };
        void CloseNotification(object? sender, EventArgs e) => dialog.Close();
        Closed += CloseNotification;
        dialog.Closed += (_, _) => { timeout.Stop(); Closed -= CloseNotification; learningDialogOpen = false; if (learningPrompt == dialog) learningPrompt = null; };
        learningPrompt = dialog;
        timeout.Start(); dialog.Show(); return dialog;
    }
    private void OpenAdministratorControls() => RestartElevated("--manage");

    /// <summary>Restarts Darkwire as administrator: --manage opens Settings, --vpn the VPN page, --setup the setup dialog.</summary>
    private void RestartElevated(string purpose)
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "Darkwire.exe");
        if (!File.Exists(executable)) { ShowToast("Run the published Darkwire.exe to open administrator controls."); return; }
        try
        {
            // The elevated instance replaces this one, tray icon and notifications included, instead of running beside it.
            using var elevated = Process.Start(new ProcessStartInfo(executable, $"{purpose} --replace {Environment.ProcessId}") { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory });
            if (elevated is null) return;
            quitting = true; Close();
        }
        catch (System.ComponentModel.Win32Exception ex) { ShowToast("Administrator controls were not opened: " + ex.Message); }
    }
    /// <summary>Shows the window when another launch asks the running instance to come forward.</summary>
    internal void BringToFront() => ShowMain();
}
