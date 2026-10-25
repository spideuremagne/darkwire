using System.Text.RegularExpressions;

namespace Darkwire.Host;

public partial class MainWindow
{
    private UIElement RegionsPage()
    {
        var countries = CountryOptions();
        string Name(string code) => countries.FirstOrDefault(c => c.Code.Equals(code, StringComparison.OrdinalIgnoreCase))?.Name ?? code;
        // Blocking names countries apps may not reach; an allow list names the only ones they may.
        var blockMode = new RadioButton { Content = "Block the countries chosen", GroupName = "CountryMode", IsChecked = !state.CountryAllowList, Margin = new(0, 14, 0, 6) };
        var allowMode = new RadioButton { Content = "Allow only the countries chosen", GroupName = "CountryMode", IsChecked = state.CountryAllowList, Margin = new(0, 0, 0, 14) };
        blockMode.Checked += (_, _) => SetCountryMode(false, countries);
        allowMode.Checked += (_, _) => SetCountryMode(true, countries);
        var left = Ui.Stack(Ui.Label("COUNTRY RESTRICTIONS"), Ui.Gap(9), Ui.Text("Choose where apps can connect.", 19, "#E8E0F2", FontWeights.SemiBold), blockMode, allowMode,
            Ui.Button("Choose countries…", () => ChooseCountries(countries, state.CountryAllowList), true), Ui.Gap(22));
        var chosen = state.CountryAllowList ? state.AllowedCountries : state.BlockedCountries;
        foreach (var code in chosen.OrderBy(Name, StringComparer.CurrentCulture).ToArray())
            left.Children.Add(RestrictionRow($"{code.ToUpperInvariant()}   {Name(code)}", () =>
            {
                if (state.CountryAllowList && chosen.Count == 1) { ShowToast("Keep one country at least, or block countries instead."); return; }
                chosen.Remove(code); Navigate("Regions");
                PolicyChanged(PolicyPart.Geography, state.CountryAllowList ? $"{Name(code)} is no longer allowed." : $"{Name(code)} is no longer blocked.");
            }));
        if (chosen.Count == 0) left.Children.Add(Ui.Text(state.CountryAllowList ? "Choose the countries apps may reach." : "No countries blocked.", 12, "#93889F"));
        if (state.CountryAllowList)
            left.Children.Add(Ui.Text("Darkwire's connection router refuses every connection this PC makes to another country; connections coming in follow your rules. Addresses no country claims, such as internal ones, pass.", 11, "#A49AAF"));
        var asn = Ui.Input("", "Autonomous system number, for example AS13335"); var right = Ui.Stack(Ui.Label("AUTONOMOUS SYSTEMS"), Ui.Gap(9), Ui.Text("Control network operators.", 19, "#E8E0F2", FontWeights.SemiBold), Ui.Gap(7), asn);
        right.Children.Add(Ui.Button("+  Block ASN", () =>
        {
            var text = asn.Text.Trim(); if (text.StartsWith("AS", StringComparison.OrdinalIgnoreCase)) text = text[2..];
            if (!uint.TryParse(text, out var number) || number == 0) { ShowToast("Enter an ASN from 1 to 4294967295."); return; }
            BlockAsn(number);
        }));
        right.Children.Add(Ui.Gap(22)); right.Children.Add(AsnLookup()); right.Children.Add(Ui.Gap(22));
        foreach (var number in state.BlockedAsns.ToArray())
            right.Children.Add(RestrictionRow("AS" + number, () => { state.BlockedAsns.Remove(number); Navigate("Regions"); PolicyChanged(PolicyPart.Geography, $"AS{number} is no longer blocked."); }));
        if (state.BlockedAsns.Count == 0) right.Children.Add(Ui.Text("No ASN restrictions.", 12, "#93889F"));
        var columns = Ui.Columns(0, 0); var leftCard = Ui.Card(left, 23); leftCard.Margin = new(0, 0, 14, 0); Ui.Add(columns, leftCard, 0); Ui.Add(columns, Ui.Card(right, 23), 1);
        var note = Ui.Card(Ui.Stack(Ui.Text("Resolved locally from the bundled DB-IP data.", 14, "#CCB7F2", FontWeights.SemiBold), Ui.Gap(7), Ui.Text(
            "While Darkwire enforces policy, changes apply as you make them. Blocked countries and autonomous systems become kernel filters in both directions, within the filter budget: smaller countries fit, the largest are refused. " +
            "An allow list is enforced by the connection router, as each connection is made. Allow all bypasses restrictions.", 12, "#A49AAF")), 18);
        return Ui.Scroll(Ui.Stack(columns, Ui.Gap(18), note));
    }

    private void BlockAsn(uint number)
    {
        if (state.BlockedAsns.Contains(number)) { ShowToast($"AS{number} is blocked already."); return; }
        state.BlockedAsns.Add(number); Navigate("Regions");
        PolicyChanged(PolicyPart.Geography, $"AS{number} is blocked.");
    }

    /// <summary>
    /// Switches between blocking the countries chosen and allowing only them. An allow list starts by choosing its countries,
    /// since an empty one would refuse them all; cancelling keeps blocking.
    /// </summary>
    private void SetCountryMode(bool allowList, CountryOption[] countries)
    {
        if (state.CountryAllowList == allowList) return;
        if (allowList && state.AllowedCountries.Count == 0) { ChooseCountries(countries, true, () => Navigate("Regions")); return; }
        state.CountryAllowList = allowList; Navigate("Regions");
        PolicyChanged(PolicyPart.Geography, allowList ? $"Apps may reach only the {state.AllowedCountries.Count} allowed countr{(state.AllowedCountries.Count == 1 ? "y" : "ies")}." : "The countries chosen are blocked.");
    }

    /// <summary>
    /// Every country in three columns, A to Z left to right, under a box that selects them all. Saving sets the list the mode
    /// uses: countries blocked, or the only ones allowed.
    /// </summary>
    private void ChooseCountries(CountryOption[] countries, bool allowList, Action? cancelled = null) => CountryChooser(countries, allowList, cancelled).ShowDialog();

    private Window CountryChooser(CountryOption[] countries, bool allowList, Action? cancelled = null)
    {
        var current = (allowList ? state.AllowedCountries : state.BlockedCountries).Select(c => c.ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
        var grid = new System.Windows.Controls.Primitives.UniformGrid { Columns = 3 };
        List<(CountryOption Country, CheckBox Box)> boxes = [];
        var all = new CheckBox { Content = "Select all", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        var count = Ui.Text("", 11, "#A49AAF"); count.VerticalAlignment = VerticalAlignment.Center; count.Margin = new(18, 0, 0, 0);
        var syncing = false;
        void Sync()
        {
            var selected = boxes.Count(b => b.Box.IsChecked == true);
            count.Text = $"{selected} of {boxes.Count} chosen";
            syncing = true; all.IsChecked = selected == boxes.Count ? true : selected == 0 ? false : null; syncing = false;
        }
        foreach (var country in countries)
        {
            var box = new CheckBox { Content = new TextBlock { Text = country.Name, TextTrimming = TextTrimming.CharacterEllipsis }, IsChecked = current.Contains(country.Code),
                Margin = new(0, 5, 14, 5), ToolTip = $"{country.Name} ({country.Code})" };
            System.Windows.Automation.AutomationProperties.SetName(box, country.Name);
            box.Checked += (_, _) => { if (!syncing) Sync(); }; box.Unchecked += (_, _) => { if (!syncing) Sync(); };
            boxes.Add((country, box)); grid.Children.Add(box);
        }
        void SetAll(bool value) { if (syncing) return; syncing = true; foreach (var (_, box) in boxes) box.IsChecked = value; syncing = false; Sync(); }
        all.Checked += (_, _) => SetAll(true); all.Unchecked += (_, _) => SetAll(false);
        // From partly chosen, a click selects everything.
        all.Indeterminate += (_, _) => { if (!syncing) SetAll(true); };
        Sync();
        var error = Ui.Text("", 11, "#F2849C");
        var panel = Ui.Stack(Ui.Text(allowList ? "Allow only these countries" : "Block these countries", 23, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(8),
            Ui.Text(allowList ? "Apps may connect only to addresses in the countries chosen. Addresses no country claims, such as internal ones, pass." : "Apps may not connect to addresses in the countries chosen, nor take connections from them.", 12, "#A99DBA"),
            Ui.Gap(16), Ui.Row(all, count), Ui.Gap(10),
            new Border { BorderBrush = Ui.Brush("#34303E"), BorderThickness = new(0, 1, 0, 1), Padding = new(0, 6, 0, 6),
                Child = new ScrollViewer { Content = grid, MaxHeight = 430, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } },
            Ui.Gap(10), error);
        var window = Dialog(allowList ? "Allowed countries" : "Blocked countries", panel, 780);
        var saved = false;
        var save = Ui.Button("Save", () =>
        {
            var chosen = boxes.Where(b => b.Box.IsChecked == true).Select(b => b.Country.Code).ToList();
            if (allowList && chosen.Count == 0) { error.Text = "Choose one country at least, or block countries instead."; return; }
            if (allowList) { state.AllowedCountries = chosen; state.CountryAllowList = true; } else state.BlockedCountries = chosen;
            saved = true; window.Close(); Navigate("Regions");
            PolicyChanged(PolicyPart.Geography, allowList ? $"Apps may reach only the {chosen.Count} allowed countr{(chosen.Count == 1 ? "y" : "ies")}." : $"{chosen.Count} countr{(chosen.Count == 1 ? "y is" : "ies are")} blocked.");
        }, true);
        var cancel = Ui.Button("Cancel", window.Close); cancel.Margin = new(10, 0, 0, 0);
        panel.Children.Add(Ui.Gap(12)); panel.Children.Add(Ui.Row(save, cancel));
        window.Closed += (_, _) => { if (!saved) cancelled?.Invoke(); };
        return window;
    }

    /// <summary>
    /// Who runs an address: its autonomous system, operator and place from the local GeoIP data, for an IP address or the
    /// addresses a host name resolves to, each with a button that blocks its system.
    /// </summary>
    private UIElement AsnLookup()
    {
        var input = Ui.Input("", "IP address or host name, for example 1.1.1.1");
        var results = Ui.Stack();
        async Task LookUp()
        {
            results.Children.Clear();
            var text = input.Text.Trim();
            if (text.Length == 0) return;
            if (geo is null) { results.Children.Add(Ui.Text(demo ? "The demo has no GeoIP data to look in." : "No GeoIP database is loaded yet.", 12, "#E89AAE")); return; }
            IReadOnlyList<System.Net.IPAddress> addresses;
            if (System.Net.IPAddress.TryParse(text, out var address)) addresses = [address];
            else
            {
                using var timeout = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { addresses = [.. (await System.Net.Dns.GetHostAddressesAsync(text, timeout.Token)).Distinct().Take(6)]; }
                catch (Exception error) when (error is System.Net.Sockets.SocketException or OperationCanceledException or ArgumentException)
                { results.Children.Add(Ui.Text($"{text} could not be resolved.", 12, "#E89AAE")); return; }
            }
            foreach (var found in addresses)
            {
                var record = geo.Lookup(found.ToString());
                var place = record is null ? "" : string.Join(", ", new[] { record.City, record.CountryName }.Where(p => !string.IsNullOrEmpty(p)));
                var line = new DockPanel { Margin = new(0, 8, 0, 0) };
                if (record is { Asn: > 0 } owned)
                {
                    var block = Ui.Button(state.BlockedAsns.Contains(owned.Asn) ? "Blocked" : $"Block AS{owned.Asn}", () => BlockAsn(owned.Asn));
                    block.IsEnabled = !state.BlockedAsns.Contains(owned.Asn); block.Padding = new(10, 5, 10, 5); block.Margin = new(10, 0, 0, 0);
                    DockPanel.SetDock(block, Dock.Right); line.Children.Add(block);
                }
                var summary = record is null ? "Not in the GeoIP data" : record.Asn == 0 ? $"No autonomous system · {place}" : $"AS{record.Asn} · {record.Organization}" + (place.Length > 0 ? $" · {place}" : "");
                line.Children.Add(Ui.Stack(Ui.Text(found.ToString(), 12, "#ECE5F6", FontWeights.SemiBold), Ui.Gap(2), Ui.Text(summary, 11, "#B4A9C4")));
                results.Children.Add(line);
            }
        }
        var button = Ui.AsyncButton("Look up", LookUp); button.Margin = new(0, 8, 0, 0);
        input.KeyDown += async (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) await LookUp(); };
        return Ui.Stack(Ui.Label("WHO RUNS AN ADDRESS"), Ui.Gap(7), input, button, results);
    }
    private UIElement RestrictionRow(string title, Action remove)
    {
        var row = new DockPanel { Margin = new(0, 0, 0, 10) }; var button = Ui.Button("×", remove); button.Padding = new(9, 4, 9, 4); DockPanel.SetDock(button, Dock.Right); row.Children.Add(button); var text = Ui.Text(title, 13, "#C8BACF"); text.VerticalAlignment = VerticalAlignment.Center; row.Children.Add(text); return Ui.Card(row, 12);
    }
    private UIElement SettingsPage()
    {
        var body = Ui.Stack();
        body.Children.Add(AppearanceSettingsCard()); body.Children.Add(Ui.Gap(18));
        body.Children.Add(ServicePanel()); body.Children.Add(Ui.Gap(18));
        var close = new CheckBox { Content = "Keep running in the tray when closed", IsChecked = state.CloseToTray }; close.Checked += (_, _) => { state.CloseToTray = true; Save(); }; close.Unchecked += (_, _) => { state.CloseToTray = false; Save(); };
        body.Children.Add(Ui.Card(Ui.Stack(SettingsText("Window behavior", 17, weight: FontWeights.SemiBold), Ui.Gap(12), close), 23)); body.Children.Add(Ui.Gap(18));
        body.Children.Add(StartupCard()); body.Children.Add(Ui.Gap(18));
        body.Children.Add(WindowsSecurityCard()); body.Children.Add(Ui.Gap(18));
        body.Children.Add(AtlasBackgroundControls()); body.Children.Add(Ui.Gap(18));
        body.Children.Add(MapOriginCard()); body.Children.Add(Ui.Gap(18));
        var reverse = new CheckBox { Content = "Look up hostnames for IP-only connections", IsChecked = state.ReverseDnsEnabled };
        reverse.Checked += (_, _) => SetReverseDns(true); reverse.Unchecked += (_, _) => SetReverseDns(false);
        body.Children.Add(Ui.Card(Ui.Stack(Ui.Label("CONNECTION NAMES"), Ui.Gap(15), reverse, Ui.Gap(8), Ui.Text("Uses your system DNS resolver. Reverse names appear in parentheses and never determine policy.", 11, "#A599B3")), 23)); body.Children.Add(Ui.Gap(18));
        body.Children.Add(GeoCard()); body.Children.Add(Ui.Gap(18));
        // How Darkwire works with Windows, as the service last reported when the page was built.
        var integration = Ui.Stack(Ui.Label("WINDOWS INTEGRATION"), Ui.Gap(15));
        var authority = serviceStatus switch
        {
            null => "Service not connected",
            { Active: true } active => $"Darkwire service · {ModeName(active.Mode)} · persistent WFP filters",
            { Phase: "Inactive" } => "Windows Firewall · Darkwire monitors only",
            _ => "Recovery required"
        };
        // The router holds what it routes until the answer; what it can't hold is blocked, and its application tries again.
        var prompts = state.RouteConnections ? "Routed connections are held for your answer; others are blocked, and apps retry" : "Unmatched attempts are blocked until you answer; apps retry";
        foreach (var pair in new[] { ("Connection telemetry", "IPv4 / IPv6 TCP snapshots"), ("Rule import", "Windows rule store: exact, reduced or kept disabled; broader blocks need consent"), ("Filtering authority", authority), ("Learning prompts", prompts), ("VPN routing", VpnState.Summary(serviceStatus)), ("Tamper protection", serviceStatus is not null ? "Protected service policy; administrator-only changes" : "Service not connected"), ("Graphics", demo ? "WPF / Direct3D" : $"WPF / Direct3D rendering tier {RenderCapability.Tier >> 16}") })
        { var row = Ui.Columns(180, 0); Ui.Add(row, Ui.Text(pair.Item1, 12, "#A397B1"), 0); Ui.Add(row, Ui.Text(pair.Item2, 12, "#D2C6DE"), 1); row.Margin = new(0, 0, 0, 13); integration.Children.Add(row); }
        body.Children.Add(Ui.Card(integration, 23));
        return Ui.Scroll(body);
    }
    /// <summary>
    /// Starting with Windows: this user's app at sign-in, a preference of the app, and the startup lock, which is policy the
    /// service enforces and applies like the other policy settings.
    /// </summary>
    private UIElement StartupCard()
    {
        var signIn = new CheckBox { Content = "Start Darkwire when I sign in", IsChecked = state.StartAtSignIn };
        signIn.Checked += (_, _) => { state.StartAtSignIn = true; Save(); }; signIn.Unchecked += (_, _) => { state.StartAtSignIn = false; Save(); };
        var hold = new CheckBox { Content = "Block the internet until Darkwire has started", IsChecked = state.StartupLock };
        void Hold(bool on)
        {
            state.StartupLock = on;
            PolicyChanged(PolicyPart.Startup, on ? "The internet will stay blocked at startup until Darkwire is ready." : "The internet will no longer be blocked while Darkwire starts.");
        }
        hold.Checked += (_, _) => Hold(true); hold.Unchecked += (_, _) => Hold(false);
        return Ui.Card(Ui.Stack(Ui.Label("STARTUP"), Ui.Gap(15),
            signIn, Ui.Text("The Darkwire service starts with Windows either way; this opens the app in the tray, so its prompts and alerts reach you.", 11, "#A599B3"), Ui.Gap(12),
            hold, Ui.Text("From the moment Windows starts, nothing but local networking reaches the network until Darkwire has its policy in force, its router running and its VPN tunnels up, or for a minute at most. Whenever the Darkwire service stops, the block returns until it starts again.", 11, "#A599B3")), 23);
    }
    /// <summary>
    /// Windows Security reports its firewall as off while Darkwire filters in its place, so the service hides that area and its
    /// warnings while it enforces. Showing them is a choice of the policy, applied like the other policy settings.
    /// </summary>
    private UIElement WindowsSecurityCard()
    {
        var show = new CheckBox { Content = "Show Windows Security's firewall warnings", IsChecked = state.ShowFirewallWarnings };
        void Show(bool on)
        {
            state.ShowFirewallWarnings = on;
            PolicyChanged(PolicyPart.WindowsSecurity, on ? "Windows Security will show its firewall page again, which says the firewall is off." : "Windows Security will stop warning that its firewall is off.");
        }
        show.Checked += (_, _) => Show(true); show.Unchecked += (_, _) => Show(false);
        var now = serviceStatus?.FirewallWarningsHidden switch { true => " Hidden now.", false => " Shown now.", null => "" };
        return Ui.Card(Ui.Stack(Ui.Label("WINDOWS SECURITY"), Ui.Gap(15), show,
            Ui.Text("While Darkwire filters in Windows Firewall's place, Windows Security would say its firewall is off and keep asking you to turn it on, so Darkwire hides its Firewall & network protection page, " +
                "and those warnings with it, through Windows' own policy setting. Tick this to show them anyway. Virus and other warnings always appear, and restoring Windows Firewall brings the page back." + now, 11, "#A599B3")), 23);
    }
    private UIElement Empty(string title, string description, string action, Action callback)
    {
        var button = Ui.Button(action, callback, true); button.HorizontalAlignment = HorizontalAlignment.Center;
        var text = Ui.Text(title, 25, "#E7DFF2", FontWeights.SemiBold); text.TextAlignment = TextAlignment.Center; var desc = Ui.Text(description, 13, "#A295B1"); desc.TextAlignment = TextAlignment.Center;
        return Ui.Card(Ui.Stack(Ui.Gap(60), text, Ui.Gap(12), desc, Ui.Gap(25), button, Ui.Gap(60)), 25);
    }
    private sealed record CountryOption(string Code, string Name) { public string Display => Code.Length == 0 ? Name : $"{Name} ({Code})"; public override string ToString() => Display; }
    private static CountryOption[]? countryOptions;
    /// <summary>
    /// Every country and territory with an ISO 3166 code the region data names, by English name: the invariant pseudo-region
    /// and Serbia and Montenegro, whose code is withdrawn, are left out.
    /// </summary>
    private static CountryOption[] CountryOptions() => countryOptions ??= [.. Enumerable.Range('A', 26).SelectMany(first => Enumerable.Range('A', 26).Select(second => $"{(char)first}{(char)second}"))
        .Where(code => code is not ("IV" or "CS"))
        .Select(code => { try { return new System.Globalization.RegionInfo(code) is { TwoLetterISORegionName: var two } region && two == code ? new CountryOption(code, region.EnglishName) : null; } catch (ArgumentException) { return null; } })
        .OfType<CountryOption>().OrderBy(c => c.Name, StringComparer.CurrentCulture)];
}
