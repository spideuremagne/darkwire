using Darkwire.Engine;
using System.Windows.Controls.Primitives;
using System.Windows.Input;

namespace Darkwire.Host;

public partial class MainWindow
{
    private TextBlock? dnsStatusText, blockedNamesHits;

    /// <summary>How Darkwire's DNS proxy answers; a demo shows one answering.</summary>
    private DnsStatus? DnsStatusNow => demo ? Demo.DnsStatus() : serviceStatus?.Dns;

    /// <summary>
    /// Who answers lookups bound for the internet: the network's own servers, or encrypted DNS servers chosen from the public
    /// resolver list or entered by hand, each with what it says of itself.
    /// </summary>
    private Border EncryptedDnsCard()
    {
        var stack = Ui.Stack(Ui.Label("ENCRYPTED DNS"), Ui.Gap(6), Ui.Text("Lookups for names outside your local network go encrypted, over DNS over HTTPS or DNSCrypt, to the servers you choose, " +
            "along the route set for Darkwire's own connections (VPN page); the fastest to answer is used. Local names, such as your router's or a printer's, still go to your network's own DNS.", 11, "#A097B1"), Ui.Gap(12));
        if (state.DnsServers.Count == 0) stack.Children.Add(Ui.Text("Your network's DNS servers answer every lookup, unencrypted.", 13, "#D9CCEA"));
        foreach (var server in state.DnsServers) stack.Children.Add(DnsServerRow(server));
        if (state.DnsServers.Count > 0 && state.DnsServers.Any(s => !Validates(s)))
            stack.Children.Add(Ui.Text("Servers marked without DNSSEC do not check signatures, so a forged answer for a signed name gets through them. Choose servers that validate DNSSEC to have forgeries refused.", 11, "#E8C9A8"));
        if (state.DnsServers.Count > 0 && !state.RouteConnections) stack.Children.Add(Ui.Text("Encrypted DNS needs connection routing. Turn it on in Settings.", 11, "#F2849C"));
        dnsStatusText = Ui.Text("", 11, "#B9A2F0"); dnsStatusText.Margin = new(0, 10, 0, 0); stack.Children.Add(dnsStatusText);
        var actions = Ui.Row(Ui.AsyncButton(state.DnsServers.Count == 0 ? "Choose servers…" : "Change servers…", ChooseDnsServers, true));
        if (state.DnsServers.Count > 0)
        {
            var network = Ui.Button("Use the network's DNS", () => SetDnsServers([], "Lookups go to your network's own DNS servers again."));
            network.Margin = new(10, 0, 0, 0); actions.Children.Add(network);
        }
        actions.Margin = new(0, 14, 0, 0); stack.Children.Add(actions);
        ApplyDnsStatus();
        return Ui.Card(stack, 20);
    }

    private static bool Validates(DnsServer server) => server.Stamps.Count > 0 && DnsStamp.TryParse(server.Stamps[0], out var stamp) && stamp.Dnssec;

    private UIElement DnsServerRow(DnsServer server)
    {
        DnsStamp.TryParse(server.Stamps.FirstOrDefault(), out var stamp);
        var remove = Ui.Button("×", () => SetDnsServers([.. state.DnsServers.Where(s => s != server)], $"{server.Name} no longer answers lookups."));
        remove.Padding = new(9, 4, 9, 4); remove.VerticalAlignment = VerticalAlignment.Center;
        System.Windows.Automation.AutomationProperties.SetName(remove, "Remove " + server.Name);
        var row = new DockPanel { Margin = new(0, 0, 0, 8) }; DockPanel.SetDock(remove, Dock.Right); row.Children.Add(remove);
        var about = stamp is null ? "" : string.Join("  ·  ", new[] { stamp.ProtocolName, stamp.Dnssec ? "DNSSEC" : "no DNSSEC", stamp.NoLog ? "no logs" : null, stamp.NoFilter ? null : server.Listed ? "filters" : null,
            server.Listed ? DnsProviders.Of(server.Name) : "your own: " + stamp.Display }.OfType<string>());
        var details = Ui.Text(about, 11, stamp?.Dnssec == true ? "#9A90AD" : "#E8C9A8");
        row.Children.Add(Ui.Stack(Ui.Text(server.Name, 13, "#ECE5F6", FontWeights.SemiBold), Ui.Gap(2), details));
        return Ui.Card(row, 10);
    }

    private void SetDnsServers(List<DnsServer> servers, string change)
    {
        state.DnsServers = servers;
        Navigate("Blocklists");
        PolicyChanged(PolicyPart.Dns, change);
    }

    /// <summary>What the DNS proxy is doing, under the servers chosen.</summary>
    private void ApplyDnsStatus()
    {
        if (dnsStatusText is null) return;
        var status = DnsStatusNow; string text = "", color = "#B9A2F0";
        if (state.DnsServers.Count == 0) text = "";
        else if (!demo && serviceStatus is not { Active: true }) text = "In force once Darkwire takes over.";
        else if (status is null) text = pendingParts.HasFlag(PolicyPart.Dns) || settingsApplying ? "Applying…" : "Not running yet.";
        else
        {
            var counts = status.Answered + status.Failed > 0 ? $"  ·  {status.Answered:N0} lookups answered, {status.Failed:N0} failed" + (status.LatencyMs is { } ms ? $", the last in {ms} ms" : "") : "";
            (text, color) = status.State switch
            {
                "Ready" => ("Answering" + (status.Fastest is { } fastest ? $"  ·  fastest {fastest} ({status.FastestMs} ms)" : "") +
                    (status.LiveServers is { } live ? $"  ·  {live} server{(live == 1 ? "" : "s")} reachable" : "") + counts, "#7CE3BA"),
                "Waiting" => ("No chosen server answers yet. Check that this network, or the route for Darkwire's own connections, reaches them; lookups fail meanwhile." + counts, "#E8B07A"),
                "Starting" => ("Starting the DNS proxy…" + counts, "#C9B4EF"),
                _ => ("Not answering: " + (status.Error ?? "the DNS proxy stopped.") + " Lookups bound for the internet fail until it recovers." + counts, "#F2849C")
            };
        }
        dnsStatusText.Text = text; dnsStatusText.Foreground = Ui.Brush(color);
        dnsStatusText.Visibility = text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Opens the server picker over the service's verified copy of the public resolver list, fetching it first if it has none.</summary>
    private async Task ChooseDnsServers()
    {
        var catalog = demo ? Demo.DnsCatalog() : await LoadDnsCatalog();
        if (catalog is not null) DnsServerChooser(catalog).ShowDialog();
    }

    private async Task<DnsCatalog?> LoadDnsCatalog()
    {
        try
        {
            for (var attempt = 0; attempt < 20; attempt++)
            {
                var response = await ServiceClient.SendAsync(new("dns-servers"));
                if (!response.Success || response.DnsCatalog is not { } catalog) { ShowToast(response.Message); return null; }
                // A list fetched for the first time takes a moment; a failed fetch still leaves servers of your own.
                if (catalog.Servers.Count > 0 || !catalog.Checking) return catalog;
                if (attempt == 0) ShowToast("The service is fetching the public resolver list…");
                await Task.Delay(TimeSpan.FromSeconds(1.5));
            }
            ShowToast("The public resolver list is still on its way. Try again in a moment.");
        }
        catch (Exception error) when (error is not OutOfMemoryException) { ShowToast("Service unavailable: " + error.Message); }
        return null;
    }

    /// <summary>
    /// Every server on the resolver list in one list, A to Z, each with its provider, protocol and what it says of itself,
    /// narrowed by provider, search and those claims, DNSSEC validation first; and servers of your own, by DNS over HTTPS URL
    /// or DNS stamp. Saving sets the servers that answer lookups bound for the internet.
    /// </summary>
    private Window DnsServerChooser(DnsCatalog catalog)
    {
        var entries = catalog.Servers.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var listed = entries.Select(e => e.Name).ToHashSet(StringComparer.Ordinal);
        var chosen = state.DnsServers.Where(s => s.Listed).Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        // Chosen servers the list no longer names keep the stamps they were chosen with.
        var kept = state.DnsServers.Where(s => s.Listed && !listed.Contains(s.Name)).ToList();
        var own = state.DnsServers.Where(s => !s.Listed).Select(s => new DnsServer { Name = s.Name, Stamps = [.. s.Stamps] }).ToList();

        var search = Ui.Input("", "Search by name or description"); search.Margin = new(0, 0, 12, 0); search.Width = 260;
        System.Windows.Automation.AutomationProperties.SetName(search, "Search DNS servers");
        var providers = new ComboBox { ItemsSource = (string[])["All providers", .. DnsProviders.Names, DnsProviders.Other], SelectedIndex = 0, Width = 210, VerticalAlignment = VerticalAlignment.Center };
        System.Windows.Automation.AutomationProperties.SetName(providers, "Provider");
        CheckBox Filter(string text, bool on, string tip) => new() { Content = text, IsChecked = on, Margin = new(0, 0, 18, 0), ToolTip = tip, VerticalAlignment = VerticalAlignment.Center };
        var dnssec = Filter("Validates DNSSEC", true, "Only servers that check DNSSEC signatures, so forged answers for signed names are refused.");
        var noLog = Filter("No logs", false, "Only servers whose operators say they keep no logs of lookups.");
        var noFilter = Filter("No filtering", false, "Only servers that block nothing themselves; filtering ones block ads, malware or adult sites.");
        var doh = Filter("DNS over HTTPS", true, "Servers reached over HTTPS, port 443 as a rule.");
        var dnscrypt = Filter("DNSCrypt", true, "Servers reached over the DNSCrypt protocol.");
        var ipv6 = Filter("IPv6 servers", false, "Servers reached over IPv6. Choose them only where this PC has IPv6.");
        // One row a server, whose columns line up with the header's: name, provider, protocol and claims, description.
        double[] columns = [290, 150, 230, 0];
        Grid Row(params UIElement[] cells)
        {
            var row = Ui.Columns(columns);
            for (var i = 0; i < cells.Length; i++) { if (cells[i] is FrameworkElement cell) cell.Margin = new(0, 0, 14, 0); Ui.Add(row, cells[i], i); }
            return row;
        }
        static TextBlock Cell(string text, double size, string color)
        {
            var cell = Ui.Text(text, size, color); cell.TextWrapping = TextWrapping.NoWrap; cell.TextTrimming = TextTrimming.CharacterEllipsis; cell.VerticalAlignment = VerticalAlignment.Center;
            return cell;
        }
        var list = Ui.Stack();
        // The header sits over the rows' text, past each row's tick box.
        var header = Row(Ui.Label("SERVER"), Ui.Label("PROVIDER"), Ui.Label("PROTOCOL · CLAIMS"), Ui.Label("ABOUT")); header.Margin = new(25, 0, 12, 6);
        var count = Ui.Text("", 11, "#A49AAF"); count.VerticalAlignment = VerticalAlignment.Center;
        int Total() => chosen.Count + own.Count;
        void Count(int shown) => count.Text = $"{shown:N0} of {entries.Count:N0} shown  ·  {Total()} chosen";
        void Fill()
        {
            list.Children.Clear();
            var query = search.Text.Trim(); var provider = providers.SelectedIndex == 0 ? null : (string)providers.SelectedItem;
            var shown = entries.Where(e => (provider is null || e.Provider == provider) && (dnssec.IsChecked != true || e.Dnssec) && (noLog.IsChecked != true || e.NoLog) &&
                (noFilter.IsChecked != true || e.NoFilter) && (e.Protocol == DnsProtocol.Https ? doh.IsChecked == true : dnscrypt.IsChecked == true) && (ipv6.IsChecked == true || !e.Ipv6) &&
                (query.Length == 0 || e.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || e.Description.Contains(query, StringComparison.CurrentCultureIgnoreCase))).ToList();
            foreach (var entry in shown)
            {
                var traits = string.Join(" · ", new[] { entry.Protocol == DnsProtocol.Https ? "DoH" : "DNSCrypt", entry.Dnssec ? "DNSSEC" : "no DNSSEC", entry.NoLog ? "no logs" : null, entry.NoFilter ? null : "filters", entry.Ipv6 ? "IPv6" : null }.OfType<string>());
                var content = Row(Cell(entry.Name, 12, "#ECE5F6"), Cell(entry.Provider, 11, "#B7ADC8"), Cell(traits, 11, entry.Dnssec ? "#9A90AD" : "#E8C9A8"), Cell(entry.Description, 11, "#8F859F"));
                // The whole row ticks its box.
                var box = new CheckBox { Content = content, IsChecked = chosen.Contains(entry.Name), Margin = new(0, 0, 0, 0), Padding = new(8, 7, 0, 7), HorizontalContentAlignment = HorizontalAlignment.Stretch,
                    ToolTip = $"{entry.Name} · {entry.Provider}\n{entry.Description}" };
                System.Windows.Automation.AutomationProperties.SetName(box, entry.Name);
                box.Checked += (_, _) => { chosen.Add(entry.Name); Count(shown.Count); };
                box.Unchecked += (_, _) => { chosen.Remove(entry.Name); Count(shown.Count); };
                list.Children.Add(new Border { Child = box, BorderBrush = Ui.Brush("#211F2B"), BorderThickness = new(0, 0, 0, 1) });
            }
            if (shown.Count == 0) list.Children.Add(Ui.Text(entries.Count == 0 ? "No servers to show yet." : "No server matches these filters.", 12, "#A49AAF"));
            Count(shown.Count);
        }
        search.TextChanged += (_, _) => Fill(); providers.SelectionChanged += (_, _) => Fill();
        foreach (var filter in new[] { dnssec, noLog, noFilter, doh, dnscrypt, ipv6 }) { filter.Checked += (_, _) => Fill(); filter.Unchecked += (_, _) => Fill(); }

        // Servers of your own: a DoH URL or host name, or a DNS stamp for DNSCrypt.
        var custom = Ui.Input("", "https://dns.example/dns-query, or an sdns:// stamp"); custom.Margin = new(0, 0, 10, 0); custom.Width = 420;
        System.Windows.Automation.AutomationProperties.SetName(custom, "Your own DNS server");
        var ownList = Ui.Stack();
        var error = Ui.Text("", 11, "#F2849C");
        void DrawOwn()
        {
            ownList.Children.Clear();
            foreach (var server in own)
            {
                DnsStamp.TryParse(server.Stamps[0], out var stamp);
                var remove = Ui.Button("×", () => { own.Remove(server); DrawOwn(); Fill(); }); remove.Padding = new(8, 2, 8, 2);
                var line = new DockPanel { Margin = new(0, 6, 0, 0) }; DockPanel.SetDock(remove, Dock.Right); line.Children.Add(remove);
                line.Children.Add(Ui.Text($"{server.Name}  ·  {stamp?.ProtocolName}  ·  {stamp?.Display}", 12, "#D9CCEA"));
                ownList.Children.Add(line);
            }
        }
        void AddOwn()
        {
            error.Text = "";
            var text = custom.Text.Trim();
            if (text.Length == 0) return;
            try
            {
                var stamp = text.StartsWith(DnsStamp.Scheme, StringComparison.Ordinal) ? text : DnsStamp.FromUrl(text);
                var parsed = DnsStamp.Parse(stamp);
                if (own.Any(s => s.Stamps.Contains(stamp, StringComparer.Ordinal))) { error.Text = "That server is on your list already."; return; }
                own.Add(new() { Name = OwnName(parsed, own.Select(s => s.Name).Concat(listed)), Stamps = [stamp] });
                custom.Text = ""; DrawOwn(); Fill();
            }
            catch (InvalidDataException failure) { error.Text = failure.Message; }
        }
        custom.KeyDown += (_, e) => { if (e.Key == Key.Enter) AddOwn(); };
        var addOwn = Ui.Button("+  Add server", AddOwn);
        DrawOwn(); Fill();

        var signed = catalog.SignedAt is { } at ? $"Public resolver list from the DNSCrypt project, signed {at.ToLocalTime():MMM d, yyyy}, its signature verified by the Darkwire service." : "";
        var unavailable = entries.Count == 0 ? $"The public resolver list isn't available yet{(catalog.Error is { } why ? ": " + why : ".")} You can still add servers of your own." : "";
        var panel = Ui.Stack(Ui.Text("Encrypted DNS servers", 23, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(8),
            Ui.Text("Lookups that leave your local network go to the servers you tick, encrypted; Darkwire uses whichever answers fastest. Servers that validate DNSSEC refuse forged answers.", 12, "#A99DBA"),
            Ui.Gap(14), Ui.Row(search, providers), Ui.Gap(10), Ui.Row(dnssec, noLog, noFilter, doh, dnscrypt, ipv6), Ui.Gap(10), count, Ui.Gap(10), header,
            new Border { BorderBrush = Ui.Brush("#34303E"), BorderThickness = new(0, 1, 0, 1),
                Child = new ScrollViewer { Content = list, Height = 380, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });
        if (unavailable.Length > 0) panel.Children.Add(Ui.Text(unavailable, 11, "#E8B07A"));
        if (kept.Count > 0) panel.Children.Add(Ui.Text($"Kept from before, no longer on the list: {string.Join(", ", kept.Select(s => s.Name))}.", 11, "#E8C9A8"));
        panel.Children.Add(Ui.Gap(12)); panel.Children.Add(Ui.Label("YOUR OWN SERVERS")); panel.Children.Add(Ui.Gap(6));
        panel.Children.Add(Ui.Row(custom, addOwn)); panel.Children.Add(ownList); panel.Children.Add(error);
        if (signed.Length > 0) { panel.Children.Add(Ui.Gap(8)); panel.Children.Add(Ui.Text(signed, 10, "#857A96")); }
        var window = Dialog("Encrypted DNS servers", panel, 1080);
        var save = Ui.Button("Save", () =>
        {
            if (Total() > PolicyValidation.MaximumDnsServers) { error.Text = $"Choose up to {PolicyValidation.MaximumDnsServers} servers."; return; }
            List<DnsServer> servers = [.. entries.Where(e => chosen.Contains(e.Name)).Select(e => new DnsServer { Name = e.Name, Stamps = [.. e.Stamps], Listed = true }),
                .. kept.Where(s => chosen.Contains(s.Name)), .. own];
            window.Close();
            SetDnsServers(servers, servers.Count == 0 ? "Lookups go to your network's own DNS servers again."
                : $"{servers.Count} encrypted DNS server{(servers.Count == 1 ? "" : "s")} answer lookups that leave the local network.");
        }, true);
        var cancel = Ui.Button("Cancel", window.Close); cancel.Margin = new(10, 0, 0, 0);
        var none = Ui.Button("Clear all", () => { chosen.Clear(); own.Clear(); DrawOwn(); Fill(); }); none.Margin = new(10, 0, 0, 0);
        panel.Children.Add(Ui.Gap(12)); panel.Children.Add(Ui.Row(save, cancel, none));
        return window;
    }

    /// <summary>A name for a server of your own from where it is, unlike any taken: own-, then its host or address in the list's characters.</summary>
    public static string OwnName(DnsStamp stamp, IEnumerable<string> taken)
    {
        var place = stamp.Protocol == DnsProtocol.Https ? stamp.Host : stamp.Address;
        var cleaned = new string([.. place.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '-')]).Trim('-', '.');
        var name = "own-" + (cleaned.Length == 0 ? "server" : cleaned.Length > 52 ? cleaned[..52].TrimEnd('-', '.') : cleaned);
        var used = taken.ToHashSet(StringComparer.Ordinal);
        var unique = name;
        for (var i = 2; used.Contains(unique); i++) unique = $"{name}-{i}";
        return unique;
    }

    /// <summary>
    /// Names blocked one by one, with their subdomains: DNS filtering answers them with this PC's own address, so whatever asks
    /// reaches nothing. Each applies as it is added.
    /// </summary>
    private Border BlockedNamesCard()
    {
        var input = Ui.Input("", "A name such as tracker.example.com; its subdomains are blocked too"); input.Margin = new(0, 0, 10, 0); input.MinWidth = 340;
        System.Windows.Automation.AutomationProperties.SetName(input, "Name to block");
        void Block()
        {
            var text = input.Text.Trim();
            // A pasted address keeps only its host.
            if (Uri.TryCreate(text, UriKind.Absolute, out var url) && url.Host.Length > 0 && text.Contains("://", StringComparison.Ordinal)) text = url.Host;
            if (BlocklistNames.Normalize(text) is not { } name) { ShowToast("Enter a DNS name, such as tracker.example.com."); return; }
            if (state.BlockedNames.Contains(name)) { ShowToast($"{name} is blocked already."); return; }
            if (state.BlockedNames.Count >= PolicyValidation.MaximumBlockedNames) { ShowToast($"Darkwire blocks up to {PolicyValidation.MaximumBlockedNames:N0} names one by one; use a custom list for more."); return; }
            state.BlockedNames = [.. state.BlockedNames.Append(name).Order(StringComparer.Ordinal)];
            Navigate("Blocklists");
            PolicyChanged(PolicyPart.BlockedNames, $"{name} now answers with this PC's own address.");
        }
        input.KeyDown += (_, e) => { if (e.Key == Key.Enter) Block(); };
        var add = Ui.Button("+  Block name", Block, true);
        var stack = Ui.Stack(Ui.Label("BLOCKED NAMES"), Ui.Gap(6),
            Ui.Text("Names you block one by one, each with its subdomains. Darkwire answers them with this PC's own address (127.0.0.1 and ::1), so apps reach nothing, even where a list or rule would allow it. Like domain lists, they need connection routing and apply in Learning and Block new.", 11, "#A097B1"),
            Ui.Gap(12), Ui.Row(input, add));
        blockedNamesHits = Ui.Text("", 11, "#C9B6EE"); blockedNamesHits.Margin = new(0, 8, 0, 0); stack.Children.Add(blockedNamesHits);
        if (state.BlockedNames.Count == 0) { stack.Children.Add(Ui.Gap(4)); stack.Children.Add(Ui.Text("No names blocked one by one.", 12, "#93889F")); }
        var shown = Ui.Stack(); shown.Margin = new(0, 8, 0, 0);
        foreach (var name in state.BlockedNames.Take(200))
            shown.Children.Add(RestrictionRow(name, () =>
            {
                state.BlockedNames = [.. state.BlockedNames.Where(n => n != name)];
                Navigate("Blocklists");
                PolicyChanged(PolicyPart.BlockedNames, $"{name} resolves again.");
            }));
        stack.Children.Add(shown);
        if (state.BlockedNames.Count > 200) stack.Children.Add(Ui.Text($"And {state.BlockedNames.Count - 200:N0} more.", 11, "#93889F"));
        return Ui.Card(stack, 20);
    }
}
