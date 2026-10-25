using Darkwire.Engine;
using System.Windows.Automation;
using System.Windows.Media.Animation;

namespace Darkwire.Host;

public partial class MainWindow
{
    private readonly Dictionary<string, BlocklistRow> blocklistRows = [];
    private readonly Dictionary<string, TextBlock> customHitTexts = [];
    private IReadOnlyList<BlocklistStatus>? blocklistStatus;
    private bool blocklistReading;

    private sealed record BlocklistRow(BlocklistCatalogEntry Entry, TextBlock Icon, TextBlock Count, TextBlock State, TextBlock Hits, Button Download);

    /// <summary>What blocklists blocked since the service started; a demo shows some.</summary>
    private BlocklistHits? ListHits => demo ? Demo.ListHits() : serviceStatus?.ListHits;

    private UIElement BlocklistsPage()
    {
        blocklistRows.Clear(); customHitTexts.Clear(); catalogToggles.Clear();
        if (demo) blocklistStatus ??= Demo.ListStatus();
        var body = Ui.Stack(Ui.Text("Tick a list to block what it names. While Darkwire enforces policy it downloads the list and puts it in force at once: the spinning icon shows it loading, the green check that it blocks. The download button fetches a list ahead of ticking it. The service refreshes enforced lists daily.", 12, "#A49AAF"), Ui.Gap(18));
        body.Children.Add(EncryptedDnsCard());
        body.Children.Add(Ui.Gap(16));
        body.Children.Add(CatalogCard("DNS FILTERING", "Domain lists. Darkwire's router answers lookups for a listed name as nonexistent, so apps never reach it.", BlocklistCatalog.Entries.Where(e => e.Domains)));
        body.Children.Add(Ui.Gap(16));
        body.Children.Add(BlockedNamesCard());
        body.Children.Add(Ui.Gap(16));
        body.Children.Add(CatalogCard("IP FILTERING", "Address lists, blocked in both directions by kernel filters.", BlocklistCatalog.Entries.Where(e => !e.Domains)));
        body.Children.Add(Ui.Gap(16));
        body.Children.Add(CustomBlocklists());
        body.Children.Add(Ui.Gap(16));
        body.Children.Add(Ui.Card(Ui.Stack(Ui.Text("How lists are enforced", 14, "#CCB7F2", FontWeights.SemiBold), Ui.Gap(7), Ui.Text(
            "DNS filtering needs connection routing (Settings) and covers plain DNS, over UDP and TCP. Apps using encrypted DNS go around it: turn off secure DNS in browsers, or enable HaGeZi Encrypted DNS Bypass. " +
            "Firefox's automatic encrypted DNS is switched off for you. While domain lists are enforced, DNS servers on link-local addresses are refused, so Windows asks servers the filter sees. " +
            "Lists never block loopback, private, link-local or multicast addresses; rules still can. Blocks count lookups answered, connections refused and packets dropped since the service started; one several lists name counts for each of them.", 12, "#A49AAF")), 18));
        ApplyBlocklistStatus();
        if (!demo) _ = RefreshBlocklists();
        return Ui.Scroll(body);
    }

    private Border CatalogCard(string label, string description, IEnumerable<BlocklistCatalogEntry> entries)
    {
        var listed = entries.ToArray();
        // One button turns every list in the card on, or, once they all are, off.
        var toggle = Ui.Button("", () => SetCatalogLists(label, listed, !AllEnabled(listed)));
        toggle.Padding = new(10, 5, 10, 5); toggle.HorizontalAlignment = HorizontalAlignment.Right; toggle.VerticalAlignment = VerticalAlignment.Top;
        catalogToggles.Add((toggle, listed));
        var header = Ui.Columns(0, 130); Ui.Add(header, Ui.Stack(Ui.Label(label), Ui.Gap(6), Ui.Text(description, 11, "#A097B1")), 0); Ui.Add(header, toggle, 1);
        var stack = Ui.Stack(header, Ui.Gap(6));
        foreach (var entry in listed)
        {
            var row = Ui.Columns(34, 0, 30, 170, 46); row.Margin = new(0, 12, 0, 0);
            var check = new CheckBox { IsChecked = state.Blocklists.Any(l => l.CatalogId == entry.Id && l.Enabled), VerticalAlignment = VerticalAlignment.Top, Margin = new(0, 2, 0, 0) };
            AutomationProperties.SetName(check, "Block with " + entry.Name);
            check.Checked += (_, _) => SetCatalogList(entry, true); check.Unchecked += (_, _) => SetCatalogList(entry, false);
            var about = Ui.Stack(Ui.Text(entry.Name, 14, "#ECE5F6", FontWeights.SemiBold), Ui.Gap(3), Ui.Text(entry.Description, 11, "#A49AAF"), Ui.Gap(3),
                Ui.Text(entry.Publisher + (entry.License is null ? "" : " · " + entry.License), 10, "#857A96"));
            var icon = new TextBlock { FontFamily = new FontFamily("Segoe Fluent Icons"), FontSize = 16, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Top,
                Margin = new(0, 2, 0, 0), RenderTransformOrigin = new(.5, .5), RenderTransform = new RotateTransform() };
            var count = Ui.Text("", 13, "#D9CCEA", FontWeights.SemiBold); count.TextAlignment = TextAlignment.Right;
            var status = Ui.Text("", 10, "#8E859F"); status.TextAlignment = TextAlignment.Right;
            var hits = Ui.Text("", 10, "#C9B6EE"); hits.TextAlignment = TextAlignment.Right;
            var download = Ui.Button("", () => _ = PreloadBlocklist(entry));
            download.FontFamily = new FontFamily("Segoe Fluent Icons"); download.Padding = new(10, 7, 10, 7);
            download.HorizontalAlignment = HorizontalAlignment.Right; download.VerticalAlignment = VerticalAlignment.Top; download.ToolTip = "Download now";
            AutomationProperties.SetName(download, "Download " + entry.Name);
            Ui.Add(row, check, 0); Ui.Add(row, about, 1); Ui.Add(row, icon, 2); Ui.Add(row, Ui.Stack(count, Ui.Gap(3), status, Ui.Gap(2), hits), 3); Ui.Add(row, download, 4);
            blocklistRows[entry.Id] = new(entry, icon, count, status, hits, download);
            stack.Children.Add(row);
        }
        return Ui.Card(stack, 20);
    }

    /// <summary>Catalog lists travel in the policy by name only; the service downloads and keeps them, and enforces them as they arrive.</summary>
    private void SetCatalogList(BlocklistCatalogEntry entry, bool enabled)
    {
        state.Blocklists.RemoveAll(l => l.CatalogId == entry.Id);
        if (enabled) state.Blocklists.Add(new() { CatalogId = entry.Id, Name = entry.Name, Url = entry.Url });
        PolicyChanged(PolicyPart.Blocklists, enabled ? $"{entry.Name} is on." : $"{entry.Name} is off.");
        ApplyBlocklistStatus();
    }

    private readonly List<(Button Toggle, BlocklistCatalogEntry[] Entries)> catalogToggles = [];
    private bool AllEnabled(IEnumerable<BlocklistCatalogEntry> entries) => entries.All(e => state.Blocklists.Any(l => l.CatalogId == e.Id && l.Enabled));

    /// <summary>Turns every list of a catalog card on or off at once, applied as one change; custom lists are left as they are.</summary>
    private void SetCatalogLists(string card, IReadOnlyList<BlocklistCatalogEntry> entries, bool enabled)
    {
        foreach (var entry in entries)
        {
            state.Blocklists.RemoveAll(l => l.CatalogId == entry.Id);
            if (enabled) state.Blocklists.Add(new() { CatalogId = entry.Id, Name = entry.Name, Url = entry.Url });
        }
        var lists = card == "DNS FILTERING" ? "domain lists" : "address lists";
        PolicyChanged(PolicyPart.Blocklists, enabled ? $"All {entries.Count} {lists} are on." : $"Every {lists[..^1]} is off.");
        Navigate("Blocklists");
    }

    /// <summary>Each catalog card's button offers what its lists are not all: Select all until every one is on, then Select none.</summary>
    private void UpdateCatalogToggles()
    {
        foreach (var (toggle, entries) in catalogToggles)
        {
            var all = AllEnabled(entries);
            toggle.Content = all ? "Select none" : "Select all";
            System.Windows.Automation.AutomationProperties.SetName(toggle, (all ? "Turn off every list in " : "Turn on every list in ") + (entries.FirstOrDefault()?.Domains == true ? "DNS filtering" : "IP filtering"));
        }
    }

    /// <summary>
    /// Each catalog list's state: a spinning icon while it downloads or waits to be in force, a green check once it blocks, a
    /// warning when it failed; then its size, when it was updated, and what it blocked.
    /// </summary>
    private void ApplyBlocklistStatus()
    {
        var hits = ListHits;
        foreach (var (id, row) in blocklistRows)
        {
            var status = blocklistStatus?.FirstOrDefault(s => s.Id == id);
            var enabled = state.Blocklists.Any(l => l.CatalogId == id && l.Enabled);
            var unit = row.Entry.Domains ? "domains" : "networks";
            var stored = status is { Count: > 0 };
            row.Count.Text = stored ? $"{status!.Count:N0} {unit}" : $"≈ {row.Entry.Estimate:N0} {unit}";
            row.Count.Foreground = Ui.Brush(stored ? "#D9CCEA" : "#8E859F");
            row.Count.ToolTip = stored ? null : "Approximate. Download the list to count it.";
            var updated = status?.UpdatedAt?.ToLocalTime().ToString("MMM d, HH:mm");
            var waiting = enabled && status is { Enforced: false, Downloading: false } && !demo && serviceStatus is not { Active: true };
            row.State.Text = status is null ? demo ? "Not downloaded" : "Service not connected"
                : status.Downloading ? stored ? "Updating…" : "Downloading…"
                : status.Error is { } error ? stored ? $"Update failed; copy from {updated}" : error
                : waiting ? "In force once Darkwire takes over"
                : enabled && !status.Enforced ? "Loading…"
                : !stored ? "Not downloaded"
                : (status.Enforced ? "Blocking · updated " : "Updated ") + updated;
            row.State.ToolTip = status?.Error;
            row.State.Foreground = Ui.Brush(status?.Enforced == true ? "#B9A2F0" : status?.Error is not null ? "#E89AAE" : "#8E859F");
            row.Download.IsEnabled = status is not null && !status.Downloading;
            var count = hits?.ByList.GetValueOrDefault(id) ?? 0;
            row.Hits.Text = status?.Enforced == true ? count > 0 ? $"{count:N0} blocked" : "Nothing blocked yet" : count > 0 ? $"{count:N0} blocked" : "";
            if (status?.Downloading == true || enabled && status is { Enforced: false, Error: null } && !waiting) ShowIcon(row.Icon, "", "#C9B4EF", "Loading", spin: true);
            else if (enabled && status?.Enforced == true) ShowIcon(row.Icon, "", "#7CE3BA", "Active");
            else if (enabled && status?.Error is not null) ShowIcon(row.Icon, "", "#E89AAE", "Failed");
            else ShowIcon(row.Icon, "", "#8E859F", null);
        }
        foreach (var (name, text) in customHitTexts)
            text.Text = hits?.ByList.GetValueOrDefault(BlocklistHits.CustomKey(name)) is > 0 and var count ? $"    {count:N0} blocked" : "";
        if (blockedNamesHits is not null)
            blockedNamesHits.Text = hits?.ByList.GetValueOrDefault(BlocklistHits.NamesKey) is > 0 and var answered ? $"{answered:N0} lookup{(answered == 1 ? "" : "s")} answered with this PC's address since {hits.Since.ToLocalTime():MMM d, HH:mm}." : "";
        UpdateCatalogToggles();
        ApplyDnsStatus();
    }

    /// <summary>A Segoe Fluent glyph in the row's state column, turning while something is under way.</summary>
    private static void ShowIcon(TextBlock icon, string glyph, string color, string? meaning, bool spin = false)
    {
        icon.Text = glyph; icon.Foreground = Ui.Brush(color); icon.ToolTip = meaning;
        AutomationProperties.SetName(icon, meaning ?? "");
        var turn = (RotateTransform)icon.RenderTransform;
        if (spin && turn.HasAnimatedProperties) return;
        turn.BeginAnimation(RotateTransform.AngleProperty, spin ? new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1)) { RepeatBehavior = RepeatBehavior.Forever } : null);
    }

    /// <summary>
    /// Reads the service's lists, and keeps reading every two seconds while one downloads or waits to be in force and this page
    /// is open.
    /// </summary>
    private async Task RefreshBlocklists()
    {
        if (blocklistReading) return;
        blocklistReading = true;
        try
        {
            for (var round = 0; round < 150; round++)
            {
                try
                {
                    var response = await ServiceClient.SendAsync(new("blocklists"));
                    blocklistStatus = response.Success ? response.Blocklists : null;
                }
                catch (Exception) { blocklistStatus = null; }
                if (currentPage != "Blocklists") return;
                ApplyBlocklistStatus();
                var loading = blocklistStatus?.Any(s => s.Downloading || serviceStatus is { Active: true } && s.Error is null && !s.Enforced &&
                    state.Blocklists.Any(l => l.CatalogId == s.Id && l.Enabled)) == true;
                if (!loading && pendingParts == PolicyPart.None && !settingsApplying) return;
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }
        finally { blocklistReading = false; }
    }

    private async Task PreloadBlocklist(BlocklistCatalogEntry entry)
    {
        if (demo) { ShowToast($"Demo session: {entry.Name} is not downloaded."); return; }
        try
        {
            var response = await ServiceClient.SendAsync(new("preload-blocklist", BlocklistId: entry.Id));
            if (response.Blocklists is { } statuses) blocklistStatus = statuses;
            ShowToast(response.Message);
        }
        catch (Exception error) { ShowToast("Service unavailable: " + error.Message); return; }
        if (currentPage == "Blocklists") ApplyBlocklistStatus();
        await RefreshBlocklists();
    }

    private Border CustomBlocklists()
    {
        var header = Ui.Columns(0, 170);
        Ui.Add(header, Ui.Stack(Ui.Label("CUSTOM LISTS"), Ui.Gap(6), Ui.Text("Hosts files, domain lists, IP addresses and CIDRs from HTTPS sources you choose, downloaded into the draft. A listed domain blocks its subdomains too.", 11, "#A097B1")), 0);
        var add = Ui.Button("+  Add custom list", AddBlocklist); add.HorizontalAlignment = HorizontalAlignment.Right; add.VerticalAlignment = VerticalAlignment.Top;
        Ui.Add(header, add, 1);
        var stack = Ui.Stack(header);
        var custom = state.Blocklists.Where(l => l.CatalogId is null).ToList();
        if (custom.Count == 0) { stack.Children.Add(Ui.Gap(12)); stack.Children.Add(Ui.Text("No custom lists.", 12, "#93889F")); }
        foreach (var source in custom)
        {
            var title = Ui.Columns(0, 140); var enabled = new CheckBox { Content = "Enabled in policy", IsChecked = source.Enabled };
            enabled.Checked += (_, _) => { source.Enabled = true; PolicyChanged(PolicyPart.Blocklists, $"{source.Name} is on."); };
            enabled.Unchecked += (_, _) => { source.Enabled = false; PolicyChanged(PolicyPart.Blocklists, $"{source.Name} is off."); };
            Ui.Add(title, Ui.Stack(Ui.Text(source.Name, 16, "#ECE5F6", FontWeights.SemiBold), Ui.Gap(6), Ui.Text(source.Url, 11, "#9689A8")), 0); Ui.Add(title, enabled, 1);
            var update = Ui.AsyncButton("↻  Download update", async () =>
            {
                var text = await Downloads.Text(source.Url, 16 * 1024 * 1024); var entries = BlocklistParser.Parse(text);
                if (entries.Count == 0) throw new InvalidDataException("The source contains no supported entries. Previous list retained.");
                source.Entries = entries; source.UpdatedAt = DateTimeOffset.Now; Navigate("Blocklists");
                if (source.Enabled) PolicyChanged(PolicyPart.Blocklists, $"Updated {source.Name}: {entries.Count:N0} entries."); else { Save(); ShowToast($"Updated {source.Name}: {entries.Count:N0} entries."); }
            });
            var remove = Ui.Button("Remove", () =>
            {
                state.Blocklists.Remove(source); Navigate("Blocklists");
                if (source.Enabled) PolicyChanged(PolicyPart.Blocklists, $"Removed {source.Name}."); else Save();
            });
            remove.Margin = new(10, 0, 0, 0);
            var hits = Ui.Text("", 11, "#C9B6EE"); customHitTexts[source.Name] = hits;
            var info = Ui.Row(Ui.Pill(source.CountDisplay), Ui.Text("    Updated " + source.UpdatedDisplay, 11, "#9C90AD"), hits);
            var card = Ui.Card(Ui.Stack(title, Ui.Gap(16), info, Ui.Gap(16), Ui.Row(update, remove)), 18); card.Margin = new(0, 14, 0, 0);
            stack.Children.Add(card);
        }
        return Ui.Card(stack, 20);
    }

    private void AddBlocklist()
    {
        TextBox name = Ui.Input(""), url = Ui.Input("https://"); var error = Ui.Text("", 11, "#F2849C");
        var panel = Ui.Stack(Ui.Text("Add custom list", 23, "#ECE4F7", FontWeights.SemiBold), Ui.Gap(20), Ui.Label("Name"), name, Ui.Label("HTTPS URL"), url, error, Ui.Gap(12)); var window = Dialog("Add custom list", panel);
        panel.Children.Add(Ui.Button("Add list", () => { if (string.IsNullOrWhiteSpace(name.Text) || !Uri.TryCreate(url.Text, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo)) { error.Text = "Enter a name and a valid HTTPS URL."; return; } state.Blocklists.Add(new() { Name = name.Text.Trim(), Url = uri.AbsoluteUri }); Save(); window.Close(); Navigate("Blocklists"); }, true)); window.ShowDialog();
    }
}
