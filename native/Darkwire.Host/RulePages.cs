using System.Globalization;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Threading;
using System.Text.Json;

namespace Darkwire.Host;

public partial class MainWindow
{
    private UIElement RulesPage()
    {
        var root = new DockPanel();
        var toolbar = new WrapPanel { Orientation = Orientation.Horizontal, Margin = new(0, 0, 0, 10) };
        toolbar.Children.Add(Ui.Button("+  New rule", AddRule, true));
        foreach (var button in new[] { Ui.AsyncButton("Import Windows rules", ImportWindowsRules), Ui.Button("Columns", ColumnPicker), Ui.Button("Export", ExportRules), Ui.Button("Delete", DeleteRule) })
        { button.Margin = new(8, 0, 0, 0); toolbar.Children.Add(button); }
        toolbar.Children.Add(InternalNetworksPicker());
        // Keep each action intact when the sidebar leaves less room; the internal-network group wraps as one item.
        foreach (FrameworkElement control in toolbar.Children)
            control.Margin = new(control.Margin.Left, 0, control.Margin.Right, 6);
        DockPanel.SetDock(toolbar, Dock.Top); root.Children.Add(toolbar);
        var search = Ui.Input("", "Search application, group, or path"); search.Width = 360; search.HorizontalAlignment = HorizontalAlignment.Left;
        var review = rules.Count(r => RuleEnforcement.NeedsConsent(r) || r.Enabled && r.Import == ImportOutcome.Refused);
        var searchRow = new DockPanel(); var count = Ui.Text($"{rules.Count:N0} rules  ·  {review:N0} need review", 11, review > 0 ? "#E3B3FF" : "#A192B4"); count.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(count, Dock.Right); searchRow.Children.Add(count); searchRow.Children.Add(search); DockPanel.SetDock(searchRow, Dock.Top); root.Children.Add(searchRow);
        ruleGrid = new DataGrid { RowHeight = 45, CanUserResizeColumns = true, CanUserReorderColumns = true, IsReadOnly = false };
        var view = new ListCollectionView(rules); ruleGrid.ItemsSource = view;
        search.TextChanged += (_, _) => { if (view.IsEditingItem) return; view.Filter = r => r is FirewallRule f && $"{f.ApplicationName} {f.Group} {f.Path}".Contains(search.Text, StringComparison.OrdinalIgnoreCase); };
        ruleGrid.Columns.Add(ApplicationIcons.Column("Application name", "ApplicationName", "Path", 220, editable: true));
        AddRuleText("Group", "Group", 150); AddRuleText("Path", "Path", 270);
        AddRuleText("Location", "Location", 110);
        ruleGrid.Columns.Add(new DataGridCheckBoxColumn { Header = "Enabled", Binding = new Binding("Enabled") { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged }, Width = 80 });
        // A combo box column's own editing style replaces the app's, leaving the theme's white list behind light item text.
        var picker = new Style(typeof(ComboBox), (Style)FindResource(typeof(ComboBox)));
        picker.Setters.Add(new Setter(Selector.IsSynchronizedWithCurrentItemProperty, false));
        picker.Setters.Add(new Setter(MinHeightProperty, 0.0)); picker.Setters.Add(new Setter(HeightProperty, 32.0));
        ruleGrid.Columns.Add(new DataGridComboBoxColumn { Header = "Action", SelectedItemBinding = new Binding("Action") { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged }, ItemsSource = Enum.GetValues<RuleAction>(), Width = 100, EditingElementStyle = picker });
        ruleGrid.Columns.Add(new DataGridComboBoxColumn { Header = "Direction", SelectedItemBinding = new Binding("Direction") { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged }, ItemsSource = new[] { TrafficDirection.Any, TrafficDirection.Inbound, TrafficDirection.Outbound }, Width = 120, EditingElementStyle = picker });
        ruleGrid.Columns.Add(RouteColumn(picker));
        ruleGrid.BeginningEdit += (_, e) => { if (e.Column.Header is RouteHeader && e.Row.Item is FirewallRule rule && RuleRoute(rule) is null) e.Cancel = true; };
        AddRuleText("Local ports", "LocalPorts", 120); AddRuleText("Remote addresses", "RemoteAddresses", 210); AddRuleText("Remote ports", "RemotePorts", 120);
        AddRuleText("Protocol", "Protocol", 110);
        AddRuleText("Service", "Service", 130); AddRuleText("User", "User", 140);
        AddRuleText("Local addresses", "LocalAddresses", 210); ruleGrid.Columns[^1].Visibility = Visibility.Collapsed;
        AddRuleText("ICMP types/codes", "IcmpTypesAndCodes", 150); ruleGrid.Columns[^1].Visibility = Visibility.Collapsed;
        AddRuleText("Package", "Package", 180); ruleGrid.Columns[^1].Visibility = Visibility.Collapsed;
        ruleGrid.Columns.Add(new DataGridCheckBoxColumn { Header = "Edge traversal", Binding = new Binding("EdgeTraversal") { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged }, Width = 110, Visibility = Visibility.Collapsed });
        ruleGrid.Columns.Add(Ui.Column("Windows import", "ImportStatus", 150));
        foreach (var preference in state.Columns.OrderBy(p => p.Order))
        {
            var column = ruleGrid.Columns.FirstOrDefault(c => c.Header.ToString() == preference.Name);
            if (column is null) continue;
            column.DisplayIndex = Math.Clamp(preference.Order, 0, ruleGrid.Columns.Count - 1);
            column.Visibility = preference.Visible ? Visibility.Visible : Visibility.Collapsed;
            column.Width = Math.Clamp(preference.Width, 55, 800);
        }
        ruleGrid.RowEditEnding += (_, e) =>
        {
            if (e.EditAction != DataGridEditAction.Commit || e.Row.Item is not FirewallRule rule) return;
            var errors = RuleValidator.Validate(rule);
            if (errors.Count > 0) { e.Cancel = true; ShowToast(string.Join(" ", errors)); return; }
            if (RuleEnforcement.NeedsConsent(rule)) ShowToast(rule.ImportStatus + ": " + rule.ImportWarning);
            Dispatcher.BeginInvoke(() => { Save(); foreach (var row in connections) row.Update(Preview(row.Connection)); }, DispatcherPriority.Background);
        };
        // The selected rule's import status shows in place, rather than as a notification for every row selected.
        var detail = Ui.Text("", 11, "#C9BCD8"); detail.Margin = new(0, 12, 0, 0); DockPanel.SetDock(detail, Dock.Bottom);
        ruleGrid.SelectionChanged += (_, _) => detail.Text = ruleGrid.SelectedItem is FirewallRule { ImportWarning: not null } r ? r.ImportStatus + ": " + r.ImportWarning : "";
        var note = Ui.Text("Edits save to your draft; apply them from Settings. A VPN route applies as soon as you choose it while Darkwire enforces policy. Edits to a Windows rule persist until Windows changes that rule.", 11, "#91879F"); note.Margin = new(0, 6, 0, 0); DockPanel.SetDock(note, Dock.Bottom); root.Children.Add(note); root.Children.Add(detail); root.Children.Add(Ui.Card(ruleGrid, 0));
        return root;
    }
    private static readonly (InternalAccess Access, string Label, string Change)[] InternalChoices =
    [
        (InternalAccess.Allow, "Allow all internal", "Internal networks are allowed."),
        (InternalAccess.Block, "Block internal unless a rule allows it", "Internal networks are blocked unless a rule allows them."),
        (InternalAccess.Rules, "Decide internal by rules and prompts", "Rules and prompts decide internal network traffic.")
    ];

    /// <summary>What happens to traffic with the PC's own networks, which applies at once while Darkwire enforces policy.</summary>
    private UIElement InternalNetworksPicker()
    {
        var picker = new ComboBox { ItemsSource = InternalChoices.Select(c => c.Label).ToArray(), SelectedIndex = Math.Max(0, Array.FindIndex(InternalChoices, c => c.Access == state.InternalNetworks)), Width = 290,
            ToolTip = "Private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local and unique local addresses, multicast and broadcast. " +
                "Allowed covers connections this PC makes, and connections in on networks Windows calls private or domain; on a public network, strangers share its private addresses." };
        System.Windows.Automation.AutomationProperties.SetName(picker, "Internal networks");
        picker.SelectionChanged += (_, _) =>
        {
            var chosen = InternalChoices[Math.Max(0, picker.SelectedIndex)];
            if (chosen.Access == state.InternalNetworks) return;
            state.InternalNetworks = chosen.Access;
            foreach (var row in connections) row.Update(Preview(row.Connection));
            PolicyChanged(PolicyPart.Internal, chosen.Change);
        };
        var label = Ui.Text("INTERNAL NETWORKS", 10, "#A192B4", FontWeights.SemiBold); label.VerticalAlignment = VerticalAlignment.Center; label.Margin = new(24, 0, 10, 0);
        return Ui.Row(label, picker);
    }

    private void AddRuleText(string title, string property, double width)
    {
        var col = Ui.Column(title, property, width, false); ((Binding)col.Binding).UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged; ruleGrid!.Columns.Add(col);
    }

    private const string RouteHeader = "VPN route";
    /// <summary>The program whose VPN route a rule shows: one executable, outbound or either way, not one service of a shared host.</summary>
    private static string? RuleRoute(FirewallRule rule) => RuleRoute(rule.Path, rule.Direction, rule.Service);
    private static string? RuleRoute(string? path, TrafficDirection direction, string? service) =>
        direction == TrafficDirection.Inbound || !RuleValidator.IsAny(service) ? null : VpnState.Routable(path);

    /// <summary>The default route, which names the profile carrying unassigned programs, then each profile.</summary>
    private List<RouteOption> RuleRouteOptions()
    {
        var fallback = state.VpnProfiles.FirstOrDefault(p => p.Id == state.DefaultOutboundVpnProfileId)?.Name ?? "Windows route";
        var options = new List<RouteOption> { new(null, "Default · " + fallback) };
        options.AddRange(state.VpnProfiles.Select(p => new RouteOption(p.Id, p.Name + " · " + p.Kind)));
        return options;
    }
    private RouteOption RouteOf(string program, List<RouteOption> options)
    {
        var profile = state.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(program, StringComparer.OrdinalIgnoreCase))?.Id;
        return options.FirstOrDefault(o => o.ProfileId == profile) ?? options[0];
    }

    /// <summary>
    /// The VPN route of each rule's program. A profile carries a whole executable, so every rule for it shows the same route
    /// and choosing one sets it for all of them. Inbound rules, service rules and rules for any program have none.
    /// </summary>
    private DataGridTemplateColumn RouteColumn(Style picker)
    {
        var options = RuleRouteOptions();
        MultiBinding Route(Func<string?, object?> show)
        {
            var binding = new MultiBinding { Mode = BindingMode.OneWay, Converter = new Computed(v => show(RuleRoute(v[0] as string, v[1] is TrafficDirection d ? d : TrafficDirection.Any, v[2] as string))) };
            foreach (var property in new[] { nameof(FirewallRule.Path), nameof(FirewallRule.Direction), nameof(FirewallRule.Service) }) binding.Bindings.Add(new Binding(property));
            return binding;
        }
        var text = new FrameworkElementFactory(typeof(TextBlock));
        // The cell names the profile alone; the list beside it says which kind each one is.
        text.SetBinding(TextBlock.TextProperty, Route(program => program is null ? "—"
            : state.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(program, StringComparer.OrdinalIgnoreCase))?.Name ?? options[0].Label));
        text.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        var choice = new FrameworkElementFactory(typeof(ComboBox));
        choice.SetValue(StyleProperty, picker);
        choice.SetValue(ItemsControl.ItemsSourceProperty, options);
        choice.SetValue(ItemsControl.DisplayMemberPathProperty, nameof(RouteOption.Label));
        choice.SetBinding(Selector.SelectedItemProperty, Route(program => program is null ? null : RouteOf(program, options)));
        choice.AddHandler(Selector.SelectionChangedEvent, new SelectionChangedEventHandler(RouteChosen));
        return new DataGridTemplateColumn { Header = RouteHeader, Width = 170, CanUserSort = false, CellTemplate = new DataTemplate { VisualTree = text }, CellEditingTemplate = new DataTemplate { VisualTree = choice } };
    }

    /// <summary>Sets the route of the edited rule's program, and shows it on every rule for that program.</summary>
    private void RouteChosen(object sender, SelectionChangedEventArgs e)
    {
        e.Handled = true;
        if (sender is not ComboBox { DataContext: FirewallRule rule, SelectedItem: RouteOption choice } || RuleRoute(rule) is not { } program) return;
        if (choice.ProfileId == state.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(program, StringComparer.OrdinalIgnoreCase))?.Id) return;
        if (choice.ProfileId is { } id) VpnAssignments.Assign(state, id, program); else VpnAssignments.UseDefault(state, program);
        foreach (var other in rules.Where(r => RuleRoute(r) is { } path && path.Equals(program, StringComparison.OrdinalIgnoreCase))) other.Notify(nameof(FirewallRule.Path));
        var name = Path.GetFileName(program);
        VpnRoutesChanged(choice.ProfileId is null ? $"{name} uses the default route again." : $"Every connection {name} makes now goes through {choice.Label}.");
    }

    /// <summary>A converter from a function, for bindings in templates built in code.</summary>
    private sealed class Computed(Func<object?[], object?> compute) : IMultiValueConverter
    {
        public object? Convert(object?[] values, Type targetType, object? parameter, CultureInfo culture) => compute(values);
        public object?[] ConvertBack(object? value, Type[] targetTypes, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }
    private void SaveColumns()
    {
        if (ruleGrid is null || currentPage != "Rules") return;
        ruleGrid.CommitEdit(DataGridEditingUnit.Cell, true); ruleGrid.CommitEdit(DataGridEditingUnit.Row, true);
        state.Columns = ruleGrid.Columns.Select(c => new ColumnPreference { Name = c.Header.ToString()!, Order = c.DisplayIndex, Visible = c.Visibility == Visibility.Visible, Width = c.ActualWidth }).ToList();
        Save(); ruleGrid = null;
    }
    private void ColumnPicker()
    {
        if (ruleGrid is null) return;
        var panel = Ui.Stack(Ui.Text("Visible columns", 21, "#EEE7F6", FontWeights.SemiBold), Ui.Gap());
        foreach (var column in ruleGrid.Columns.OrderBy(c => c.DisplayIndex))
        {
            var check = new CheckBox { Content = column.Header, IsChecked = column.Visibility == Visibility.Visible, Margin = new(0, 7, 0, 7) };
            check.Checked += (_, _) => column.Visibility = Visibility.Visible;
            check.Unchecked += (_, _) => { if (ruleGrid.Columns.Count(c => c.Visibility == Visibility.Visible) <= 1) check.IsChecked = true; else column.Visibility = Visibility.Collapsed; };
            panel.Children.Add(check);
        }
        var window = Dialog("Rule columns", panel, 360); var done = Ui.Button("Done", () => window.Close(), true); done.Margin = new(0, 16, 0, 0); panel.Children.Add(done); window.ShowDialog();
    }
    private void AddRule()
    {
        TextBox name = Ui.Input(""), path = Ui.Input("*"), addresses = Ui.Input("*"), ports = Ui.Input("*");
        var icon = ApplicationIcons.Image(path.Text, 32); icon.Margin = new(0, 0, 13, 0);
        icon.SetBinding(ApplicationIconImage.ExecutablePathProperty, new Binding(nameof(TextBox.Text)) { Source = path });
        var heading = Ui.Row(icon, Ui.Text("New firewall rule", 23, "#EAE3F7", FontWeights.SemiBold));
        var panel = Ui.Stack(heading, Ui.Gap(20));
        var direction = new ComboBox { ItemsSource = new[] { TrafficDirection.Outbound, TrafficDirection.Inbound, TrafficDirection.Any }, SelectedIndex = 0, Margin = new(0, 5, 0, 12) };
        var action = new ComboBox { ItemsSource = Enum.GetValues<RuleAction>(), SelectedIndex = 0, Margin = new(0, 5, 0, 12) };
        var protocol = new ComboBox { ItemsSource = new[] { "Any", "TCP", "UDP", "ICMPv4", "ICMPv6" }, SelectedIndex = 0, Margin = new(0, 5, 0, 12) };
        var routes = RuleRouteOptions();
        var route = new ComboBox { ItemsSource = routes, DisplayMemberPath = nameof(RouteOption.Label), SelectedIndex = 0, Margin = new(0, 5, 0, 12), ToolTip = "A VPN profile carries every connection of the program, not only this rule's." };
        // The route belongs to the program, so naming one shows the route it already has.
        path.TextChanged += (_, _) => route.SelectedItem = VpnState.Routable(path.Text) is { } known ? RouteOf(known, routes) : routes[0];
        panel.Children.Add(Ui.Label("Application name")); panel.Children.Add(name); panel.Children.Add(Ui.Label("Application path"));
        var pathRow = new DockPanel(); var browse = Ui.Button("Browse", () => { var picker = new Microsoft.Win32.OpenFileDialog { Filter = "Applications|*.exe|All files|*.*" }; if (picker.ShowDialog(this) == true) { path.Text = picker.FileName; if (name.Text.Length == 0) name.Text = Path.GetFileNameWithoutExtension(picker.FileName); } }); browse.Margin = new(7, 5, 0, 12); DockPanel.SetDock(browse, Dock.Right); pathRow.Children.Add(browse); pathRow.Children.Add(path); panel.Children.Add(pathRow);
        foreach (var (label, control) in new (string, UIElement)[] { ("Action", action), ("Direction", direction), ("VPN route", route), ("Protocol", protocol), ("Remote addresses", addresses), ("Remote ports", ports) }) { panel.Children.Add(Ui.Label(label)); panel.Children.Add(control); }
        var error = Ui.Text("", 11, "#F2849C"); panel.Children.Add(error); var window = Dialog("New rule", panel);
        panel.Children.Add(Ui.Button("Save rule", () =>
        {
            var rule = new FirewallRule { ApplicationName = name.Text.Trim(), Path = path.Text.Trim(), Action = (RuleAction)action.SelectedItem, Direction = (TrafficDirection)direction.SelectedItem, Protocol = (string)protocol.SelectedItem, RemoteAddresses = addresses.Text.Trim(), RemotePorts = ports.Text.Trim() };
            var errors = RuleValidator.Validate(rule); if (errors.Count > 0) { error.Text = string.Join("\n", errors); return; }
            var picked = (RouteOption)route.SelectedItem; var program = RuleRoute(rule);
            if (picked.ProfileId is not null && program is null) { error.Text = "A VPN route needs one program (.exe) and outbound traffic. svchost.exe can't take one: every service it runs would go along."; return; }
            var before = program is null ? null : state.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(program, StringComparer.OrdinalIgnoreCase))?.Id;
            if (program is not null) { if (picked.ProfileId is { } id) VpnAssignments.Assign(state, id, program); else VpnAssignments.UseDefault(state, program); }
            rules.Add(rule); Save(); window.Close(); Navigate("Rules");
            if (program is null || before == picked.ProfileId) ShowToast("Rule saved. Edit all fields in the table.");
            else VpnRoutesChanged(picked.ProfileId is null ? $"Rule saved. {Path.GetFileName(program)} uses the default route again." : $"Rule saved. {Path.GetFileName(program)} goes through {picked.Label}.");
        }, true)); window.ShowDialog();
    }
    private async Task ImportWindowsRules()
    {
        var imported = await Task.Run(WindowsFirewall.Import);
        // Replace only the previously imported source, retaining user-created policy.
        var retained = rules.Where(r => r.Source != "Windows Firewall").ToList(); rules.Clear(); foreach (var r in retained.Concat(imported.Rules)) rules.Add(r);
        Save(); Navigate("Rules");
        ShowToast($"Imported {imported.Rules.Count:N0} rules: {imported.Rules.Count(r => r.Import == ImportOutcome.Exact):N0} exact, {imported.RestrictedCount:N0} need review, {imported.Rules.Count(r => r.Import == ImportOutcome.Inert):N0} kept disabled."
            + (imported.Errors.Count > 0 ? " Takeover is blocked: " + string.Join(" ", imported.Errors) : ""));
    }
    private void DeleteRule()
    {
        if (ruleGrid?.SelectedItem is not FirewallRule rule) { ShowToast("Select a rule to delete."); return; }
        rules.Remove(rule); Save(); ShowToast("Rule deleted.");
    }
    private void ExportRules()
    {
        var picker = new Microsoft.Win32.SaveFileDialog { Filter = "JSON|*.json", FileName = "darkwire-rules.json" }; if (picker.ShowDialog(this) != true) return;
        File.WriteAllText(picker.FileName, JsonSerializer.Serialize(rules, StateStore.JsonOptions)); ShowToast("Rules exported, including original import restrictions.");
    }
}
