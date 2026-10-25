using System.ComponentModel;
using Microsoft.Win32;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    private void InitializeAppearance()
    {
        AppearancePreferences.Normalize(state);
        ApplyAppearancePreferences(false);
        SystemEvents.UserPreferenceChanged += SystemAppearanceChanged;
        SystemParameters.StaticPropertyChanged += SystemMotionChanged;
        Closed += (_, _) =>
        {
            SystemEvents.UserPreferenceChanged -= SystemAppearanceChanged;
            SystemParameters.StaticPropertyChanged -= SystemMotionChanged;
        };
    }
    private void SystemAppearanceChanged(object sender, UserPreferenceChangedEventArgs e) => QueueAppearanceRefresh();
    private void SystemMotionChanged(object? sender, PropertyChangedEventArgs e) => QueueAppearanceRefresh();
    private bool appearanceRefreshQueued;
    private void QueueAppearanceRefresh()
    {
        if (Dispatcher.HasShutdownStarted) return;
        Dispatcher.BeginInvoke(() =>
        {
            if (appearanceRefreshQueued || quitting) return;
            appearanceRefreshQueued = true;
            Dispatcher.BeginInvoke(() => { appearanceRefreshQueued = false; if (!quitting) ApplyAppearancePreferences(false); }, DispatcherPriority.Background);
        });
    }
    private void ApplyAppearancePreferences(bool rebuildPage = true)
    {
        AppearancePreferences.Normalize(state);
        AppearanceTheme.Apply(state.AppAppearance);
        // Refresh existing scenes too: following Windows changes the open atlas and any location dialog in place.
        foreach (Window window in Application.Current.Windows)
            foreach (var visual in AtlasVisuals(window))
                if (visual is GlobeView globe) globe.RefreshAppearance();
                else if (visual is AtlasBackground environment) environment.RefreshAppearance();
        var top = state.NavigationPlacement == "Top";
        NavigationColumn.Width = new(top ? 0 : 202);
        NavigationRow.Height = top ? GridLength.Auto : new(0);
        Grid.SetRow(NavigationShell, top ? 0 : 1);
        Grid.SetColumn(NavigationShell, 0); Grid.SetColumnSpan(NavigationShell, top ? 2 : 1);
        NavigationShell.BorderThickness = top ? new(0, 0, 0, 1) : new(0, 0, 1, 0);
        NavigationLayout.LastChildFill = !top;
        NavigationLayout.Margin = top ? new(18, 5, 18, 5) : new(13, 25, 13, 18);
        DeviceSection.Visibility = top ? Visibility.Collapsed : Visibility.Visible;
        AuthorityCard.Visibility = top ? Visibility.Collapsed : Visibility.Visible;
        VersionLabel.Visibility = top ? Visibility.Collapsed : Visibility.Visible;
        PolicyNavHeading.Visibility = top ? Visibility.Collapsed : Visibility.Visible;
        DockPanel.SetDock(NavigationFooter, top ? Dock.Right : Dock.Bottom);
        Navigation.Orientation = top ? Orientation.Horizontal : Orientation.Vertical;
        foreach (var button in Navigation.Children.OfType<Button>().Append(SettingsNavigation))
        {
            button.Padding = top ? new(10, 10, 10, 10) : new(13, 12, 13, 12);
            button.Margin = top ? new(2, 0, 2, 0) : new(0, 3, 0, 3);
            button.FontSize = top ? 12 : 13;
            if (button.Content is StackPanel row && row.Children[0] is TextBlock glyph) glyph.Visibility = top ? Visibility.Collapsed : Visibility.Visible;
        }
        RefreshNavigationSelection();
        UpdateAtlasMotion();
        foreach (var card in vpnCards.Values)
        {
            card.Received.Color = AppearanceTheme.Token("Green").Color; card.Sent.Color = AppearanceTheme.Token("Accent").Color;
            card.Received.InvalidateVisual(); card.Sent.InvalidateVisual();
        }
        if (rebuildPage && IsLoaded)
        {
            ruleGrid?.CommitEdit(DataGridEditingUnit.Cell, true); ruleGrid?.CommitEdit(DataGridEditingUnit.Row, true);
            Navigate(currentPage);
        }
    }
    private void RefreshNavigationSelection()
    {
        foreach (var button in Navigation.Children.OfType<Button>().Append(SettingsNavigation))
        {
            var selected = (string)button.Tag == currentPage;
            button.Background = selected ? AppearanceTheme.Token("Selected") : Brushes.Transparent;
            button.Foreground = AppearanceTheme.Token(selected ? "Text" : "Muted");
            button.BorderBrush = selected ? AppearanceTheme.Token("Accent") : Brushes.Transparent;
            button.BorderThickness = state.NavigationPlacement == "Top" ? new(0, 0, 0, selected ? 2 : 0) : new(selected ? 2 : 0, 0, 0, 0);
            System.Windows.Automation.AutomationProperties.SetItemStatus(button, selected ? "Selected" : "");
        }
    }

    private static IEnumerable<DependencyObject> AtlasVisuals(DependencyObject parent)
    {
        yield return parent;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            foreach (var child in AtlasVisuals(VisualTreeHelper.GetChild(parent, i))) yield return child;
    }
}
