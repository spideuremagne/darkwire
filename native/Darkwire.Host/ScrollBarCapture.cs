using System.Text.Json;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    /// <summary>
    /// Scroll bars page when their empty track is clicked: on the Connections page, at the narrowest window, the table's
    /// horizontal bar pages right from the track beyond its thumb and back from the track before it, repeating while held as
    /// Windows' bars do; and a very long list's thumb stays long enough to grab.
    /// </summary>
    private async Task CaptureScrollBars(string output)
    {
        if (!capture) return;
        var savedPage = currentPage; var savedWidth = Width; var savedHeight = Height;
        var checks = new Dictionary<string, bool>();
        // A scroll viewer carries out a page command on its next layout pass, and reports the new offset on the one after.
        async Task Settle()
        {
            for (var pass = 0; pass < 2; pass++) { UpdateLayout(); await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); }
        }
        static IEnumerable<DependencyObject> Visuals(DependencyObject parent) =>
            Enumerable.Range(0, VisualTreeHelper.GetChildrenCount(parent)).Select(i => VisualTreeHelper.GetChild(parent, i)).SelectMany(child => Visuals(child).Prepend(child));
        // As a click on the track does: the automation peer raises the button's click, which sends its command.
        static void Click(RepeatButton button) => ((IInvokeProvider)new RepeatButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)!).Invoke();
        try
        {
            Width = MinWidth; Height = MinHeight;
            Navigate("Connections"); await Settle();
            Visuals(this).OfType<CheckBox>().Single(box => Equals(box.Content, "All columns")).IsChecked = true;
            await Settle();
            var table = Visuals(this).OfType<DataGrid>().First();
            var viewer = Visuals(table).OfType<ScrollViewer>().First();
            var bar = Visuals(viewer).OfType<ScrollBar>().First(b => b.Orientation == Orientation.Horizontal);
            var track = bar.Template?.FindName("PART_Track", bar) as Track ?? throw new InvalidOperationException("The table's horizontal scroll bar has no track.");
            if (track.DecreaseRepeatButton is not { } back || track.IncreaseRepeatButton is not { } forward)
                throw new InvalidOperationException("The scroll bar's track has no page buttons.");
            checks["trackPagesBothWays"] = back.Command == ScrollBar.PageLeftCommand && forward.Command == ScrollBar.PageRightCommand;
            checks["trackRepeatsWhileHeld"] = forward is { Delay: 200, Interval: 50 } && back is { Delay: 200, Interval: 50 };
            checks["tableOverflowsSideways"] = bar.Visibility == Visibility.Visible && viewer.ScrollableWidth > 0;
            viewer.ScrollToHorizontalOffset(0); await Settle();
            Click(forward); await Settle();
            var paged = viewer.HorizontalOffset;
            checks["trackClickPagesForward"] = paged > 0;
            Click(back); await Settle();
            checks["trackClickPagesBack"] = viewer.HorizontalOffset < paged;

            // A list a hundred thousand times longer than it shows would make a sliver of a thumb.
            var probe = new ScrollBar { Orientation = Orientation.Vertical, Height = 300, Minimum = 0, Maximum = 100_000, ViewportSize = 1, HorizontalAlignment = HorizontalAlignment.Left };
            PageContent.Content = new Grid { Children = { probe } }; await Settle();
            checks["longListThumbStaysGrabbable"] = ((Track)probe.Template.FindName("PART_Track", probe)).Thumb.ActualHeight >= 24;

            File.WriteAllText(Path.Combine(output, "scrollbar-check.json"), JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
            if (checks.Values.Any(passed => !passed))
                throw new InvalidOperationException("Scroll bar capture failed: " + string.Join(", ", checks.Where(check => !check.Value).Select(check => check.Key)));
        }
        finally
        {
            Width = savedWidth; Height = savedHeight;
            Navigate(savedPage); await Settle();
        }
    }
}
