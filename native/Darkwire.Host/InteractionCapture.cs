using System.Text.Json;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Darkwire.Host;

/// <summary>
/// Captures checks of how the window behaves rather than looks: a page built again after a change keeps its scroll while a
/// sidebar click starts it at the top; the map's legend follows whether the service answers; a connection request's
/// notification goes the moment Allow is clicked and shows a full bar of time to decide; and the status shield is drawn
/// mirror-true, its exclamation mark upright and centered.
/// </summary>
public partial class MainWindow
{
    private async Task CaptureInteractions(string output)
    {
        var checks = new Dictionary<string, bool>();
        async Task Settle() { await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); UpdateLayout(); }

        // Settings is long: scrolled down, a change that builds it again keeps the place, and the sidebar starts it afresh.
        Navigate("Settings", keepScroll: false); await Settle();
        if (PageScrollers((DependencyObject)PageContent.Content).FirstOrDefault() is not { } scroller) throw new InvalidOperationException("Settings has no scroll viewer.");
        var target = Math.Min(300, scroller.ScrollableHeight);
        scroller.ScrollToVerticalOffset(target); await Settle();
        Navigate("Settings"); await Settle();
        checks["changeKeepsScroll"] = target > 0 && PageScrollers((DependencyObject)PageContent.Content).FirstOrDefault() is { } rebuilt && Math.Abs(rebuilt.VerticalOffset - target) < .5;
        Navigate("Settings", keepScroll: false); await Settle();
        checks["sidebarStartsAtTop"] = PageScrollers((DependencyObject)PageContent.Content).FirstOrDefault() is { VerticalOffset: 0 };

        // The map's legend and note follow whose red its arcs show: the service's refusals, or the editor's preview while the
        // window has not heard from the service, as after restarting into an update; and back once it answers.
        Navigate("Map", keepScroll: false); await Settle();
        string[] Texts() => [.. Tree((DependencyObject)PageContent.Content).OfType<TextBlock>().Select(t => t.Text)];
        var refusals = Texts() is var before && before.Contains("●  Blocked") && !before.Contains("●  Would be blocked") && before.Any(t => t.Contains("refused lately", StringComparison.Ordinal));
        previewOnly = true; followMapService?.Invoke(); await Settle();
        var preview = Texts() is var during && during.Contains("●  Would be blocked") && !during.Contains("●  Blocked") && during.Any(t => t.Contains("would deny", StringComparison.Ordinal));
        previewOnly = false; followMapService?.Invoke(); await Settle();
        checks["mapLegendFollowsService"] = refusals && preview && Texts() is var after && after.Contains("●  Blocked") && after.Any(t => t.Contains("refused lately", StringComparison.Ordinal));

        // Allow closes the notification at once, whatever the service then takes; the bar of time left starts full.
        static IEnumerable<DependencyObject> Tree(DependencyObject parent) => LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>().SelectMany(child => Tree(child).Prepend(child));
        var connection = new Connection("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 4242, "203.0.113.42", 443, 52914, "TCP", TrafficDirection.Outbound, LocalAddress: "192.0.2.10");
        var prompt = ShowLearningRequest(new LearningRequest(Guid.NewGuid(), connection, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(60), 1), state);
        await Settle(); prompt.UpdateLayout();
        var track = Tree(prompt).OfType<Border>().FirstOrDefault(b => System.Windows.Automation.AutomationProperties.GetName(b) == "Time left to decide");
        checks["countdownBarStartsFull"] = track is { ActualWidth: > 100, Child: Border { RenderTransform: ScaleTransform { ScaleX: 1 } } bar } && bar.ActualWidth >= track.ActualWidth - 1;
        var closed = false; prompt.Closed += (_, _) => closed = true;
        var allow = Tree(prompt).OfType<Button>().First(b => b.Content as string == "Allow");
        var decisions = new[] { allow, Tree(prompt).OfType<Button>().First(b => b.Content as string == "Block"), Tree(prompt).OfType<Button>().First(b => b.Content as string == "Dismiss") };
        var positions = decisions.Select(button => button.TranslatePoint(new Point(), prompt).X).ToArray();
        checks["decisionButtonsHaveRoom"] = decisions.All(button => button.ActualWidth >= 100 && button.ActualHeight >= 44);
        // Equal star columns can differ by one physical pixel when their shared width is not divisible by three.
        var pixel = 1 / VisualTreeHelper.GetDpi(prompt).DpiScaleX + .01;
        checks["decisionButtonsEvenlySpaced"] = decisions.All(button => Math.Abs(button.ActualWidth - allow.ActualWidth) <= pixel)
            && Math.Abs(positions[1] - positions[0] - decisions[0].ActualWidth - 10) < 1
            && Math.Abs(positions[2] - positions[1] - decisions[1].ActualWidth - 10) < 1;
        File.WriteAllText(Path.Combine(output, "notification-layout.json"), JsonSerializer.Serialize(new
        {
            widths = decisions.Select(button => button.ActualWidth).ToArray(),
            heights = decisions.Select(button => button.ActualHeight).ToArray(),
            gaps = new[] { positions[1] - positions[0] - decisions[0].ActualWidth, positions[2] - positions[1] - decisions[1].ActualWidth }
        }, new JsonSerializerOptions { WriteIndented = true }));
        ((IInvokeProvider)new ButtonAutomationPeer(allow).GetPattern(PatternInterface.Invoke)!).Invoke();
        // Invoke raises the click once input settles; nothing but the click may come between it and the notification closing.
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Input);
        checks["allowClosesAtOnce"] = closed;
        if (!closed) prompt.Close();

        // The shield's pixels mirror about its middle in every state but the check mark's: the marks, around the middle,
        // exactly; the outline's smoothed edge within the shade WPF's anti-aliasing leans right by, under a fifth of a pixel,
        // where a mark or outline half a pixel off center, as the exclamation mark was, would differ by half a pixel's worth.
        foreach (var shown in new[] { ShieldState.Unknown, ShieldState.Starting, ShieldState.Inactive })
        {
            var shield = new StatusShield { Pulse = false, State = shown };
            shield.Measure(new(24, 24)); shield.Arrange(new(0, 0, 24, 24)); shield.UpdateLayout();
            var bitmap = new RenderTargetBitmap(24, 24, 96, 96, PixelFormats.Pbgra32); bitmap.Render(shield);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (var file = File.Create(Path.Combine(output, $"Shield-24-{shown}.png"))) encoder.Save(file);
            var pixels = new byte[24 * 24 * 4]; bitmap.CopyPixels(pixels, 24 * 4, 0);
            var mirrored = true;
            for (var y = 0; y < 24; y++)
                for (var x = 0; x < 12; x++)
                    for (var channel = 0; channel < 4; channel++)
                    {
                        var difference = Math.Abs(pixels[(y * 24 + x) * 4 + channel] - pixels[(y * 24 + 23 - x) * 4 + channel]);
                        if (difference > (x >= 7 && y is >= 5 and <= 18 ? 2 : 40)) mirrored = false;
                    }
            checks["shieldMirrored" + shown] = mirrored;
        }

        File.WriteAllText(Path.Combine(output, "interaction-check.json"), JsonSerializer.Serialize(checks, new JsonSerializerOptions { WriteIndented = true }));
        if (checks.Values.Any(passed => !passed))
            throw new InvalidOperationException("Interaction capture failed: " + string.Join(", ", checks.Where(check => !check.Value).Select(check => check.Key)));
    }
}
