using System.Text.Json;
using System.Windows.Automation;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    /// <summary>Exercises the appearance matrix with a private demo-state copy, never the user's settings file.</summary>
    private async Task CaptureAppearanceViews(string output)
    {
        if (!capture || !demo) return;
        toastTimer.Stop(); Toast.Visibility = Visibility.Collapsed;
        var savedState = state;
        var savedPage = currentPage;
        var savedSize = (Width, Height, Left, Top, WindowState);
        var savedScroll = PageContent.Content is DependencyObject shown ? PageScrollers(shown).Select(v => (v.HorizontalOffset, v.VerticalOffset)).ToList() : [];
        var checks = new Dictionary<string, bool>();
        var layoutProblems = new Dictionary<string, string[]>();
        var frames = new List<string>();
        state = JsonSerializer.Deserialize<AppState>(JsonSerializer.Serialize(savedState, StateStore.JsonOptions), StateStore.JsonOptions)!;

        async Task Settle()
        {
            UpdateLayout();
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            // Shell icon extraction is asynchronous; the captures should include the finished icon, not its placeholder.
            await Task.Delay(300);
            UpdateLayout();
            foreach (var globe in AppearanceVisualTree(PageContent).OfType<GlobeView>())
            {
                globe.Animate = false;
                globe.SampleAt(2.4);
                await globe.DetailSettled();
            }
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
            UpdateLayout();
        }
        void Screenshot(string name)
        {
            var filename = name + ".png";
            var bitmap = new RenderTargetBitmap((int)Math.Round(ActualWidth), (int)Math.Round(ActualHeight), 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(this);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (var file = File.Create(Path.Combine(output, filename))) encoder.Save(file);
            frames.Add(filename);
        }
        static byte[] ScenePixels(FrameworkElement scene)
        {
            var width = (int)Math.Ceiling(scene.ActualWidth); var height = (int)Math.Ceiling(scene.ActualHeight);
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(scene);
            var pixels = new byte[width * height * 4]; bitmap.CopyPixels(pixels, width * 4, 0); return pixels;
        }
        static bool MeaningfullyLighter(byte[] dark, byte[] light)
        {
            if (dark.Length == 0 || dark.Length != light.Length) return false;
            var changed = 0; double gain = 0;
            for (var index = 0; index < dark.Length; index += 4)
            {
                // BGRA luminance comparison ignores alpha; a control border alone cannot pass this whole-scene check.
                var before = .0722 * dark[index] + .7152 * dark[index + 1] + .2126 * dark[index + 2];
                var after = .0722 * light[index] + .7152 * light[index + 1] + .2126 * light[index + 2];
                gain += after - before; if (after - before > 20) changed++;
            }
            var count = dark.Length / 4;
            return gain / count > 20 && changed > count * .15;
        }
        Rect Bounds(FrameworkElement element) => element.TransformToAncestor(this).TransformBounds(new Rect(element.RenderSize));
        static bool Finite(Rect rectangle) => double.IsFinite(rectangle.X) && double.IsFinite(rectangle.Y) &&
            double.IsFinite(rectangle.Width) && double.IsFinite(rectangle.Height) && rectangle.Width > 0 && rectangle.Height > 0;
        static bool Within(Rect outer, Rect inner)
        {
            outer.Inflate(1.5, 1.5);
            return Finite(inner) && outer.Contains(inner);
        }
        static bool HasAncestor<T>(DependencyObject item) where T : DependencyObject
        {
            for (var parent = VisualTreeHelper.GetParent(item); parent is not null; parent = VisualTreeHelper.GetParent(parent))
                if (parent is T) return true;
            return false;
        }
        void CheckLayout(string name, double expectedWidth, double expectedHeight)
        {
            var problems = new List<string>();
            var window = new Rect(0, 0, ActualWidth, ActualHeight);
            var page = Bounds(PageContent); var nav = Bounds(NavigationShell);
            checks[name + ".windowSize"] = Math.Abs(ActualWidth - expectedWidth) < 2 && Math.Abs(ActualHeight - expectedHeight) < 2;
            checks[name + ".palette"] = AppearanceTheme.IsLight == (state.AppAppearance == "Light") &&
                ((SolidColorBrush)FindResource("Background")).Color == (SystemParameters.HighContrast ? SystemColors.WindowColor :
                    (Color)ColorConverter.ConvertFromString(state.AppAppearance == "Light" ? "#EDF2F5" : "#090D14"));
            checks[name + ".navigationPlacement"] = state.NavigationPlacement == "Top"
                ? Grid.GetRow(NavigationShell) == 0 && Grid.GetColumnSpan(NavigationShell) == 2 && NavigationColumn.ActualWidth < 1 && nav.Bottom <= page.Top
                : Grid.GetRow(NavigationShell) == 1 && Grid.GetColumnSpan(NavigationShell) == 1 && Math.Abs(NavigationColumn.ActualWidth - 202) < 1 && nav.Right <= page.Left;
            foreach (var element in new FrameworkElement[] { PageContent, PageEyebrow, PageTitle, PageDescription, SourceLabel, NavigationShell, FooterStatus, RenderStatus })
                if (!Within(window, Bounds(element))) problems.Add("Outside window: " + element.Name);
            var title = Bounds(PageTitle); var description = Bounds(PageDescription);
            if (title.Bottom > description.Top + 1 || description.Bottom > page.Top + 1) problems.Add("Header overlaps page content");
            foreach (var button in Navigation.Children.OfType<Button>().Append(SettingsNavigation))
            {
                if (!Within(nav, Bounds(button))) problems.Add("Navigation button clipped: " + button.Tag);
                foreach (var label in AppearanceVisualTree(button).OfType<TextBlock>().Where(t => t.IsVisible))
                    if (!Within(Bounds(button), Bounds(label))) problems.Add("Navigation label clipped: " + button.Tag);
            }
            var navigationButtons = Navigation.Children.OfType<Button>().Append(SettingsNavigation).Where(b => b.IsVisible).Select(Bounds).ToArray();
            for (var first = 0; first < navigationButtons.Length; first++)
                for (var second = first + 1; second < navigationButtons.Length; second++)
                {
                    var intersection = Rect.Intersect(navigationButtons[first], navigationButtons[second]);
                    if (!intersection.IsEmpty && intersection.Width > 1 && intersection.Height > 1) problems.Add("Navigation buttons overlap");
                }
            if (PageContent.Content is FrameworkElement root && !Within(page, Bounds(root))) problems.Add("Page root exceeds viewport");
            // Scrolling is intentional in settings and tables. Check the non-scrolling page controls and every control's
            // horizontal extent; table cells have their own horizontal scroll and clipping contract.
            foreach (var control in AppearanceVisualTree(PageContent).OfType<Control>().Where(c =>
                c.IsVisible && c is Button or ComboBox or TextBox or CheckBox && !HasAncestor<DataGrid>(c)))
            {
                if (control.ActualWidth <= 0 || control.ActualHeight <= 0) continue;
                var box = Bounds(control);
                var label = AutomationProperties.GetName(control);
                if (label.Length == 0) label = control is ContentControl content ? content.Content?.ToString() ?? control.GetType().Name : control.GetType().Name;
                if (box.Left < page.Left - 2 || box.Right > page.Right + 2) problems.Add("Control clipped horizontally: " + label);
                if (!HasAncestor<ScrollViewer>(control) && (box.Top < page.Top - 2 || box.Bottom > page.Bottom + 2))
                    problems.Add("Control clipped vertically: " + label);
            }
            checks[name + ".pageHeaderAndNavigationFit"] = problems.Count == 0;
            if (problems.Count > 0) layoutProblems[name] = problems.Distinct().ToArray();
        }

        try
        {
            WindowState = WindowState.Normal;
            state.MapProjection = "Flat"; state.MapProjectionChosen = true; state.ReducedMotion = true;
            state.SpaceSunMoon = false; state.SpaceUfos = false;
            AppearancePreferences.ApplyEffectPreset(state, "Balanced");
            foreach (var (width, height, suffix) in new[] { (1480d, 940d, ""), (1120d, 760d, "-Compact") })
            {
                Width = width; Height = height;
                foreach (var palette in new[] { "Dark", "Light" })
                    foreach (var navigation in new[] { "Left", "Top" })
                    {
                        state.AppAppearance = palette; state.NavigationPlacement = navigation;
                        state.Theme = palette == "Light" ? "Glacier" : "Amethyst";
                        ApplyAppearancePreferences(false);
                        foreach (var page in new[] { "Overview", "Connections", "Rules", "VPN", "Blocklists", "Regions", "Settings", "Map", "Observatory" })
                        {
                            state.AtlasPresentation = page == "Observatory" ? "Observatory" : "Standard";
                            state.MapProjection = page == "Observatory" ? "Globe" : "Flat";
                            Navigate(page == "Observatory" ? "Map" : page, keepScroll: false);
                            await Settle();
                            var name = $"Appearance-{palette}-{navigation}-{page}{suffix}";
                            Screenshot(name); CheckLayout(name, width, height);
                            if (page == "Settings" && suffix.Length == 0 && PageContent.Content is ScrollViewer scroll)
                            {
                                scroll.ScrollToVerticalOffset(350); await Settle(); Screenshot(name + "-Motion");
                            }
                        }
                    }
            }

            Width = 1480; Height = 940;
            state.NavigationPlacement = "Left"; state.Theme = "Classic"; state.MapProjection = "Flat";
            foreach (var palette in new[] { "Dark", "Light" })
                foreach (var page in new[] { "Overview", "Observatory" })
                {
                    state.AppAppearance = palette; state.AtlasPresentation = page == "Observatory" ? "Observatory" : "Standard";
                    ApplyAppearancePreferences(false); Navigate(page == "Observatory" ? "Map" : page, keepScroll: false); await Settle();
                    var name = $"Appearance-{palette}-Left-{page}-Classic-Flat";
                    Screenshot(name); CheckLayout(name, 1480, 940);
                }
            state.AppAppearance = "Dark"; state.NavigationPlacement = "Left"; state.AtlasPresentation = "Standard";
            state.Theme = "Amethyst"; state.ReducedMotion = false; ApplyAppearancePreferences(false); Navigate("Settings", keepScroll: false); await Settle();
            T Named<T>(string name) where T : DependencyObject => AppearanceVisualTree(PageContent).OfType<T>().First(e => AutomationProperties.GetName(e) == name);
            var particles = Named<CheckBox>("Route particles");
            particles.IsChecked = false;
            checks["settings.routeSwitchUpdatesModel"] = !state.RouteParticles && state.MapEffectPreset == "Custom";
            particles.IsChecked = true;
            checks["settings.routeSwitchRestoresModel"] = state.RouteParticles;
            Named<Button>("Focus motion preset").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            checks["settings.focusPreset"] = state.MapEffectPreset == "Focus" && !state.RouteParticles && !state.EndpointRipples && !state.PolicyShockwaves && !state.AmbientParticles && !state.AtmosphereGlow && !state.AutoRotateGlobe;
            Named<Button>("Cinematic motion preset").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            checks["settings.cinematicPreset"] = state.MapEffectPreset == "Cinematic" && state.RouteParticles && state.EndpointRipples && state.PolicyShockwaves && state.AmbientParticles && state.AtmosphereGlow && state.AutoRotateGlobe;
            Named<Slider>("Map effect intensity").Value = 73;
            Named<CheckBox>("Reduce motion").IsChecked = true;
            checks["settings.intensityAndMotion"] = state.EffectIntensity == 73 && state.MapEffectPreset == "Custom" && state.ReducedMotion;
            void Choose(string name, string value)
            {
                var picker = Named<ComboBox>(name);
                picker.SelectedItem = picker.Items.OfType<AppearanceChoice>().Single(choice => choice.Value == value);
            }
            Choose("App appearance", "Light"); await Settle();
            checks["settings.appearancePickerAppliesTheme"] = state.AppAppearance == "Light" && AppearanceTheme.IsLight;
            Choose("Navigation placement", "Top"); await Settle();
            checks["settings.navigationPickerMovesNavigation"] = state.NavigationPlacement == "Top" && Grid.GetRow(NavigationShell) == 0 && NavigationColumn.ActualWidth < 1;
            Choose("Connection map layout", "Observatory"); await Settle();
            checks["settings.presentationPickerAppliesLayout"] = state.AtlasPresentation == "Observatory";
            Choose("Map palette", "Verdant"); await Settle();
            checks["settings.mapPalettePickerUpdatesPreview"] = state.Theme == "Verdant" && AppearanceVisualTree(PageContent).OfType<GlobeView>().Single().Theme == "Verdant";
            var preview = AppearanceVisualTree(PageContent).OfType<GlobeView>().Single();
            checks["settings.previewHonorsReducedMotion"] = !preview.Animate;
            Named<Button>("Balanced motion preset").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            checks["settings.presetPreservesReducedMotion"] = state.ReducedMotion && !preview.Animate && state.MapEffectPreset == "Balanced" && !state.AutoRotateGlobe;
            // The wheel over the sample scrolls the page past it, as the input system routes it: tunnelling, then bubbling.
            checks["settings.previewWheelScrollsPage"] = false;
            if (PageContent.Content is ScrollViewer settingsPage)
            {
                settingsPage.ScrollToVerticalOffset(0); await Settle();
                var wheel = new MouseWheelEventArgs(Mouse.PrimaryDevice, Environment.TickCount, -120) { RoutedEvent = UIElement.PreviewMouseWheelEvent };
                preview.RaiseEvent(wheel); wheel.RoutedEvent = UIElement.MouseWheelEvent; preview.RaiseEvent(wheel); await Settle();
                checks["settings.previewWheelScrollsPage"] = settingsPage.VerticalOffset > 0;
            }
            Named<Slider>("Map effect intensity").Value = 73;
            await Task.Delay(300);
            var persistencePath = Path.Combine(output, "appearance-preferences-roundtrip.json");
            StateStore.Write(persistencePath, state); var roundtrip = StateStore.Read(persistencePath);
            checks["settings.preferencesRoundtrip"] = roundtrip.AppAppearance == state.AppAppearance && roundtrip.NavigationPlacement == state.NavigationPlacement &&
                roundtrip.AtlasPresentation == state.AtlasPresentation && roundtrip.MapEffectPreset == state.MapEffectPreset && roundtrip.EffectIntensity == 73 && roundtrip.ReducedMotion &&
                roundtrip.RouteParticles == state.RouteParticles && roundtrip.EndpointRipples == state.EndpointRipples && roundtrip.PolicyShockwaves == state.PolicyShockwaves &&
                roundtrip.AmbientParticles == state.AmbientParticles && roundtrip.AtmosphereGlow == state.AtmosphereGlow && roundtrip.AutoRotateGlobe == state.AutoRotateGlobe;
            Navigate("Overview", keepScroll: false); await Settle();
            checks["settings.previewDetachedAfterNavigation"] = !preview.IsLoaded && !preview.IsVisible;

            Navigate("Connections", keepScroll: false); await Settle();
            var selected = AppearanceVisualTree(PageContent).OfType<DataGrid>().First().SelectedItem as ConnectionRow;
            checks["connections.initialSelection"] = selected is not null;
            if (selected is not null)
            {
                TextBlock? InspectorValue(string property) => AppearanceVisualTree(PageContent).OfType<TextBlock>().FirstOrDefault(text =>
                    BindingOperations.GetBinding(text, TextBlock.TextProperty) is { } binding &&
                    ReferenceEquals(binding.Source, selected) && binding.Path?.Path == property);
                var destination = InspectorValue(nameof(ConnectionRow.Destination));
                var decision = InspectorValue(nameof(ConnectionRow.Decision));
                var reason = InspectorValue(nameof(ConnectionRow.Reason));
                var route = InspectorValue(nameof(ConnectionRow.Route));
                checks["connections.inspectorInitiallyPopulated"] = destination is { IsVisible: true } && destination.Text == selected.Destination &&
                    decision?.Text == selected.Decision && reason?.Text == selected.Reason && route?.Text == selected.Route;
                checks["connections.inspectorUsesLiveBindings"] = destination is not null && decision is not null && reason is not null && route is not null;
                var restoredDecision = Preview(selected.Connection); var restoredRoute = selected.Route;
                try
                {
                    selected.Update(new(DecisionKind.Deny, "Appearance capture policy preview")); selected.SetRoute("Appearance capture route");
                    await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.DataBind);
                    checks["connections.inspectorUpdatesWithoutReselection"] = decision?.Text == "Deny" && reason?.Text == "Appearance capture policy preview" && route?.Text == "Appearance capture route";
                }
                finally { selected.Update(restoredDecision); selected.SetRoute(restoredRoute); }
            }

            // A system-theme event refreshes the scene in place. Keep its map palette and camera instead of navigating
            // to a new page, so a shell-only recolor cannot hide stale geography or a dark preview background.
            state.NavigationPlacement = "Left"; state.Theme = "Amethyst"; state.ReducedMotion = true;
            foreach (var (page, presentation, projection, label) in new[]
            {
                ("Overview", "Standard", "Flat", "Overview-Flat"), ("Overview", "Standard", "Globe", "Overview-Globe"),
                ("Map", "Standard", "Flat", "Map-Flat"), ("Map", "Standard", "Globe", "Map-Globe"),
                ("Map", "Observatory", "Flat", "Observatory-Flat"), ("Map", "Observatory", "Globe", "Observatory-Globe"),
                ("Settings", "Standard", "Globe", "Settings-Preview")
            })
            {
                state.AtlasPresentation = presentation; state.MapProjection = projection; state.AppAppearance = "Dark";
                ApplyAppearancePreferences(false); Navigate(page, keepScroll: false); await Settle();
                var existing = AppearanceVisualTree(PageContent).OfType<GlobeView>().Single();
                var scene = (FrameworkElement)existing.Parent;
                // Retain the direct brush references used by legacy helpers. WPF also seals brushes in styles,
                // so this must exercise a sealed setter rather than merely look up fresh resources after switching.
                var retainedText = page == "Overview" ? Ui.Text("Live appearance probe") : null;
                var retainedCard = retainedText is null ? null : Ui.Card(retainedText);
                var textBrush = AppearanceTheme.Token("Text"); var panelBrush = AppearanceTheme.Token("Panel");
                var overviewCount = page == "Overview" ? connectionCount : null;
                var overviewCards = page == "Overview" ? AppearanceVisualTree(PageContent).OfType<Border>()
                    .Where(card => ReferenceEquals(card.Background, panelBrush)).ToArray() : [];
                TextBlock? styledText = null;
                if (retainedText is not null)
                {
                    var style = new Style(typeof(TextBlock));
                    style.Setters.Add(new Setter(TextBlock.ForegroundProperty, textBrush)); style.Seal();
                    styledText = new TextBlock { Style = style, Text = "Sealed appearance probe" };
                    checks["liveAppearance." + label + ".retainedControlsStartDark"] =
                        textBrush.Color == (SystemParameters.HighContrast ? SystemColors.WindowTextColor : (Color)ColorConverter.ConvertFromString("#EDF2FA")) &&
                        panelBrush.Color == (SystemParameters.HighContrast ? SystemColors.WindowColor : (Color)ColorConverter.ConvertFromString("#101620"));
                }
                var darkPixels = ScenePixels(scene); Screenshot("Appearance-Live-" + label + "-Dark");
                state.AppAppearance = "Light"; ApplyAppearancePreferences(false); await Settle();
                checks["liveAppearance." + label + ".keepsScene"] = ReferenceEquals(existing, AppearanceVisualTree(PageContent).OfType<GlobeView>().Single()) && existing.Projection == projection;
                checks["liveAppearance." + label + ".keepsMapPalette"] = state.Theme == "Amethyst" && existing.Theme == "Amethyst";
                checks["liveAppearance." + label + ".atlasBecomesLight"] = MeaningfullyLighter(darkPixels, ScenePixels(scene));
                if (retainedText is not null)
                {
                    var lightText = SystemParameters.HighContrast ? SystemColors.WindowTextColor : (Color)ColorConverter.ConvertFromString("#192C3B");
                    var lightPanel = SystemParameters.HighContrast ? SystemColors.WindowColor : (Color)ColorConverter.ConvertFromString("#FFFFFF");
                    checks["liveAppearance." + label + ".retainedBrushesStayMutable"] =
                        !textBrush.CanFreeze && !textBrush.IsFrozen && !panelBrush.CanFreeze && !panelBrush.IsFrozen &&
                        ReferenceEquals(textBrush, AppearanceTheme.Token("Text")) && ReferenceEquals(panelBrush, AppearanceTheme.Token("Panel"));
                    checks["liveAppearance." + label + ".retainedControlsRecolor"] =
                        ReferenceEquals(retainedText.Foreground, textBrush) && textBrush.Color == lightText &&
                        ReferenceEquals(retainedCard!.Background, panelBrush) && panelBrush.Color == lightPanel &&
                        styledText!.Foreground is SolidColorBrush styledBrush && styledBrush.Color == lightText && !styledBrush.CanFreeze;
                    checks["liveAppearance." + label + ".overviewMetricsRecolor"] =
                        overviewCount is not null && ReferenceEquals(overviewCount, connectionCount) &&
                        overviewCount.Foreground is SolidColorBrush countBrush && countBrush.Color == lightText;
                    checks["liveAppearance." + label + ".overviewCardsRecolor"] = overviewCards.Length > 0 && overviewCards.All(card =>
                        card.IsVisible && ReferenceEquals(card.Background, panelBrush) && ((SolidColorBrush)card.Background).Color == lightPanel);
                }
                Screenshot("Appearance-Live-" + label + "-Light");
            }

            foreach (var palette in new[] { "Dark", "Light" })
            {
                state.AppAppearance = palette; ApplyAppearancePreferences(false);
                var requestId = Guid.NewGuid(); var previousPromptRequest = learningPromptRequest;
                var connection = new Connection("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 4242,
                    "203.0.113.42", 443, 52914, "TCP", TrafficDirection.Outbound, Hostname: "example.com", LocalAddress: "192.0.2.10");
                var notification = ShowLearningRequest(new LearningRequest(requestId, connection, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(60), 1), state);
                try
                {
                    await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); await Task.Delay(300); notification.UpdateLayout();
                    var content = (FrameworkElement)notification.Content;
                    var area = new Rect(0, 0, Math.Ceiling(content.ActualWidth), Math.Ceiling(content.ActualHeight));
                    var visual = new DrawingVisual();
                    using (var drawing = visual.RenderOpen()) drawing.DrawRectangle(new VisualBrush(content) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top }, null, area);
                    var bitmap = new RenderTargetBitmap((int)area.Width, (int)area.Height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual);
                    var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                    var filename = $"Appearance-{palette}-Learning-request.png";
                    using (var file = File.Create(Path.Combine(output, filename))) encoder.Save(file); frames.Add(filename);
                    var decisions = AppearanceVisualTree(content).OfType<Button>().Where(button => button.Content is "Allow" or "Block" or "Dismiss").ToArray();
                    checks[$"learning.{palette}.decisionButtonsFit"] = decisions.Length == 3 && decisions.All(button =>
                    {
                        var location = button.TranslatePoint(new Point(), content);
                        return button.ActualWidth >= 100 && button.ActualHeight >= 44 && location.X >= 0 && location.Y >= 0 &&
                            location.X + button.ActualWidth <= area.Width + 1 && location.Y + button.ActualHeight <= area.Height + 1;
                    });
                }
                finally { notification.Close(); shownRequests.Remove(requestId); learningPromptRequest = previousPromptRequest; }
            }
            state.AppAppearance = "System"; ApplyAppearancePreferences(false);
            checks["systemAppearanceFollowsWindows"] = AppearanceTheme.IsLight == AppearanceTheme.WindowsUsesLight();
        }
        finally
        {
            // Flush and detach the sample settings page before restoring the original model reference.
            Navigate("Overview", keepScroll: false);
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            state = savedState;
            WindowState = WindowState.Normal; Width = savedSize.Width; Height = savedSize.Height; Left = savedSize.Left; Top = savedSize.Top;
            ApplyAppearancePreferences(false); Navigate(savedPage, keepScroll: false); RestoreScroll(savedScroll);
            WindowState = savedSize.WindowState;
            File.WriteAllText(Path.Combine(output, "appearance-check.json"), JsonSerializer.Serialize(new { checks, layoutProblems, frames }, new JsonSerializerOptions { WriteIndented = true }));
        }
        if (checks.Values.Any(passed => !passed))
            throw new InvalidOperationException("Appearance capture failed: " + string.Join(", ", checks.Where(c => !c.Value).Select(c => c.Key)));
    }

    private static IEnumerable<DependencyObject> AppearanceVisualTree(DependencyObject root)
    {
        yield return root;
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
            foreach (var child in AppearanceVisualTree(VisualTreeHelper.GetChild(root, index))) yield return child;
    }
}
