using System.ComponentModel;
using System.Windows.Automation;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    private sealed record AppearanceChoice(string Value, string Label)
    {
        public override string ToString() => Label;
    }

    /// <summary>Saved presentation preferences and an independent, disposable sample atlas.</summary>
    private UIElement AppearanceSettingsCard()
    {
        AppearancePreferences.Normalize(state);
        var body = Ui.Stack(SettingsText("Appearance & motion", 22, weight: FontWeights.SemiBold), Ui.Gap(7),
            SettingsText("Choose a theme, navigation, and how your maps move.", 13, "Muted"), Ui.Gap(22));

        ComboBox Picker(string name, AppearanceChoice[] choices, string selected, Action<string> changed)
        {
            var picker = new ComboBox { ItemsSource = choices, SelectedItem = choices.FirstOrDefault(c => c.Value == selected) ?? choices[0], MinHeight = 38 };
            AutomationProperties.SetName(picker, name);
            picker.SelectionChanged += (_, _) => { if (picker.SelectedItem is AppearanceChoice choice) changed(choice.Value); };
            return picker;
        }
        void ChangeShell(Action change) { change(); Save(); ApplyAppearancePreferences(); }
        var appearance = Picker("App appearance", [new("System", "Follow Windows"), new("Dark", "Obsidian · Dark"), new("Light", "Glacier · Light")],
            state.AppAppearance, value => ChangeShell(() => state.AppAppearance = value));
        var navigation = Picker("Navigation placement", [new("Left", "Left sidebar"), new("Top", "Top navigation")],
            state.NavigationPlacement, value => ChangeShell(() => state.NavigationPlacement = value));
        var presentation = Picker("Connection map layout", [new("Standard", "Standard · Map and details"), new("Observatory", "Observatory · Immersive atlas")],
            state.AtlasPresentation, value => ChangeShell(() => state.AtlasPresentation = value));

        var previewEnvironment = new AtlasBackground(state.BackgroundPreset, state.CloudDirection, Ui.MotionEnabled(state), state.SpaceSunMoon, state.SpaceUfos);
        var preview = new GlobeView([
            new(40.7128, -74.0060, false, TrafficDirection.Outbound),
            new(51.5074, -.1278, false, TrafficDirection.Outbound),
            new(35.6762, 139.6503, false, TrafficDirection.Inbound),
            new(-23.5505, -46.6333, true, TrafficDirection.Outbound)
        ], "Globe", MapOrigin.Default) { Height = 254 };
        preview.SetEnvironment(previewEnvironment);
        preview.SetTheme(state.Theme, false);
        preview.ConfigureEffects(state);
        var paused = false;
        var disposed = false;
        var synchronizing = false;
        var previewStatus = SettingsText("", 12, "Muted");
        var motionStatus = SettingsText("", 12, "Muted");
        Button? pause = null;
        void UpdatePreview()
        {
            if (disposed) return;
            preview.ConfigureEffects(state);
            preview.Animate = Ui.MotionEnabled(state) && !paused;
            previewStatus.Text = $"{state.MapEffectPreset} effects · {state.EffectIntensity}% intensity";
            motionStatus.Text = SystemParameters.HighContrast
                ? "Windows high contrast is keeping decorative motion off. Routes and labels remain visible."
                : !SystemParameters.ClientAreaAnimation ? "Windows has turned animations off. Routes and labels remain visible."
                : state.ReducedMotion ? "Decorative motion is off. Routes, labels, and manual map controls remain available."
                : "Your Windows animation preference is respected. These choices never change network policy.";
            if (pause is not null)
            {
                pause.Content = paused ? "Resume preview" : "Pause preview";
                pause.IsEnabled = Ui.MotionEnabled(state);
            }
        }
        var mapTheme = Picker("Map palette", GlobeView.Themes.Select(t => new AppearanceChoice(t, t)).ToArray(), state.Theme, value =>
        {
            state.Theme = value; Save(); preview.SetTheme(value, false); UpdatePreview();
        });
        var choices = Ui.Columns(0, 0);
        var firstChoices = Ui.Stack(SettingsField("App appearance", appearance), Ui.Gap(16), SettingsField("Connection map layout", presentation));
        firstChoices.Margin = new(0, 0, 20, 0);
        Ui.Add(choices, firstChoices, 0);
        Ui.Add(choices, Ui.Stack(SettingsField("Navigation placement", navigation), Ui.Gap(16), SettingsField("Map palette", mapTheme)), 1);
        body.Children.Add(choices); body.Children.Add(Ui.Gap(24)); body.Children.Add(SettingsDivider()); body.Children.Add(Ui.Gap(24));

        var effects = Ui.Stack(SettingsText("Map effects", 17, weight: FontWeights.SemiBold), Ui.Gap(6),
            SettingsText("Start with a preset, then make it yours.", 13, "Muted"), Ui.Gap(14));
        var presetButtons = new Dictionary<string, Button>();
        var presets = new UniformGrid { Columns = 3 };
        var switches = new List<(CheckBox Control, Func<bool> Read)>();
        Slider? intensity = null;
        TextBlock? intensityValue = null;
        var pendingSave = false;
        var saveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        void FlushSave()
        {
            saveTimer.Stop();
            if (!pendingSave) return;
            pendingSave = false; Save();
        }
        saveTimer.Tick += (_, _) => FlushSave();
        void RefreshControls()
        {
            synchronizing = true;
            foreach (var (control, read) in switches) control.IsChecked = read();
            if (intensity is not null) intensity.Value = state.EffectIntensity;
            if (intensityValue is not null) intensityValue.Text = $"{state.EffectIntensity}%";
            foreach (var pair in presetButtons)
            {
                pair.Value.SetResourceReference(Control.BorderBrushProperty, pair.Key == state.MapEffectPreset ? "Accent" : "Stroke");
                pair.Value.SetResourceReference(Control.BackgroundProperty, pair.Key == state.MapEffectPreset ? "PanelRaised" : "Panel");
                AutomationProperties.SetHelpText(pair.Value, pair.Key == state.MapEffectPreset ? "Selected motion preset" : "Apply motion preset");
            }
            synchronizing = false;
        }
        void EffectsChanged(bool saveImmediately = true)
        {
            if (synchronizing) return;
            AppearancePreferences.Normalize(state);
            RefreshControls(); UpdatePreview(); ApplyAppearancePreferences(false);
            pendingSave = true;
            if (saveImmediately) FlushSave(); else { saveTimer.Stop(); saveTimer.Start(); }
        }
        foreach (var (name, detail) in new[] { ("Focus", "Minimal effects"), ("Balanced", "Gentle motion"), ("Cinematic", "Full atmosphere") })
        {
            var button = Ui.Button("", () => { AppearancePreferences.ApplyEffectPreset(state, name); EffectsChanged(); });
            button.Content = Ui.Stack(SettingsText(name, 13, weight: FontWeights.SemiBold), Ui.Gap(4), SettingsText(detail, 11, "Muted"));
            button.Padding = new(11, 11, 11, 11); button.Margin = new(0, 0, name == "Cinematic" ? 0 : 8, 0);
            button.HorizontalContentAlignment = HorizontalAlignment.Left;
            AutomationProperties.SetName(button, name + " motion preset");
            presetButtons.Add(name, button); presets.Children.Add(button);
        }
        effects.Children.Add(presets); effects.Children.Add(Ui.Gap(12));
        void Effect(string title, string detail, Func<bool> read, Action<bool> write)
        {
            var toggle = SettingsSwitch(title, detail, read());
            void Change()
            {
                if (synchronizing) return;
                write(toggle.IsChecked == true); state.MapEffectPreset = "Custom"; EffectsChanged();
            }
            toggle.Checked += (_, _) => Change(); toggle.Unchecked += (_, _) => Change();
            switches.Add((toggle, read)); effects.Children.Add(SettingsSwitchRow(title, detail, toggle));
        }
        Effect("Route particles", "Travelling lights show connection direction.", () => state.RouteParticles, value => state.RouteParticles = value);
        Effect("Endpoint ripples", "Gentle rings highlight route destinations.", () => state.EndpointRipples, value => state.EndpointRipples = value);
        Effect("Policy shockwaves", "Repeating rings highlight denied routes; they do not indicate new attacks.", () => state.PolicyShockwaves, value => state.PolicyShockwaves = value);
        Effect("Ambient particles", "Sparse drifting lights across the map.", () => state.AmbientParticles, value => state.AmbientParticles = value);
        Effect("Atmosphere & route glow", "Soft illumination stays within the map.", () => state.AtmosphereGlow, value => state.AtmosphereGlow = value);
        Effect("Automatic globe rotation", "Slowly orbit the globe when you are not interacting.", () => state.AutoRotateGlobe, value => state.AutoRotateGlobe = value);

        intensityValue = SettingsText($"{state.EffectIntensity}%", 13, weight: FontWeights.SemiBold);
        var intensityHeading = Ui.Columns(0, 54);
        Ui.Add(intensityHeading, SettingsText("Map effect intensity", 13, weight: FontWeights.SemiBold), 0);
        intensityValue.TextAlignment = TextAlignment.Right; Ui.Add(intensityHeading, intensityValue, 1);
        intensity = new Slider { Minimum = 0, Maximum = 100, TickFrequency = 1, IsSnapToTickEnabled = true, IsMoveToPointEnabled = true,
            Value = state.EffectIntensity, Margin = new(0, 12, 0, 10), MinHeight = 28, Template = AppearanceSliderTemplate };
        intensity.SetResourceReference(Control.ForegroundProperty, "Accent");
        AutomationProperties.SetName(intensity, "Map effect intensity");
        AutomationProperties.SetHelpText(intensity, "Zero to one hundred percent. Adjusts decorative effects, not route information.");
        intensity.ValueChanged += (_, _) =>
        {
            if (synchronizing) return;
            state.EffectIntensity = (int)Math.Round(intensity.Value); state.MapEffectPreset = "Custom"; EffectsChanged(false);
        };
        intensity.PreviewMouseLeftButtonUp += (_, _) => FlushSave(); intensity.LostKeyboardFocus += (_, _) => FlushSave();
        effects.Children.Add(Ui.Gap(20)); effects.Children.Add(intensityHeading); effects.Children.Add(intensity);
        var reduced = SettingsSwitch("Reduce motion", "Keeps routes and meaning while stopping decorative movement.", state.ReducedMotion);
        void ChangeReducedMotion()
        {
            if (synchronizing) return;
            state.ReducedMotion = reduced.IsChecked == true; EffectsChanged();
        }
        reduced.Checked += (_, _) => ChangeReducedMotion(); reduced.Unchecked += (_, _) => ChangeReducedMotion();
        switches.Add((reduced, () => state.ReducedMotion));
        effects.Children.Add(SettingsSwitchRow("Reduce motion", "Keep routes and meaning. Stop decorative movement.", reduced));
        effects.Children.Add(Ui.Gap(10)); effects.Children.Add(motionStatus);

        var scene = new Grid { Height = 254, ClipToBounds = true };
        scene.Children.Add(previewEnvironment); scene.Children.Add(preview);
        // The sample sits in a scrolling page: the wheel scrolls the page past it, and its own buttons zoom it.
        preview.PreviewMouseWheel += (_, e) =>
        {
            e.Handled = true;
            scene.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = UIElement.MouseWheelEvent });
        };
        var previewPanel = Ui.Stack(SettingsText("LIVE VISUAL PREVIEW", 11, "Muted", FontWeights.SemiBold), Ui.Gap(12), scene,
            Ui.Gap(14), SettingsText("A quieter kind of striking.", 16, weight: FontWeights.SemiBold), Ui.Gap(8),
            SettingsText("Sample connections show the effect of each control. Your traffic and policy are unchanged.", 12, "Muted"), Ui.Gap(15));
        pause = Ui.Button("Pause preview", () => { paused = !paused; UpdatePreview(); }); pause.HorizontalAlignment = HorizontalAlignment.Left;
        previewPanel.Children.Add(pause); previewPanel.Children.Add(Ui.Gap(12)); previewPanel.Children.Add(previewStatus);
        var previewCard = SettingsCard(previewPanel, 18); previewCard.VerticalAlignment = VerticalAlignment.Top; previewCard.Margin = new(22, 0, 0, 0);
        var content = Ui.Columns(0, 300); Ui.Add(content, effects, 0); Ui.Add(content, previewCard, 1); body.Children.Add(content);
        var card = SettingsCard(body, 24);
        PropertyChangedEventHandler systemChanged = (_, args) =>
        {
            if (args.PropertyName is nameof(SystemParameters.ClientAreaAnimation) or nameof(SystemParameters.HighContrast) && !disposed)
                Dispatcher.BeginInvoke(() => { if (!disposed) UpdatePreview(); });
        };
        card.Loaded += (_, _) => { if (!disposed) { SystemParameters.StaticPropertyChanged += systemChanged; UpdatePreview(); } };
        card.Unloaded += (_, _) =>
        {
            if (disposed) return;
            disposed = true; SystemParameters.StaticPropertyChanged -= systemChanged;
            FlushSave(); preview.Dispose(); previewEnvironment.Dispose();
        };
        RefreshControls(); UpdatePreview(); return card;
    }

    private static TextBlock SettingsText(string text, double size = 13, string color = "Text", FontWeight? weight = null)
    {
        var block = new TextBlock { Text = text, FontSize = size, FontWeight = weight ?? FontWeights.Normal, TextWrapping = TextWrapping.Wrap };
        block.SetResourceReference(TextBlock.ForegroundProperty, color); return block;
    }
    private static StackPanel SettingsField(string title, UIElement control) => Ui.Stack(SettingsText(title, 13, weight: FontWeights.SemiBold), Ui.Gap(8), control);
    private static Border SettingsDivider()
    {
        var line = new Border { Height = 1 }; line.SetResourceReference(Border.BackgroundProperty, "Stroke"); return line;
    }
    private static Border SettingsCard(UIElement child, double padding)
    {
        var card = new Border { Child = child, Padding = new(padding), CornerRadius = new(12), BorderThickness = new(1) };
        card.SetResourceReference(Border.BackgroundProperty, "Panel"); card.SetResourceReference(Border.BorderBrushProperty, "Stroke"); return card;
    }
    private static UIElement SettingsSwitchRow(string title, string detail, CheckBox toggle)
    {
        var row = Ui.Columns(0, 52);
        var description = Ui.Stack(SettingsText(title, 13, weight: FontWeights.SemiBold), Ui.Gap(4), SettingsText(detail, 12, "Muted"));
        description.Margin = new(0, 0, 15, 0); Ui.Add(row, description, 0); Ui.Add(row, toggle, 1);
        var border = new Border { Child = row, Padding = new(0, 13, 0, 13), BorderThickness = new(0, 0, 0, 1) };
        border.SetResourceReference(Border.BorderBrushProperty, "Stroke"); return border;
    }
    private static CheckBox SettingsSwitch(string name, string description, bool value)
    {
        var toggle = new CheckBox { IsChecked = value, Width = 48, MinHeight = 34, VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Right, Cursor = Cursors.Hand, Template = AppearanceSwitchTemplate, ToolTip = description };
        AutomationProperties.SetName(toggle, name); AutomationProperties.SetHelpText(toggle, description); return toggle;
    }
    private static readonly ControlTemplate AppearanceSwitchTemplate = (ControlTemplate)XamlReader.Parse("""
        <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="CheckBox">
          <Grid Background="Transparent">
            <Border x:Name="Track" Width="38" Height="22" CornerRadius="11" Background="{DynamicResource Stroke}" BorderBrush="{DynamicResource Muted}" BorderThickness="1">
              <Ellipse x:Name="Thumb" Width="14" Height="14" Margin="3,0" HorizontalAlignment="Left" Fill="{DynamicResource Text}"/>
            </Border>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsChecked" Value="True"><Setter TargetName="Track" Property="Background" Value="{DynamicResource Accent}"/><Setter TargetName="Track" Property="BorderBrush" Value="{DynamicResource Accent}"/><Setter TargetName="Thumb" Property="HorizontalAlignment" Value="Right"/><Setter TargetName="Thumb" Property="Fill" Value="{DynamicResource OnAccent}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Track" Property="BorderBrush" Value="{DynamicResource Text}"/><Setter TargetName="Track" Property="BorderThickness" Value="2"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Track" Property="Opacity" Value="0.45"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
        """);

    private static readonly ControlTemplate AppearanceSliderTemplate = (ControlTemplate)XamlReader.Parse("""
        <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="Slider">
          <Grid x:Name="Surface" Background="Transparent" MinHeight="28">
            <Track x:Name="PART_Track" Minimum="{TemplateBinding Minimum}" Maximum="{TemplateBinding Maximum}" Value="{TemplateBinding Value}" IsDirectionReversed="{TemplateBinding IsDirectionReversed}" Orientation="Horizontal">
              <Track.DecreaseRepeatButton>
                <RepeatButton Command="{x:Static Slider.DecreaseLarge}" Focusable="False" IsTabStop="False" Height="4" VerticalAlignment="Center" Background="{DynamicResource Accent}">
                  <RepeatButton.Template><ControlTemplate TargetType="RepeatButton"><Border Background="{TemplateBinding Background}" CornerRadius="2"/></ControlTemplate></RepeatButton.Template>
                </RepeatButton>
              </Track.DecreaseRepeatButton>
              <Track.IncreaseRepeatButton>
                <RepeatButton Command="{x:Static Slider.IncreaseLarge}" Focusable="False" IsTabStop="False" Height="4" VerticalAlignment="Center" Background="{DynamicResource Stroke}">
                  <RepeatButton.Template><ControlTemplate TargetType="RepeatButton"><Border Background="{TemplateBinding Background}" CornerRadius="2"/></ControlTemplate></RepeatButton.Template>
                </RepeatButton>
              </Track.IncreaseRepeatButton>
              <Track.Thumb>
                <Thumb x:Name="Grip" Width="16" Height="16" Background="{DynamicResource Accent}" BorderBrush="{DynamicResource Accent}" BorderThickness="1" Cursor="Hand">
                  <Thumb.Template><ControlTemplate TargetType="Thumb"><Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8"/></ControlTemplate></Thumb.Template>
                </Thumb>
              </Track.Thumb>
            </Track>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Grip" Property="BorderBrush" Value="{DynamicResource Text}"/><Setter TargetName="Grip" Property="BorderThickness" Value="2"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Surface" Property="Opacity" Value="0.45"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
        """);
}
