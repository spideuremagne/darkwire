using System.Windows.Media.Animation;
using System.Windows.Shapes;
using Path = System.Windows.Shapes.Path;

namespace Darkwire.Host;

public enum ShieldState { Unknown, Active, Starting, Inactive }

/// <summary>
/// Darkwire's protection at a glance, in the sidebar's status card: a green shield with a check mark while the service
/// filters; amber with three dots while it starts up with the internet held; red with an exclamation mark, pulsing, while
/// nothing is filtered; and grey until the service has answered. The pulse is slow, well under three flashes a second; it
/// stops with reduced motion and pauses while the shield is off screen, as in a window hidden in the tray.
/// </summary>
public sealed class StatusShield : Viewbox
{
    // Drawn on a 24-pixel grid, mirrored about x = 12, which falls between pixels: the marks' edges sit on whole pixels, so
    // at 24 pixels, or any whole multiple, nothing straddles a pixel and the exclamation mark stays upright and centered. The
    // shield is its left half and that half's mirror: a curve traced the other way round is smoothed differently, so a
    // single outline came out lopsided by a shade at the edges, while mirrored halves fill mirrored pixels.
    private readonly Path body = new() { Data = Shield() };
    private readonly Path check = new() { Data = Geometry.Parse("M7.5,12 L10.5,15 L16.5,9"), StrokeThickness = 2, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round };
    private readonly Path bar = Mark(new(11, 6, 2, 7)), dot = Mark(new(11, 15, 2, 2));
    private readonly Path[] waiting = [Mark(new(7, 11, 2, 2)), Mark(new(11, 11, 2, 2)), Mark(new(15, 11, 2, 2))];
    private ShieldState state = ShieldState.Unknown;
    private bool pulse = true;

    public StatusShield()
    {
        Width = 24; Height = 24; Stretch = Stretch.Uniform;
        var canvas = new Canvas { Width = 24, Height = 24 };
        UIElement[] parts = [body, check, bar, dot, .. waiting];
        foreach (var part in parts) canvas.Children.Add(part);
        Child = canvas;
        IsVisibleChanged += (_, _) => Update();
        Update();
    }

    public ShieldState State { get => state; set { if (state == value) return; state = value; Update(); } }
    /// <summary>Whether the red shield pulses; off with reduced motion and in captures.</summary>
    public bool Pulse { get => pulse; set { if (pulse == value) return; pulse = value; Update(); } }

    private static Geometry Shield()
    {
        var half = Geometry.Parse("M12,1.5 L3.5,4.5 V11 C3.5,16.6 7,20.9 12,22.5 Z");
        var mirrored = half.Clone(); mirrored.Transform = new ScaleTransform(-1, 1, 12, 0);
        return new GeometryGroup { FillRule = FillRule.Nonzero, Children = { half, mirrored } };
    }

    /// <summary>
    /// A filled mark on whole pixels, as geometry, which layout never moves or rounds apart from the rest. Its ends are
    /// square: rounded ones are smoothed a shade heavier on the right, the way WPF's anti-aliasing leans.
    /// </summary>
    private static Path Mark(Rect area) => new() { Data = new RectangleGeometry(area) };

    private void Update()
    {
        var (fill, mark, name) = state switch
        {
            ShieldState.Active => ("#7CE3BA", "#0D2A20", "Filtering active"),
            ShieldState.Starting => ("#F2C46D", "#3B2A0C", "Starting up"),
            ShieldState.Inactive => ("#F2849C", "#3D0D19", "Not filtering"),
            _ => ("#4A4658", "#4A4658", "Checking the service")
        };
        body.Fill = Ui.Brush(fill);
        check.Stroke = Ui.Brush(mark); bar.Fill = dot.Fill = Ui.Brush(mark);
        foreach (var part in waiting) part.Fill = Ui.Brush(mark);
        check.Visibility = state == ShieldState.Active ? Visibility.Visible : Visibility.Collapsed;
        bar.Visibility = dot.Visibility = state == ShieldState.Inactive ? Visibility.Visible : Visibility.Collapsed;
        foreach (var part in waiting) part.Visibility = state == ShieldState.Starting ? Visibility.Visible : Visibility.Collapsed;
        System.Windows.Automation.AutomationProperties.SetName(this, name);
        if (state == ShieldState.Inactive && pulse && IsVisible)
            BeginAnimation(OpacityProperty, new DoubleAnimation(1, .3, TimeSpan.FromMilliseconds(700)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut } });
        else { BeginAnimation(OpacityProperty, null); Opacity = 1; }
    }
}
