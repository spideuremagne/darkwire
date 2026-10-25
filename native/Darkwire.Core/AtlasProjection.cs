namespace Darkwire.Core;

/// <summary>A point on the flat atlas: longitude spans -2 to 2 and latitude spans -1 to 1.</summary>
public readonly record struct AtlasPoint(double X, double Y);

public static class AtlasProjection
{
    /// <summary>How far north or south of its center the flat map's view may be panned; east and west the map wraps around.</summary>
    public const double MaximumPanY = .95;

    /// <summary>The same place on the copy of the flat map nearest its center: the map repeats every 4 units east and west.</summary>
    public static double Wrap(double x) => x - 4 * Math.Floor((x + 2) / 4);

    /// <summary>
    /// The view centered on a point of the flat map: exactly east to west, since the map wraps around, and north to south as
    /// far as the map still fills a view of the given half height, so the world's top or bottom edge shows only when the
    /// whole map is shorter than the view.
    /// </summary>
    public static (double X, double Y) Home(AtlasPoint point, double halfHeight)
    {
        var reach = Math.Max(0, 1 - halfHeight);
        return (Wrap(point.X), Math.Clamp(point.Y, -reach, reach));
    }

    /// <summary>
    /// The orbit (yaw and pitch in degrees, as the globe's camera takes them) that puts a place in the middle of the globe's
    /// face. The globe is first turned about its axis and then tilted toward the viewer by the given angles, right-handed as
    /// WPF rotates; the pitch stays within the orbit's ±80 degrees.
    /// </summary>
    public static (double Yaw, double Pitch) Facing(double latitude, double longitude, double turn, double tilt)
    {
        double Radians(double degrees) => degrees * Math.PI / 180;
        var (lat, lon) = (Radians(latitude), Radians(longitude));
        var (x, y, z) = (Math.Cos(lat) * Math.Sin(lon), Math.Sin(lat), Math.Cos(lat) * Math.Cos(lon));
        var (turnCos, turnSin) = (Math.Cos(Radians(turn)), Math.Sin(Radians(turn)));
        (x, z) = (x * turnCos + z * turnSin, -x * turnSin + z * turnCos);
        var (tiltCos, tiltSin) = (Math.Cos(Radians(tilt)), Math.Sin(Radians(tilt)));
        (y, z) = (y * tiltCos - z * tiltSin, y * tiltSin + z * tiltCos);
        return (Math.Atan2(x, z) * 180 / Math.PI, Math.Clamp(Math.Asin(Math.Clamp(y, -1, 1)) * 180 / Math.PI, -80, 80));
    }

    public static AtlasPoint Project(double latitude, double longitude)
    {
        if (!double.IsFinite(latitude) || latitude is < -90 or > 90)
            throw new ArgumentOutOfRangeException(nameof(latitude));
        if (!double.IsFinite(longitude) || longitude is < -180 or > 180)
            throw new ArgumentOutOfRangeException(nameof(longitude));
        return new(longitude / 90, latitude / 90);
    }

    /// <summary>
    /// The flat map's view center after a zoom that keeps the place under a point where it is: the point's offset from the
    /// view's middle in pixels (down positive), and the map units a pixel spans before and after the zoom.
    /// </summary>
    public static (double X, double Y) ZoomToward(double panX, double panY, double offsetX, double offsetY, double before, double after) =>
        (Wrap(panX + offsetX * (before - after)), Math.Clamp(panY - offsetY * (before - after), -MaximumPanY, MaximumPanY));

    /// <summary>The place at a point of the flat map, on any of its copies east and west; null beyond the poles.</summary>
    public static (double Latitude, double Longitude)? Unproject(AtlasPoint point) =>
        double.IsFinite(point.X) && double.IsFinite(point.Y) && Math.Abs(point.Y) <= 1 ? (point.Y * 90, Wrap(point.X) * 90) : null;

    /// <summary>
    /// Builds a decorative traffic arc along the shortest longitude span. Its polylines are
    /// separated at the antimeridian, so no rendered segment crosses the whole world.
    /// </summary>
    public static AtlasRoute CreateRoute(double fromLatitude, double fromLongitude,
        double toLatitude, double toLongitude, int samples = 64, double curvature = .14)
    {
        var from = Project(fromLatitude, fromLongitude);
        var to = Project(toLatitude, toLongitude);
        if (samples is < 2 or > 4096) throw new ArgumentOutOfRangeException(nameof(samples));
        if (!double.IsFinite(curvature) || curvature is < 0 or > 1)
            throw new ArgumentOutOfRangeException(nameof(curvature));
        return new(from, to, samples, curvature);
    }
}

public sealed class AtlasRoute
{
    readonly AtlasPoint from;
    readonly AtlasPoint to;
    readonly double deltaX;
    readonly double deltaY;
    readonly double endX;
    readonly double bow;

    /// <summary>Independent polylines with matching latitude at opposite map edges.</summary>
    public IReadOnlyList<IReadOnlyList<AtlasPoint>> Segments { get; }

    internal AtlasRoute(AtlasPoint from, AtlasPoint to, int samples, double curvature)
    {
        this.from = from; this.to = to;
        endX = to.X;
        if (to.X - from.X > 2) endX -= 4;
        else if (to.X - from.X < -2) endX += 4;
        deltaX = endX - from.X;
        deltaY = to.Y - from.Y;
        var distance = Math.Sqrt(deltaX * deltaX + deltaY * deltaY);
        // Keep the bow inside the map, including routes whose endpoints sit at a pole.
        bow = Math.Min(Math.Min(curvature, distance * .18), 1 - Math.Max(from.Y, to.Y));
        if (distance == 0) { Segments = Array.Empty<IReadOnlyList<AtlasPoint>>(); return; }

        var segments = new List<IReadOnlyList<AtlasPoint>>(2);
        if (endX > 2)
        {
            var crossing = (2 - from.X) / deltaX;
            AddSegment(0, crossing, 0, endEdge: 2);
            AddSegment(crossing, 1, -4, startEdge: -2);
        }
        else if (endX < -2)
        {
            var crossing = (-2 - from.X) / deltaX;
            AddSegment(0, crossing, 0, endEdge: -2);
            AddSegment(crossing, 1, 4, startEdge: 2);
        }
        else AddSegment(0, 1, 0);
        Segments = segments.AsReadOnly();

        void AddSegment(double start, double end, double offset, double? startEdge = null, double? endEdge = null)
        {
            if (end <= start) return;
            var points = new List<AtlasPoint> { At(start) };
            for (var i = 1; i < samples; i++)
            {
                var progress = (double)i / samples;
                if (progress > start && progress < end) points.Add(At(progress));
            }
            points.Add(At(end));
            if (startEdge is { } startX) points[0] = points[0] with { X = startX };
            if (endEdge is { } endX) points[^1] = points[^1] with { X = endX };
            segments.Add(points.AsReadOnly());

            AtlasPoint At(double progress)
            {
                var point = UnwrappedPointAt(progress);
                return point with { X = Math.Clamp(point.X + offset, -2, 2) };
            }
        }
    }

    /// <summary>Samples the same arc used by Segments, wrapping animated traffic at map edges.</summary>
    public AtlasPoint PointAt(double progress)
    {
        if (!double.IsFinite(progress) || progress is < 0 or > 1)
            throw new ArgumentOutOfRangeException(nameof(progress));
        if (progress == 0) return from;
        if (progress == 1) return to;
        var point = UnwrappedPointAt(progress);
        var x = point.X;
        if (x > 2) x -= 4;
        else if (x < -2) x += 4;
        return point with { X = x };
    }

    AtlasPoint UnwrappedPointAt(double progress) => progress switch
    {
        0 => from,
        1 => new(endX, to.Y),
        _ => new(from.X + deltaX * progress,
            Math.Clamp(from.Y + deltaY * progress + bow * 4 * progress * (1 - progress), -1, 1))
    };
}
