using System.Windows.Media.Media3D;

namespace Darkwire.Host;

public sealed partial class GlobeView
{
    private GeometryModel3D GlobeSurface()
    {
        const int stacks = 90, slices = 180;
        var mesh = new MeshGeometry3D();
        for (var i = 0; i <= stacks; i++)
            for (var j = 0; j <= slices; j++)
            {
                var p = Position(i * 180d / stacks - 90, j * 360d / slices - 180, 1);
                mesh.Positions.Add(p); mesh.Normals.Add((Vector3D)p);
                mesh.TextureCoordinates.Add(new((double)j / slices, 1 - (double)i / stacks));
            }
        for (var i = 0; i < stacks; i++)
            for (var j = 0; j < slices; j++)
            {
                var a = i * (slices + 1) + j;
                Triangle(mesh, a, a + 1, a + slices + 1);
                Triangle(mesh, a + 1, a + slices + 2, a + slices + 1);
            }
        mesh.Freeze();
        var artwork = WorldMapArtwork.Create(Theme, IsLightAtlas, frame: false);
        return new(mesh, SurfaceMaterial(artwork, IsLightAtlas));
    }

    private static Material SurfaceMaterial(Brush artwork, bool light)
    {
        if (light)
        {
            var daylight = new DiffuseMaterial(artwork); daylight.Freeze(); return daylight;
        }
        // Emission keeps country names legible on the unlit hemisphere in dark mode.
        var material = new MaterialGroup();
        material.Children.Add(new DiffuseMaterial(artwork));
        material.Children.Add(new EmissiveMaterial(artwork) { Color = Color.FromRgb(60, 60, 60) });
        material.Freeze();
        return material;
    }

    private Color RouteColor(MapRoute route) => IsLightAtlas
        ? route.Blocked ? Color.FromRgb(177, 42, 76)
            : route.Direction == TrafficDirection.Inbound ? Color.FromRgb(0, 105, 92)
            : route.Direction == TrafficDirection.Unknown ? Color.FromRgb(76, 94, 110) : accent
        : route.Blocked ? Color.FromRgb(250, 113, 151)
            : route.Direction == TrafficDirection.Inbound ? Color.FromRgb(119, 215, 199)
            : route.Direction == TrafficDirection.Unknown ? Color.FromRgb(126, 132, 150) : accent;
}
