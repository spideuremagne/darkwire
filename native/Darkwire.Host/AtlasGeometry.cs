using System.Windows.Media.Media3D;

namespace Darkwire.Host;

/// <summary>Closed, lit meshes for the atlas environment. Coordinates are relative to Earth's center.</summary>
internal static class AtlasGeometry
{
    public static MeshGeometry3D Sphere(double radius, int stacks = 32, int slices = 64)
    {
        var mesh = new MeshGeometry3D();
        for (var i = 0; i <= stacks; i++)
        for (var j = 0; j <= slices; j++)
        {
            var lat = Math.PI * (i / (double)stacks - .5); var lon = j * Math.Tau / slices;
            var normal = new Vector3D(Math.Cos(lat) * Math.Sin(lon), Math.Sin(lat), Math.Cos(lat) * Math.Cos(lon));
            mesh.Positions.Add((Point3D)(normal * radius)); mesh.Normals.Add(normal);
            mesh.TextureCoordinates.Add(new(j / (double)slices, 1 - i / (double)stacks));
        }
        for (var i = 0; i < stacks; i++) for (var j = 0; j < slices; j++)
        {
            var a = i * (slices + 1) + j;
            Triangle(mesh, a, a + 1, a + slices + 1); Triangle(mesh, a + 1, a + slices + 2, a + slices + 1);
        }
        mesh.Freeze(); return mesh;
    }

    public static GeometryModel3D Solid(MeshGeometry3D mesh, Brush color, double gloss = 0, bool emissive = false)
    {
        var material = new MaterialGroup();
        material.Children.Add(emissive ? new EmissiveMaterial(color) : new DiffuseMaterial(color));
        if (gloss > 0) material.Children.Add(new SpecularMaterial(Brushes.White, gloss));
        material.Freeze(); return new(mesh, material) { BackMaterial = material };
    }

    public static MeshGeometry3D Lathe(params Point[] profile)
    {
        const int slices = 64;
        var mesh = new MeshGeometry3D();
        for (var row = 0; row < profile.Length; row++)
        {
            var before = profile[Math.Max(0, row - 1)]; var after = profile[Math.Min(profile.Length - 1, row + 1)];
            for (var i = 0; i <= slices; i++)
            {
                var angle = i * Math.Tau / slices; var p = profile[row];
                mesh.Positions.Add(new(p.X * Math.Cos(angle), p.Y, p.X * Math.Sin(angle)));
                var normal = new Vector3D((after.Y - before.Y) * Math.Cos(angle), before.X - after.X, (after.Y - before.Y) * Math.Sin(angle));
                normal.Normalize(); mesh.Normals.Add(normal);
            }
        }
        for (var row = 0; row < profile.Length - 1; row++) for (var i = 0; i < slices; i++)
        {
            var a = row * (slices + 1) + i;
            Triangle(mesh, a, a + slices + 1, a + 1); Triangle(mesh, a + 1, a + slices + 1, a + slices + 2);
        }
        mesh.Freeze(); return mesh;
    }

    public static MeshGeometry3D Torus(double radius, double tube, double height)
    {
        var mesh = new MeshGeometry3D(); const int rings = 64, sides = 8;
        for (var i = 0; i <= rings; i++) for (var j = 0; j <= sides; j++)
        {
            var a = i * Math.Tau / rings; var b = j * Math.Tau / sides;
            var n = new Vector3D(Math.Cos(a) * Math.Cos(b), Math.Sin(b), Math.Sin(a) * Math.Cos(b));
            mesh.Positions.Add(new(radius * Math.Cos(a) + tube * n.X, height + tube * n.Y, radius * Math.Sin(a) + tube * n.Z)); mesh.Normals.Add(n);
        }
        for (var i = 0; i < rings; i++) for (var j = 0; j < sides; j++)
        {
            var a = i * (sides + 1) + j;
            Triangle(mesh, a, a + 1, a + sides + 1); Triangle(mesh, a + 1, a + sides + 2, a + sides + 1);
        }
        mesh.Freeze(); return mesh;
    }

    private static void Triangle(MeshGeometry3D mesh, int a, int b, int c)
    { mesh.TriangleIndices.Add(a); mesh.TriangleIndices.Add(b); mesh.TriangleIndices.Add(c); }
}
