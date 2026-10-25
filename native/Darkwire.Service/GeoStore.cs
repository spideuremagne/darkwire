using Darkwire.Core;
using System.Text;

namespace Darkwire.Service;

public interface IGeoStore
{
    /// <summary>An administrator's imported database when there is one; otherwise the compact database the service kept, or the newest one until it keeps one.</summary>
    IGeoLookup? Read();
    GeoDatabase Save(string csv);
    /// <summary>Whether an administrator imported a database, which weekly updates never replace.</summary>
    bool Imported { get; }
    /// <summary>Keeps a copy of the compact database the service uses; Read returns it from then on, whatever newer files appear.</summary>
    void Keep(GeoIpDatabase database);
}

/// <summary>
/// Only CSV bytes cross IPC; the service never opens a client-supplied path as SYSTEM. Without an import, the service reads its own
/// copy of the compact database it uses, so after a restart it enforces the data it enforced before, never a newer file it did not
/// check against the policy, such as a weekly release that did not apply. Until it keeps one, it uses the newest of the
/// weekly-updated database and the one installed with it.
/// </summary>
public sealed class GeoStore(string directory, params string[] databases) : IGeoStore
{
    public const int MaximumBytes = 4 * 1024 * 1024;
    private string DatabasePath => Path.Combine(directory, "geoip.csv");
    private string KeptPath => Path.Combine(directory, "geoip.dat");
    public bool Imported => File.Exists(DatabasePath);
    public IGeoLookup? Read()
    {
        if (!Imported) return GeoIpDatabase.Newest([KeptPath]) ?? GeoIpDatabase.Newest(databases);
        if (new FileInfo(DatabasePath).Length > MaximumBytes) throw new InvalidDataException("Service GeoIP data exceeds 4 MB.");
        using var reader = File.OpenText(DatabasePath); return GeoDatabase.Load(reader);
    }
    public GeoDatabase Save(string csv)
    {
        if (Encoding.UTF8.GetByteCount(csv) > MaximumBytes) throw new InvalidDataException("Service GeoIP upload exceeds 4 MB. Import a normalized subset covering the required regions.");
        var parsed = GeoDatabase.Load(new StringReader(csv));
        var bytes = new UTF8Encoding(false).GetBytes(csv);
        Replace(DatabasePath, stream => stream.Write(bytes));
        return parsed;
    }
    public void Keep(GeoIpDatabase database)
    {
        if (GeoIpUpdater.InstalledRelease(KeptPath) != database.Release) Replace(KeptPath, database.Write);
    }

    /// <summary>Replaces a file in one move, so a reader sees the old file or the new one.</summary>
    private void Replace(string path, Action<Stream> write)
    {
        var temporary = Path.Combine(directory, "geo-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.WriteThrough))
            { write(stream); stream.Flush(true); }
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
