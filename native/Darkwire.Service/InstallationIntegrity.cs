using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Darkwire.Service;

internal static class InstallationIntegrity
{
    private sealed record Manifest(int Version, List<Entry> Files);
    private sealed record Entry(string Path, string Sha256);
    public const string ManifestName = "installation-integrity.json";
    private static readonly JsonSerializerOptions Options = new()
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, AllowDuplicateProperties = false, MaxDepth = 8 };

    // ACL and reparse-point checks must run before calling this method. The installer creates
    // this manifest in protected storage. It detects changes; it is not a publisher signature.
    public static void Verify(string directory)
    {
        var root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var manifestPath = Path.Combine(root, ManifestName);
        using var input = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 or > 1024 * 1024) throw new InvalidDataException("Invalid installation integrity manifest size.");
        var manifest = JsonSerializer.Deserialize<Manifest>(input, Options) ?? throw new InvalidDataException("Missing installation manifest.");
        if (manifest.Version != 1 || manifest.Files is null || manifest.Files.Count is 0 or > 4096)
            throw new InvalidDataException("Invalid installation integrity manifest.");
        var declared = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in manifest.Files)
        {
            if (entry is null || string.IsNullOrEmpty(entry.Path) || entry.Path.Length > 32768 || Path.IsPathRooted(entry.Path) || entry.Path.Contains(':') ||
                entry.Path.Split(['/', '\\']).Any(p => p is "" or "." or "..") || entry.Path.Equals(ManifestName, StringComparison.OrdinalIgnoreCase) ||
                !declared.Add(entry.Path.Replace('/', '\\')) || entry.Sha256 is null || entry.Sha256.Length != 64 || !entry.Sha256.All(char.IsAsciiHexDigit))
                throw new InvalidDataException("Invalid installation integrity entry.");
            var full = Path.GetFullPath(Path.Combine(root, entry.Path));
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Installation integrity entry escapes its directory.");
            using var file = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(file), Convert.FromHexString(entry.Sha256)))
                throw new InvalidDataException("A protected installation file changed. Reinstall Darkwire.");
        }
        var actual = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(p => !p.Equals(manifestPath, StringComparison.OrdinalIgnoreCase))
            .Select(p => Path.GetRelativePath(root, p).Replace('/', '\\'));
        if (!declared.SetEquals(actual)) throw new InvalidDataException("The protected installation file set changed. Reinstall Darkwire.");
    }
}
