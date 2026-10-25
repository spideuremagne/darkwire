using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Darkwire.Service;

public interface IVpnProfileVault
{
    StoredVpnProfile Save(Guid id, string kind, string configuration);
    IReadOnlyList<StoredVpnProfile> List();
    ParsedVpnConfiguration Read(Guid id, Guid revision);
    void Delete(Guid id);
}

/// <summary>Machine DPAPI is combined with the service directory's SYSTEM/admin ACL, never used alone.</summary>
internal sealed class VpnProfileVault(string stateDirectory, Action verifyStorage) : IVpnProfileVault
{
    private readonly object gate = new();
    private readonly string directory = Path.Combine(Path.GetFullPath(stateDirectory), "Profiles");
    private static readonly JsonSerializerOptions Options = new(StateStore.JsonOptions)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, AllowDuplicateProperties = false, MaxDepth = 8 };
    private const int MaximumFileBytes = 6 * 1024 * 1024;
    private sealed record Envelope(int Version, StoredVpnProfile Profile, string Ciphertext);

    public StoredVpnProfile Save(Guid id, string kind, string configuration)
    {
        ValidateId(id);
        var parsed = VpnConfiguration.Parse(kind, configuration);
        var profile = new StoredVpnProfile(id, parsed.Kind, parsed.Endpoint, Guid.NewGuid(), DateTimeOffset.UtcNow);
        // Preserve the validated original, including DNS that the backend-normalized form deliberately removes.
        var bytes = Encoding.UTF8.GetBytes(configuration);
        byte[] encrypted;
        try { encrypted = DpapiSecrets.Protect(bytes, Context(profile), machine: true); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        lock (gate)
        {
            Verify();
            if (!File.Exists(Filename(id)) && Directory.EnumerateFiles(directory, "*.json").Count() >= TunnelRoutingPlan.MaximumProfiles)
                throw new InvalidDataException("The service stores at most 100 VPN configurations. Remove an unused profile first.");
            var payload = JsonSerializer.SerializeToUtf8Bytes(new Envelope(1, profile, Convert.ToBase64String(encrypted)), Options);
            if (payload.Length > MaximumFileBytes) throw new InvalidDataException("The protected configuration exceeds the storage limit.");
            var temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
                { file.Write(payload); file.Flush(true); }
                File.Move(temporary, Filename(id), true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            return profile;
        }
    }
    public IReadOnlyList<StoredVpnProfile> List()
    {
        lock (gate)
        {
            Verify();
            var files = Directory.EnumerateFiles(directory, "*.json").Take(TunnelRoutingPlan.MaximumProfiles + 1).ToArray();
            if (files.Length > TunnelRoutingPlan.MaximumProfiles) throw new InvalidDataException("Too many stored VPN profiles.");
            return files.Select(file =>
            {
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file), "N", out var id)) throw new InvalidDataException("Invalid VPN storage entry.");
                return Load(id).Profile;
            }).OrderBy(p => p.Id).ToArray();
        }
    }
    public ParsedVpnConfiguration Read(Guid id, Guid revision)
    {
        lock (gate)
        {
            Verify(); var envelope = Load(id);
            if (revision == Guid.Empty || envelope.Profile.Revision != revision) throw new InvalidDataException("The stored VPN configuration changed. Reload its metadata.");
            var bytes = DpapiSecrets.Unprotect(Convert.FromBase64String(envelope.Ciphertext), Context(envelope.Profile));
            try
            {
                var parsed = VpnConfiguration.Parse(envelope.Profile.Kind, new UTF8Encoding(false, true).GetString(bytes));
                if (parsed.Endpoint != envelope.Profile.Endpoint) throw new InvalidDataException("VPN metadata does not match its protected configuration.");
                return parsed;
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    public void Delete(Guid id) { lock (gate) { ValidateId(id); Verify(); File.Delete(Filename(id)); } }
    private Envelope Load(Guid id)
    {
        ValidateId(id);
        using var file = new FileStream(Filename(id), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is <= 0 or > MaximumFileBytes) throw new InvalidDataException("Invalid VPN storage size.");
        var envelope = JsonSerializer.Deserialize<Envelope>(file, Options) ?? throw new InvalidDataException("Empty VPN storage entry.");
        // Earlier builds stored OpenVPN profiles too: they are still listed, so they can be deleted, but never read.
        if (envelope.Version != 1 || envelope.Profile is null || envelope.Profile.Id != id || envelope.Profile.Revision == Guid.Empty ||
            envelope.Profile.Kind is not ("WireGuard" or "OpenVPN") || string.IsNullOrEmpty(envelope.Ciphertext))
            throw new InvalidDataException("Invalid VPN storage entry.");
        return envelope;
    }
    private void Verify()
    {
        verifyStorage(); Directory.CreateDirectory(directory);
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            if ((File.GetAttributes(entry) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new UnauthorizedAccessException("VPN storage must contain ordinary files only.");
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("VPN storage cannot be redirected.");
    }
    private string Filename(Guid id) => Path.Combine(directory, id.ToString("N") + ".json");
    private static string Context(StoredVpnProfile profile) => $"Darkwire.Service.Vpn.v1/{profile.Id:N}/{profile.Revision:N}/{profile.Kind}";
    private static void ValidateId(Guid id) { if (id == Guid.Empty) throw new InvalidDataException("A VPN profile ID is required."); }
}
