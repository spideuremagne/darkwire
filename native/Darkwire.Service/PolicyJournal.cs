using Darkwire.Core;
using System.Text.Json;

namespace Darkwire.Service;

public sealed class ServiceJournal
{
    public int Version { get; set; } = 1;
    public long Revision { get; set; }
    public string Phase { get; set; } = "Inactive";
    public AppState Policy { get; set; } = new();
    public Dictionary<int, bool> OriginalProfiles { get; set; } = [];
    public string? BackupFile { get; set; }
    /// <summary>Audit settings Darkwire changed to receive drop events, keyed by subcategory GUID; restored with Windows Firewall.</summary>
    public Dictionary<Guid, uint>? OriginalAudit { get; set; }
    /// <summary>
    /// Windows Security's Firewall and network protection policy value as it was before Darkwire hid that area; null while
    /// Darkwire leaves the area alone. Restored with Windows Firewall, or when the policy shows the area again.
    /// </summary>
    public SavedValue? OriginalFirewallArea { get; set; }
}
/// <summary>A setting's value before Darkwire changed it; null when it was not set.</summary>
public sealed record SavedValue(int? Value);
public interface IPolicyJournal
{
    ServiceJournal Read();
    void Write(ServiceJournal journal);
    string BackupPath();
}
public sealed class PolicyJournal(string directory) : IPolicyJournal
{
    private string FilePath => Path.Combine(directory, "service-policy.json");
    public ServiceJournal Read()
    {
        if (!File.Exists(FilePath)) return new();
        var info = new FileInfo(FilePath); if (info.Length > 8 * 1024 * 1024) throw new InvalidDataException("Service policy is too large.");
        var result = JsonSerializer.Deserialize<ServiceJournal>(File.ReadAllText(FilePath), StateStore.JsonOptions) ?? throw new InvalidDataException("Service policy is empty.");
        if (result.Version != 1 || result.Revision < 0 || result.Policy is null || result.OriginalProfiles is null || result.Phase is not ("Inactive" or "Prepared" or "Active" or "Applying" or "Restoring")) throw new InvalidDataException("Invalid service journal.");
        if (result.Phase != "Inactive" && (result.OriginalProfiles.Count != 3 || !new[] { 1, 2, 4 }.All(result.OriginalProfiles.ContainsKey)))
            throw new InvalidDataException("The recovery journal must contain all three original firewall profile states.");
        return result;
    }
    public void Write(ServiceJournal journal)
    {
        Directory.CreateDirectory(directory);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(journal, StateStore.JsonOptions);
        if (bytes.Length > 8 * 1024 * 1024) throw new InvalidDataException("Service policy is too large.");
        var temporary = Path.Combine(directory, "journal-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(bytes); stream.Flush(true); }
            // MOVEFILE_WRITE_THROUGH returns only after the rename is flushed, so a power loss leaves the old or new journal, never neither.
            if (!MoveFileEx(temporary, FilePath, 0x1 | 0x8)) throw new IOException("Service journal replacement failed.", new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existing, string replacement, uint flags);
    public string BackupPath() => Path.Combine(directory, "windows-firewall-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N") + ".wfw");
}
