using Darkwire.Core;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Darkwire.Service;

public sealed record FirewallSnapshot(List<FirewallRule> Rules, Dictionary<int, bool> Profiles, List<string> Errors)
{
    public Dictionary<int, bool> InboundAllowed { get; init; } = [];
    public Dictionary<int, bool> OutboundAllowed { get; init; } = [];
}

public interface IWindowsFirewallControl
{
    FirewallSnapshot Read();
    void Export(string path);
    void SetProfiles(IReadOnlyDictionary<int, bool> profiles);
    /// <summary>Current enabled state per profile bit (1 Domain, 2 Private, 4 Public), without reading rules.</summary>
    Dictionary<int, bool> Profiles() => Read().Profiles;
    /// <summary>Other firewall managers that would fight a takeover.</summary>
    IReadOnlyList<string> Conflicts() => [];
}

/// <summary>Profile state is changed only after the coordinator commits a complete WFP policy.</summary>
public sealed class WindowsFirewallControl : IWindowsFirewallControl
{
    private static dynamic Open() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new PlatformNotSupportedException("Windows Firewall is unavailable."))!;
    public FirewallSnapshot Read()
    {
        var result = Darkwire.Engine.WindowsFirewallReader.Read();
        return new(result.Rules, result.Profiles, result.Errors) { InboundAllowed = result.InboundAllowed, OutboundAllowed = result.OutboundAllowed };
    }
    public Dictionary<int, bool> Profiles()
    {
        dynamic policy = Open();
        try { return new[] { 1, 2, 4 }.ToDictionary(p => p, p => (bool)policy.FirewallEnabled[p]); }
        finally { Marshal.FinalReleaseComObject(policy); }
    }
    public IReadOnlyList<string> Conflicts()
    {
        List<string> conflicts = [];
        // Products registered through INetFwProducts own Windows Firewall rule categories.
        dynamic products = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwProducts") ?? throw new PlatformNotSupportedException("Windows Firewall is unavailable."))!;
        try
        {
            for (var i = 0; i < (int)products.Count; i++)
            {
                dynamic product = products.Item(i);
                try { conflicts.Add($"{product.DisplayName} is registered as a firewall product. Disable it before takeover."); }
                finally { Marshal.FinalReleaseComObject(product); }
            }
        }
        finally { Marshal.FinalReleaseComObject(products); }
        // Windows Firewall Control re-enables profiles and rewrites rules when its protection options are on.
        var running = Process.GetProcessesByName("wfc"); foreach (var process in running) process.Dispose();
        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\_wfcs"))
            if (key is not null || running.Length > 0)
                conflicts.Add("Windows Firewall Control is installed. It can re-enable Windows Firewall; uninstall it before takeover.");
        return conflicts;
    }
    public void Export(string path)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "advfirewall", "export", path }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("Could not export Windows Firewall policy.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000)) { process.Kill(); throw new TimeoutException("Windows Firewall export timed out."); }
        Task.WaitAll(output, error);
        if (process.ExitCode != 0 || !File.Exists(path) || new FileInfo(path).Length == 0) throw new IOException("Windows Firewall backup failed: " + error.Result + output.Result);
    }
    public void SetProfiles(IReadOnlyDictionary<int, bool> profiles)
    {
        if (profiles.Count != 3 || new[] { 1, 2, 4 }.Any(p => !profiles.ContainsKey(p))) throw new InvalidDataException("A complete firewall profile backup is required.");
        dynamic policy = Open();
        try
        {
            if ((int)policy.LocalPolicyModifyState != 0) throw new InvalidOperationException("Group Policy prevents local firewall changes.");
            foreach (var profile in new[] { 1, 2, 4 }) policy.FirewallEnabled[profile] = profiles[profile];
            foreach (var profile in new[] { 1, 2, 4 }) if ((bool)policy.FirewallEnabled[profile] != profiles[profile]) throw new IOException("Windows Firewall profile verification failed.");
        }
        finally { Marshal.FinalReleaseComObject(policy); }
    }
}
