using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.IO.Compression;

namespace Darkwire.Host;

public static class WindowsTelemetry
{
    private static readonly ConnectionDirectionTracker directions = new();
    private static readonly object snapshotGate = new();
    public static List<Connection> Snapshot()
    {
        lock (snapshotGate) return directions.Apply(ReadSnapshot());
    }
    private static List<Connection> ReadSnapshot()
    {
        List<Connection> result = []; Dictionary<int, (string, string)> processes = [];
        // Service hosts are named by the service each connection belongs to: the one they run, or the one Windows tagged the
        // socket with when they run several.
        IReadOnlyDictionary<int, IReadOnlyList<string>> hosted;
        try { hosted = Darkwire.Engine.ServiceProcesses.Read(); }
        catch (System.ComponentModel.Win32Exception) { hosted = new Dictionary<int, IReadOnlyList<string>>(); }
        foreach (var v6 in new[] { false, true })
            foreach (var row in Darkwire.Engine.FlowAttribution.ReadTcp(v6))
            {
                var pid = row.ProcessId;
                if (row.State is not (3 or 4 or 5 or 8) || row.RemotePort == 0) continue;
                if (!processes.TryGetValue(pid, out var process))
                {
                    string name = pid == 4 ? "System" : $"Process {pid}", path = "";
                    try { using var proc = Process.GetProcessById(pid); name = proc.ProcessName; }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
                    // The limited query right reads the image of service processes too, where MainModule is denied.
                    if (pid != Darkwire.Engine.FlowAttribution.SystemProcessId) path = Darkwire.Engine.FlowAttribution.ReadProcess(pid, 0)?.ImagePath ?? "";
                    process = (name, path); processes[pid] = process;
                }
                // SYN_SENT / SYN_RCVD expose handshake direction. Established-only observations remain unknown.
                var direction = DirectionForTcpState(row.State);
                var services = hosted.GetValueOrDefault(pid) ?? [];
                var service = services.Count == 1 ? services[0] : Darkwire.Engine.FlowAttribution.TaggedService(row, services) ?? "";
                result.Add(new(process.Item1, process.Item2, pid, row.RemoteAddress!.ToString(), row.RemotePort, row.LocalPort, "TCP", direction,
                    Service: service, LocalAddress: row.LocalAddress.ToString(), State: row.State == 5 ? "Established" : row.State == 8 ? "Closing" : "Connecting",
                    HostedServices: string.Join(", ", services)));
            }
        return result.OrderBy(c => c.Application).ThenBy(c => c.RemoteAddress).ThenBy(c => c.LocalPort).ToList();
    }
    // MIB_TCP_STATE values from the Windows SDK's tcpmib.h.
    public static TrafficDirection DirectionForTcpState(int state) => state switch
    {
        3 => TrafficDirection.Outbound, // MIB_TCP_STATE_SYN_SENT
        4 => TrafficDirection.Inbound,  // MIB_TCP_STATE_SYN_RCVD
        _ => TrafficDirection.Unknown
    };
    public static (long Received, long Sent) Bytes()
    {
        long received = 0, sent = 0;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        { var stats = nic.GetIPStatistics(); received += stats.BytesReceived; sent += stats.BytesSent; }
        return (received, sent);
    }
}

public sealed record FirewallImport(List<FirewallRule> Rules, int RestrictedCount, Dictionary<int, bool> ProfileStates, List<string> Errors);
public static class WindowsFirewall
{
    // Read errors (Group Policy, a changing store) are shown with the import; the service refuses takeover on them.
    public static FirewallImport Import()
    {
        var result = Darkwire.Engine.WindowsFirewallReader.Read();
        return new(result.Rules, result.Rules.Count(r => RuleEnforcement.NeedsConsent(r) || r.Enabled && r.Import == ImportOutcome.Refused), result.Profiles, result.Errors);
    }
}
public static class SecureConfig
{
    public static string Unprotect(string encrypted)
    {
        // Existing desktop imports used DPAPI with no optional entropy.
        var bytes = DpapiSecrets.Unprotect(Convert.FromBase64String(encrypted), "");
        try { return new System.Text.UTF8Encoding(false, true).GetString(bytes); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
    public static string Protect(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        try { return Convert.ToBase64String(DpapiSecrets.Protect(bytes, "", description: "Darkwire VPN configuration")); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
}

public static class Downloads
{
    public static async Task<string> Text(string url, int maxBytes)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo)) throw new InvalidDataException("Enter an HTTPS URL without embedded credentials.");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(90) };
        using var cancellation = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(90));
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > maxBytes) throw new InvalidDataException("The download is too large.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token);
        using var output = new MemoryStream(); var buffer = new byte[65536]; int read;
        while ((read = await stream.ReadAsync(buffer, cancellation.Token)) > 0)
        { if (output.Length + read > maxBytes) throw new InvalidDataException("The download is too large."); await output.WriteAsync(buffer.AsMemory(0, read), cancellation.Token); }
        output.Position = 0;
        if (uri.AbsolutePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
        {
            using var gzip = new GZipStream(output, CompressionMode.Decompress); using var plain = new MemoryStream();
            while ((read = await gzip.ReadAsync(buffer, cancellation.Token)) > 0)
            { if (plain.Length + read > maxBytes) throw new InvalidDataException("The expanded download is too large."); await plain.WriteAsync(buffer.AsMemory(0, read), cancellation.Token); }
            return Encoding.UTF8.GetString(plain.ToArray());
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }
}
