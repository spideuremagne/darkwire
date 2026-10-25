using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Darkwire.Service;

/// <summary>
/// Owns demand-start WireGuard services and SYSTEM-encrypted runtime configurations. Starting a
/// backend is not traffic routing: the caller must first commit guards and later install scoped routes.
/// </summary>
internal sealed class WireGuardBackend
{
    internal static string Executable => TunnelBackends.Executable(AppContext.BaseDirectory, "WireGuard");
    private static string RuntimeDirectory => Path.Combine(ServiceHost.StateDirectory, "Tunnels");
    /// <summary>What a started tunnel leaves on record until it stops: its profile, credentials and name (version 1 had the first name).</summary>
    private sealed record Intent(int Version, Guid Id, Guid Revision, string? Name = null);

    /// <summary>
    /// The names a profile's tunnel takes in turn. WireGuard names its interface and its service after the tunnel and gives
    /// the interface the same identity for the same name and keys, while Windows removes a stopped tunnel's interface only once
    /// nothing uses it, which can take minutes; a tunnel started again takes a name its predecessors left free. The first is
    /// the profile ID; the others replace its last digit with a letter no ID has, so none is ever another profile's first.
    /// </summary>
    internal static IReadOnlyList<string> Names(Guid id)
    {
        var first = id != Guid.Empty ? id.ToString("N") : throw new InvalidDataException("A tunnel ID is required.");
        return [first, first[..31] + "x", first[..31] + "y"];
    }

    /// <summary>A tunnel's SCM service; its unrestricted service SID identifies the backend's sockets to WFP.</summary>
    internal static string ServiceName(string name) => "WireGuardTunnel$" + name;

    /// <summary>
    /// Whether a filter is one of the permits a WireGuard tunnel service adds for itself, for a tunnel with one of
    /// <paramref name="serviceSids"/>. WireGuard's firewall, which it enables with every tunnel, permits the tunnel service
    /// everything, in and out, under a provider of its own and clearing the action right, so no block in another sublayer
    /// reaches it. Those permits have exactly two conditions: the application, here the bundled wireguard.exe, and a
    /// descriptor that grants only that tunnel's service SID. A separately installed WireGuard's, or any other program's,
    /// do not match.
    /// </summary>
    internal static bool OwnPermit(FilterRecord filter, string applicationId, IReadOnlySet<string> serviceSids) =>
        filter.Conditions.Count == 2
        && filter.Conditions.Any(c => c is { Field: "ALE_APP_ID", Match: "EQUAL" } && c.Value.Equals(applicationId, StringComparison.OrdinalIgnoreCase))
        && filter.Conditions.Any(c => c is { Field: "ALE_USER_ID", Match: "EQUAL" } && GrantsOnly(c.Value, serviceSids));

    private static bool GrantsOnly(string descriptor, IReadOnlySet<string> sids)
    {
        try
        {
            var entries = new RawSecurityDescriptor(descriptor).DiscretionaryAcl;
            return entries is { Count: > 0 } && entries.Cast<GenericAce>().All(entry =>
                entry is CommonAce { AceQualifier: AceQualifier.AccessAllowed, IsCallback: false } allow && sids.Contains(allow.SecurityIdentifier.Value));
        }
        catch (Exception error) when (error is ArgumentException or System.ComponentModel.Win32Exception) { return false; }
    }
    private static string ConfigurationPath(string name) => Path.Combine(RuntimeDirectory, name + ".conf.dpapi");
    private static string IntentPath(string name) => Path.Combine(RuntimeDirectory, name + ".wireguard.json");

    /// <param name="config">The stored configuration, read with this revision.</param>
    /// <param name="runtime">What WireGuard runs: the normalized configuration with its peers' host names looked up.</param>
    /// <param name="shared">
    /// Addresses of the profile another tunnel's interface holds. Windows gives an address to one interface only, so WireGuard
    /// leaves them off its interface, which sends from them where they are, and takes one over once no interface holds it.
    /// </param>
    public async Task<Instance> StartAsync(Guid id, Guid revision, ParsedVpnConfiguration config, string runtime, IReadOnlySet<IPAddress> shared,
        Action verifyPersistentGuards, CancellationToken cancellation)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem) throw new UnauthorizedAccessException("Tunnel backends require the LocalSystem service.");
        ProtectedStorage.Verify(); verifyPersistentGuards();
        if (!File.Exists(Executable)) throw new IOException("The protected WireGuard backend is not installed.");
        if (config.Kind != "WireGuard") throw new InvalidDataException("This profile is not a WireGuard configuration.");
        var prefixes = InterfacePrefixes(config.NormalizedConfiguration);
        var owned = prefixes.Select(p => p.Address).Where(a => !shared.Contains(a)).ToArray();
        Directory.CreateDirectory(RuntimeDirectory);
        var name = await FreeNameAsync(Names(id), Holding, other => File.Exists(IntentPath(other)) || File.Exists(ConfigurationPath(other)), LeftoverWait, cancellation).ConfigureAwait(false);
        var previous = NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        WriteNew(IntentPath(name), JsonSerializer.SerializeToUtf8Bytes(new Intent(2, id, revision, name)));
        OwnedTunnelService? service = null; WindowsFlowProcess? process = null;
        try
        {
            var plaintext = Encoding.UTF8.GetBytes(shared.Count == 0 ? runtime : WithoutAddresses(runtime, shared));
            try { WriteNew(ConfigurationPath(name), DpapiSecrets.Protect(plaintext, "", description: name)); }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
            service = OwnedTunnelService.Create(ServiceName(name), Executable, ConfigurationPath(name));
            var pid = await service.StartAsync(cancellation).ConfigureAwait(false);
            process = WindowsFlowProcess.Open((ulong)pid);
            if (!process.ApplicationPath.Equals(Executable, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Unexpected WireGuard service executable.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(30));
            while (true)
            {
                if (!process.IsAlive || !service.IsRunning(pid)) throw new IOException("WireGuard exited before its interface was ready.");
                var network = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(n => n.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && !previous.Contains(n.Id));
                if (network?.OperationalStatus == OperationalStatus.Up && Guid.TryParse(network.Id, out var interfaceId))
                {
                    var actual = network.GetIPProperties().UnicastAddresses.Select(a => a.Address).ToArray();
                    if (owned.All(a => actual.Contains(a)))
                    {
                        var instance = new Instance(id, name, interfaceId, prefixes, shared, config.Networks, config.DnsServers, service, process);
                        instance.Maintain();
                        return instance;
                    }
                }
                await Task.Delay(200, timeout.Token).ConfigureAwait(false);
            }
        }
        catch
        {
            try
            {
                if (service is not null) await service.StopAndDeleteAsync(CancellationToken.None).ConfigureAwait(false);
                // If Create failed due to an existing name, leave the intent for exact ownership verification.
                if (service is not null) { File.Delete(ConfigurationPath(name)); File.Delete(IntentPath(name)); }
            }
            finally { process?.Dispose(); service?.Dispose(); }
            throw;
        }
    }
    /// <summary>How long a start waits for one of the profile's names to be free while every one is taken.</summary>
    internal static readonly TimeSpan LeftoverWait = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The first of a profile's names free now: no interface carries it, and no tunnel by it is on record. While every one is
    /// taken, as when Windows has yet to remove the interfaces earlier tunnels left, the start waits; past the limit it fails,
    /// saying what holds them.
    /// </summary>
    /// <param name="holding">The interface carrying a name, described; null when none does.</param>
    /// <param name="recorded">Whether a tunnel by the name is on record, its files not yet removed.</param>
    internal static async Task<string> FreeNameAsync(IReadOnlyList<string> names, Func<string, string?> holding, Func<string, bool> recorded, TimeSpan limit, CancellationToken cancellation)
    {
        string? Taken(string name) => holding(name) ?? (recorded(name) ? "an earlier tunnel's records" : null);
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellation); wait.CancelAfter(limit);
        while (true)
        {
            foreach (var name in names) if (Taken(name) is null) return name;
            try { await Task.Delay(250, wait.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
            {
                throw new InvalidOperationException($"Windows still has the network interfaces of this profile's earlier tunnels ({string.Join("; ", names.Select(Taken).Where(t => t is not null))}) after {limit.TotalSeconds:N0} seconds, so a new one cannot start yet.");
            }
        }
    }

    private static string? Holding(string name) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) is { } network ? $"{network.Description}, {network.OperationalStatus}" : null;

    internal static IReadOnlyList<IPAddress> InterfaceAddresses(string normalized) => [.. InterfacePrefixes(normalized).Select(p => p.Address)];

    /// <summary>The interface's addresses with their prefix lengths, a whole address where the profile gives none.</summary>
    internal static IReadOnlyList<(IPAddress Address, int Prefix)> InterfacePrefixes(string normalized)
    {
        var prefixes = new List<(IPAddress Address, int Prefix)>();
        foreach (var raw in normalized.Split('\n'))
        {
            var line = raw.Trim(); if (line == "[Peer]") break;
            var separator = line.IndexOf('=');
            if (separator < 0 || !line[..separator].Trim().Equals("Address", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var part in line[(separator + 1)..].Split(','))
            {
                var pieces = part.Trim().Split('/');
                if (!IPAddress.TryParse(pieces[0], out var address) || !VpnConfiguration.IsUnicast(address) || address.IsIPv6LinkLocal)
                    throw new InvalidDataException("WireGuard requires unicast tunnel interface addresses.");
                var whole = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32; var length = whole;
                if (pieces.Length > 2 || pieces.Length == 2 && (!int.TryParse(pieces[1], NumberStyles.None, CultureInfo.InvariantCulture, out length) || length > whole))
                    throw new InvalidDataException("Invalid WireGuard IP prefix.");
                if (!prefixes.Any(p => p.Address.Equals(address))) prefixes.Add((address, length));
            }
        }
        if (prefixes.Count == 0) throw new InvalidDataException("WireGuard has no tunnel address.");
        return prefixes;
    }

    /// <summary>The runtime configuration without some of its interface addresses, and without the Address line once none is left.</summary>
    internal static string WithoutAddresses(string runtime, IReadOnlySet<IPAddress> omitted)
    {
        var output = new List<string>(); var peer = false;
        foreach (var raw in runtime.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line is "[Interface]" or "[Peer]") peer = line == "[Peer]";
            var separator = line.IndexOf('=');
            if (peer || separator < 0 || !line[..separator].Trim().Equals("Address", StringComparison.OrdinalIgnoreCase)) { output.Add(raw); continue; }
            var kept = line[(separator + 1)..].Split(',').Select(p => p.Trim()).Where(p => !IPAddress.TryParse(p.Split('/')[0], out var address) || !omitted.Contains(address)).ToArray();
            if (kept.Length > 0) output.Add($"{line[..separator].TrimEnd()} = {string.Join(", ", kept)}{raw[line.Length..]}");
        }
        return string.Join('\n', output);
    }
    public static async Task RecoverOrphansAsync(CancellationToken cancellation)
    {
        if (!Directory.Exists(RuntimeDirectory)) return;
        ProtectedStorage.Verify();
        var intents = Directory.EnumerateFiles(RuntimeDirectory, "*.wireguard.json").Take(101).ToArray();
        if (intents.Length > 100) throw new InvalidDataException("Too many tunnel recovery records.");
        foreach (var path in intents)
        {
            if (new FileInfo(path).Length > 2048) throw new InvalidDataException("Invalid tunnel recovery record.");
            var intent = JsonSerializer.Deserialize<Intent>(File.ReadAllText(path)) ?? throw new InvalidDataException("Empty tunnel recovery record.");
            if (intent.Version is not (1 or 2) || intent.Id == Guid.Empty || intent.Revision == Guid.Empty || (intent.Version == 1) != (intent.Name is null))
                throw new InvalidDataException("Invalid tunnel recovery identity.");
            var name = intent.Name ?? Names(intent.Id)[0];
            if (!Names(intent.Id).Contains(name) || !path.Equals(IntentPath(name), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Invalid tunnel recovery identity.");
            using var service = OwnedTunnelService.OpenExisting(ServiceName(name), Executable, ConfigurationPath(name));
            if (service is not null) await service.StopAndDeleteAsync(cancellation).ConfigureAwait(false);
            File.Delete(ConfigurationPath(name)); File.Delete(path);
        }
    }
    private static void WriteNew(string path, byte[] data)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        file.Write(data); file.Flush(true);
    }
    internal sealed class Instance(Guid id, string name, Guid interfaceId, IReadOnlyList<(IPAddress Address, int Prefix)> prefixes, IReadOnlySet<IPAddress> shared,
        IReadOnlyList<NetPrefix> networks, IReadOnlyList<IPAddress> resolvers, OwnedTunnelService service, WindowsFlowProcess process) : ITunnelInstance
    {
        private bool stopped;
        public Guid ProfileId => id;
        public IReadOnlyList<TunnelRoute> Routes { get; } = prefixes.Select(p => new TunnelRoute(interfaceId, p.Address)).ToArray();
        public IReadOnlyList<IPAddress> Shared { get; } = [.. prefixes.Select(p => p.Address).Where(shared.Contains)];
        public IReadOnlyList<NetPrefix> Networks => networks;
        public IReadOnlyList<IPAddress> Resolvers => resolvers;
        public bool Healthy
        {
            get
            {
                if (stopped || !process.IsAlive || !service.IsRunning(process.Id)) return false;
                var network = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(n => Guid.TryParse(n.Id, out var current) && current == interfaceId && n.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                return network?.OperationalStatus == OperationalStatus.Up && TunnelAddresses.Held(network, prefixes.Select(p => p.Address), shared);
            }
        }

        public void Maintain()
        {
            if (!stopped) TunnelAddresses.Keep(interfaceId, prefixes.Where(p => shared.Contains(p.Address)));
        }

        // The adapter's device, looked up again after a read through it fails, and why reading last failed, logged once.
        private string? device, failure;
        public PeerTraffic? Peers
        {
            get
            {
                if (stopped) return null;
                try
                {
                    if ((device ??= WireGuardPeers.Device(name)) is not { } path) throw new InvalidDataException("WireGuard's adapter was not found.");
                    var traffic = WireGuardPeers.Read(path);
                    failure = null;
                    return traffic;
                }
                catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException)
                {
                    device = null;
                    if (failure != error.Message) { failure = error.Message; ServiceHost.Log($"WireGuard's handshakes on tunnel {name} could not be read: {error.Message}"); }
                    return null;
                }
            }
        }
        // The supervisor has the router abandon the tunnel's flows before it disposes the instance.
        public async ValueTask DisposeAsync()
        {
            if (stopped) return; stopped = true;
            try
            {
                await service.StopAndDeleteAsync(CancellationToken.None).ConfigureAwait(false);
                File.Delete(ConfigurationPath(name)); File.Delete(IntentPath(name));
            }
            finally { process.Dispose(); service.Dispose(); }
        }
    }
}
