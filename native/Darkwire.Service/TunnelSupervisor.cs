using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Service;

/// <summary>A VPN profile the router must run, with the credential revision the policy was admitted with.</summary>
public sealed record TunnelDemand(Guid ProfileId, string Kind, Guid Revision);

internal enum TunnelState { Starting, Up, Failed }

/// <summary>What the router may use of a profile's tunnel now. Only an Up tunnel has an egress, and a closed egress carries nothing.</summary>
internal sealed record TunnelView(Guid ProfileId, TunnelState State, TunnelEgress? Egress);

internal interface ITunnelDirectory
{
    TunnelView? Find(Guid profile);
    /// <summary>The interface belongs to a VPN tunnel and is never a physical egress.</summary>
    bool Owns(ulong luid);
    /// <summary>The router sent a flow through the profile's tunnel; called while the router's lock may be held.</summary>
    void Used(Guid profile) { }
}

/// <summary>A started backend: its interface and addresses, what it carries, its resolvers, and whether it still works.</summary>
internal interface ITunnelInstance : IAsyncDisposable
{
    Guid ProfileId { get; }
    IReadOnlyList<TunnelRoute> Routes { get; }
    /// <summary>Its addresses another tunnel's interface holds: its own sends from them over Windows' weak host model.</summary>
    IReadOnlyList<IPAddress> Shared => [];
    IReadOnlyList<NetPrefix> Networks { get; }
    IReadOnlyList<IPAddress> Resolvers { get; }
    bool Healthy { get; }
    /// <summary>Puts back what the tunnel needs of the system, such as the addresses it shares; called before each health check.</summary>
    void Maintain() { }
    /// <summary>What WireGuard counts for the tunnel's servers, handshakes included; null where the backend cannot tell.</summary>
    PeerTraffic? Peers => null;
}

internal interface ITunnelBackends
{
    Task<ITunnelInstance> StartAsync(TunnelDemand demand, CancellationToken cancellation);
}

/// <summary>Interface lookup, routes and traffic counters on a tunnel's own interface.</summary>
internal interface ITunnelInterfaces
{
    (ulong Luid, uint Index) Resolve(Guid interfaceId);
    void AddRoute(ulong luid, IPAddress network, int prefix, uint metric);
    void DeleteRoute(ulong luid, IPAddress network, int prefix);
    /// <summary>Takes an address off the interface, ending every connection still bound to it.</summary>
    void DeleteAddress(ulong luid, IPAddress address) { }
    /// <summary>Bytes the interface has sent and received; null once it is gone.</summary>
    (long Sent, long Received)? Counters(Guid interfaceId) => null;
}

internal sealed class NativeTunnelInterfaces : ITunnelInterfaces
{
    public static readonly NativeTunnelInterfaces Instance = new();
    public (ulong Luid, uint Index) Resolve(Guid interfaceId) => TunnelNetwork.Interface(interfaceId);
    public void AddRoute(ulong luid, IPAddress network, int prefix, uint metric) => TunnelNetwork.AddRoute(luid, network, prefix, metric);
    public void DeleteRoute(ulong luid, IPAddress network, int prefix) => TunnelNetwork.DeleteRoute(luid, network, prefix);
    public void DeleteAddress(ulong luid, IPAddress address) => TunnelNetwork.DeleteAddress(luid, address);
    public (long Sent, long Received)? Counters(Guid interfaceId)
    {
        var nic = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => Guid.TryParse(n.Id, out var id) && id == interfaceId);
        if (nic is null) return null;
        var statistics = nic.GetIPStatistics();
        return (statistics.BytesSent, statistics.BytesReceived);
    }
}

/// <summary>The protected WireGuard backend, started with service-stored credentials.</summary>
internal sealed class TunnelBackends(IVpnProfileVault vault, Action verifyGuards) : ITunnelBackends
{
    private Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? resolver;
    private Func<IReadOnlyList<IPAddress>, IDisposable>? pin;
    private readonly AddressClaims claims = new();
    // The interfaces of the backends running now; an address one of them holds is shared rather than taken.
    private readonly ConcurrentDictionary<Guid, Guid> adapters = new();

    /// <summary>
    /// Looks up endpoint host names for the backends, so each runs with addresses whose routes the service holds: on the
    /// physical network while a default profile confines the Windows DNS client to its tunnel, through Windows otherwise.
    /// Null leaves names to the backends. Read as each backend starts.
    /// </summary>
    public Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? Resolver { get => Volatile.Read(ref resolver); set => Volatile.Write(ref resolver, value); }

    /// <summary>Routes a backend's server addresses over the physical network until the handle is disposed.</summary>
    public Func<IReadOnlyList<IPAddress>, IDisposable>? Pin { get => Volatile.Read(ref pin); set => Volatile.Write(ref pin, value); }

    /// <summary>
    /// The configuration a backend runs: the stored one, with endpoint host names replaced by addresses when a resolver is
    /// given, so the backend never resolves a name itself. A name that does not resolve fails the start.
    /// </summary>
    public static async Task<string> RuntimeConfigurationAsync(ParsedVpnConfiguration configuration, Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? resolve,
        CancellationToken cancellation) => (await PrepareAsync(configuration, resolve, cancellation).ConfigureAwait(false)).Runtime;

    /// <summary>
    /// The runtime configuration, and every server address the backend may send to: the addresses the profile names, and
    /// all those looked up for its names.
    /// </summary>
    public static async Task<(string Runtime, IReadOnlyList<IPAddress> Peers)> PrepareAsync(ParsedVpnConfiguration configuration,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? resolve, CancellationToken cancellation)
    {
        var resolved = new Dictionary<string, IReadOnlyList<IPAddress>>(StringComparer.OrdinalIgnoreCase);
        List<IPAddress> peers = [];
        foreach (var (host, _) in VpnConfiguration.Endpoints(configuration.Endpoint))
        {
            if (IPAddress.TryParse(host, out var literal)) { peers.Add(literal); continue; }
            if (resolve is null || resolved.ContainsKey(host)) continue;
            var addresses = resolved[host] = await resolve(host, cancellation).ConfigureAwait(false);
            peers.AddRange(addresses.Where(a => VpnConfiguration.IsUnicast(a) && !a.IsIPv6LinkLocal));
        }
        var runtime = resolve is null ? configuration.NormalizedConfiguration
            : VpnConfiguration.ResolveEndpoints(configuration.Kind, configuration.NormalizedConfiguration, host => resolved.GetValueOrDefault(host) ?? []);
        return (runtime, [.. peers.Distinct()]);
    }

    public static string Executable(string serviceDirectory, string kind) => kind == "WireGuard"
        ? Path.Combine(serviceDirectory, "Backends", "WireGuard", "wireguard.exe")
        : throw new InvalidDataException(VpnConfiguration.Unsupported(kind));

    public static bool Installed(string kind) => kind == "WireGuard" && File.Exists(Executable(AppContext.BaseDirectory, kind));

    /// <summary>
    /// Starts a profile's backend once its server addresses are routed over the physical network: WireGuard's driver chooses
    /// its routes from the system table, where Darkwire's capture routes would otherwise carry its own transport into the
    /// router, and under a default profile into the very tunnel it carries. A profile whose address another running tunnel
    /// holds, as profiles from one provider often do, shares it. Claims on an address take turns, so each start sees where
    /// the others put theirs.
    /// </summary>
    public async Task<ITunnelInstance> StartAsync(TunnelDemand demand, CancellationToken cancellation)
    {
        if (demand.Kind != "WireGuard") throw new InvalidDataException(VpnConfiguration.Unsupported(demand.Kind));
        var configuration = vault.Read(demand.ProfileId, demand.Revision);
        if (configuration.Kind != demand.Kind) throw new InvalidDataException($"This profile is not a {demand.Kind} configuration.");
        var (runtime, peers) = await PrepareAsync(configuration, Resolver, cancellation).ConfigureAwait(false);
        var pinned = Pin?.Invoke(peers);
        try
        {
            IPAddress[] addresses = [.. WireGuardBackend.InterfaceAddresses(configuration.NormalizedConfiguration)];
            ITunnelInstance instance;
            using (await claims.ClaimAsync(addresses, cancellation).ConfigureAwait(false))
            {
                var shared = Shared(addresses, TunnelNetwork.Holder, adapters.ContainsKey);
                instance = Register(await new WireGuardBackend().StartAsync(demand.ProfileId, demand.Revision, configuration, runtime, shared, verifyGuards, cancellation).ConfigureAwait(false));
            }
            var interfaces = instance.Routes.Select(r => r.InterfaceId).Distinct().ToArray();
            return new Running(instance, pinned, () => { foreach (var adapter in interfaces) adapters.TryRemove(adapter, out _); });
        }
        catch { pinned?.Dispose(); throw; }
    }

    // Under the start's claim, so the next start claiming one of its addresses sees this interface as a tunnel's.
    private ITunnelInstance Register(ITunnelInstance instance)
    {
        foreach (var route in instance.Routes) adapters[route.InterfaceId] = instance.ProfileId;
        return instance;
    }

    /// <summary>
    /// Of a profile's addresses, those another of these backends' tunnels holds now. Windows gives an address to one interface
    /// only, so the profile shares them rather than take them. An address that an interface outside Darkwire holds while it
    /// is up refuses the start; WireGuard clears it from an interface that is down as it starts.
    /// </summary>
    internal static IReadOnlySet<IPAddress> Shared(IEnumerable<IPAddress> addresses, Func<IPAddress, AddressHolder?> holder, Func<Guid, bool> tunnel)
    {
        HashSet<IPAddress> shared = [];
        foreach (var address in addresses)
        {
            if (holder(address) is not { } held) continue;
            if (tunnel(held.Interface)) shared.Add(address);
            else if (held.Up) throw new InvalidOperationException($"The network interface {held.Name} already has this profile's address {address}, and Windows gives an address to one interface only.");
        }
        return shared;
    }

    /// <summary>A started backend: once it has stopped, its interface leaves the running ones and its server routes go.</summary>
    private sealed class Running(ITunnelInstance inner, IDisposable? routes, Action stopped) : ITunnelInstance
    {
        public Guid ProfileId => inner.ProfileId;
        public IReadOnlyList<TunnelRoute> Routes => inner.Routes;
        public IReadOnlyList<IPAddress> Shared => inner.Shared;
        public IReadOnlyList<NetPrefix> Networks => inner.Networks;
        public IReadOnlyList<IPAddress> Resolvers => inner.Resolvers;
        public bool Healthy => inner.Healthy;
        public void Maintain() => inner.Maintain();
        public PeerTraffic? Peers => inner.Peers;
        public async ValueTask DisposeAsync()
        {
            try { await inner.DisposeAsync().ConfigureAwait(false); }
            finally { stopped(); routes?.Dispose(); }
        }
    }

    /// <summary>
    /// What a profile's backend may send to its peers around the tunnel: UDP, scoped to the SID of the service each of the
    /// profile's tunnel names runs as. Only the peers' ports, and their addresses when the profile names addresses.
    /// </summary>
    public static IEnumerable<TunnelEndpoint> Endpoints(string serviceDirectory, string kind, Guid profile, string summary)
    {
        var executable = Executable(serviceDirectory, kind);
        var services = WireGuardBackend.Names(profile).Select(WireGuardBackend.ServiceName).ToArray();
        foreach (var (host, port) in VpnConfiguration.Endpoints(summary))
        {
            var peer = IPAddress.TryParse(host, out var address) ? address + (address.AddressFamily == AddressFamily.InterNetworkV6 ? "/128" : "/32") : null;
            foreach (var service in services) yield return new(executable, service, 17, peer, port);
        }
    }
}

/// <summary>
/// Runs the VPN profiles the policy routes through, only while the router runs. Each profile starts with its protected
/// backend and service-stored credentials, gets routes on its own interface so relay sockets pinned there reach what it
/// carries, and is health-checked. A tunnel that stops working is closed at once, so its flows are refused and withdrawn
/// instead of leaving anywhere else, then restarted with backoff; one whose server stops answering is reconnected, less often
/// each time until the server answers. A tunnel that comes up, or whose address another tunnel takes or gives back, is
/// checked end to end, and one that carries nothing back is restarted with every tunnel sharing its address. Changes are
/// reported outside the lock.
/// </summary>
internal sealed class TunnelSupervisor : ITunnelDirectory, IAsyncDisposable
{
    /// <summary>Tunnel routes tie Darkwire's capture routes on prefix length and lose on metric, so only sockets pinned to the tunnel use them.</summary>
    public const uint RouteMetric = 4096;
    public static readonly TimeSpan FirstRetry = TimeSpan.FromSeconds(2), LastRetry = TimeSpan.FromMinutes(1), StopTimeout = TimeSpan.FromSeconds(30);
    /// <summary>Rate samples kept per tunnel: five minutes of two-second health checks.</summary>
    public const int RateSamples = 150;
    /// <summary>
    /// After its server has answered, a tunnel counts as silent once it has sent for this long with nothing back and no pause
    /// longer than <see cref="SilenceGap"/>; a lone send, such as the last acknowledgment of a closed connection, is no silence.
    /// </summary>
    public static readonly TimeSpan SilentAfter = TimeSpan.FromSeconds(4), SilenceGap = TimeSpan.FromSeconds(10);
    /// <summary>
    /// A running tunnel whose server has answered nothing it sent for this long, since it came up or since the server fell
    /// silent, is reconnected: a new backend, so a new local port and handshake, which mends a path that dropped the old one.
    /// Each further reconnect before an answer waits twice as long, up to <see cref="LastReconnect"/>.
    /// </summary>
    public static readonly TimeSpan FirstReconnect = TimeSpan.FromSeconds(45), LastReconnect = TimeSpan.FromMinutes(10);
    /// <summary>
    /// WireGuard renews a tunnel's session every two minutes while it sends and drops the session's keys after three. Sending
    /// on with no handshake completed for that long, since the last or since the tunnel came up, goes unanswered.
    /// </summary>
    public static readonly TimeSpan HandshakeSilence = TimeSpan.FromMinutes(3);
    /// <summary>
    /// A tunnel's end-to-end check asks its DNS server through it up to <see cref="CheckTries"/> times, <see cref="CheckRetry"/>
    /// apart, and passes at its first answer, or once the tunnel has received <see cref="CheckReceived"/> bytes meanwhile, as one
    /// carrying traffic whose server ignores the question does. A tunnel whose check fails is restarted with every tunnel sharing
    /// its address, all of them gone before any starts again, so the first to start holds the address afresh; while checks go on
    /// failing, each further restart waits from <see cref="FirstReconnect"/>, twice as long each time, up to <see cref="LastReconnect"/>.
    /// </summary>
    public const int CheckTries = 4, CheckReceived = 4_096;
    public static readonly TimeSpan CheckRetry = TimeSpan.FromSeconds(2);
    private static readonly (IPAddress Network, int Prefix)[] Halves4 = [(IPAddress.Parse("0.0.0.0"), 1), (IPAddress.Parse("128.0.0.0"), 1)],
        Halves6 = [(IPAddress.Parse("::"), 1), (IPAddress.Parse("8000::"), 1)], Whole4 = [(IPAddress.Any, 0)], Whole6 = [(IPAddress.IPv6Any, 0)];
    private readonly object gate = new();
    // Health checks wait while a leaving tunnel's addresses pass to a tunnel sharing them, which would fail one in between.
    private readonly object handover = new();
    private readonly ITunnelBackends backends;
    private readonly ITunnelInterfaces interfaces;
    private readonly Action<Guid> changed;
    private readonly Action<ulong>? released;
    private readonly Func<Guid, TunnelEgress, bool?>? check;
    private readonly TimeProvider clock;
    private readonly bool ipv6;
    private readonly Dictionary<Guid, Slot> slots = [];
    // A replaced profile's successor starts only once the old backend and its routes are gone.
    private readonly Dictionary<Guid, Task> retiring = [];
    private readonly ConcurrentDictionary<Guid, TunnelView> views = new();
    private readonly ConcurrentDictionary<ulong, ITunnelInstance> owned = new();
    private readonly List<Task> work = [];
    private Task? disposal;
    private bool stopped;

    /// <param name="changed">Told each time a profile's state changes; called outside the supervisor's lock.</param>
    /// <param name="ipv6">Darkwire captures IPv6, so tunnels may carry it.</param>
    /// <param name="released">
    /// Told a tunnel's interface, by its LUID, as the tunnel goes away, to close whatever Darkwire still has open through it;
    /// called outside the supervisor's lock.
    /// </param>
    /// <param name="check">
    /// Asks a profile's DNS server a question through its tunnel: true once it answers, false when nothing comes back, null when
    /// it names none to ask. Called off the lock, one try at a time for each tunnel; without it, a tunnel counts as checked once up.
    /// </param>
    public TunnelSupervisor(ITunnelBackends backends, ITunnelInterfaces interfaces, Action<Guid> changed, bool ipv6, TimeProvider? clock = null, Action<ulong>? released = null,
        Func<Guid, TunnelEgress, bool?>? check = null)
    { this.backends = backends; this.interfaces = interfaces; this.changed = changed; this.ipv6 = ipv6; this.clock = clock ?? TimeProvider.System; this.released = released; this.check = check; }

    public TunnelView? Find(Guid profile) => views.GetValueOrDefault(profile);
    public bool Owns(ulong luid) => owned.ContainsKey(luid);

    /// <summary>
    /// When the router first sent a flow through each tunnel since it came up. WireGuard's driver counts neither its handshakes
    /// nor data it holds back for want of one, so a tunnel whose server never answers would show nothing sent; this shows it was tried.
    /// </summary>
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> routed = new();
    /// <summary>
    /// How many flows the router has sent through each tunnel. Once a silent server's session lapses, WireGuard holds back
    /// all data for a handshake and counts none of it sent, so the flows the router goes on sending are what show the tunnel
    /// still in use, unanswered.
    /// </summary>
    private readonly ConcurrentDictionary<Guid, long> tries = new();
    public void Used(Guid profile)
    {
        if (!views.TryGetValue(profile, out var view) || view.State != TunnelState.Up) return;
        routed.TryAdd(profile, clock.GetUtcNow());
        tries.AddOrUpdate(profile, 1, (_, count) => count + 1);
    }

    public IReadOnlyList<TunnelStatus> Status()
    {
        lock (gate)
            return slots.Values.OrderBy(s => s.Demand.ProfileId).Select(s => new TunnelStatus(s.Demand.ProfileId, s.Demand.Kind, s.State.ToString(), s.Since,
                s.Egress?.Index, s.Egress?.Sources.Select(a => a.ToString()).ToArray(), s.Error, s.Egress?.Resolvers.Select(a => a.ToString()).ToArray(),
                s.State == TunnelState.Up ? s.Sent : 0, s.State == TunnelState.Up ? s.Received : 0, s.State == TunnelState.Up ? s.LastReceived : null,
                s.State == TunnelState.Up && routed.TryGetValue(s.Demand.ProfileId, out var first) ? first : null,
                s.Egress is { Shared.Count: > 0 } egress ? [.. egress.Shared.Select(a => a.ToString())] : null,
                s.State == TunnelState.Up && s.Rates.Count > 0 ? [.. s.Rates.Select(r => r.In)] : null,
                s.State == TunnelState.Up && s.Rates.Count > 0 ? [.. s.Rates.Select(r => r.Out)] : null,
                s.State == TunnelState.Up ? s.Silent : null, s.Reconnects, s.State == TunnelState.Up ? s.Checked : null,
                s.State == TunnelState.Up && s.CheckDue && s.CheckFailed is null, s.State == TunnelState.Up ? s.CheckFailed : null, s.CheckRestarts)).ToArray();
    }

    /// <summary>Checks every running tunnel end to end again, as when it came up; one that fails is restarted as then.</summary>
    public void Recheck()
    {
        lock (gate)
        {
            if (stopped || check is null) return;
            var now = clock.GetUtcNow();
            foreach (var slot in slots.Values) if (slot.State == TunnelState.Up) Recheck(slot, now);
        }
    }

    /// <summary>
    /// Reconnects a profile's tunnel at once, as asked from its card: a running one gets a new backend, its connections
    /// withdrawn and new ones held meanwhile, and a failed one starts again without waiting for its retry. Neither counts as a
    /// reconnect for silence. False when the profile has no tunnel, or is already starting.
    /// </summary>
    public bool Reconnect(Guid profile)
    {
        lock (gate)
        {
            if (stopped || !slots.TryGetValue(profile, out var slot)) return false;
            if (slot.State == TunnelState.Up) Detach(slot);
            else if (slot.State != TunnelState.Failed) return false;
            Launch(slot, slot.Teardown);
        }
        Notify(profile);
        return true;
    }

    /// <summary>Starts the demanded profiles, stops the others, and replaces any whose credential revision or kind changed.</summary>
    public void Sync(IReadOnlyList<TunnelDemand> demands)
    {
        List<Guid> notify = [];
        lock (gate)
        {
            if (stopped) return;
            var wanted = demands.GroupBy(d => d.ProfileId).ToDictionary(g => g.Key, g => g.Last());
            foreach (var slot in slots.Values.ToArray())
            {
                if (wanted.TryGetValue(slot.Demand.ProfileId, out var demand) && demand == slot.Demand) continue;
                Retire(slot); notify.Add(slot.Demand.ProfileId);
            }
            foreach (var demand in wanted.Values)
            {
                if (slots.ContainsKey(demand.ProfileId)) continue;
                var slot = slots[demand.ProfileId] = new(demand);
                Launch(slot, retiring.GetValueOrDefault(demand.ProfileId) ?? Task.CompletedTask);
                notify.Add(demand.ProfileId);
            }
        }
        foreach (var profile in notify.Distinct()) Notify(profile);
    }

    /// <summary>Checks running tunnels, counts their traffic, and restarts failed ones that are due. Call about every two seconds.</summary>
    public void Tick()
    {
        List<(Slot Slot, ITunnelInstance Instance)> running;
        lock (gate)
        {
            if (stopped) return;
            running = slots.Values.Where(s => s.State == TunnelState.Up).Select(s => (s, s.Instance!)).ToList();
        }
        // Health checks and counters read interface and service tables; never under the lock the router's lookups take.
        List<(Slot Slot, ITunnelInstance Instance)> lost;
        lock (handover)
        {
            foreach (var (_, instance) in running) Maintain(instance);
            lost = running.Where(r => !Healthy(r.Instance)).ToList();
        }
        var counted = running.Select(r => (r.Slot, r.Instance, Counters: Counters(r.Instance), Peers: Peers(r.Instance))).ToList();
        List<Guid> notify = [];
        lock (gate)
        {
            if (stopped) return;
            var now = clock.GetUtcNow();
            // Bytes since the tunnel came up; the time of the last increase tells whether its server still answers. The
            // rates between counts, kept for the last few minutes, chart its throughput.
            foreach (var (slot, instance, counters, peers) in counted)
            {
                if (counters is not { } read || !ReferenceEquals(slot.Instance, instance) || slot.Baseline is not { } baseline) continue;
                var received = Math.Max(0, read.Received - baseline.Received); var sent = Math.Max(0, read.Sent - baseline.Sent);
                var tried = tries.GetValueOrDefault(slot.Demand.ProfileId);
                var seconds = (now - slot.CountedAt).TotalSeconds;
                if (seconds > 0)
                {
                    slot.Rates.Enqueue(((long)(Math.Max(0, received - slot.Received) * 8 / seconds), (long)(Math.Max(0, sent - slot.Sent) * 8 / seconds)));
                    while (slot.Rates.Count > RateSamples) slot.Rates.Dequeue();
                }
                if (received > slot.Received) { slot.LastReceived = now; slot.Quiet = slot.QuietLast = slot.Silent = null; slot.Reconnects = 0; }
                // A flow the router sent through counts as sending too: WireGuard counts none while it waits for a handshake. Not
                // in a tunnel sharing another's address, whose answers to what the router sends it can come in through the other.
                else if ((sent > slot.Sent || tried > slot.Tried && slot.Egress is not { Shared.Count: > 0 }) && received > 0) Unheard(slot, now);
                if (peers is { } peer) Handshakes(slot, peer, now);
                slot.Sent = sent; slot.Received = received; slot.Tried = tried; slot.CountedAt = now;
            }
            foreach (var (slot, instance) in lost)
                if (slot.State == TunnelState.Up && ReferenceEquals(slot.Instance, instance) && Current(slot)) { Lose(slot, "The tunnel stopped working."); notify.Add(slot.Demand.ProfileId); }
            foreach (var (slot, instance, _, _) in counted)
                if (slot.State == TunnelState.Up && ReferenceEquals(slot.Instance, instance) && Current(slot) && Unanswered(slot) is { } quiet && now - quiet >= ReconnectAfter(slot.Reconnects))
                { Reconnect(slot); notify.Add(slot.Demand.ProfileId); }
            foreach (var slot in slots.Values)
                if (slot.State == TunnelState.Failed && now >= slot.RetryAt) { Launch(slot, slot.Teardown); notify.Add(slot.Demand.ProfileId); }
            // Checks due now ask in the background, one try at a time for each tunnel.
            foreach (var slot in slots.Values)
                if (slot is { State: TunnelState.Up, CheckDue: true, Checking: false, Instance: { } instance, Egress: { } egress } && now >= slot.CheckAt && Current(slot))
                {
                    if (slot.CheckFailures == 0) slot.CheckBaseline = slot.Received;
                    slot.Checking = true; var round = slot.CheckRound; var profile = slot.Demand.ProfileId;
                    Track(Task.Run(() => CheckDone(slot, instance, round, Probe(profile, egress))));
                }
        }
        foreach (var profile in notify) Notify(profile);
    }

    private bool? Probe(Guid profile, TunnelEgress egress)
    {
        try { return check!(profile, egress); }
        catch (Exception error) when (error is not OutOfMemoryException) { return false; }
    }

    /// <summary>Whether a try of the profile's check is out now.</summary>
    internal bool CheckInFlight(Guid profile) { lock (gate) return slots.TryGetValue(profile, out var slot) && slot.Checking; }

    /// <summary>
    /// A check's try came back. An answer, or traffic received meanwhile, passes the check and ends the restarts failed ones led
    /// to; a failed try leads to the next, and the last restarts the tunnel with every one sharing its address, unless its
    /// restarts must wait, when it is checked again once they may. A try from before a recheck or another backend counts for nothing.
    /// </summary>
    private void CheckDone(Slot slot, ITunnelInstance instance, int round, bool? answered)
    {
        List<Guid> notify = [];
        lock (gate)
        {
            if (!ReferenceEquals(slot.Instance, instance)) return;
            slot.Checking = false;
            if (stopped || slot.State != TunnelState.Up || slot.CheckRound != round || !Current(slot)) return;
            var now = clock.GetUtcNow();
            if (answered != false || slot.Received - slot.CheckBaseline >= CheckReceived)
            { slot.CheckDue = false; slot.Checked = now; slot.CheckFailed = null; slot.CheckFailures = 0; slot.CheckRestarts = 0; slot.CheckRestarted = null; }
            else if (++slot.CheckFailures < CheckTries) slot.CheckAt = now + CheckRetry;
            else
            {
                slot.CheckFailed ??= now; slot.CheckFailures = 0;
                var wait = slot.CheckRestarts == 0 ? TimeSpan.Zero : ReconnectAfter(slot.CheckRestarts - 1);
                if (slot.CheckRestarted is { } last && now - last < wait) slot.CheckAt = last + wait;
                else notify.AddRange(RestartGroup(slot, now));
            }
        }
        foreach (var profile in notify) Notify(profile);
    }

    /// <summary>
    /// Restarts a tunnel whose check failed together with every running one sharing its address: all of them carry nothing
    /// from now on, and none starts again before every old backend is gone, so the first to start takes the address afresh
    /// rather than one taking over another's. Only the failed one's restarts count.
    /// </summary>
    private List<Guid> RestartGroup(Slot slot, DateTimeOffset now)
    {
        var sources = slot.Egress!.Sources;
        List<Slot> group = [.. slots.Values.Where(s => s.State == TunnelState.Up && s.Egress is { } egress && egress.Sources.Intersect(sources).Any())];
        foreach (var member in group) Detach(member);
        var gone = Task.WhenAll(group.Select(m => m.Teardown));
        foreach (var member in group) Launch(member, gone);
        slot.CheckRestarts = Math.Min(slot.CheckRestarts + 1, 1_000); slot.CheckRestarted = now;
        return [.. group.Select(m => m.Demand.ProfileId)];
    }

    /// <summary>A tunnel came up or went away: every running one sharing an address with it is checked again, as the address may have moved.</summary>
    private void RecheckSharing(IReadOnlyList<IPAddress> sources, Slot changed)
    {
        if (check is null) return;
        var at = clock.GetUtcNow() + CheckRetry;
        foreach (var other in slots.Values)
            if (other != changed && other.State == TunnelState.Up && other.Egress is { } egress && egress.Sources.Intersect(sources).Any()) Recheck(other, at);
    }

    private static void Recheck(Slot slot, DateTimeOffset at) { slot.CheckDue = true; slot.CheckFailures = 0; slot.CheckRound++; slot.CheckAt = at; }

    /// <summary>
    /// A count that found the tunnel sending with nothing back since its server last answered. Sending that goes on so for
    /// <see cref="SilentAfter"/> marks the server silent from the first such count until anything comes back.
    /// </summary>
    private static void Unheard(Slot slot, DateTimeOffset now)
    {
        if (slot.Silent is null && (slot.QuietLast is not { } last || now - last > SilenceGap)) slot.Quiet = now;
        slot.QuietLast = now;
        if (slot.Silent is null && now - slot.Quiet >= SilentAfter) slot.Silent = slot.Quiet;
    }

    /// <summary>
    /// What WireGuard counts for the tunnel's servers. A handshake completed since the tunnel came up, or anything more back
    /// from them, is an answer, and dates the last one heard. WireGuard sending on with neither for <see cref="HandshakeSilence"/>
    /// is unanswered sending, whatever the interface counts: WireGuard counts nothing there while it waits for a handshake, and
    /// what the router sends a tunnel sharing another's address can be answered through the other. Only traffic coming back
    /// through the interface ends the silence.
    /// </summary>
    private static void Handshakes(Slot slot, PeerTraffic peer, DateTimeOffset now)
    {
        DateTimeOffset? answered = peer.LastHandshake is { } handshake && handshake > slot.Since ? handshake < now ? handshake : now : null;
        if (slot.PeerReceived is { } received && peer.Received > received) answered = now;
        if (answered is { } heard && heard > (slot.PeerHeard ?? slot.Since))
        {
            slot.PeerHeard = heard;
            if (slot.LastReceived is not { } last || heard > last) slot.LastReceived = heard;
        }
        else if (slot.PeerSent is { } sent && peer.Sent > sent && now - (slot.PeerHeard ?? slot.Since) >= HandshakeSilence) Unheard(slot, now);
        slot.PeerSent = peer.Sent; slot.PeerReceived = peer.Received;
    }

    /// <summary>
    /// Since when a running tunnel has had traffic its server has not answered, by the same rule as
    /// <see cref="TunnelStatus.Unanswered"/>: since the first flow routed or byte sent if nothing came back since it came up,
    /// else since its server fell silent.
    /// </summary>
    private DateTimeOffset? Unanswered(Slot slot) => slot.Received > 0 ? slot.Silent
        : routed.TryGetValue(slot.Demand.ProfileId, out var first) ? first : slot.Sent > 0 ? slot.Since : slot.Silent;

    private static TimeSpan ReconnectAfter(int reconnects) => TimeSpan.FromTicks(Math.Min(LastReconnect.Ticks, FirstReconnect.Ticks << Math.Min(reconnects, 16)));

    private void Notify(Guid profile)
    {
        try { changed(profile); }
        catch (Exception error) when (error is not OutOfMemoryException) { ServiceHost.Log("A VPN tunnel change was not applied to its flows: " + error.Message); }
    }

    private void Launch(Slot slot, Task after)
    {
        slot.State = TunnelState.Starting; slot.Since = clock.GetUtcNow();
        Publish(slot);
        var attempt = slot.Attempt = new();
        slot.Start = Track(Task.Run(() => StartAsync(slot, attempt, after)));
    }

    private async Task StartAsync(Slot slot, object attempt, Task after)
    {
        ITunnelInstance? instance = null; ulong luid = 0; List<(IPAddress Network, int Prefix)> routes = [];
        string? failure = null; var up = false;
        try
        {
            await after.ConfigureAwait(false);
            slot.Lifetime.Token.ThrowIfCancellationRequested();
            instance = await backends.StartAsync(slot.Demand, slot.Lifetime.Token).ConfigureAwait(false);
            if (instance.ProfileId != slot.Demand.ProfileId || instance.Routes.Count == 0 || instance.Routes.Select(r => r.InterfaceId).Distinct().Count() != 1)
                throw new InvalidDataException("The tunnel backend reported an unexpected interface.");
            var (found, index) = interfaces.Resolve(instance.Routes[0].InterfaceId);
            luid = found;
            owned[luid] = instance;
            // One source per family the router captures. Relay sockets pinned to the tunnel need routes on its interface.
            var sources = instance.Routes.Select(r => r.SourceAddress).Where(a => a.AddressFamily == AddressFamily.InterNetwork || ipv6)
                .GroupBy(a => a.AddressFamily).Select(g => g.First()).ToArray();
            if (sources.Length == 0) throw new InvalidDataException("The tunnel has no address the router can use.");
            var shared = instance.Shared;
            foreach (var source in sources)
            foreach (var (network, prefix) in Routes(source, shared.Contains(source)))
            {
                interfaces.AddRoute(luid, network, prefix, RouteMetric);
                routes.Add((network, prefix));
            }
            var egress = new TunnelEgress(luid, index, sources, instance.Networks, instance.Resolvers, shared);
            var baseline = Counters(instance) ?? (0, 0);
            lock (gate)
            {
                if (Current(slot) && ReferenceEquals(slot.Attempt, attempt))
                {
                    slot.Instance = instance; slot.Egress = egress; slot.Luid = luid; slot.Routes = routes;
                    slot.Baseline = baseline; slot.Sent = slot.Received = 0; slot.LastReceived = slot.Quiet = slot.QuietLast = slot.Silent = null; routed.TryRemove(slot.Demand.ProfileId, out _);
                    slot.Tried = tries.GetValueOrDefault(slot.Demand.ProfileId); slot.PeerSent = slot.PeerReceived = null; slot.PeerHeard = null;
                    slot.CountedAt = clock.GetUtcNow(); slot.Rates.Clear();
                    slot.State = TunnelState.Up; slot.Since = clock.GetUtcNow(); slot.Failures = 0; slot.Error = null;
                    // Checked end to end before it counts as carrying traffic, and so again are those sharing its address.
                    slot.CheckDue = check is not null; slot.Checking = false; slot.CheckFailures = 0; slot.CheckRound++; slot.CheckAt = slot.Since;
                    slot.Checked = check is null ? slot.Since : null; slot.CheckFailed = null;
                    RecheckSharing(egress.Sources, slot);
                    Publish(slot); up = true;
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException) { failure = error is OperationCanceledException ? "The tunnel start was canceled." : error.Message; }
        if (up) { Notify(slot.Demand.ProfileId); return; }
        // Retired while starting, or failed after the backend came up: nothing of this attempt may remain.
        if (instance is not null) await DiscardAsync(instance, luid, routes).ConfigureAwait(false);
        var report = false;
        lock (gate)
        {
            if (Current(slot) && ReferenceEquals(slot.Attempt, attempt) && slot.State == TunnelState.Starting)
            { Fail(slot, failure ?? "The tunnel did not start."); report = true; }
        }
        if (report) Notify(slot.Demand.ProfileId);
    }

    /// <summary>
    /// A tunnel's routes for one source's family. One that shares its source sends over the weak host model, under which
    /// sockets bound to any interface's address may use its routes too, so it gets only a default route at the tunnel
    /// metric, which the physical default route outranks for them; its own source's tunnel keeps the halves.
    /// </summary>
    private static (IPAddress Network, int Prefix)[] Routes(IPAddress source, bool shared) =>
        source.AddressFamily == AddressFamily.InterNetworkV6 ? shared ? Whole6 : Halves6 : shared ? Whole4 : Halves4;

    /// <summary>The tunnel stopped working: it carries nothing from now on, and its backend and routes go away.</summary>
    private void Lose(Slot slot, string error)
    {
        Detach(slot);
        Fail(slot, error);
    }

    /// <summary>
    /// Its server stopped answering: the tunnel carries nothing more, as a lost one, and starts again at once with a new backend
    /// once the old one and its routes are gone, its applications waiting meanwhile as for any start.
    /// </summary>
    private void Reconnect(Slot slot)
    {
        Detach(slot);
        slot.Reconnects = Math.Min(slot.Reconnects + 1, 1_000);
        Launch(slot, slot.Teardown);
    }

    /// <summary>The running backend leaves the slot: its egress closes at once, and its routes and backend go in the background.</summary>
    private void Detach(Slot slot)
    {
        if (slot.Egress is { } leaving) RecheckSharing(leaving.Sources, slot);
        slot.Egress?.Close();
        var instance = slot.Instance!; var luid = slot.Luid; var routes = slot.Routes;
        slot.Instance = null; slot.Egress = null; slot.Routes = [];
        slot.Teardown = Track(Task.Run(() => DiscardAsync(instance, luid, routes)));
    }

    private void Fail(Slot slot, string error)
    {
        slot.State = TunnelState.Failed; slot.Error = error; slot.Since = clock.GetUtcNow();
        slot.Failures = Math.Min(slot.Failures + 1, 16);
        slot.RetryAt = slot.Since + TimeSpan.FromTicks(Math.Min(LastRetry.Ticks, FirstRetry.Ticks << (slot.Failures - 1)));
        Publish(slot);
    }

    /// <summary>No longer demanded, or replaced: it carries nothing, and a successor waits until it is fully gone.</summary>
    private void Retire(Slot slot)
    {
        var profile = slot.Demand.ProfileId;
        slots.Remove(profile); views.TryRemove(profile, out _); routed.TryRemove(profile, out _);
        slot.Lifetime.Cancel();
        if (slot.Egress is { } leaving) RecheckSharing(leaving.Sources, slot);
        slot.Egress?.Close();
        if (slot.Instance is { } instance)
        {
            var luid = slot.Luid; var routes = slot.Routes;
            slot.Instance = null; slot.Egress = null; slot.Routes = [];
            slot.Teardown = Track(Task.Run(() => DiscardAsync(instance, luid, routes)));
        }
        var previous = retiring.GetValueOrDefault(profile) ?? Task.CompletedTask;
        retiring[profile] = Task.WhenAll(previous, slot.Start, slot.Teardown);
    }

    /// <summary>
    /// A backend leaving: what Darkwire has open through its interface closes, its routes and own addresses go, then the
    /// backend. Windows removes a stopped tunnel's interface only once nothing uses it, and the profile's next tunnel cannot
    /// start while its interface name is taken.
    /// </summary>
    private async Task DiscardAsync(ITunnelInstance instance, ulong luid, List<(IPAddress Network, int Prefix)> routes)
    {
        if (luid != 0 && released is not null)
        {
            try { released(luid); }
            catch (Exception error) when (error is not OutOfMemoryException) { ServiceHost.Log("What Darkwire had open through a VPN tunnel did not all close: " + error.Message); }
        }
        // Routes go before the backend, so nothing ever prefers a tunnel that is going away.
        foreach (var (network, prefix) in routes)
        {
            try { interfaces.DeleteRoute(luid, network, prefix); }
            catch (Win32Exception error) { ServiceHost.Log("A VPN tunnel route could not be removed: " + error.Message); }
        }
        // Its own addresses go too, ending the connections still bound to them, those of a tunnel sharing them included,
        // which would otherwise keep this interface alive; that tunnel takes them over as it is maintained, at once here.
        IPAddress[] holding = luid == 0 ? [] : [.. instance.Routes.Select(r => r.SourceAddress).Distinct().Where(a => !instance.Shared.Contains(a))];
        if (holding.Length > 0)
        {
            List<ITunnelInstance> others;
            lock (gate) others = [.. slots.Values.Where(s => s.State == TunnelState.Up && s.Instance is not null && !ReferenceEquals(s.Instance, instance)).Select(s => s.Instance!)];
            lock (handover)
            {
                foreach (var address in holding)
                {
                    try { interfaces.DeleteAddress(luid, address); }
                    catch (Win32Exception error) { ServiceHost.Log("A VPN tunnel address could not be removed: " + error.Message); }
                }
                foreach (var other in others) Maintain(other);
            }
        }
        try { await instance.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) when (error is not OutOfMemoryException) { ServiceHost.Log("A VPN backend did not stop cleanly: " + error.Message); }
        finally { if (luid != 0) owned.TryRemove(new KeyValuePair<ulong, ITunnelInstance>(luid, instance)); }
    }

    private bool Current(Slot slot) => !stopped && !slot.Lifetime.IsCancellationRequested && slots.GetValueOrDefault(slot.Demand.ProfileId) == slot;

    private void Publish(Slot slot) => views[slot.Demand.ProfileId] = new(slot.Demand.ProfileId, slot.State, slot.State == TunnelState.Up ? slot.Egress : null);

    private Task Track(Task task)
    {
        work.RemoveAll(t => t.IsCompleted);
        work.Add(task);
        return task;
    }

    private static bool Healthy(ITunnelInstance instance)
    {
        try { return instance.Healthy; }
        catch (Exception error) when (error is not OutOfMemoryException) { return false; }
    }

    // What cannot be put back shows in the health check that follows.
    private static void Maintain(ITunnelInstance instance)
    {
        try { instance.Maintain(); }
        catch (Exception error) when (error is not OutOfMemoryException) { }
    }

    private (long Sent, long Received)? Counters(ITunnelInstance instance)
    {
        try { return instance.Routes.Count > 0 ? interfaces.Counters(instance.Routes[0].InterfaceId) : null; }
        catch (Exception error) when (error is not OutOfMemoryException) { return null; }
    }

    private static PeerTraffic? Peers(ITunnelInstance instance)
    {
        try { return instance.Peers; }
        catch (Exception error) when (error is not OutOfMemoryException) { return null; }
    }

    /// <summary>
    /// Stops every tunnel: each carries nothing from the first instant, then its routes and backend go away. Every caller
    /// waits for the same teardown, up to <see cref="StopTimeout"/>.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        List<Guid> notify = []; Task stopping;
        lock (gate)
        {
            if (disposal is null)
            {
                notify = [.. slots.Keys];
                foreach (var slot in slots.Values.ToArray()) Retire(slot);
                stopped = true;
                disposal = Task.WhenAll(work.ToArray());
            }
            stopping = disposal;
        }
        foreach (var profile in notify) Notify(profile);
        try { await stopping.WaitAsync(StopTimeout).ConfigureAwait(false); }
        catch (TimeoutException) { ServiceHost.Log("VPN backends did not stop in time; they stop with the service."); }
    }

    private sealed class Slot(TunnelDemand demand)
    {
        public TunnelDemand Demand { get; } = demand;
        public CancellationTokenSource Lifetime { get; } = new();
        public TunnelState State;
        public object? Attempt;
        public ITunnelInstance? Instance;
        public TunnelEgress? Egress;
        public ulong Luid;
        public List<(IPAddress Network, int Prefix)> Routes = [];
        public string? Error;
        public DateTimeOffset Since, RetryAt;
        public int Failures;
        // Reconnects because its server stopped answering, since the server last answered; kept across them.
        public int Reconnects;
        // The interface's counters when the tunnel came up, the bytes since, when its server last answered (bytes received, or a
        // handshake WireGuard completed), when they were last counted, and the bits per second between counts. Since the last
        // answer: the first and latest counts that found it sending, and the first once that went on long enough to call its
        // server silent.
        public (long Sent, long Received)? Baseline;
        public long Sent, Received;
        public DateTimeOffset? LastReceived, Quiet, QuietLast, Silent;
        // The router's flows through it, and the bytes WireGuard sent its servers and received from them, as last counted, and
        // when WireGuard last heard from them.
        public long Tried;
        public long? PeerSent, PeerReceived;
        public DateTimeOffset? PeerHeard;
        // The end-to-end check: whether one is due and when, whether a try is out, the tries failed and the round they count
        // for, which a recheck moves on, and the bytes received when it began; when one last passed, and when one failed since.
        // The restarts failed checks led to since one last passed, kept across them, and when the last was.
        public bool CheckDue, Checking;
        public int CheckFailures, CheckRound, CheckRestarts;
        public long CheckBaseline;
        public DateTimeOffset CheckAt;
        public DateTimeOffset? Checked, CheckFailed, CheckRestarted;
        public DateTimeOffset CountedAt;
        public readonly Queue<(long In, long Out)> Rates = new();
        public Task Start = Task.CompletedTask, Teardown = Task.CompletedTask;
    }
}
