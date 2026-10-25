using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Darkwire.Service;

public interface IFilterBackend : IDisposable
{
    bool LearningEventsReady { get; }
    int FilterCount { get; }
    int BootFilterCount => 0;
    void VerifyIntegrity() { }
    void Apply(FilterPlan plan);
    void RemoveOwnedFilters();
    IReadOnlyList<Connection> DrainBlockedConnections();
    /// <summary>
    /// Other providers' permits that clear the action right; they override Darkwire blocks from a higher sublayer. Those the
    /// WireGuard tunnels of <paramref name="wireGuardTunnels"/> add for their own services are Darkwire's backend's, not others'.
    /// </summary>
    IReadOnlyList<string> HardPermits(IReadOnlyCollection<Guid> wireGuardTunnels) => [];
    /// <summary>True only when a deliberately blocked probe produced a drop event on the learning subscription.</summary>
    bool ProbeLearningEvents() => LearningEventsReady;
    /// <summary>Drops Windows reported for Darkwire's named denies, such as a blocklist's, by filter name, since the backend opened.</summary>
    IReadOnlyDictionary<string, long> DropsByName => new Dictionary<string, long>();
    /// <summary>Those drops one by one since the last drain, each with its deny's name.</summary>
    IReadOnlyList<(Connection Connection, string Filter)> DrainNamedDrops() => [];
    /// <summary>Lifts the startup lock for as long as the backend lives; it holds again once the backend is gone.</summary>
    void ReleaseStartupLock() { }
    /// <summary>The startup lock filters the last apply registered; null when the backend does not count them.</summary>
    int? LockFilterCount => null;
    /// <summary>Whether this backend holds the startup lock's release.</summary>
    bool StartupLockReleased => false;
    /// <summary>The policy and startup lock filters the last integrity check found; null before the first.</summary>
    (int Filters, int Lock)? Audited => null;
    /// <summary>The filters the last apply added and deleted; null when the backend does not count them.</summary>
    (int Added, int Removed)? LastChanges => null;
}
public sealed class WfpBackend : IFilterBackend
{
    private readonly PersistentFilterSession session = new();
    public bool LearningEventsReady => session.LearningEventsReady;
    public int FilterCount => session.FilterCount;
    public int BootFilterCount => session.BootFilterCount;
    public int? LockFilterCount => session.LockFilterCount;
    public bool StartupLockReleased => session.StartupLockReleased;
    public (int Filters, int Lock)? Audited => session.Audited;
    public (int Added, int Removed)? LastChanges => session.LastChanges;
    public void ReleaseStartupLock() => session.ReleaseStartupLock();
    public void VerifyIntegrity() => session.VerifyIntegrity();
    public bool ProbeLearningEvents() => session.ProbeLearningEvents(TimeSpan.FromSeconds(3));
    public IReadOnlyList<string> HardPermits(IReadOnlyCollection<Guid> wireGuardTunnels)
    {
        var services = wireGuardTunnels.SelectMany(WireGuardBackend.Names).Select(name => IdentitySelectors.ServiceSid(WireGuardBackend.ServiceName(name))).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var wireGuard = services.Count > 0 ? WfpInventory.ApplicationIdText(WireGuardBackend.Executable) : "";
        return WfpInventory.Read(p => p != PersistentFilterSession.ProviderKey)
            .Where(f => f.Action == "PERMIT" && (f.Flags & 0x8) != 0 && f.Layer.StartsWith("ALE_AUTH_", StringComparison.Ordinal))
            .Where(f => services.Count == 0 || !WireGuardBackend.OwnPermit(f, wireGuard, services))
            .Select(f => $"{f.Name} ({f.Provider}, {f.Layer})").Distinct().ToArray();
    }
    public void Apply(FilterPlan plan) => session.Apply(plan);
    public void RemoveOwnedFilters() => session.RemoveOwnedFilters();
    public IReadOnlyList<Connection> DrainBlockedConnections() => session.DrainBlockedConnections();
    public IReadOnlyDictionary<string, long> DropsByName => session.DropsByName;
    public IReadOnlyList<(Connection Connection, string Filter)> DrainNamedDrops() => session.DrainNamedDrops();
    public void Dispose() => session.Dispose();
}

/// <summary>Orders durable intent, WFP transactions, and Windows Firewall changes so failures keep protection.</summary>
public sealed class TakeoverCoordinator : IDisposable
{
    private readonly object gate = new();
    private readonly IWindowsFirewallControl firewall;
    private readonly IPolicyJournal journal;
    private readonly Func<IFilterBackend> createBackend;
    private readonly IGeoStore? geoStore;
    private readonly IVpnProfileVault? vpnVault;
    private readonly INetworkEnvironment network;
    private readonly Func<FilterPlan, IReadOnlyList<string>> nativePreflight;
    private readonly Func<IReadOnlyDictionary<string, int>> protections;
    private readonly IAuditPolicy audit;
    private readonly IFirewallAreaPolicy firewallArea;
    private readonly Func<IConnectionRouter>? createRouter;
    private readonly IBlocklistStore? blocklists;
    private readonly IResolverCatalog? resolvers;
    private readonly IGeoUpdates? geoUpdates;
    private readonly FlowAttribution attribution;
    private readonly Func<IReadOnlyList<FlowProcess>>? connected;
    private readonly TimeProvider clock;
    private readonly DateTimeOffset started;
    // The startup lock was released, or had nothing to hold: from here on every install releases it first.
    private bool restored;
    private IConnectionRouter? router;
    private DateTimeOffset routerRetry;
    private static readonly Guid[] AuditSubcategories = [WindowsAuditPolicy.FilteringConnection, WindowsAuditPolicy.FilteringPacketDrop];
    private bool learningVerified;
    private IGeoLookup? geoDatabase;
    private bool geoLoaded;
    private ServiceJournal state;
    private IFilterBackend? backend;
    private readonly LearningBroker learning;
    private string message = "Service installed. Windows Firewall remains in control.";
    // Keyword rules (LocalSubnet, DNS...) are resolved per compile; the monitor recompiles when interfaces change.
    private NetworkSnapshot? compiledNetwork;
    private string? appliedNetwork;
    private int ticks;

    /// <param name="createRouter">Creates the connection router from the learning broker it asks through, and a check that Darkwire's installed filters are intact, run before a VPN backend starts.</param>
    /// <param name="attribution">Finds the process behind a blocked attempt from the socket owner tables.</param>
    /// <param name="connected">The processes with outbound connections open at takeover, which keep their access; none when null.</param>
    /// <param name="clock">Times the startup lock's limit.</param>
    /// <param name="resolvers">The public resolver list, which the DNS picker offers and the policy's listed servers take their stamps from.</param>
    /// <param name="firewallArea">Windows Security's policy for its Firewall and network protection area, which hides that area's warnings.</param>
    public TakeoverCoordinator(IWindowsFirewallControl firewall, IPolicyJournal journal, Func<IFilterBackend> createBackend, IGeoStore? geoStore = null, IVpnProfileVault? vpnVault = null,
        INetworkEnvironment? network = null, Func<FilterPlan, IReadOnlyList<string>>? nativePreflight = null, Func<IReadOnlyDictionary<string, int>>? protections = null,
        IAuditPolicy? audit = null, Func<LearningBroker, Action, IConnectionRouter>? createRouter = null, IBlocklistStore? blocklists = null, FlowAttribution? attribution = null,
        IGeoUpdates? geoUpdates = null, Func<IReadOnlyList<FlowProcess>>? connected = null, TimeProvider? clock = null, IResolverCatalog? resolvers = null,
        IFirewallAreaPolicy? firewallArea = null)
    {
        this.firewall = firewall; this.journal = journal; this.createBackend = createBackend; this.geoStore = geoStore; this.vpnVault = vpnVault; this.blocklists = blocklists; this.resolvers = resolvers;
        this.geoUpdates = geoUpdates; this.connected = connected; this.clock = clock ?? TimeProvider.System; started = this.clock.GetUtcNow();
        this.attribution = attribution ?? new FlowAttribution();
        this.network = network ?? new NetworkEnvironment(); this.nativePreflight = nativePreflight ?? WfpConditions.Preflight;
        this.protections = protections ?? WfpInventory.ProtectionBlocks; this.audit = audit ?? new WindowsAuditPolicy();
        this.firewallArea = firewallArea ?? new WindowsFirewallAreaPolicy();
        state = journal.Read(); learning = new(state.Policy);
        if (createRouter is not null) this.createRouter = () => createRouter(learning, VerifyFilters);
        Publish();
    }

    // The status as it stood when the lock was last released, for reads that must not wait for it.
    private ServiceStatus? published;
    private void Publish() => Volatile.Write(ref published, Status());

    /// <summary>
    /// The status without waiting for whatever holds the coordinator lock (a takeover, an apply, the monitor's tick): read fresh
    /// when the lock is free, otherwise as published when it was last released, which the monitor refreshes every second.
    /// </summary>
    private ServiceStatus CurrentStatus()
    {
        if (Monitor.TryEnter(gate))
        {
            try { DrainEvents(); }
            catch (Exception error) when (error is not OutOfMemoryException) { message = error.Message; }
            finally { Publish(); Monitor.Exit(gate); }
        }
        return Volatile.Read(ref published)!;
    }

    /// <summary>
    /// The TCP connections Darkwire's router carries while it enforces, an apply under way included, each with the VPN profile
    /// it takes, at most <see cref="MaximumRouted"/> so the reply stays well within a message. Never waits for the coordinator lock.
    /// </summary>
    private static string ProfileName(AppState policy, Guid id) => policy.VpnProfiles.FirstOrDefault(p => p.Id == id)?.Name ?? "This VPN profile";

    /// <summary>How long a tunnel check waits for its DNS server's answer.</summary>
    public static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(3);
    /// <summary>
    /// Asks a running tunnel's own DNS server a question through the tunnel, as the card's Refresh does, and says whether and
    /// how soon it answered; an answer also counts as the tunnel hearing from its server. Never waits for the coordinator lock.
    /// </summary>
    private ServiceResponse CheckVpn(Guid? requested)
    {
        try
        {
            var id = requested ?? throw new InvalidDataException("A VPN profile ID is required.");
            var name = ProfileName(Volatile.Read(ref state).Policy, id); var current = Volatile.Read(ref router);
            if (current?.Tunnels.FirstOrDefault(t => t.ProfileId == id) is not { State: "Up" } tunnel) return new(false, $"{name} has no tunnel up to check.", CurrentStatus());
            foreach (var server in tunnel.Resolvers ?? [])
            {
                if (!IPAddress.TryParse(server, out var address) || current.OwnEgress(address, id) is not { } route) continue;
                var took = TunnelProbe.Ask(route, new(address, 53), CheckTimeout);
                var check = new VpnCheck(id, took is not null, server, took is { } time ? (int)Math.Ceiling(time.TotalMilliseconds) : null);
                return new(true, check.Answered ? $"{name}'s DNS server {server} answered through the tunnel in {check.Milliseconds:N0} ms."
                    : $"{name}'s DNS server {server} did not answer through the tunnel within {CheckTimeout.TotalSeconds:N0} seconds.", CurrentStatus(), Check: check);
            }
            return new(true, $"{name} is up, but names no DNS server its tunnel carries, so there is nothing to ask; its card shows what it sends and receives.", CurrentStatus(),
                Check: new(id, false));
        }
        catch (Exception error) when (error is InvalidDataException or System.Net.Sockets.SocketException or ObjectDisposedException)
        { return new(false, "The tunnel could not be checked: " + error.Message, CurrentStatus()); }
    }

    private ServiceResponse RoutedConnections()
    {
        IReadOnlyList<RoutedConnection> routed = Volatile.Read(ref state).Phase != "Inactive" && Volatile.Read(ref router) is { } active ? [.. active.Connections.Take(MaximumRouted)] : [];
        return new(true, $"{routed.Count:N0} connections through Darkwire's router.", Routed: routed);
    }
    public const int MaximumRouted = 8_192;

    /// <summary>Darkwire's installed filters are intact, guards and backend permits included. Runs on tunnel threads, without the coordinator lock.</summary>
    private void VerifyFilters() => (Volatile.Read(ref backend) ?? throw new InvalidOperationException("Darkwire filters are not installed.")).VerifyIntegrity();

    public void Recover()
    {
        lock (gate)
        {
            try
            {
                if (state.Phase == "Inactive") return;
                if (state.Phase is "Prepared" or "Restoring") { RestoreCore(); message = "Interrupted takeover was rolled back to Windows Firewall."; return; }
                try
                {
                    backend ??= createBackend();
                    var plans = Plans(state.Policy, Ready(state.Policy), strict: false); Require(plans.Kernel);
                    Install(plans.Kernel, "recovery");
                    firewall.SetProfiles(new Dictionary<int, bool> { [1] = false, [2] = false, [4] = false });
                    var recovered = WithPhase(state, "Active"); journal.Write(recovered); state = recovered; learning.UpdatePolicy(state.Policy);
                    SyncFirewallArea();
                    message = "Persistent policy recovered.";
                    // The kernel plan already fails closed without the router; a start failure is retried by the monitor.
                    TrySyncRouter(state.Policy, plans);
                    RequestDownloads(state.Policy);
                }
                catch
                {
                    // Keep persistent filters until the Windows baseline is successfully restored.
                    RestoreCore(); throw;
                }
            }
            finally { Publish(); }
        }
    }

    public ServiceResponse Handle(ServiceRequest request)
    {
        // A status read never waits for a takeover, an apply or the monitor's tick, nor does a read of the routed connections.
        if (request.Command == "status") { var status = CurrentStatus(); return new(true, status.Message, status); }
        if (request.Command == "routed-connections") return RoutedConnections();
        // A check waits seconds for a server, never for the coordinator.
        if (request.Command == "check-vpn") return CheckVpn(request.VpnProfileId);
        // A recheck only marks the tunnels' checks due; the supervisor asks in the background.
        if (request.Command == "check-tunnels")
        {
            if (Volatile.Read(ref router) is not { } running || running.Tunnels.Count == 0) return new(true, "No VPN tunnel runs to check.", CurrentStatus());
            running.Recheck();
            return new(true, "Checking each VPN tunnel end to end.", CurrentStatus());
        }
        lock (gate)
        {
            try
            {
                DrainEvents();
                switch (request.Command)
                {
                    case "policy": return new(true, "Authoritative service policy.", Status(), Clone(state.Policy));
                    case "pending": return new(true, "Unmatched attempts remain blocked until approval. Applications must retry.", Status(), Pending: learning.Pending);
                    case "vpn-profiles": return new(true, "Service VPN configuration metadata.", Status(), VpnProfiles: RequireVault().List());
                    case "blocklists": return new(true, "Catalog blocklists the service keeps.", Status(), Blocklists: BlocklistStatuses());
                    case "preload-blocklist":
                    {
                        // Only lists the service's own catalog names are fetched, so any user may ask ahead of enabling one.
                        if (BlocklistCatalog.Find(request.BlocklistId) is not { } listed) throw new InvalidDataException("Unknown catalog blocklist.");
                        RequireBlocklists().Request(listed.Id, BlocklistStore.Preload);
                        return new(true, $"Downloading {listed.Name} in the service.", Status(), Blocklists: BlocklistStatuses());
                    }
                    case "refresh-geoip":
                    {
                        // The updater fetches only DB-IP's fixed release addresses, at most once a minute, so any user may ask.
                        (geoUpdates ?? throw new InvalidOperationException("GeoIP updates run only in the Darkwire service.")).Request();
                        return new(true, "Checking DB-IP for a newer GeoIP release.", Status());
                    }
                    case "dns-servers":
                    {
                        // The store fetches only the DNSCrypt project's own list, at most once a minute, so any user may ask for it.
                        var store = resolvers ?? throw new InvalidOperationException("The resolver list is kept only in the Darkwire service.");
                        if (store.Servers.Count == 0) store.Request();
                        var catalog = store.Catalog();
                        return new(true, catalog.Servers.Count > 0 ? $"{catalog.Servers.Count:N0} servers on the public resolver list." : "The service is fetching the public resolver list.", Status(), DnsCatalog: catalog);
                    }
                    case "import-vpn":
                    {
                        var upload = request.VpnConfiguration ?? throw new InvalidDataException("A VPN configuration is required.");
                        RequireUnusedProfile(upload.Id);
                        var stored = RequireVault().Save(upload.Id, upload.Kind, upload.Configuration);
                        return new(true, "VPN configuration saved in protected service storage. Connect it, assign applications to it, or make it the default route to use it.", Status(), VpnProfiles: [stored]);
                    }
                    case "remove-vpn":
                    {
                        var id = request.VpnProfileId ?? throw new InvalidDataException("A VPN profile ID is required.");
                        RequireUnusedProfile(id); RequireVault().Delete(id);
                        return new(true, "Service VPN configuration removed.", Status());
                    }
                    case "preflight":
                    {
                        var (candidate, errors, defaults) = Prepare(request.Policy ?? new());
                        return new(errors.Count == 0, errors.Count == 0 ? "Policy can be translated and installed. Live activation and recovery still require Windows integration validation." : "Takeover refused; Windows Firewall is unchanged.",
                            Status(), candidate, Errors: errors, Defaults: defaults);
                    }
                    case "takeover": TakeOver(request.Policy ?? throw new InvalidDataException("A policy is required.")); break;
                    case "apply": Apply(request.Policy ?? throw new InvalidDataException("A policy is required."), request.ExpectedRevision); break;
                    case "apply-vpn":
                    {
                        // Only the VPN routes change, on the enforced policy at its current revision, so rules learned since the
                        // editor last loaded the policy stay.
                        var routes = request.Routes ?? throw new InvalidDataException("VPN routes are required.");
                        if (state.Phase != "Active") throw new InvalidOperationException("Darkwire is not enforcing policy yet. Your VPN routes take effect when it takes over.");
                        var next = Clone(state.Policy);
                        next.VpnProfiles = [.. routes.Profiles ?? throw new InvalidDataException("VPN profiles are required.")];
                        next.DefaultOutboundVpnProfileId = routes.DefaultProfileId;
                        next.LocalNetworkBypassesVpn = routes.BypassLocal;
                        next.OwnTraffic = routes.OwnTraffic; next.OwnTrafficProfileId = routes.OwnTraffic == OwnRoute.Profile ? routes.OwnTrafficProfileId : null;
                        Apply(next, state.Revision);
                        var connected = VpnAssignments.Connected(next).Any();
                        var disconnected = VpnAssignments.Running(next).Where(p => p.Disconnected).Select(p => p.Name).ToArray();
                        message = (next.Mode == FirewallMode.Lockdown && (connected || VpnAssignments.Routed(next)) ? "VPN routes applied. Lockdown refuses routed connections, so no tunnel runs until you leave it."
                            : VpnAssignments.Routed(next) ? "VPN routes applied. Their applications use only their tunnel, and wait while it connects."
                            : connected ? "VPN profiles connecting. Nothing goes through them until you assign applications or a default route."
                            : "VPN routes removed. Every application uses the Windows route.") +
                            (disconnected.Length > 0 ? $" Disconnected: {string.Join(", ", disconnected)}; what {(disconnected.Length == 1 ? "it carries" : "they carry")} is refused until you connect {(disconnected.Length == 1 ? "it" : "them")}." : "");
                        break;
                    }
                    case "apply-settings":
                    {
                        // Like VPN routes, only the settings given change, on the enforced policy at its current revision.
                        var settings = request.Settings ?? throw new InvalidDataException("Settings are required.");
                        if (state.Phase != "Active") throw new InvalidOperationException("Darkwire is not enforcing policy yet. Your changes take effect when it takes over.");
                        var next = Clone(state.Policy); List<string> changed = [];
                        if (settings.Blocklists is { } lists) { next.Blocklists = [.. lists]; changed.Add("Blocklists applied; one still downloading takes effect when it arrives."); }
                        if (settings.InternalNetworks is { } access)
                        {
                            next.InternalNetworks = access;
                            changed.Add(access switch
                            {
                                InternalAccess.Allow => "Internal networks are allowed.",
                                InternalAccess.Block => "Internal networks are blocked unless a rule allows them.",
                                _ => "Rules decide internal network traffic."
                            });
                        }
                        if (settings.Geography is { } geo)
                        {
                            next.BlockedCountries = [.. geo.BlockedCountries]; next.CountryAllowList = geo.CountryAllowList;
                            next.AllowedCountries = [.. geo.AllowedCountries]; next.BlockedAsns = [.. geo.BlockedAsns];
                            changed.Add(geo.CountryAllowList ? $"Only {geo.AllowedCountries.Count} allowed countr{(geo.AllowedCountries.Count == 1 ? "y" : "ies")} can be reached." : "Country and ASN restrictions applied.");
                        }
                        if (settings.StartupLock is { } hold)
                        {
                            next.StartupLock = hold;
                            changed.Add(hold ? "From the next start, the internet stays blocked until Darkwire has restored its policy and VPN tunnels, and whenever the service stops."
                                : "The internet is no longer blocked while Darkwire starts.");
                        }
                        if (settings.BlockedNames is { } blockedNames)
                        {
                            next.BlockedNames = [.. blockedNames];
                            changed.Add(blockedNames.Count == 0 ? "No names are blocked one by one." : $"{blockedNames.Count:N0} blocked name{(blockedNames.Count == 1 ? "" : "s")} now answer with this PC's own address.");
                        }
                        if (settings.DnsServers is { } servers)
                        {
                            next.DnsServers = [.. servers];
                            changed.Add(servers.Count == 0 ? "Lookups go to the networks' own DNS servers again." : $"Lookups that leave the local network go to {servers.Count} encrypted DNS server{(servers.Count == 1 ? "" : "s")}.");
                        }
                        if (settings.ShowFirewallWarnings is { } show)
                        {
                            next.ShowFirewallWarnings = show;
                            changed.Add(show ? "Windows Security shows its Firewall and network protection page again, which says its firewall is off."
                                : "Windows Security no longer warns that its firewall is off; its Firewall and network protection page stays hidden until Windows Firewall is back in control.");
                        }
                        Apply(next, state.Revision);
                        message = string.Join(" ", changed);
                        break;
                    }
                    case "resolve":
                    {
                        if (state.Phase != "Active") throw new InvalidOperationException("Darkwire is not enforcing policy.");
                        var answering = request.RequestId ?? throw new InvalidDataException("A request ID is required.");
                        var rules = learning.PrepareResolution(answering, request.Action ?? throw new InvalidDataException("A decision is required."), request.Scope ?? LearningScope.Exact);
                        var rule = rules[0];
                        var next = Clone(state.Policy);
                        if (request.LearningRoute is not null)
                        {
                            if (rule.Action != RuleAction.Allow || rule.Direction != TrafficDirection.Outbound)
                                throw new InvalidDataException("A route can only be selected when allowing outbound traffic.");
                            if (request.LearningRoute.VpnProfileId is { } selected)
                            {
                                // A profile carries a whole executable; for a shared service host that would be every service it runs,
                                // whether or not the prompt could name the one that asked. A service running alone in a program of its
                                // own, outside Windows, can take one: everything that program sends is that service's.
                                if (!RuleValidator.IsAny(rule.Service))
                                {
                                    if (!VpnAssignments.Carriable(rule.Path)) throw new InvalidDataException(VpnAssignments.ServiceHostRefusal);
                                    if (learning.Pending.FirstOrDefault(p => p.Id == answering)?.Connection is not { } asked || !VpnAssignments.CarriableService(asked.Path, asked.HostedServices))
                                        throw new InvalidDataException(VpnAssignments.WindowsServiceRefusal);
                                }
                                VpnAssignments.Assign(next, selected, rule.Path);
                                // A profile the policy starts running uses the credentials the service holds for it now.
                                if (!VpnAssignments.Running(state.Policy).Any(p => p.Id == selected)) UseStoredCredentials(next, selected);
                            }
                            else VpnAssignments.UseDefault(next, rule.Path);
                        }
                        next.Rules.AddRange(rules);
                        // The broker withdraws the waiting requests the new rules decide, such as the app's other attempts on a port.
                        var waiting = learning.Pending.Select(p => p.Id).Where(id => id != answering).ToArray();
                        Apply(next, state.Revision);
                        var answered = waiting.Except(learning.Pending.Select(p => p.Id)).Count();
                        if (answered > 0) message += $" This decision also answered {answered} other waiting request{(answered == 1 ? "" : "s")}.";
                        break;
                    }
                    case "restore": RestoreCore(); break;
                    case "reconnect-vpn":
                    {
                        var id = request.VpnProfileId ?? throw new InvalidDataException("A VPN profile ID is required.");
                        var name = ProfileName(state.Policy, id);
                        if (state.Phase != "Active" || router is not { Running: true } running) throw new InvalidOperationException("Darkwire runs no VPN tunnels until it enforces policy.");
                        if (!running.Reconnect(id))
                            throw new InvalidOperationException(running.Tunnels.Any(t => t.ProfileId == id && t.State == "Starting") ? $"{name} is already connecting." : $"{name} has no tunnel to reconnect; connect it first.");
                        message = $"Reconnecting {name}: its tunnel starts again with a new connection, and its applications wait meanwhile.";
                        break;
                    }
                    case "import-geo":
                        if (state.Phase != "Inactive") throw new InvalidOperationException("Restore Windows Firewall before replacing the service GeoIP database.");
                        if (geoStore is null) throw new InvalidOperationException("The service has no protected GeoIP store.");
                        geoDatabase = geoStore.Save(request.GeoCsv ?? throw new InvalidDataException("CSV data is required.")); geoLoaded = true;
                        message = $"Protected GeoIP database imported: {geoDatabase.Count:N0} networks.";
                        break;
                    default: throw new InvalidDataException("Unknown service command.");
                }
                return request.Command is "takeover" or "apply" or "apply-vpn" or "apply-settings" or "resolve"
                    ? new(true, message, Status(), Clone(state.Policy)) : Reply(message);
            }
            catch (Exception error) { message = error.Message; return new(false, message, Status()); }
            finally { Publish(); }
        }
    }

    private (AppState Candidate, List<string> Errors, WindowsDefaults Defaults) Prepare(AppState requested)
    {
        ValidatePolicy(requested);
        var imported = firewall.Read(); var candidate = Merge(Clone(requested), imported.Rules);
        var errors = imported.Errors.ToList();
        try { errors.AddRange(firewall.Conflicts()); }
        catch (COMException) { errors.Add("Other firewall products could not be checked."); }
        // Validate the inherited baseline even for Open/Lockdown, whose runtime compilers bypass rules by design.
        var baseline = Clone(candidate); baseline.Mode = FirewallMode.BlockNew;
        var baselinePlan = Compile(baseline, true);
        errors.AddRange(baselinePlan.Errors);
        // Resolve every native identity, app ID and keyword now, so a translatable policy cannot fail at WFP commit.
        if (baselinePlan.CanApply) errors.AddRange(nativePreflight(baselinePlan));
        errors.AddRange(Compile(candidate, true).Errors);
        if (candidate.Mode == FirewallMode.Open) errors.Add("Initial takeover requires Learning, Block new, or Lockdown. Open can be selected after activation.");
        if (Routes(candidate) && (createRouter is null || !Router().Available)) errors.Add(RuntimeMissing(candidate));
        else if (Routes(candidate)) errors.AddRange(Vpn(candidate).Errors);
        return (candidate, errors.Distinct().ToList(), new(imported.InboundAllowed, imported.OutboundAllowed));
    }

    private static string RuntimeMissing(AppState policy) => VpnAssignments.Running(policy).Any()
        ? @"VPN profiles run in the connection router, which needs the Wintun runtime in Service\Backends\Router."
        : @"Routing connections needs the Wintun runtime in Service\Backends\Router. Install it, or turn off connection routing to enforce with kernel filters only.";

    /// <summary>
    /// Re-imports Windows rules by stable ID. A draft copy keeps its edits and consent only while its Windows definition is unchanged;
    /// the import classification always comes from Windows. Rules imported before IDs existed are replaced.
    /// </summary>
    internal static AppState Merge(AppState draft, IReadOnlyList<FirewallRule> current)
    {
        var edited = draft.Rules.Where(r => r.WindowsRuleId is not null).GroupBy(r => r.WindowsRuleId!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var rules = draft.Rules.Where(r => r.WindowsRuleId is null && r.Source != "Windows Firewall").ToList();
        foreach (var fresh in current)
        {
            if (fresh.WindowsRuleId is { } id && edited.TryGetValue(id, out var copy) && copy.OriginalDefinition == fresh.OriginalDefinition)
            {
                copy.Import = fresh.Import; copy.ImportWarning = fresh.ImportWarning; copy.Source = fresh.Source;
                rules.Add(copy);
            }
            else rules.Add(fresh);
        }
        draft.Rules = rules; return draft;
    }

    private void TakeOver(AppState requested)
    {
        if (state.Phase != "Inactive") throw new InvalidOperationException("A takeover is already active or requires recovery.");
        var (candidate, errors, _) = Prepare(requested);
        if (errors.Count > 0) throw new InvalidOperationException("Takeover refused: " + string.Join(Environment.NewLine, errors));
        var snapshot = firewall.Read();
        // Re-read and compile the final inherited snapshot immediately before exporting and committing it.
        candidate = Merge(candidate, snapshot.Rules);
        if (snapshot.Errors.Count > 0) throw new InvalidOperationException(string.Join(Environment.NewLine, snapshot.Errors));
        // What Windows Firewall let out at this moment keeps going: each connected application gets a rule allowing it out.
        var accepted = TakeoverAcceptance.Rules(connected?.Invoke() ?? [], Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!, candidate.Rules);
        candidate.Rules.AddRange(accepted);
        var baseline = Clone(candidate); baseline.Mode = FirewallMode.BlockNew; var baselinePlan = Compile(baseline, true); Require(baselinePlan);
        if (nativePreflight(baselinePlan) is { Count: > 0 } nativeErrors) throw new InvalidOperationException(string.Join(Environment.NewLine, nativeErrors));
        var backup = journal.BackupPath(); firewall.Export(backup);
        var prepared = new ServiceJournal { Revision = checked(state.Revision + 1), Phase = "Prepared", Policy = candidate, OriginalProfiles = snapshot.Profiles, BackupFile = backup };
        journal.Write(prepared); state = prepared;
        try
        {
            backend ??= createBackend(); var plans = Plans(candidate, Ready(candidate), strict: true); Require(plans.Kernel);
            Install(plans.Kernel, "takeover");
            // The router asks through the learning broker, so the broker learns the policy first.
            learning.UpdatePolicy(candidate);
            if (Routes(candidate)) Router().Start(Context(candidate, plans));
            var hardening = protections();
            firewall.SetProfiles(new Dictionary<int, bool> { [1] = false, [2] = false, [4] = false });
            RequireProtections(hardening);
            var active = WithPhase(state, "Active"); journal.Write(active); state = active;
            SyncFirewallArea();
            RequestDownloads(candidate);
            message = "Darkwire is enforcing persistent policy. Windows Firewall profile filtering is disabled; BFE and MpsSvc remain running." +
                (Routes(candidate) ? " New outbound connections are routed through Darkwire and held until a rule decides them." : "") +
                (plans.Vpn.Profiles.Count > 0 ? " VPN profiles are starting; their applications wait for them and never use another network." : "") +
                (accepted.Count > 0 ? $" {accepted.Count} application{(accepted.Count == 1 ? " that was" : "s that were")} connected keep{(accepted.Count == 1 ? "s" : "")} access through the default route; their rules are in the {TakeoverAcceptance.Group} group." : "");
        }
        catch
        {
            RestoreCore(); throw;
        }
    }

    /// <summary>
    /// Disabling profiles must leave Windows Service Hardening and AppContainer isolation blocks in place. MPSSVC may rebuild
    /// them asynchronously, so the check waits briefly before restoring Windows Firewall.
    /// </summary>
    private void RequireProtections(IReadOnlyDictionary<string, int> before)
    {
        for (var attempt = 0; ; attempt++)
        {
            var after = protections();
            var lost = before.Where(p => after.GetValueOrDefault(p.Key) < p.Value).Select(p => $"{p.Key} {p.Value} → {after.GetValueOrDefault(p.Key)}").ToArray();
            if (lost.Length == 0) return;
            if (attempt >= 10) throw new InvalidOperationException("Disabling Windows Firewall profiles removed protection filters (" + string.Join(", ", lost) + "). Windows Firewall was restored.");
            Thread.Sleep(500);
        }
    }

    private void Apply(AppState requested, long? expectedRevision)
    {
        if (state.Phase != "Active" || backend is null) throw new InvalidOperationException("Activate firewall takeover before changing enforced policy.");
        if (expectedRevision is null || expectedRevision.Value != state.Revision) throw new InvalidOperationException("The policy changed or was not loaded from the service. Load the active policy before applying edits.");
        ValidatePolicy(requested); var candidate = Clone(requested);
        if (Routes(candidate) && (createRouter is null || !Router().Available)) throw new InvalidOperationException(RuntimeMissing(candidate));
        var plans = Plans(candidate, Ready(candidate), strict: true); var plan = plans.Kernel; Require(plan);
        if (nativePreflight(plan) is { Count: > 0 } nativeErrors) throw new InvalidOperationException(string.Join(Environment.NewLine, nativeErrors));
        var old = state;
        var staged = new ServiceJournal { Revision = checked(old.Revision + 1), Phase = "Applying", Policy = candidate, OriginalProfiles = old.OriginalProfiles, BackupFile = old.BackupFile, OriginalAudit = old.OriginalAudit,
            OriginalFirewallArea = old.OriginalFirewallArea };
        journal.Write(staged); state = staged;
        try { Install(plan, "policy change"); }
        catch
        {
            try { journal.Write(old); state = old; }
            catch { learning.UpdatePolicy(new() { Mode = FirewallMode.BlockNew }); throw; }
            throw;
        }
        var committed = new ServiceJournal { Revision = staged.Revision, Phase = "Active", Policy = candidate, OriginalProfiles = old.OriginalProfiles, BackupFile = old.BackupFile, OriginalAudit = old.OriginalAudit,
            OriginalFirewallArea = old.OriginalFirewallArea };
        try { journal.Write(committed); }
        catch { learning.UpdatePolicy(new() { Mode = FirewallMode.BlockNew }); throw; }
        state = committed; learning.UpdatePolicy(candidate);
        SyncFirewallArea();
        message = candidate.Mode == FirewallMode.Learning
            ? Routes(candidate) ? "Learning enforced: new connections wait for your decision." : "Learning enforced: unmatched attempts are blocked until approved, then applications retry."
            : "Enforced policy updated.";
        // A rule added for a prompt releases the connections held for it; a route choice starts its profile.
        TrySyncRouter(candidate, plans);
        RequestDownloads(candidate);
    }

    /// <summary>Routing is on in every enforced mode, and in Open only to carry VPN assignments, run connected profiles and answer through encrypted DNS.</summary>
    private static bool Routes(AppState policy) => policy.RouteConnections && (policy.Mode != FirewallMode.Open || VpnAssignments.Running(policy).Any() || policy.DnsServers.Count > 0);
    private IConnectionRouter Router() => router ??= createRouter?.Invoke() ?? throw new InvalidOperationException("Connection routing is unavailable in this service.");

    /// <summary>VPN routing for a policy: the assignments, the profiles to run, their backends' peer permits, and what is wrong with them.</summary>
    private sealed record VpnRouting(TunnelRoutingPlan? Plan, IReadOnlyList<TunnelDemand> Profiles, IReadOnlyList<TunnelEndpoint> Endpoints, IReadOnlyList<string> Errors)
    {
        public static readonly VpnRouting None = new(null, [], [], []);
    }

    /// <summary>The decision plan the router evaluates, the kernel plan WFP installs (with router filters when routing), and the VPN routing behind both.</summary>
    private sealed record PolicyPlans(FilterPlan Decision, FilterPlan Kernel, VpnRouting Vpn);

    /// <summary>
    /// Admission (strict) refuses any VPN profile that cannot run. At runtime such a profile is left out and reported: its
    /// applications stay guarded and their flows are refused, never sent around the tunnel.
    /// </summary>
    private PolicyPlans Plans(AppState policy, bool learningReady, bool strict)
    {
        var decision = Compile(policy, learningReady);
        if (!Routes(policy) || !decision.CanApply) return new(decision, Locked(policy, decision, null), VpnRouting.None);
        var vpn = Vpn(policy);
        if (vpn.Errors.Count > 0 && (strict || vpn.Plan is null && VpnAssignments.Routed(policy)))
        {
            FilterPlan refused = new([], vpn.Errors);
            return new(refused, refused, vpn);
        }
        if (vpn.Errors.Count > 0) ReportVpn(vpn.Errors);
        // Encrypted DNS runs dnscrypt-proxy; without it, lookups bound for the internet fail rather than go anywhere else.
        if (policy.DnsServers.Count > 0 && !Router().Supports(DnsBackend))
        {
            const string missing = @"Encrypted DNS runs dnscrypt-proxy, which is not installed in Service\Backends\DnsCrypt.";
            if (strict) { FilterPlan refused = new([], [missing]); return new(refused, refused, vpn); }
            if (!reportedDnsBackend) Alert(missing + " Lookups bound for the internet fail until it is.");
            reportedDnsBackend = true;
        }
        else reportedDnsBackend = false;
        var directory = Path.GetDirectoryName(Router().Plan.ServicePath)!;
        var routerPlan = Router().Plan with
        {
            TunneledApplications = vpn.Plan?.Applications.Select(a => a.ApplicationPath).ToArray() ?? [],
            TunnelAll = vpn.Plan?.DefaultProfileId is not null, Endpoints = vpn.Endpoints, LeakGuard = policy.Mode != FirewallMode.Open,
            FiltersDns = NameFilter(policy) is not null || policy.DnsServers.Count > 0, LocalNetworks = LocalNetworks(policy),
            // The DNS proxy answers the DNS client, which the startup lock lets through, so it reaches its servers under the lock too.
            OwnApplications = policy.DnsServers.Count > 0 && policy.Mode != FirewallMode.Lockdown ? [DnsCryptProxy.Executable(directory)] : []
        };
        return new(FilterCompiler.Endpoints(decision, routerPlan), Locked(policy, FilterCompiler.Route(decision, routerPlan), routerPlan), vpn);
    }

    /// <summary>The kernel plan with the startup lock the policy asks for, which lets this service and its VPN backends through.</summary>
    private static FilterPlan Locked(AppState policy, FilterPlan kernel, RouterPlan? router) =>
        kernel with { StartupLock = FilterCompiler.StartupLock(policy, kernel, Environment.ProcessPath ?? "", router) };

    /// <summary>How long the startup lock waits for the router and the VPN tunnels; what is still missing then stays blocked by its own guards.</summary>
    public static readonly TimeSpan StartupLockLimit = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Releases the startup lock once the policy is in force, the router runs and every VPN tunnel it starts is up or failed,
    /// or once the limit has passed. A failed tunnel's flows stay refused and a default profile's carry nothing, so
    /// releasing the lock never lets a VPN's traffic leave around its tunnel.
    /// </summary>
    private void ReleaseWhenRestored()
    {
        if (restored) return;
        var enforcing = state.Phase == "Active" && backend is not null;
        var settled = !enforcing || !Routes(state.Policy) || router?.Running == true && router.Tunnels.All(t => t.State != "Starting");
        if (!settled && clock.GetUtcNow() - started < StartupLockLimit) return;
        restored = true;
        if (!enforcing) return;
        if (Release()) { message = "Darkwire restored its policy" + (router?.Tunnels.Count > 0 ? " and VPN tunnels" : "") + "; the startup lock is released."; return; }
        // Unreleased, the lock would hold for good: install the plan without it.
        var plan = Plans(state.Policy, Ready(state.Policy), strict: false).Kernel;
        if (plan.CanApply) Install(plan, "unreleased lock");
    }

    private bool Release()
    {
        try { backend!.ReleaseStartupLock(); return true; }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException or ObjectDisposedException)
        { Alert("The startup lock could not be released, so it is left out of the installed filters: " + error.Message); return false; }
    }

    /// <summary>
    /// Every profile the policy runs, routed through or kept connected, must have the same credentials stored in the service
    /// and an installed backend. Lockdown refuses every routed flow, so no tunnel runs there; the assignments still guard
    /// their applications.
    /// </summary>
    private VpnRouting Vpn(AppState policy)
    {
        if (!VpnAssignments.Running(policy).Any()) return VpnRouting.None;
        TunnelRoutingPlan plan;
        try { plan = TunnelRoutingPlan.Build(policy.VpnProfiles.Select(p => new TunnelProfileAssignment(p.Id, p.Kind, p.Applications)), policy.DefaultOutboundVpnProfileId); }
        catch (InvalidDataException error) { return new(null, [], [], [error.Message]); }
        var service = Router().Plan.ServicePath; var directory = Path.GetDirectoryName(service)!;
        // Darkwire's service relays every flow and the backends carry the tunnels; neither can travel inside one. Its DNS proxy
        // takes the route set for Darkwire's own connections.
        var own = new[] { service, TunnelBackends.Executable(directory, "WireGuard"), DnsCryptProxy.Executable(directory) };
        if (plan.Applications.FirstOrDefault(a => own.Contains(a.ApplicationPath, StringComparer.OrdinalIgnoreCase)) is { } self)
            return new(null, [], [], [$"{Path.GetFileName(self.ApplicationPath)} is part of Darkwire and cannot be assigned to a VPN profile."]);
        if (policy.Mode == FirewallMode.Lockdown) return new(plan, [], [], []);
        List<string> errors = []; List<TunnelDemand> profiles = []; List<TunnelEndpoint> endpoints = [];
        var stored = new Dictionary<Guid, StoredVpnProfile>();
        try { foreach (var profile in RequireVault().List()) stored[profile.Id] = profile; }
        catch (Exception error) when (error is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or JsonException)
        { errors.Add("Stored VPN credentials are unavailable: " + error.Message); }
        // A disconnected profile starts no tunnel, so it needs neither credentials nor a permit to its server; its routes stay
        // in the plan, so what it carries is held, then refused, never sent another way.
        foreach (var profile in VpnAssignments.Tunneled(policy))
        {
            // An OpenVPN profile from an earlier build stays in the routes, so what it carries is refused, but never runs.
            if (profile.Kind != "WireGuard") { errors.Add($"{profile.Name}: {VpnConfiguration.Unsupported(profile.Kind)}"); continue; }
            if (!stored.TryGetValue(profile.Id, out var credentials) || credentials.Kind != profile.Kind || credentials.Revision != profile.CredentialsRevision)
            { errors.Add($"{profile.Name}: store this configuration in the service (VPN, Store in service), then apply the policy again."); continue; }
            if (!Router().Supports(profile.Kind)) { errors.Add($@"{profile.Name}: the protected {profile.Kind} backend is not installed in Service\Backends\{profile.Kind}."); continue; }
            try { endpoints.AddRange(TunnelBackends.Endpoints(directory, profile.Kind, profile.Id, credentials.Endpoint)); }
            catch (InvalidDataException error) { errors.Add($"{profile.Name}: {error.Message}"); continue; }
            profiles.Add(new(profile.Id, profile.Kind, credentials.Revision));
        }
        return new(plan, profiles, endpoints, errors);
    }

    private string? reportedVpn;
    private void ReportVpn(IReadOnlyList<string> errors)
    {
        var text = string.Join(" ", errors);
        if (text == reportedVpn) return;
        reportedVpn = text;
        Alert("VPN profiles that cannot run keep their applications blocked: " + text);
    }

    private RouterContext Context(AppState policy, PolicyPlans plans)
    {
        // Darkwire's own connections take the default route's profile, or the one chosen for them; one that cannot run takes
        // them nowhere. Lockdown runs no DNS proxy, as it runs no tunnel.
        var ownProfile = VpnAssignments.OwnProfile(policy);
        return new(plans.Decision, policy.Mode, compiledNetwork ?? network.Capture())
        {
            Tunnels = plans.Vpn.Plan, Profiles = plans.Vpn.Profiles, Names = NameFilter(policy), BypassLocal = policy.LocalNetworkBypassesVpn,
            AllowedCountries = policy.CountryAllowList ? policy.AllowedCountries.Select(c => c.ToUpperInvariant()).ToHashSet(StringComparer.Ordinal) : null,
            // A weekly GeoIP update reaches the router's checks without another plan.
            CountryOf = address => Volatile.Read(ref geoDatabase)?.Lookup(address.ToString())?.Country,
            NameBlocked = NameBlocked, FlowDenied = FlowDenied,
            LoopbackNames = LoopbackFilter(policy), NameAnswered = _ => listHits.Hit([BlocklistHits.NamesKey]),
            Dns = policy.Mode == FirewallMode.Lockdown ? [] : DnsUpstreams(policy),
            OwnTunnel = ownProfile, OwnRefused = ownProfile is { } profile && plans.Vpn.Profiles.All(p => p.ProfileId != profile),
            Refused = refusals.Record
        };
    }

    private readonly BlockedFlowLog refusals = new();

    public const string DnsBackend = "DnsCrypt";
    private bool reportedDnsBackend;

    /// <summary>
    /// The policy's encrypted DNS servers with their stamps: a listed server's from the verified resolver list the service holds,
    /// or those the policy kept when the list is missing or no longer names it.
    /// </summary>
    private IReadOnlyList<DnsUpstream> DnsUpstreams(AppState policy)
    {
        var listed = resolvers?.Servers ?? [];
        return [.. policy.DnsServers.Select(server => new DnsUpstream(server.Name,
            server.Listed && listed.FirstOrDefault(e => e.Name == server.Name) is { } entry ? entry.Stamps : [.. server.Stamps]))];
    }

    /// <summary>A changed resolver list reaches the DNS proxy when the enforced policy runs servers from it.</summary>
    public void UpdateResolvers()
    {
        lock (gate)
        {
            try
            {
                if (state.Phase != "Active" || backend is null || !state.Policy.DnsServers.Any(s => s.Listed) || router?.Running != true) return;
                TrySyncRouter(state.Policy, Plans(state.Policy, Ready(state.Policy), strict: false));
            }
            finally { Publish(); }
        }
    }

    /// <summary>
    /// Where Darkwire's own downloads to an address leave: through the tunnel of the profile the enforced policy sends its own
    /// connections through, or physically. While that tunnel is not up they do not leave at all. Never waits for the
    /// coordinator lock.
    /// </summary>
    public Egress? OwnEgress(IPAddress destination)
    {
        var current = Volatile.Read(ref state);
        var profile = current.Phase == "Active" && Routes(current.Policy) && current.Policy.Mode != FirewallMode.Lockdown ? VpnAssignments.OwnProfile(current.Policy) : null;
        var active = Volatile.Read(ref router);
        if (profile is not null) return active?.Running == true ? active.OwnEgress(destination, profile) : null;
        return active?.Running == true ? active.OwnEgress(destination, null) : ServiceDownloads.Physical(destination, luid => active?.Owns(luid) == true);
    }

    /// <summary>
    /// The local networks a default profile leaves to rules, from the interfaces the plan was compiled with, none of them a
    /// VPN tunnel the router runs, and the internal address ranges. Empty unless the policy keeps local traffic off the tunnels.
    /// </summary>
    private IReadOnlyList<string> LocalNetworks(AppState policy) => policy.LocalNetworkBypassesVpn
        ? [.. (compiledNetwork ?? network.Capture()).LocalNetworks(luid => router?.Owns(luid) == true), .. InternalNetworks.Unicast] : [];

    private (string Key, DomainFilter? Filter) names = ("", null);
    // Each list's own names, by hit key, to tell which lists a blocked lookup belongs to.
    private (string Key, DomainFilter Filter)[] nameLists = [];
    private readonly BlocklistHitCounter listHits = new();
    /// <summary>
    /// What DNS filtering answers as nonexistent in Learning and Block new: the policy's downloaded catalog domain lists and the
    /// names in its custom lists, plus Firefox's canary, which turns Firefox's automatic encrypted DNS off, also while only
    /// blocked names are enforced. The hosts Darkwire downloads from stay resolvable. Rebuilt only when the lists change.
    /// </summary>
    private DomainFilter? NameFilter(AppState policy)
    {
        if (policy.Mode is not (FirewallMode.Learning or FirewallMode.BlockNew) || !policy.RouteConnections) return null;
        var enabled = policy.Blocklists.Where(l => l.Enabled).ToArray();
        var catalog = enabled.Select(l => BlocklistCatalog.Find(l.CatalogId)).OfType<BlocklistCatalogEntry>().Where(e => e.Domains).Select(e => e.Id).Distinct().ToArray();
        var custom = enabled.Where(l => l.CatalogId is null).Select(l => (l.Name, Names: l.Entries.Where(e => !IpNetwork.TryParse(e, out _)).ToArray())).Where(l => l.Names.Length > 0).ToArray();
        if (catalog.Length == 0 && custom.Length == 0 && policy.BlockedNames.Count == 0) return null;
        var fingerprint = new HashCode();
        foreach (var (name, entries) in custom) { fingerprint.Add(name, StringComparer.Ordinal); foreach (var entry in entries) fingerprint.Add(entry, StringComparer.Ordinal); }
        var key = $"{string.Join(",", catalog)}|{blocklists?.Version}|{custom.Length}:{fingerprint.ToHashCode()}";
        if (names.Key == key) return names.Filter;
        List<(string Key, DomainFilter Filter)> lists = [.. custom.Select(l => (BlocklistHits.CustomKey(l.Name), new DomainFilter([], l.Names, BlocklistCatalog.SourceHosts)))];
        foreach (var id in catalog) if (blocklists?.Names(id) is { } stored) lists.Add((id, stored));
        names = (key, DomainFilter.Combine([new([], [BlocklistCatalog.Canary], BlocklistCatalog.SourceHosts), .. lists.Select(l => l.Filter)]));
        Volatile.Write(ref nameLists, [.. lists]);
        return names.Filter;
    }

    private (string Key, DomainFilter? Filter) loopbackNames = ("", null);
    /// <summary>
    /// The names DNS filtering answers with this PC's own address in Learning and Block new: the policy's blocked names, each
    /// with its subdomains. Rebuilt only when they change.
    /// </summary>
    private DomainFilter? LoopbackFilter(AppState policy)
    {
        if (policy.Mode is not (FirewallMode.Learning or FirewallMode.BlockNew) || !policy.RouteConnections || policy.BlockedNames.Count == 0) return null;
        var key = string.Join("\n", policy.BlockedNames);
        if (loopbackNames.Key != key) loopbackNames = (key, new DomainFilter([], policy.BlockedNames, []));
        return loopbackNames.Filter;
    }

    /// <summary>A lookup DNS filtering answered as nonexistent counts for each list that names it; Firefox's canary for none.</summary>
    private void NameBlocked(string name) => listHits.Hit(Volatile.Read(ref nameLists).Where(l => l.Filter.Blocks(name)).Select(l => l.Key));

    /// <summary>A flow an explicit deny refused counts for the list that deny belongs to, if any.</summary>
    private void FlowDenied(string filter)
    {
        if (ListKey(filter, Volatile.Read(ref state).Policy) is { } key) listHits.Hit([key]);
    }

    /// <summary>The hit key of the list a deny filter belongs to: catalog lists' filters carry their names, custom lists' theirs.</summary>
    private static string? ListKey(string filter, AppState policy) =>
        BlocklistCatalog.Entries.FirstOrDefault(e => e.Name == filter)?.Id ??
        (policy.Blocklists.Any(l => l.CatalogId is null && l.Name == filter) ? BlocklistHits.CustomKey(filter) : null);

    /// <summary>What blocklists blocked since the service started: the router's counts, and the kernel's drops for each list's filters.</summary>
    private BlocklistHits ListHits() => listHits.Snapshot((backend?.DropsByName ?? new Dictionary<string, long>())
        .Select(p => (Key: ListKey(p.Key, state.Policy), Count: p.Value)).Where(p => p.Key is not null).Select(p => (p.Key!, p.Count)));

    /// <summary>Asks the store for enabled catalog lists without a fresh copy; each applies as it arrives.</summary>
    private void RequestDownloads(AppState policy)
    {
        if (blocklists is null) return;
        foreach (var source in policy.Blocklists.Where(l => l.Enabled && l.CatalogId is not null))
        {
            try { blocklists.Request(source.CatalogId!, BlocklistStore.Refresh); }
            catch (InvalidDataException) { }
        }
    }

    /// <summary>Catalog lists the enforced policy enables; the store keeps them fresh.</summary>
    public IReadOnlyList<string> EnabledBlocklists()
    {
        lock (gate) return state.Phase == "Active" ? state.Policy.Blocklists.Where(l => l.Enabled && l.CatalogId is not null).Select(l => l.CatalogId!).ToArray() : [];
    }

    /// <summary>
    /// Applies a freshly downloaded catalog list. Network lists reach the kernel only if the plan still installs, otherwise the
    /// previous filters stay; domain lists reach the router's DNS filter.
    /// </summary>
    public void UpdateBlocklists()
    {
        lock (gate)
        {
            try
            {
                if (state.Phase != "Active" || backend is null || !state.Policy.Blocklists.Any(l => l.Enabled && l.CatalogId is not null)) return;
                var plans = Plans(state.Policy, Ready(state.Policy), strict: false); var plan = plans.Kernel;
                if (!plan.CanApply) { Alert("Downloaded blocklists were not applied; the previous filters remain: " + plan.Errors[0]); return; }
                try
                {
                    if (installed is null || !plan.Filters.SequenceEqual(installed)) Install(plan, "blocklist update");
                    else ReportWarnings(plan);
                    if (router?.Running == true) TrySyncRouter(state.Policy, plans);
                }
                catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException or IOException)
                { Alert("Downloaded blocklists were not applied; the previous filters remain: " + error.Message); }
            }
            finally { Publish(); }
        }
    }

    /// <summary>The store's lists, each marked enforced when the active policy enables it and its data is in force.</summary>
    private IReadOnlyList<BlocklistStatus> BlocklistStatuses()
    {
        var statuses = RequireBlocklists().Status();
        if (state.Phase != "Active") return statuses;
        var enabled = state.Policy.Blocklists.Where(l => l.Enabled && l.CatalogId is not null).Select(l => l.CatalogId!).ToHashSet();
        var routed = router?.Running == true && NameFilter(state.Policy) is not null;
        return statuses.Select(s => s with
        {
            Enforced = s.Count > 0 && enabled.Contains(s.Id) && BlocklistCatalog.Find(s.Id) is { } entry &&
                (entry.Domains ? routed : installed?.Any(f => f.Name == entry.Name) == true)
        }).ToArray();
    }

    private IBlocklistStore RequireBlocklists() => blocklists ?? throw new InvalidOperationException("The service has no blocklist store.");

    /// <summary>Starts, updates or stops the router to match the policy. Failures leave the kernel plan failing closed and are retried.</summary>
    private void TrySyncRouter(AppState policy, PolicyPlans plans)
    {
        try
        {
            if (!Routes(policy)) { router?.Stop(); return; }
            if (!plans.Decision.CanApply) throw new InvalidOperationException(string.Join(Environment.NewLine, plans.Decision.Errors));
            var context = Context(policy, plans);
            var active = Router();
            if (active.Running) active.Update(context); else active.Start(context);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            routerRetry = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
            Alert("Connection routing is not running; routed traffic stays blocked until it recovers: " + error.Message);
        }
    }

    private void WatchRouter()
    {
        WatchTunnels();
        WatchDns();
        if (!Routes(state.Policy) || router?.Running == true || DateTimeOffset.UtcNow < routerRetry) return;
        if (router?.Fault is { } fault) Alert("Connection routing stopped (" + fault + "); restarting it.");
        TrySyncRouter(state.Policy, Plans(state.Policy, Ready(state.Policy), strict: false));
    }

    private string? reportedDns;
    /// <summary>Reports the DNS proxy failing, once for each reason, and answering again.</summary>
    private void WatchDns()
    {
        var dns = state.Policy.DnsServers.Count > 0 && router?.Running == true ? router.Dns : null;
        var failing = dns is { State: "Failed" } ? dns.Error ?? "it stopped." : null;
        if (failing is not null && failing != reportedDns) Alert("Darkwire's DNS proxy is not answering, so lookups bound for the internet fail: " + failing);
        else if (failing is null && reportedDns is not null && dns is { State: "Ready" }) Alert("Darkwire's DNS proxy is answering again.");
        if (failing is not null || dns is null or { State: "Ready" }) reportedDns = failing;
    }

    private readonly Dictionary<Guid, string> tunnelStates = [];
    // Per profile: the last silence past its limit and whether it was reported, and when its server falling silent last was.
    private readonly Dictionary<Guid, (DateTimeOffset Since, bool Reported)> unanswered = [];
    private readonly Dictionary<Guid, DateTimeOffset> silenceReported = [];
    private Guid? reportedSilent;
    /// <summary>How long a tunnel may send without hearing from its server, at first or after it answered, before that is reported.</summary>
    public static readonly TimeSpan UnansweredAfter = TimeSpan.FromSeconds(15);
    /// <summary>A server that falls silent again this soon after the last report shows on its card but is not reported again.</summary>
    public static readonly TimeSpan SilenceReportEvery = TimeSpan.FromMinutes(10);
    // Per profile, the reconnects for silence last seen, so each is reported once.
    private readonly Dictionary<Guid, int> reconnectsSeen = [], checkRestartsSeen = [];
    /// <summary>
    /// Reports a VPN profile going down, and coming back, once each; a tunnel that sends but hears nothing from its server,
    /// which carries nothing, once each time it comes up without an answer and whenever a server that answered falls silent;
    /// the supervisor reconnecting such a tunnel, at its first, second, fourth and later doubling reconnects, which stand for
    /// the silence until the server answers; its server answering after such a report; and a default profile whose tunnel
    /// carries no resolver, since the router refuses the Windows DNS client's lookups then.
    /// </summary>
    private void WatchTunnels()
    {
        var current = router?.Tunnels ?? [];
        var now = clock.GetUtcNow();
        string Name(TunnelStatus tunnel) => state.Policy.VpnProfiles.FirstOrDefault(p => p.Id == tunnel.ProfileId)?.Name ?? tunnel.Kind;
        foreach (var tunnel in current)
        {
            var previous = tunnelStates.GetValueOrDefault(tunnel.ProfileId);
            tunnelStates[tunnel.ProfileId] = tunnel.State;
            if (tunnel.State == "Failed" && previous != "Failed") Alert($"VPN profile {Name(tunnel)} is down; its applications are refused until it recovers: {tunnel.Error}");
            else if (tunnel.State == "Up" && previous == "Failed") Alert($"VPN profile {Name(tunnel)} is up again.");
            var reconnects = tunnel.Reconnects;
            if (reconnects > reconnectsSeen.GetValueOrDefault(tunnel.ProfileId) && (reconnects & (reconnects - 1)) == 0)
            {
                Alert(reconnects == 1 ? $"VPN profile {Name(tunnel)}'s server stopped answering, so Darkwire reconnected its tunnel."
                    : $"VPN profile {Name(tunnel)}'s server still isn't answering; Darkwire has reconnected its tunnel {reconnects} times and keeps trying, less often each time.");
                // Its answer, whenever it comes, ends a reported silence.
                unanswered[tunnel.ProfileId] = (unanswered.GetValueOrDefault(tunnel.ProfileId).Since, true);
            }
            reconnectsSeen[tunnel.ProfileId] = reconnects;
            var restarts = tunnel.CheckRestarts;
            if (restarts > checkRestartsSeen.GetValueOrDefault(tunnel.ProfileId) && (restarts & (restarts - 1)) == 0)
                Alert(restarts == 1 ? $"VPN profile {Name(tunnel)}'s DNS server did not answer through its tunnel when Darkwire checked it, so Darkwire restarted the tunnel, with any sharing its address."
                    : $"VPN profile {Name(tunnel)}'s tunnel still carries nothing back when checked; Darkwire has restarted it {restarts} times and keeps trying, less often each time.");
            checkRestartsSeen[tunnel.ProfileId] = restarts;
            // Between reconnects the silence goes on: kept while the tunnel restarts, and not reported again as a new one.
            if (tunnel.State != "Up") { if (reconnects == 0) unanswered.Remove(tunnel.ProfileId); }
            else if (tunnel.Unanswered is { } quiet)
            {
                if (reconnects > 0) continue;
                // Never answered, it is one silence each time it comes up; answered before, one each time its server falls silent.
                var since = tunnel.ReceivedBytes == 0 ? tunnel.Since : quiet;
                if (now - quiet < UnansweredAfter || unanswered.TryGetValue(tunnel.ProfileId, out var known) && known.Since == since) continue;
                var report = tunnel.ReceivedBytes == 0 || !silenceReported.TryGetValue(tunnel.ProfileId, out var last) || now - last >= SilenceReportEvery;
                unanswered[tunnel.ProfileId] = (since, report);
                if (!report) continue;
                if (tunnel.ReceivedBytes == 0)
                    Alert($"VPN profile {Name(tunnel)} is up, but its server has not answered anything sent through it. Check the server's address and keys, and that this network lets the VPN through.");
                else
                {
                    silenceReported[tunnel.ProfileId] = now;
                    Alert($"VPN profile {Name(tunnel)}'s server stopped answering{(tunnel.LastReceived is { } heard ? $" at {heard.ToLocalTime():HH:mm:ss}" : "")}: nothing sent through it since has had an answer. " +
                        "Check that the server is still up, and that this network lets the VPN through.");
                }
            }
            else if (tunnel.ReceivedBytes > 0 && unanswered.Remove(tunnel.ProfileId, out var ended) && ended.Reported) Alert($"VPN profile {Name(tunnel)}'s server is answering.");
        }
        foreach (var gone in tunnelStates.Keys.Where(id => current.All(t => t.ProfileId != id)).ToArray()) tunnelStates.Remove(gone);
        foreach (var gone in unanswered.Keys.Where(id => current.All(t => t.ProfileId != id)).ToArray()) unanswered.Remove(gone);
        foreach (var gone in silenceReported.Keys.Where(id => current.All(t => t.ProfileId != id)).ToArray()) silenceReported.Remove(gone);
        foreach (var gone in reconnectsSeen.Keys.Where(id => current.All(t => t.ProfileId != id)).ToArray()) reconnectsSeen.Remove(gone);
        foreach (var gone in checkRestartsSeen.Keys.Where(id => current.All(t => t.ProfileId != id)).ToArray()) checkRestartsSeen.Remove(gone);
        var silent = current.FirstOrDefault(t => t.ProfileId == state.Policy.DefaultOutboundVpnProfileId && t is { State: "Up", Resolvers.Count: 0 });
        if (silent is not null && reportedSilent != silent.ProfileId)
            Alert($"VPN profile {Name(silent)} carries Windows name lookups but names no DNS server its tunnel carries, so they are refused. Add DNS to its WireGuard configuration.");
        reportedSilent = silent?.ProfileId;
    }

    private void RestoreCore()
    {
        if (state.Phase == "Inactive") { message = "Windows Firewall is already in control."; return; }
        var restoring = WithPhase(state, "Restoring"); journal.Write(restoring); state = restoring;
        firewall.SetProfiles(state.OriginalProfiles);
        // Removing the adapter takes its capture routes with it; the leak guard blocks until the filters go too.
        try { router?.Stop(); }
        catch (Exception error) when (error is not OutOfMemoryException) { Alert("The tunnel router did not stop cleanly: " + error.Message); }
        backend ??= createBackend(); backend.RemoveOwnedFilters(); installed = null; appliedNetwork = null;
        RevertAudit();
        SyncFirewallArea();
        var inactive = WithPhase(state, "Inactive"); journal.Write(inactive); state = inactive; learning.UpdatePolicy(new() { Mode = FirewallMode.BlockNew });
        message = "Windows Firewall profile states restored. Darkwire filters removed.";
    }

    private void DrainEvents()
    {
        if (backend is null) return;
        FlowAttribution.Snapshot? sockets = null;
        var now = DateTimeOffset.UtcNow;
        foreach (var connection in backend.DrainBlockedConnections())
        {
            if (state.Phase != "Active") continue;
            var geo = geoDatabase?.Lookup(connection.RemoteAddress);
            var attributed = Attribute(connection, sockets ??= attribution.Begin());
            learning.Observe(geo is null ? attributed : attributed with { Country = geo.Country, Asn = geo.Asn });
            refusals.Record(Refusal(connection, now, state.Policy.Mode switch { FirewallMode.Learning => "Not allowed yet", FirewallMode.Lockdown => "Lockdown", _ => "No rule allows it" }));
        }
        // Explicit denies outside the rules, such as a blocklist's or a country's, name themselves.
        foreach (var (connection, filter) in backend.DrainNamedDrops())
            if (state.Phase == "Active") refusals.Record(Refusal(connection, now, filter));
    }

    private static BlockedFlow Refusal(Connection connection, DateTimeOffset time, string reason) => new(time, connection.Path.Length > 0 ? connection.Path : "Windows",
        connection.RemoteAddress, connection.Protocol is "TCP" or "UDP" ? connection.RemotePort : 0, connection.Protocol, connection.Direction, reason);

    /// <summary>
    /// A blocked attempt as WFP reports it names only the executable. While its socket still exists, the owner tables give the
    /// process, its token the services it runs and, in a process running several, the socket's tag the one that opened it, so
    /// a prompt from a service host names the service that asked and the rule it installs is scoped to that service. WFP
    /// tells services apart only by the token, so the prompt also lists the others sharing the process, which the rule reaches.
    /// A listening socket answers for inbound attempts.
    /// </summary>
    private static Connection Attribute(Connection connection, FlowAttribution.Snapshot sockets)
    {
        if (connection.Service.Length > 0 || !IPAddress.TryParse(connection.LocalAddress, out var local) || !IPAddress.TryParse(connection.RemoteAddress, out var remote)) return connection;
        FlowProcess? process;
        try
        {
            var endpoint = new IPEndPoint(local, connection.LocalPort);
            process = connection.Protocol switch
            {
                "TCP" => connection.Direction == TrafficDirection.Inbound ? sockets.Listener(endpoint) : sockets.Tcp(endpoint, new(remote, connection.RemotePort)),
                "UDP" => sockets.Udp(endpoint),
                _ => null
            };
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException) { return connection; }
        // The owner must be the executable WFP saw; anything else is a recycled port.
        if (process is null || !process.ImagePath.Equals(connection.Path, StringComparison.OrdinalIgnoreCase)) return connection;
        var (hosted, service) = ServiceNames.Of(process);
        return connection with { ProcessId = process.ProcessId, Service = service ?? "", HostedServices = string.Join(", ", hosted) };
    }
    public void Tick(bool verifyIntegrity = false)
    {
        lock (gate)
        {
            try
            {
                // Durable applying intent is authoritative after an uncertain commit outcome.
                if (state.Phase == "Applying") Recover();
                if (state.Phase == "Active" && backend is not null && ++ticks % 5 == 0) { RefreshNetwork(); WatchWindowsFirewall(); WatchRouter(); }
                ReleaseWhenRestored();
                if (verifyIntegrity && state.Phase == "Active" && backend is not null) { VerifyAndRepair(); WatchHardPermits(); }
                DrainEvents();
            }
            // Learning requests, tunnel states and GeoIP checks also change outside the lock; each tick republishes them.
            finally { Publish(); }
        }
    }

    private readonly List<string> alerts = [];
    private void Alert(string text)
    {
        message = text; alerts.Insert(0, DateTimeOffset.Now.ToString("HH:mm:ss") + "  " + text);
        if (alerts.Count > 20) alerts.RemoveAt(alerts.Count - 1);
        ServiceHost.Log("Alert: " + text);
    }

    private readonly Queue<DateTimeOffset> repairs = new();
    /// <summary>
    /// Someone with administrator or kernel rights changed Darkwire's filters. Reinstall the authoritative plan in place.
    /// Repeated tampering escalates to a service restart, which reinstalls policy from the journal.
    /// </summary>
    private void VerifyAndRepair()
    {
        try { backend!.VerifyIntegrity(); auditedAt = clock.GetUtcNow(); WatchLock(); return; }
        catch (InvalidDataException) { auditedAt = clock.GetUtcNow(); }
        var now = DateTimeOffset.UtcNow;
        while (repairs.Count > 0 && now - repairs.Peek() > TimeSpan.FromMinutes(10)) repairs.Dequeue();
        if (repairs.Count >= 5) throw new InvalidDataException("Darkwire filters keep changing outside the service; restarting to reinstall policy.");
        repairs.Enqueue(now);
        var plan = Plans(state.Policy, Ready(state.Policy), strict: false).Kernel; Require(plan);
        Install(plan, "repair");
        Alert("Darkwire filters were changed outside the service and have been reinstalled.");
    }

    private bool Ready(AppState policy) => policy.Mode != FirewallMode.Learning || LearningReady();
    /// <summary>
    /// Prompts for traffic the router cannot hold (inbound, broadcast, bound sockets) come from WFP drop events. A blocked
    /// probe proves they arrive. If not, enable Filtering Platform failure auditing, journal the original settings, and probe again.
    /// </summary>
    private bool LearningReady()
    {
        if (backend is null || !backend.LearningEventsReady) return false;
        if (learningVerified || backend.ProbeLearningEvents()) return learningVerified = true;
        IReadOnlyDictionary<Guid, uint> original;
        try { original = audit.Query(AuditSubcategories); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or UnauthorizedAccessException) { Alert("Audit policy is unavailable: " + error.Message); return false; }
        if (state.OriginalAudit is null)
        {
            var recorded = WithPhase(state, state.Phase); recorded.OriginalAudit = original.ToDictionary(p => p.Key, p => p.Value);
            journal.Write(recorded); state = recorded;
        }
        try { audit.Set(original.ToDictionary(p => p.Key, p => p.Value | 0x2)); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or UnauthorizedAccessException) { Alert("Failure auditing could not be enabled: " + error.Message); RevertAudit(); return false; }
        if (backend.ProbeLearningEvents())
        {
            Alert("Enabled Filtering Platform failure auditing so Darkwire receives blocked-connection events.");
            return learningVerified = true;
        }
        RevertAudit(); return false;
    }
    private void RevertAudit()
    {
        if (state.OriginalAudit is not { } original) return;
        try { audit.Set(original); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        { Alert("Original audit settings could not be restored: " + error.Message); return; }
        var cleared = WithPhase(state, state.Phase); cleared.OriginalAudit = null; journal.Write(cleared); state = cleared;
    }

    /// <summary>
    /// Hides Windows Security's Firewall and network protection area, and with it the warning that Windows Firewall is off,
    /// while Darkwire enforces, unless the policy shows them, journaling the value it replaces first; otherwise puts that
    /// value back. A failure is reported and changes nothing else.
    /// </summary>
    private void SyncFirewallArea()
    {
        var hide = state.Phase == "Active" && !state.Policy.ShowFirewallWarnings;
        try
        {
            if (hide)
            {
                if (state.OriginalFirewallArea is null)
                {
                    var recorded = WithPhase(state, state.Phase); recorded.OriginalFirewallArea = new(firewallArea.Read());
                    journal.Write(recorded); state = recorded;
                }
                if (firewallArea.Read() != 1) firewallArea.Write(1);
            }
            else if (state.OriginalFirewallArea is { } original)
            {
                firewallArea.Write(original.Value);
                var cleared = WithPhase(state, state.Phase); cleared.OriginalFirewallArea = null; journal.Write(cleared); state = cleared;
            }
            firewallWarningsHidden = hide;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Not hidden, or still hidden while the value to put back waits in the journal.
            firewallWarningsHidden = !hide && state.OriginalFirewallArea is not null;
            Alert($"Windows Security's firewall warnings could not be {(hide ? "hidden" : "shown again")}: {error.Message}");
        }
    }
    private bool firewallWarningsHidden;

    private DateTimeOffset? lastReenabled;
    private bool reenableConflict;
    /// <summary>
    /// Re-enabled Windows Firewall only adds blocking, never bypasses Darkwire, but it breaks inherited allows.
    /// Disable it again, unless another program keeps re-enabling it; then report instead of fighting.
    /// </summary>
    private void WatchWindowsFirewall()
    {
        Dictionary<int, bool> profiles;
        try { profiles = firewall.Profiles(); }
        catch (Exception error) when (error is COMException or InvalidOperationException or IOException) { return; }
        if (!profiles.Values.Any(enabled => enabled)) return;
        var now = DateTimeOffset.UtcNow;
        if (lastReenabled is { } previous && now - previous < TimeSpan.FromMinutes(1))
        {
            if (!reenableConflict) Alert("Another program keeps re-enabling Windows Firewall. Both firewalls are enforcing; remove the other firewall manager.");
            reenableConflict = true; return;
        }
        lastReenabled = now; reenableConflict = false;
        try { firewall.SetProfiles(new Dictionary<int, bool> { [1] = false, [2] = false, [4] = false }); Alert("Windows Firewall was re-enabled outside Darkwire and has been disabled again."); }
        catch (Exception error) when (error is COMException or InvalidOperationException or IOException) { Alert("Windows Firewall was re-enabled outside Darkwire and could not be disabled: " + error.Message); }
    }

    private HashSet<string> reportedPermits = [];
    private void WatchHardPermits()
    {
        IReadOnlyList<string> permits;
        // The policy's WireGuard tunnels, and any the router still runs or is starting, whose own permits are no one else's.
        var wireGuard = VpnAssignments.Running(state.Policy).Where(p => p.Kind == "WireGuard").Select(p => p.Id)
            .Concat(router?.Tunnels.Where(t => t.Kind == "WireGuard").Select(t => t.ProfileId) ?? []).ToHashSet();
        try { permits = backend!.HardPermits(wireGuard); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException) { return; }
        var added = permits.Where(p => !reportedPermits.Contains(p)).ToArray();
        reportedPermits = permits.ToHashSet();
        if (added.Length > 0) Alert("Other software installed filters that can override Darkwire blocks: " + string.Join("; ", added.Take(5)) + (added.Length > 5 ? "…" : ""));
    }
    /// <summary>Re-resolves keyword scopes after an interface change. A failed recompile keeps the installed filters.</summary>
    private void RefreshNetwork()
    {
        if (network.Capture().Fingerprint == appliedNetwork) return;
        var plans = Plans(state.Policy, Ready(state.Policy), strict: false); var plan = plans.Kernel;
        if (!plan.CanApply) { message = "Interface change not applied: " + plan.Errors[0]; return; }
        try
        {
            // Reinstalling an identical plan would only churn filter IDs and reauthorize every flow.
            if (installed is not null && plan.Filters.SequenceEqual(installed)) appliedNetwork = compiledNetwork?.Fingerprint;
            else { Install(plan, "interface change"); message = "Applied interface changes to address keyword rules."; }
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException or IOException)
        { Alert("Interface change not applied; previous filters remain: " + error.Message); return; }
        // Subnet routes, egress candidates and network profiles follow the interfaces.
        if (router?.Running == true) TrySyncRouter(state.Policy, plans);
    }
    /// <summary>
    /// Takes GeoIP data from the weekly update. An administrator's imported database stays authoritative. While country or ASN
    /// restrictions are enforced, the new data takes effect only if its plan installs; otherwise the last good data stays, also
    /// across restarts.
    /// </summary>
    public void UpdateGeo(IGeoLookup next, string release)
    {
        lock (gate)
        {
            try
            {
                if (geoStore?.Imported == true) return;
                var previous = geoDatabase; geoDatabase = next; geoLoaded = true;
                if (state.Phase != "Active" || backend is null || state.Policy.BlockedCountries.Count == 0 && state.Policy.BlockedAsns.Count == 0) { KeepGeo(); return; }
                var plans = Plans(state.Policy, Ready(state.Policy), strict: false); var plan = plans.Kernel;
                if (!plan.CanApply) { geoDatabase = previous; Alert($"GeoIP release {release} not applied; previous data remains: {plan.Errors[0]}"); return; }
                try
                {
                    if (installed is null || !plan.Filters.SequenceEqual(installed)) Install(plan, "GeoIP update");
                    if (router?.Running == true) TrySyncRouter(state.Policy, plans);
                    Alert($"GeoIP data updated to release {release}.");
                }
                catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidDataException or IOException)
                { geoDatabase = previous; Alert($"GeoIP release {release} not applied; previous filters remain: {error.Message}"); return; }
                KeepGeo();
            }
            finally { Publish(); }
        }
    }

    /// <summary>
    /// Keeps the compact data in use for the next start, so recovery compiles the data that was enforced rather than a newer
    /// file. A copy that cannot be written is reported; the data in memory stays in use.
    /// </summary>
    private void KeepGeo()
    {
        if (geoStore is null || geoDatabase is not GeoIpDatabase compact) return;
        try { geoStore.Keep(compact); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { Alert($"GeoIP release {compact.Release} could not be kept for restarts: {error.Message}"); }
    }
    private IReadOnlyList<NativeFilter>? installed;
    // The latest installs, newest first, when the last audit of WFP ran, and whether the lock is reported missing.
    private readonly List<FilterInstall> installs = [];
    private DateTimeOffset? auditedAt;
    private bool reportedLockMissing;
    /// <param name="cause">What the install is for, as the status's record of installs names it.</param>
    private void Install(FilterPlan plan, string cause)
    {
        // Once started, the lock is released before it is installed, so changing policy never holds the network; a lock that
        // cannot be released is left out.
        var planned = plan.StartupLock.Count;
        var unreleased = restored && planned > 0 && !Release();
        if (unreleased) plan = plan with { StartupLock = [] };
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        backend!.Apply(plan);
        var took = (int)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        installed = plan.Filters; appliedNetwork = compiledNetwork?.Fingerprint;
        var install = new FilterInstall(clock.GetUtcNow(), cause, state.Revision, plan.Filters.Count, planned, backend.LockFilterCount, restored,
            backend.LastChanges?.Added, backend.LastChanges?.Removed, took);
        installs.Insert(0, install);
        if (installs.Count > 12) installs.RemoveAt(installs.Count - 1);
        // A lock left out for want of a release is already reported as that.
        if (unreleased) reportedLockMissing = true; else WatchLock(install);
        ReportWarnings(plan);
    }

    /// <summary>
    /// Reports, once until it is back, the startup lock the policy asks for missing from Darkwire's filters: after an install
    /// that registered none of it, naming the install, or when an audit finds none of it in WFP.
    /// </summary>
    private void WatchLock(FilterInstall? install = null)
    {
        var registered = install is not null ? install.LockRegistered : backend?.Audited?.Lock;
        if (!state.Policy.StartupLock || installed is not { Count: > 0 } || registered is not 0) { if (registered > 0) reportedLockMissing = false; return; }
        if (reportedLockMissing) return;
        reportedLockMissing = true;
        Alert(install is not null
            ? $"The startup lock is missing after the {install.Cause} (policy revision {install.Revision}): its plan held {install.LockPlanned} lock filters and WFP registered none, so the next start is not held."
            : "The filter audit found no startup lock in WFP although the policy asks for it, so the next start is not held.");
    }
    private string reportedWarnings = "";
    /// <summary>Reports what the enforced plan leaves out, once each time that changes.</summary>
    private void ReportWarnings(FilterPlan plan)
    {
        var left = string.Join(" ", plan.Warnings);
        if (left != reportedWarnings && (reportedWarnings = left).Length > 0) Alert(left);
    }
    private ServiceStatus Status()
    {
        var active = state.Phase == "Active";
        return new(true, active, state.Phase, state.Policy.Mode, backend?.FilterCount ?? 0, backend?.LearningEventsReady ?? false, message, learning.Pending.Count, state.Revision, backend?.BootFilterCount ?? 0, alerts.ToArray(),
            router?.Tunnels is { Count: > 0 } tunnels ? tunnels : null, geoUpdates?.Status, VpnBackends(), Routes(), active ? state.Policy.LocalNetworkBypassesVpn : null,
            active ? ListHits() : null, active && state.Policy.StartupLock && !restored, active ? state.Policy.OwnTraffic : null, active ? state.Policy.OwnTrafficProfileId : null,
            active && state.Policy.DnsServers.Count > 0 && router?.Running == true ? router.Dns : null, active ? refusals.Snapshot() : null,
            backend is null || installs.Count == 0 ? null
                : new(backend.LockFilterCount, backend.StartupLockReleased, auditedAt, backend.Audited?.Filters, backend.Audited?.Lock, installs.ToArray()),
            active ? firewallWarningsHidden : null);
    }

    private static readonly string[] VpnKinds = ["WireGuard"];
    /// <summary>The VPN kinds this service can run, asked of the router once it exists; null when the service cannot route.</summary>
    private IReadOnlyList<string>? VpnBackends() => createRouter is null ? null : [.. VpnKinds.Where(kind => router?.Supports(kind) ?? TunnelBackends.Installed(kind))];

    /// <summary>The profiles the enforced policy runs, copied so a published status never shares the policy's lists.</summary>
    private IReadOnlyList<VpnRouteStatus>? Routes()
    {
        if (state.Phase != "Active") return null;
        var routes = VpnAssignments.Running(state.Policy)
            .Select(p => new VpnRouteStatus(p.Id, p.Kind, p.CredentialsRevision, [.. p.Applications], p.Id == state.Policy.DefaultOutboundVpnProfileId, p.KeepConnected, p.Disconnected)).ToArray();
        return routes.Length > 0 ? routes : null;
    }

    /// <summary>Points a profile at the credentials the service holds for it, when it holds any.</summary>
    private void UseStoredCredentials(AppState policy, Guid id)
    {
        if (vpnVault?.List().FirstOrDefault(p => p.Id == id) is not { } stored) return;
        var profile = policy.VpnProfiles.First(p => p.Id == id);
        profile.CredentialsRevision = stored.Revision; profile.Kind = stored.Kind; profile.Endpoint = stored.Endpoint;
    }
    private ServiceResponse Reply(string text) => new(true, text, Status());
    private static void Require(FilterPlan plan) { if (!plan.CanApply) throw new InvalidOperationException(string.Join(Environment.NewLine, plan.Errors)); }
    private FilterPlan Compile(AppState policy, bool learningReady)
    {
        if (!geoLoaded && (policy.BlockedCountries.Count > 0 || policy.BlockedAsns.Count > 0 || policy.CountryAllowList))
        { geoDatabase = geoStore?.Read(); geoLoaded = true; KeepGeo(); }
        compiledNetwork = network.Capture();
        return FilterCompiler.Compile(policy, learningReady, geoDatabase, compiledNetwork, blocklists);
    }
    private static void ValidatePolicy(AppState policy)
    {
        var validation = PolicyValidation.Validate(policy);
        if (validation.Count > 0) throw new InvalidDataException(string.Join(Environment.NewLine, validation));
        if (policy.SchemaVersion != 1 || policy.Rules is null || policy.Blocklists is null || policy.VpnProfiles is null || policy.BlockedCountries is null || policy.AllowedCountries is null ||
            policy.BlockedAsns is null || policy.DnsServers is null || policy.BlockedNames is null || !Enum.IsDefined(policy.Mode)) throw new InvalidDataException("Invalid service policy.");
        if (policy.Rules.Count > 20000 || policy.Blocklists.Count > 128 || policy.VpnProfiles.Count > 128 || policy.Rules.Any(r => r is null) || policy.Blocklists.Any(l => l is null || l.Entries is null || l.Entries.Any(e => e is null)) || policy.VpnProfiles.Any(p => p is null || p.Applications is null)) throw new InvalidDataException("Invalid policy collection.");
    }
    private IVpnProfileVault RequireVault() => vpnVault ?? throw new InvalidOperationException("The service VPN vault is unavailable.");
    private static ServiceJournal WithPhase(ServiceJournal source, string phase) => new()
    {
        Revision = source.Revision, Phase = phase, Policy = source.Policy, OriginalProfiles = source.OriginalProfiles, BackupFile = source.BackupFile, OriginalAudit = source.OriginalAudit,
        OriginalFirewallArea = source.OriginalFirewallArea
    };
    /// <summary>Credentials stay put while the enforced policy runs their profile. A profile it only lists may get new ones.</summary>
    private void RequireUnusedProfile(Guid id)
    {
        if (state.Phase != "Inactive" && VpnAssignments.Running(state.Policy).Any(p => p.Id == id))
            throw new InvalidOperationException("The enforced policy runs this profile. Disconnect it, and take its applications, the default route and Darkwire's own connections off it; apply that, then replace or delete its credentials.");
    }
    private static AppState Clone(AppState policy)
    {
        var result = JsonSerializer.Deserialize<AppState>(JsonSerializer.Serialize(policy, StateStore.JsonOptions), StateStore.JsonOptions) ?? throw new InvalidDataException("Empty policy.");
        foreach (var profile in result.VpnProfiles) profile.EncryptedConfig = "";
        return result;
    }
    public void Dispose()
    {
        lock (gate)
        {
            // Service shutdown keeps enforcement: the persistent kernel plan blocks routed traffic until the router returns.
            router?.Dispose();
            backend?.Dispose();
        }
    }
}
