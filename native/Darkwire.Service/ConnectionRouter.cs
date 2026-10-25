using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Darkwire.Service;

/// <summary>What the router enforces: the decision plan (without router filters), the mode, the current interfaces and the VPN routing.</summary>
public sealed record RouterContext(FilterPlan Plan, FirewallMode Mode, NetworkSnapshot Network)
{
    /// <summary>Which applications VPN profiles carry, and the default profile; null without VPN routing.</summary>
    public TunnelRoutingPlan? Tunnels { get; init; }
    /// <summary>The profiles to run, each with the credential revision the policy was admitted with.</summary>
    public IReadOnlyList<TunnelDemand> Profiles { get; init; } = [];
    /// <summary>Names whose plain DNS lookups the relay answers as nonexistent; null while no domain list is enforced.</summary>
    public DomainFilter? Names { get; init; }
    /// <summary>
    /// Flows to the physical networks' own subnets leave physically, whatever profile their application uses, and so do flows
    /// to internal addresses unless their tunnel routes that private network itself.
    /// </summary>
    public bool BypassLocal { get; init; }
    /// <summary>The countries an allow list lets flows reach; null without one.</summary>
    public IReadOnlySet<string>? AllowedCountries { get; init; }
    /// <summary>The country GeoIP places an address in, or null when none claims it.</summary>
    public Func<IPAddress, string?>? CountryOf { get; init; }
    /// <summary>Told each name DNS filtering answers as nonexistent, so blocklists can count their hits.</summary>
    public Action<string>? NameBlocked { get; init; }
    /// <summary>Told the name of each explicit deny that refuses a new flow, such as a blocklist's.</summary>
    public Action<string>? FlowDenied { get; init; }
    /// <summary>Names DNS filtering answers with the loopback address, the policy's blocked names; null while none are enforced.</summary>
    public DomainFilter? LoopbackNames { get; init; }
    /// <summary>Told each name answered with the loopback address, so the blocked names count their hits.</summary>
    public Action<string>? NameAnswered { get; init; }
    /// <summary>The encrypted DNS servers Darkwire's DNS proxy runs for lookups bound for the internet; empty leaves those to the networks' servers.</summary>
    public IReadOnlyList<DnsUpstream> Dns { get; init; } = [];
    /// <summary>The profile whose tunnel Darkwire's own connections take; null for the physical network.</summary>
    public Guid? OwnTunnel { get; init; }
    /// <summary>Darkwire's own connections are to take a profile's tunnel that cannot run, so they go nowhere.</summary>
    public bool OwnRefused { get; init; }
    /// <summary>Told each new flow the router refuses, with why; it must only record it.</summary>
    public Action<BlockedFlow>? Refused { get; init; }
    /// <summary>
    /// Darkwire's adapter names its resolver for the Windows DNS client: with a default profile, whose tunnel answers; while
    /// domain lists or blocked names are enforced, when the network's own servers answer what the filter lets through; and with
    /// encrypted DNS servers, which answer what leaves the local network.
    /// </summary>
    public bool ResolvesSystemDns => Tunnels?.DefaultProfileId is not null || Names is not null || LoopbackNames is not null || Dns.Count > 0;
}

public interface IConnectionRouter : IDisposable
{
    /// <summary>Static facts the kernel plan needs: the relaying executable and the tunnel networks.</summary>
    RouterPlan Plan { get; }
    /// <summary>The protected runtime is installed.</summary>
    bool Available { get; }
    bool Running { get; }
    /// <summary>Why a started router stopped by itself, such as its adapter being removed.</summary>
    string? Fault { get; }
    /// <summary>The protected backend for a VPN kind, or the DNS proxy (<see cref="TakeoverCoordinator.DnsBackend"/>), is installed.</summary>
    bool Supports(string kind) => false;
    /// <summary>Each VPN profile the router runs.</summary>
    IReadOnlyList<TunnelStatus> Tunnels => [];
    /// <summary>The interface is one of the VPN tunnels the router runs, never a local network.</summary>
    bool Owns(ulong luid) => false;
    /// <summary>
    /// Where Darkwire's own connection to a destination leaves: the profile's tunnel, or the physical network without one; null
    /// while that tunnel cannot carry it.
    /// </summary>
    Egress? OwnEgress(IPAddress destination, Guid? profile) => null;
    /// <summary>How Darkwire's DNS proxy answers; null without encrypted DNS servers.</summary>
    DnsStatus? Dns => null;
    /// <summary>The TCP connections the router carries or holds, with the VPN profile each takes.</summary>
    IReadOnlyList<RoutedConnection> Connections => [];
    /// <summary>Starts a running or failed profile's tunnel again at once with a new backend; false when it has none, or is starting.</summary>
    bool Reconnect(Guid profile) => false;
    /// <summary>Checks every running tunnel end to end again, as when it came up; one that fails is restarted as then.</summary>
    void Recheck() { }
    void Start(RouterContext context);
    /// <summary>Applies a new plan, mode, interface set or VPN routing; held flows a new rule now decides are released or refused.</summary>
    void Update(RouterContext context);
    void Stop();
}

internal enum RouterVerdict { Allow, Block, Ask }

/// <summary>How a flow leaves: the physical network, a VPN profile's tunnel, or nowhere.</summary>
internal readonly record struct FlowPath(Guid? Tunnel, bool Refused)
{
    public static readonly FlowPath Physical = new(null, false), Refuse = new(null, true);
    public static FlowPath Through(Guid profile) => new(profile, false);
}

/// <summary>A flow, its process, the egress policy sees it leave through and the path it takes.</summary>
internal sealed record RouterFacts(RouterFlow Flow, FlowProcess? Process, Egress? Egress, FlowPath Path = default);

/// <summary>
/// One flow's decision from the compiled plan, evaluated as if the flow left through its egress interface. Only a
/// certain default verdict for an attributed, promptable flow in Learning mode is held for the user; everything that
/// is unknown, unattributed or unmatched outside Learning is refused.
/// </summary>
internal sealed record RouterDecisions(PlanMatcher? Matcher, FirewallMode Mode, IReadOnlyDictionary<ulong, uint> Profiles, IReadOnlyList<ulong> Egress)
{
    /// <summary>Applications a VPN profile carries, by WFP application ID. An empty ID marks an executable two profiles claim.</summary>
    public IReadOnlyDictionary<string, Guid> Assigned { get; init; } = new Dictionary<string, Guid>();
    /// <summary>The profile carrying every application without its own assignment.</summary>
    public Guid? DefaultTunnel { get; init; }
    /// <summary>Darkwire's service and VPN backends: their traffic reaches the peers physically and never enters a tunnel.</summary>
    public IReadOnlySet<string> Exempt { get; init; } = new HashSet<string>();
    /// <summary>
    /// Darkwire's DNS proxy: its flows take <see cref="OwnTunnel"/>, or the physical network without one, and nowhere when
    /// <see cref="OwnRefused"/>; they pass unless an explicit deny refuses them, and nothing prompts for them.
    /// </summary>
    public IReadOnlySet<string> Own { get; init; } = new HashSet<string>();
    public Guid? OwnTunnel { get; init; }
    public bool OwnRefused { get; init; }
    /// <summary>
    /// Encrypted DNS answers lookups sent to Darkwire's resolver for names that leave the local network, so such a lookup needs
    /// no server of the network's or a tunnel's to be let through.
    /// </summary>
    public bool Forwards { get; init; }
    /// <summary>
    /// The physical network's DNS servers, which answer lookups sent to Darkwire's resolver on a physical path while domain
    /// lists are enforced; empty otherwise.
    /// </summary>
    public IReadOnlyList<IPAddress> SystemDns { get; init; } = [];
    /// <summary>The local networks, whose traffic leaves physically instead of through a VPN tunnel; empty when tunnels carry it too.</summary>
    public IReadOnlyList<NetPrefix> Local { get; init; } = [];
    /// <summary>Internal address ranges, which leave physically too unless the flow's tunnel routes the private network itself.</summary>
    public IReadOnlyList<NetPrefix> Internal { get; init; } = [];
    /// <summary>Whether a profile's tunnel routes a destination through a private network of its own, such as an office behind it.</summary>
    public Func<Guid, NetAddress, bool> RoutesPrivately { get; init; } = (_, _) => false;
    /// <summary>The countries an allow list lets flows reach; null without one.</summary>
    public IReadOnlySet<string>? AllowedCountries { get; init; }
    public Func<IPAddress, string?>? CountryOf { get; init; }
    /// <summary>Told the name of each explicit deny that refuses a new flow.</summary>
    public Action<string>? Denied { get; init; }
    /// <summary>Told each new flow refused, with why.</summary>
    public Action<BlockedFlow>? Refused { get; init; }

    /// <summary>Why a flow's path is refused: the route it would need does not exist.</summary>
    public string PathWhy(FlowProcess? process, RouterFlow flow) =>
        IsOwn(process) ? "Darkwire's own route, a VPN profile, cannot run"
        : process is null && Assigned.Count > 0 ? "Its program could not be identified, and VPN profiles carry programs"
        : process is not null && Assigned.TryGetValue(process.Owner.ApplicationId, out var profile) && profile == Guid.Empty ? "Two VPN profiles carry its program"
        : RouterAddresses.IsResolver(flow.Remote) ? "No DNS server is in reach" : "It has no route";

    /// <summary>Why the decisions refuse a flow: a country the allow list leaves out, the explicit deny that matches, or no rule allowing it.</summary>
    public string Why(RouterFacts facts)
    {
        if (!IsOwn(facts.Process) && AllowedCountries is { } allowed && CountryOf?.Invoke(facts.Flow.Remote.Address.ToIPAddress()) is { Length: > 0 } country && !allowed.Contains(country))
            return $"Country not allowed ({country})";
        if (Matcher?.Match(Query(facts)) is { Action: RuleAction.Deny } verdict)
            return !verdict.IsDefault ? verdict.Filter.Name : Mode == FirewallMode.Lockdown ? "Lockdown" : Mode == FirewallMode.Learning ? "Not allowed yet" : "No rule allows it";
        return "Refused";
    }

    /// <summary>A refused flow as the service lists it.</summary>
    public static BlockedFlow Refusal(RouterFacts facts, string reason) => new(DateTimeOffset.UtcNow, facts.Process?.ImagePath ?? "Unidentified program",
        facts.Flow.Remote.Address.ToString(), facts.Flow.Protocol is 6 or 17 ? facts.Flow.Remote.Port : 0,
        facts.Flow.Protocol switch { 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", _ => facts.Flow.Protocol.ToString(System.Globalization.CultureInfo.InvariantCulture) },
        TrafficDirection.Outbound, reason);

    /// <summary>
    /// A flow's path. One to a local network leaves physically when the policy keeps local traffic off VPN tunnels, and so does
    /// one to an internal address, unless the tunnel its application uses routes that private network itself. One whose
    /// process is unknown might belong to an application a profile carries, so it never leaves physically while assignments
    /// exist. ICMP is never attributed; it follows the default route. DNS addressed to
    /// Darkwire's resolver, which the Windows DNS client sends with a default profile or domain lists, has no server of its
    /// own: a profile's resolver answers it through the tunnel the sender's flows take, and on a physical path the network's
    /// servers do while domain lists are enforced. Without them a physical path refuses it, unless encrypted DNS answers it.
    /// </summary>
    public FlowPath Path(FlowProcess? process, RouterFlow flow)
    {
        var path = Choose(process, flow.Protocol);
        var remote = flow.Remote.Address;
        // Local network traffic stays local, except DNS, which a tunneled application's profile resolver still answers.
        if (flow.Remote.Port != 53 && (Local.Any(n => n.Contains(remote)) ||
            Internal.Any(n => n.Contains(remote)) && !(path.Tunnel is { } profile && RoutesPrivately(profile, remote))))
            return FlowPath.Physical;
        return path.Tunnel is null && RouterAddresses.IsResolver(flow.Remote) && SystemDns.Count == 0 && !Forwards ? FlowPath.Refuse : path;
    }

    /// <summary>The flow's process is Darkwire's DNS proxy.</summary>
    public bool IsOwn(FlowProcess? process) => process is not null && Own.Contains(process.Owner.ApplicationId);

    private FlowPath Choose(FlowProcess? process, byte protocol)
    {
        if (process is null)
            return protocol is 6 or 17 && Assigned.Count > 0 ? FlowPath.Refuse : DefaultTunnel is { } every ? FlowPath.Through(every) : FlowPath.Physical;
        var application = process.Owner.ApplicationId;
        if (Own.Contains(application)) return OwnRefused ? FlowPath.Refuse : OwnTunnel is { } own ? FlowPath.Through(own) : FlowPath.Physical;
        if (Exempt.Contains(application)) return FlowPath.Physical;
        if (Assigned.TryGetValue(application, out var profile)) return profile == Guid.Empty ? FlowPath.Refuse : FlowPath.Through(profile);
        return DefaultTunnel is { } fallback ? FlowPath.Through(fallback) : FlowPath.Physical;
    }

    /// <param name="count">A new flow, whose refusal by an explicit deny is reported; a flow decided again is not.</param>
    public (RouterVerdict Verdict, Connection? Prompt) Decide(RouterFacts facts, bool count = false)
    {
        var own = IsOwn(facts.Process);
        // An allow list refuses every country it leaves out, as a country block outranks every allow; an address no country
        // claims, such as an internal one or Darkwire's resolver, passes. Darkwire's own connections reach the servers chosen
        // for them, as its service's downloads do.
        if (!own && AllowedCountries is { } allowed && CountryOf?.Invoke(facts.Flow.Remote.Address.ToIPAddress()) is { Length: > 0 } country && !allowed.Contains(country))
            return (RouterVerdict.Block, null);
        // An Open plan has no filters; the coordinator routes Open only for VPN profiles and encrypted DNS.
        if (Matcher?.Match(Query(facts)) is not { } verdict || verdict.Action == RuleAction.Allow) return (RouterVerdict.Allow, null);
        if (count && !verdict.IsDefault) Denied?.Invoke(verdict.Filter.Name);
        if (own && verdict.IsDefault) return (RouterVerdict.Allow, null);
        if (!verdict.IsDefault || !verdict.Certain || Mode != FirewallMode.Learning) return (RouterVerdict.Block, null);
        return Prompt(facts) is { } prompt ? (RouterVerdict.Ask, prompt) : (RouterVerdict.Block, null);
    }

    public FlowQuery Query(RouterFacts facts)
    {
        var flow = facts.Flow; var icmp = flow.Protocol is 1 or 58;
        var remote = flow.Remote.Address.ToIPAddress();
        // The egress source is the address the flow leaves from: the physical one Windows would use without the tunnel, or
        // the VPN tunnel's. ICMP carries type and code instead of ports.
        return new(TrafficDirection.Outbound, flow.Protocol, facts.Egress?.Source ?? flow.Local.Address.ToIPAddress(), icmp ? (ushort)0 : flow.Local.Port,
            remote, icmp ? (ushort)0 : flow.Remote.Port, facts.Process?.Owner, facts.Egress?.Luid, Profile(facts.Egress),
            icmp ? (byte)(flow.Protocol == 1 ? 8 : 128) : null, icmp ? (byte)0 : null);
    }

    /// <summary>
    /// A prompt the user can turn into a narrow rule; null for flows no rule could name (kernel, ICMP, a service host's flow
    /// whose service stays unknown). A shared host's prompt lists the services its process runs, which the rule reaches too.
    /// </summary>
    public Connection? Prompt(RouterFacts facts)
    {
        if (facts.Process is not { } process || facts.Flow.Protocol is not (6 or 17) || !System.IO.Path.IsPathFullyQualified(process.ImagePath)) return null;
        var (hosted, service) = ServiceNames.Of(process);
        // Without its service, one answer would become a rule for every service svchost.exe runs.
        var host = System.IO.Path.GetFileName(process.ImagePath).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
        if (host && service is null) return null;
        var flow = facts.Flow;
        var location = Profile(facts.Egress) switch { 1 => "Public", 2 => "Private", 3 => "Domain", _ => "Unknown" };
        return new(System.IO.Path.GetFileNameWithoutExtension(process.ImagePath), process.ImagePath, process.ProcessId, flow.Remote.Address.ToString(), flow.Remote.Port,
            flow.Local.Port, flow.Protocol == 6 ? "TCP" : "UDP", TrafficDirection.Outbound, location, service ?? "",
            LocalAddress: facts.Egress?.Source.ToString() ?? "", State: "Held", HostedServices: string.Join(", ", hosted));
    }

    private uint? Profile(Egress? egress) => egress is not null && Profiles.TryGetValue(egress.Luid, out var profile) ? profile : null;
}

/// <summary>
/// The router's decisions over time. New flows are attributed and evaluated as if they left through their own egress, a
/// physical interface or their VPN profile's tunnel. Flows wait for a prompt or for their tunnel to start; the relay asks
/// each allowed flow's route here, and a tunnel's flow has no other. A policy change, or a tunnel that goes down,
/// withdraws the flows it no longer permits. Nothing here is called back while the router lock is held, except route
/// lookups and Forget, which take no lock of this class.
/// </summary>
internal sealed class FlowDecisions : IFlowRoutes
{
    private readonly object gate = new();
    private readonly Func<Connection, bool> ask;
    private readonly ITunnelDirectory tunnels;
    private readonly IEgressSelector physical;
    private readonly FlowAttribution attribution;
    private readonly ConcurrentDictionary<long, RouterFacts> facts = new();
    // Undecided flows: those asked about, and those waiting for their profile's tunnel to come up.
    private readonly ConcurrentDictionary<long, RouterFlow> prompted = new(), waiting = new();
    // The relay asks for every datagram: each flow's route is chosen once, and dropped the moment its tunnel closes.
    private readonly ConcurrentDictionary<long, (FlowRoute Route, TunnelEgress? Through)> routes = new();
    private RouterDecisions decisions;
    private PacketRouter? router;

    public FlowDecisions(RouterDecisions decisions, Func<Connection, bool> ask, ITunnelDirectory tunnels, IEgressSelector physical, FlowAttribution attribution)
    { this.decisions = decisions; this.ask = ask; this.tunnels = tunnels; this.physical = physical; this.attribution = attribution; }

    public RouterDecisions Current => Volatile.Read(ref decisions);

    public void Attach(PacketRouter router)
    {
        if (Interlocked.CompareExchange(ref this.router, router, null) is not null) throw new InvalidOperationException("The decisions already serve a router.");
    }

    /// <summary>Attributes and decides new flows; one fresh socket-table read serves the whole batch.</summary>
    public void Evaluate(IReadOnlyList<RouterFlow> batch)
    {
        var snapshot = attribution.Begin();
        foreach (var flow in batch)
        {
            try
            {
                var local = flow.Local.ToIPEndPoint(); var remote = flow.Remote.ToIPEndPoint();
                var process = flow.Protocol switch { 6 => snapshot.Tcp(local, remote), 17 => snapshot.Udp(local), _ => null };
                lock (gate) Act(new(flow, process, null), Current, first: true);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                ServiceHost.Log("Router decision failed; the flow was refused: " + error.Message);
                router!.Decide(flow.Id, false);
            }
        }
    }

    /// <summary>
    /// Applies new decisions. Held flows are decided again: those a new rule decides go, and those still undecided ask again,
    /// joining the prompt the broker kept for them. Settled flows whose verdict or path changed are withdrawn, as WFP
    /// reauthorizes connections.
    /// </summary>
    public void Update(RouterDecisions next)
    {
        lock (gate)
        {
            Volatile.Write(ref decisions, next);
            foreach (var id in prompted.Keys.Concat(waiting.Keys).ToArray())
                if (facts.TryGetValue(id, out var fact)) Act(fact, next);
            foreach (var info in router!.Flows())
            {
                if (info.State is not (RouterFlowState.Open or RouterFlowState.Connecting or RouterFlowState.Blocked) || !facts.TryGetValue(info.Id, out var fact)) continue;
                var (allowed, path) = Recheck(fact, next);
                if (allowed != (info.State != RouterFlowState.Blocked) || allowed && path != fact.Path) router.Revoke(info.Id);
            }
        }
    }

    /// <summary>A profile's tunnel came up, failed or went away: decide the flows waiting for it, and withdraw the flows it carried unless it is up.</summary>
    public void TunnelChanged(Guid profile)
    {
        lock (gate)
        {
            if (router is null) return;
            var current = Current;
            foreach (var id in waiting.Keys.ToArray())
                if (facts.TryGetValue(id, out var fact) && fact.Path.Tunnel == profile) Act(fact, current);
            if (tunnels.Find(profile) is { State: TunnelState.Up, Egress.Closed: false }) return;
            foreach (var info in router.Flows())
                if (info.State is RouterFlowState.Open or RouterFlowState.Connecting && facts.TryGetValue(info.Id, out var fact) && fact.Path.Tunnel == profile)
                    router.Revoke(info.Id);
        }
    }

    /// <summary>
    /// The relay's route for an allowed flow. A physical flow leaves through the interface Windows would choose, DNS sent to
    /// Darkwire's resolver going to the network's own server; a tunnel's flow leaves through that tunnel, its DNS going to the
    /// profile's resolver, or is refused once the tunnel is down.
    /// </summary>
    public FlowRoute? Select(RouterFlow flow)
    {
        if (routes.TryGetValue(flow.Id, out var known)) return known.Through is { Closed: true } ? null : known.Route;
        if (!facts.TryGetValue(flow.Id, out var fact) || fact.Path.Refused) return null;
        // Darkwire's DNS proxy talks to the servers it names, DNSCrypt on port 53 included.
        var own = Current.IsOwn(fact.Process);
        FlowRoute? route; TunnelEgress? through = null;
        if (fact.Path.Tunnel is not { } profile) route = PhysicalRoute(flow, Current);
        else if ((route = (through = tunnels.Find(profile)?.Egress)?.Route(flow.Protocol, flow.Remote, redirectDns: !own)) is not null) tunnels.Used(profile);
        if (route is not null && own) route = route with { Own = true };
        if (route is not null) routes[flow.Id] = (route, through);
        return route;
    }

    /// <summary>
    /// A physical flow's route. DNS sent to Darkwire's resolver goes to the network's first DNS server in the flow's family,
    /// else the first of the other, as a tunnel picks its resolver; the egress is the interface Windows would reach it through.
    /// </summary>
    private FlowRoute? PhysicalRoute(RouterFlow flow, RouterDecisions current)
    {
        if (!RouterAddresses.IsResolver(flow.Remote)) return physical.Select(flow.Remote.Address.ToIPAddress()) is { } egress ? new(egress) : null;
        var servers = current.SystemDns;
        bool SameFamily(IPAddress server) => (server.AddressFamily == AddressFamily.InterNetworkV6) == flow.Remote.Address.V6;
        foreach (var server in servers.Where(SameFamily).Concat(servers.Where(s => !SameFamily(s))))
            if (physical.Select(server) is { } egress) return new(egress, new(NetAddress.From(server), DnsAnswers.Port));
        return null;
    }

    /// <summary>
    /// The TCP connections the router carries or holds, by the application's socket and destination, each with the profile
    /// whose tunnel its path takes, none for the physical network. Refused ones are reset and forgotten at once.
    /// </summary>
    public IReadOnlyList<RoutedConnection> Connections()
    {
        if (Volatile.Read(ref router) is not { } running) return [];
        List<RoutedConnection> connections = [];
        foreach (var flow in running.Flows())
            if (flow.Protocol == 6 && flow.State != RouterFlowState.Blocked && facts.TryGetValue(flow.Id, out var fact) && !fact.Path.Refused)
                connections.Add(new(flow.Local.Address.ToIPAddress().ToString(), flow.Local.Port, flow.Remote.Address.ToIPAddress().ToString(), flow.Remote.Port, fact.Path.Tunnel));
        return connections;
    }

    /// <summary>The router forgot a flow. Called under the router lock: bookkeeping only.</summary>
    public void Forget(RouterFlow flow) => Drop(flow.Id);

    /// <summary>Drops bookkeeping for flows decided while the router was forgetting them.</summary>
    public void Collect()
    {
        var live = router!.Flows().Select(f => f.Id).ToHashSet();
        foreach (var table in new[] { facts.Keys, prompted.Keys, waiting.Keys, routes.Keys })
        foreach (var id in table) if (!live.Contains(id)) Drop(id);
    }

    private void Drop(long id)
    {
        facts.TryRemove(id, out _); prompted.TryRemove(id, out _); waiting.TryRemove(id, out _); routes.TryRemove(id, out _);
    }

    // Callers hold the gate. A flow's first decision reports which deny refused it; deciding it again does not.
    private void Act(RouterFacts fact, RouterDecisions current, bool first = false)
    {
        var flow = fact.Flow; var id = flow.Id;
        var path = current.Path(fact.Process, flow);
        var tunnel = path.Tunnel is { } profile ? tunnels.Find(profile) : null;
        var evaluated = fact with { Egress = EgressFor(flow, path, tunnel), Path = path };
        facts[id] = evaluated; routes.TryRemove(id, out _);
        // Each refusal is told once, as the flow is decided for good; one held for a prompt or a tunnel is told when refused.
        if (path.Refused) { current.Refused?.Invoke(RouterDecisions.Refusal(evaluated, current.PathWhy(fact.Process, flow))); Finish(id, false); return; }
        var (verdict, prompt) = current.Decide(evaluated, count: first);
        string? why = null;
        if (verdict == RouterVerdict.Ask)
        {
            // The broker folds repeated asks for one scope into a single prompt.
            if (ask(prompt!)) { waiting.TryRemove(id, out _); prompted[id] = flow; return; }
            verdict = RouterVerdict.Block;
        }
        if (verdict == RouterVerdict.Allow && path.Tunnel is not null)
        {
            // A tunnel's flow leaves through that tunnel or not at all: it waits while the tunnel starts, and is refused when
            // the tunnel failed or does not carry its family or destination.
            if (tunnel?.State == TunnelState.Starting) { prompted.TryRemove(id, out _); waiting[id] = flow; return; }
            if (!Carried(fact, path, tunnel, current)) { verdict = RouterVerdict.Block; why = tunnel?.State == TunnelState.Up ? "Its VPN tunnel does not carry it" : "Its VPN tunnel is down"; }
        }
        // A lookup for Darkwire's resolver with no network server in reach has nowhere to go, unless encrypted DNS answers it.
        else if (verdict == RouterVerdict.Allow && RouterAddresses.IsResolver(flow.Remote) && !current.Forwards && PhysicalRoute(flow, current) is null)
        { verdict = RouterVerdict.Block; why = "No DNS server is in reach"; }
        if (verdict != RouterVerdict.Allow) current.Refused?.Invoke(RouterDecisions.Refusal(evaluated, why ?? current.Why(evaluated)));
        Finish(id, verdict == RouterVerdict.Allow);
    }

    /// <summary>
    /// Whether a flow on a tunnel's path can leave: the tunnel carries it, or it is a lookup for Darkwire's resolver that
    /// encrypted DNS answers, a local name in it failing when no tunnel's resolver takes it.
    /// </summary>
    private bool Carried(RouterFacts fact, FlowPath path, TunnelView? tunnel, RouterDecisions current) =>
        path.Tunnel is null || tunnel?.Egress?.Route(fact.Flow.Protocol, fact.Flow.Remote, redirectDns: !current.IsOwn(fact.Process)) is not null ||
        current.Forwards && RouterAddresses.IsResolver(fact.Flow.Remote);

    private void Finish(long id, bool allow)
    {
        prompted.TryRemove(id, out _); waiting.TryRemove(id, out _);
        router!.Decide(id, allow);
    }

    /// <summary>Whether a decided flow would be allowed now, and along which path.</summary>
    private (bool Allowed, FlowPath Path) Recheck(RouterFacts fact, RouterDecisions current)
    {
        var flow = fact.Flow;
        var path = current.Path(fact.Process, flow);
        if (path.Refused) return (false, path);
        var tunnel = path.Tunnel is { } profile ? tunnels.Find(profile) : null;
        // An unchanged path keeps the egress the flow was decided with.
        var evaluated = path == fact.Path ? fact : fact with { Egress = EgressFor(flow, path, tunnel), Path = path };
        var allowed = current.Decide(evaluated).Verdict == RouterVerdict.Allow && Carried(evaluated, path, tunnel, current);
        return (allowed, path);
    }

    /// <summary>The egress policy sees: the physical one Windows would choose, or the tunnel's, unknown while it is not up.</summary>
    private Egress? EgressFor(RouterFlow flow, FlowPath path, TunnelView? tunnel)
    {
        if (path.Refused) return null;
        var remote = flow.Remote.Address.ToIPAddress();
        return path.Tunnel is null ? physical.Select(remote) : tunnel?.Egress?.Select(remote);
    }
}

/// <summary>
/// Runs the tunnel router: a Wintun adapter whose routes capture outbound unicast, the packet router, the socket relay,
/// the decision loop and the VPN profiles the policy routes through. Routes are added only after everything that
/// decides and relays is running, and removing the adapter removes them, so a stopped router leaves traffic to the
/// kernel leak guard rather than the physical network. VPN tunnels run only while the router does.
/// </summary>
internal sealed class ConnectionRouter(Func<Connection, bool> ask, IVpnProfileVault? vault = null, Action? verifyGuards = null) : IConnectionRouter
{
    public const string AdapterName = "Darkwire";
    private static readonly IReadOnlyList<NetPrefix> Private = [.. InternalNetworks.Unicast.Select(NetPrefix.Parse)];
    public const int Mtu = 9000;
    public static readonly Guid AdapterId = new("6c1f4a52-8d7e-4b0e-9a3e-2f5d7c9b1e44");
    /// <summary>How long one physical DNS server has to answer an endpoint lookup.</summary>
    public static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(2);
    private static readonly string[] TunnelNetworks = ["198.18.0.0/15", "fd5a:9c33:21e7::/64"];
    private static readonly (string Network, int Prefix)[] Capture4 = [("0.0.0.0", 1), ("128.0.0.0", 1)], Capture6 = [("::", 1), ("8000::", 1)];
    private readonly object gate = new();
    private readonly FlowAttribution attribution = new();
    private readonly HashSet<(IPAddress Network, int Prefix)> splits = [];
    private FlowDecisions? decider;
    private TunnelSupervisor? tunnels;
    private TunnelBackends? backends;
    private PeerRoutes? peers;
    private string? peerNetwork;
    /// <summary>Endpoint names looked up through Windows, when the DNS client still reaches the physical network's servers.</summary>
    private static readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> SystemLookup =
        async (host, cancellation) => await System.Net.Dns.GetHostAddressesAsync(host, cancellation).ConfigureAwait(false);
    private Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? lookup;
    private NetworkSnapshot? latestNetwork;
    private WintunTunnel? tunnel;
    private PacketRouter? router;
    private RouterRelay? relay;
    private Channel<RouterFlow>? evaluations;
    private Thread? receiver;
    private Task? decisions;
    private Timer? sweeper;
    private CancellationTokenSource? lifetime;
    private DomainFilter? names, loopbackNames;
    private DnsCryptProxy? dns;
    // The tunnel carrying Darkwire's own connections, while it is up.
    private readonly object ownGate = new();
    private Guid? ownUp;
    private EgressSelector? physicalEgress;
    // Whether the adapter names Darkwire's resolver; unknown until written at start.
    private bool? resolving;
    private bool ipv6;
    private int packetErrors, sweeps;
    private volatile string? fault;

    public static string LibraryPath => Path.Combine(AppContext.BaseDirectory, "Backends", "Router", "wintun.dll");
    public RouterPlan Plan => new(Environment.ProcessPath ?? throw new InvalidOperationException("The service executable path is unknown."), TunnelNetworks);
    public bool Available => File.Exists(LibraryPath);
    public bool Running { get { lock (gate) return receiver?.IsAlive == true && fault is null; } }
    public string? Fault => fault;
    public bool Supports(string kind) => kind == TakeoverCoordinator.DnsBackend ? DnsCryptProxy.Installed : TunnelBackends.Installed(kind);
    public IReadOnlyList<TunnelStatus> Tunnels => Volatile.Read(ref tunnels)?.Status() ?? [];
    public bool Owns(ulong luid) => Volatile.Read(ref tunnels)?.Owns(luid) == true;
    public DnsStatus? Dns => Volatile.Read(ref dns)?.Status();
    public IReadOnlyList<RoutedConnection> Connections => fault is null ? Volatile.Read(ref decider)?.Connections() ?? [] : [];
    public bool Reconnect(Guid profile) => Volatile.Read(ref tunnels)?.Reconnect(profile) == true;
    public void Recheck() => Volatile.Read(ref tunnels)?.Recheck();

    /// <summary>A tunnel's end-to-end check: its DNS servers asked through it in turn until one answers; null when it names none.</summary>
    private static bool? Check(TunnelEgress egress)
    {
        if (egress.Resolvers.Count == 0) return null;
        foreach (var resolver in egress.Resolvers)
            if (egress.Select(resolver) is { } route && TunnelProbe.Ask(route, new(resolver, 53), TakeoverCoordinator.CheckTimeout) is not null) return true;
        return false;
    }

    public Egress? OwnEgress(IPAddress destination, Guid? profile)
    {
        if (profile is not { } through) return Volatile.Read(ref physicalEgress)?.Select(destination);
        return Volatile.Read(ref tunnels)?.Find(through) is { State: TunnelState.Up, Egress: { Closed: false } egress } ? egress.Select(destination) : null;
    }

    public void Start(RouterContext context)
    {
        lock (gate)
        {
            if (receiver?.IsAlive == true && fault is null) { UpdateCore(context); return; }
            StopCore();
            fault = null;
            if (!Available) throw new FileNotFoundException("Connection routing needs the Wintun runtime at " + LibraryPath + ".", LibraryPath);
            // The runtime is loaded into this LocalSystem process: verify its protected directory first.
            ProtectedStorage.Verify();
            tunnel = WintunTunnel.Create(LibraryPath, AdapterName, AdapterId);
            try
            {
                ipv6 = TunnelNetwork.Configure(tunnel.Luid, Mtu);
                TunnelNetwork.AddAddress(tunnel.Luid, RouterAddresses.Tunnel4.ToIPAddress(), 15);
                if (ipv6) TunnelNetwork.AddAddress(tunnel.Luid, RouterAddresses.Tunnel6.ToIPAddress(), 64);
                var listeners = new List<Socket> { Bind(RouterAddresses.Tunnel4.ToIPAddress()) };
                if (ipv6) listeners.Add(Bind(RouterAddresses.Tunnel6.ToIPAddress()));
                var port4 = (ushort)((IPEndPoint)listeners[0].LocalEndPoint!).Port;
                var port6 = (ushort)((IPEndPoint)listeners[^1].LocalEndPoint!).Port;
                var device = tunnel;
                FlowDecisions? current = null;
                backends = new TunnelBackends(vault ?? new UnavailableVault(), verifyGuards ?? (() => { }));
                // A tunnel going away first closes the relay's connections and the service's downloads pinned to its interface.
                var supervisor = tunnels = new TunnelSupervisor(backends, NativeTunnelInterfaces.Instance, profile => { Volatile.Read(ref current)?.TunnelChanged(profile); OwnTunnelChanged(profile); }, ipv6,
                    released: luid => { Volatile.Read(ref relay)?.Abandon(luid); ServiceDownloads.Abandon(luid); }, check: (_, egress) => Check(egress));
                // Physical flows never leave through a VPN tunnel's interface.
                var physical = physicalEgress = new EgressSelector(() => current!.Current.Egress.Where(luid => !supervisor.Owns(luid)).ToArray());
                // Each backend reaches its servers over the physical network, not through Darkwire's adapter.
                var serverRoutes = peers = new PeerRoutes(new NativePeerRouteTable(physical));
                backends.Pin = addresses => serverRoutes.Hold(addresses);
                peerNetwork = context.Network.Fingerprint;
                // Endpoint names the backends cannot resolve through a confined Windows DNS client are asked of the physical servers.
                lookup = (host, cancellation) => DnsLookup.ResolveAsync(host, PhysicalDnsServers(Volatile.Read(ref latestNetwork) ?? NetworkSnapshot.Empty,
                    luid => luid == device.Luid || supervisor.Owns(luid)).Select(server => new IPEndPoint(server, DnsAnswers.Port)).ToArray(), physical.Select, LookupTimeout, cancellation);
                current = decider = new FlowDecisions(Build(context, device.Luid), ask, supervisor, physical, attribution);
                var channel = evaluations = Channel.CreateUnbounded<RouterFlow>(new() { SingleReader = true });
                relay = new RouterRelay(packet => device.Send(packet), current, flow => channel.Writer.TryWrite(flow), current.Forget);
                SyncNames(context);
                SyncProxy(context);
                var running = router = new PacketRouter(relay, RouterAddresses.Default(port4, port6, Mtu));
                relay.Attach(running, listeners);
                current.Attach(running);
                var stopping = lifetime = new CancellationTokenSource();
                receiver = new Thread(() => Receive(device, running, stopping.Token)) { IsBackground = true, Name = "Darkwire router" };
                receiver.Start();
                decisions = Task.Run(() => DecideAsync(channel.Reader, current, stopping.Token));
                sweeper = new Timer(_ => Sweep(running, current, supervisor), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
                // Capture last: nothing reaches the tunnel before the router can decide it.
                foreach (var (network, prefix) in ipv6 ? Capture4.Concat(Capture6) : Capture4) TunnelNetwork.AddRoute(tunnel.Luid, IPAddress.Parse(network), prefix);
                SyncSplits(context.Network);
                SyncDns(context);
                // VPN profiles start in the background; their flows wait for them and are refused if they fail.
                supervisor.Sync(context.Profiles);
            }
            catch { StopCore(); throw; }
        }
    }

    public void Update(RouterContext context)
    {
        lock (gate) if (router is not null && fault is null) UpdateCore(context);
    }

    public void Stop() { lock (gate) StopCore(); }
    public void Dispose() => Stop();

    private void UpdateCore(RouterContext context)
    {
        var next = Build(context, tunnel!.Luid);
        SyncSplits(context.Network);
        // A changed network may reach the VPN servers through another interface or gateway.
        if (context.Network.Fingerprint != peerNetwork) { peerNetwork = context.Network.Fingerprint; peers?.Refresh(); }
        SyncNames(context);
        SyncProxy(context);
        SyncDns(context);
        // Profiles start before the decisions that route through them apply, so their flows wait instead of failing.
        tunnels!.Sync(context.Profiles);
        decider!.Update(next);
    }

    /// <summary>
    /// With a default VPN profile the Windows DNS client's lookups go through that profile's tunnel: Darkwire's adapter names
    /// its resolver address, the router sends what arrives there to the profile's resolver, and the kernel plan confines the
    /// DNS client to the adapter. The backends then look up their endpoint names on the physical network through the service,
    /// since the default profile's own backend could not resolve its peer through a client waiting for its tunnel. While
    /// domain lists are enforced the adapter names the resolver too, so every Windows lookup meets the filter before the
    /// router sends it to the network's own servers; the client's own per-interface sends would otherwise go around it.
    /// Otherwise the adapter names no DNS server. Windows keeps adapter DNS servers under the adapter's GUID, which never
    /// changes, so the setting is written at every start rather than assumed.
    /// </summary>
    private void SyncDns(RouterContext context)
    {
        var resolve = context.ResolvesSystemDns;
        Volatile.Write(ref latestNetwork, context.Network);
        // The service looks up every endpoint name itself, so it knows the server addresses to route physically. With encrypted
        // DNS, Windows' lookups wait for the DNS proxy, whose own connections may wait for a tunnel: endpoints never do.
        backends!.Resolver = context.Tunnels?.DefaultProfileId is not null || context.Dns.Count > 0 ? lookup : SystemLookup;
        if (resolving == resolve) return;
        SetResolver(resolve);
        resolving = resolve;
        FlushDnsCache();
    }

    private void SetResolver(bool resolve)
    {
        TunnelNetwork.SetDnsServers(tunnel!.Luid, false, resolve ? [RouterAddresses.Resolver4.ToIPAddress()] : []);
        // An adapter without IPv6 gets no IPv6 server, but one an earlier start left there is still cleared when possible.
        try { TunnelNetwork.SetDnsServers(tunnel.Luid, true, resolve && ipv6 ? [RouterAddresses.Resolver6.ToIPAddress()] : []); }
        catch (System.ComponentModel.Win32Exception) when (!ipv6) { }
    }

    /// <summary>
    /// The physical interfaces' DNS servers, in interface order: routable unicast outside Darkwire's tunnel networks. Link-local
    /// servers are left out, since the snapshot keeps no zone to reach them with.
    /// </summary>
    internal static IReadOnlyList<IPAddress> PhysicalDnsServers(NetworkSnapshot network, Func<ulong, bool> excluded)
    {
        var tunnelNetworks = TunnelNetworks.Select(NetPrefix.Parse).ToArray();
        List<IPAddress> servers = [];
        foreach (var nic in network.Interfaces.Where(i => !excluded(i.Luid)))
        foreach (var entry in nic.DnsServers)
        {
            if (!IpNetwork.TryParse(entry, out var parsed)) continue;
            var address = NetAddress.From(parsed.Address);
            if (address.IsRoutableUnicast && !tunnelNetworks.Any(t => t.Contains(address)) && !servers.Contains(parsed.Address)) servers.Add(parsed.Address);
        }
        return servers;
    }

    /// <summary>
    /// Hands the relay the names it answers itself, as nonexistent or with the loopback address, and who hears of each one it
    /// answers. When the names change, Windows forgets its cached answers, so a newly blocked name stops resolving and an
    /// unblocked one resolves again at once.
    /// </summary>
    private void SyncNames(RouterContext context)
    {
        Volatile.Write(ref nameBlocked, context.NameBlocked); Volatile.Write(ref nameAnswered, context.NameAnswered);
        var (previous, previousLoopback) = (names, loopbackNames);
        names = context.Names; loopbackNames = context.LoopbackNames;
        relay!.BlockedNames = Answering(names, () => Volatile.Read(ref nameBlocked));
        relay.LoopbackNames = Answering(loopbackNames, () => Volatile.Read(ref nameAnswered));
        if (Changed(previous, names) || Changed(previousLoopback, loopbackNames)) FlushDnsCache();
    }
    private Action<string>? nameBlocked, nameAnswered;

    private static Func<string, bool>? Answering(DomainFilter? filter, Func<Action<string>?> told) => filter is { Count: > 0 } names ? name =>
    {
        if (!names.Blocks(name)) return false;
        told()?.Invoke(name);
        return true;
    } : null;

    private static bool Changed(DomainFilter? previous, DomainFilter? next) => previous is null ? next is not null : next is null || !previous.SameAs(next);

    /// <summary>
    /// Runs Darkwire's DNS proxy for the encrypted DNS servers, and has the relay forward to it the lookups bound for the
    /// internet; without servers the proxy stops and lookups go to the networks' servers again.
    /// </summary>
    private void SyncProxy(RouterContext context)
    {
        if (context.Dns.Count == 0)
        {
            relay!.Forwarder = null;
            dns?.Dispose(); dns = null;
            return;
        }
        dns ??= new DnsCryptProxy();
        dns.Sync(context.Dns, context.Network.LocalDomains);
        relay!.Forwarder = dns;
    }

    /// <summary>
    /// The DNS proxy reaches its servers through the tunnel carrying Darkwire's own connections, which after a start comes up
    /// only once the proxy has begun testing them: whenever that tunnel comes up, the proxy hears of it.
    /// </summary>
    private void OwnTunnelChanged(Guid profile)
    {
        if (Volatile.Read(ref decider)?.Current.OwnTunnel != profile) return;
        var up = Volatile.Read(ref tunnels)?.Find(profile)?.State == TunnelState.Up;
        lock (ownGate)
        {
            if (up == (ownUp == profile)) return;
            ownUp = up ? profile : null;
        }
        if (up) Volatile.Read(ref dns)?.RouteReady();
    }

    private static void FlushDnsCache() => ThreadPool.QueueUserWorkItem(_ =>
    {
        try { if (!DnsFlushResolverCache()) ServiceHost.Log("The Windows DNS cache could not be flushed."); }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { ServiceHost.Log("The Windows DNS cache could not be flushed: " + error.Message); }
    });

    [System.Runtime.InteropServices.DllImport("dnsapi.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool DnsFlushResolverCache();

    private RouterDecisions Build(RouterContext context, ulong tunnelLuid)
    {
        var matcher = context.Plan.Filters.Count == 0 ? null : new PlanMatcher(context.Plan, ApplicationKey, WfpConditions.ResolveAccount);
        var assigned = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
        foreach (var application in context.Tunnels?.Applications ?? [])
        {
            // Two assignments that resolve to one executable route it nowhere rather than through either.
            var key = ApplicationKey(application.ApplicationPath);
            assigned[key] = assigned.TryGetValue(key, out var other) && other != application.ProfileId ? Guid.Empty : application.ProfileId;
        }
        var directory = Path.GetDirectoryName(Plan.ServicePath)!;
        var exempt = new[] { Plan.ServicePath, TunnelBackends.Executable(directory, "WireGuard") }
            .Select(ApplicationKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var own = new[] { ApplicationKey(DnsCryptProxy.Executable(directory)) }.ToHashSet(StringComparer.OrdinalIgnoreCase);
        // While domain lists or blocked names are enforced, or encrypted DNS answers what leaves the local network, lookups sent
        // to Darkwire's resolver that no tunnel carries, and local names, go to the network's own servers.
        IReadOnlyList<IPAddress> systemDns = context.Names is null && context.LoopbackNames is null && context.Dns.Count == 0 ? []
            : PhysicalDnsServers(context.Network, luid => luid == tunnelLuid || Volatile.Read(ref tunnels)?.Owns(luid) == true);
        // The local networks are the physical interfaces' own subnets; a VPN tunnel's subnet is none of them.
        IReadOnlyList<NetPrefix> local = context.BypassLocal
            ? [.. context.Network.LocalNetworks(luid => luid == tunnelLuid || Volatile.Read(ref tunnels)?.Owns(luid) == true).Select(NetPrefix.Parse)] : [];
        return new(matcher, context.Mode, NetworkProfiles.Read(), context.Network.Interfaces.Select(i => i.Luid).Where(l => l != tunnelLuid).ToArray())
        {
            Assigned = assigned, DefaultTunnel = context.Tunnels?.DefaultProfileId, Exempt = exempt, SystemDns = systemDns, Local = local,
            Own = own, OwnTunnel = context.OwnTunnel, OwnRefused = context.OwnRefused, Forwards = context.Dns.Count > 0,
            Internal = context.BypassLocal ? Private : [],
            RoutesPrivately = (profile, address) => Volatile.Read(ref tunnels)?.Find(profile)?.Egress?.RoutesPrivately(address, Private) == true,
            AllowedCountries = context.AllowedCountries, CountryOf = context.CountryOf, Denied = context.FlowDenied, Refused = context.Refused
        };
    }

    private static string ApplicationKey(string path) => System.Text.Encoding.Unicode.GetString(WfpConditions.ApplicationId(path)).TrimEnd('\0');

    private static async Task DecideAsync(ChannelReader<RouterFlow> reader, FlowDecisions decisions, CancellationToken cancellation)
    {
        List<RouterFlow> batch = [];
        try
        {
            while (await reader.WaitToReadAsync(cancellation).ConfigureAwait(false))
            {
                batch.Clear();
                while (batch.Count < 256 && reader.TryRead(out var next)) batch.Add(next);
                decisions.Evaluate(batch);
            }
        }
        catch (OperationCanceledException) { }
    }

    private void Receive(WintunTunnel device, PacketRouter running, CancellationToken cancellation)
    {
        try
        {
            device.Run(packet =>
            {
                try { running.Process(packet); }
                catch (Exception error) when (error is not OutOfMemoryException)
                { if (Interlocked.Increment(ref packetErrors) <= 5) ServiceHost.Log("Router dropped a packet after an error: " + error); }
            }, cancellation);
        }
        catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception)
        {
            fault = error.Message;
            ServiceHost.Log("Router stopped: " + error.Message);
            // Without Darkwire's capture routes nothing may prefer a VPN tunnel's routes: close the tunnels now, not at restart.
            _ = Volatile.Read(ref tunnels)?.DisposeAsync().AsTask();
        }
    }

    private void Sweep(PacketRouter running, FlowDecisions decisions, TunnelSupervisor supervisor)
    {
        try
        {
            running.Sweep();
            if (++sweeps % 2 == 0) supervisor.Tick();
            // Facts for flows decided while the router was forgetting them would otherwise linger.
            if (sweeps % 60 == 0) decisions.Collect();
        }
        catch (Exception error) when (error is not OutOfMemoryException) { ServiceHost.Log("Router sweep failed: " + error.Message); }
    }

    /// <summary>
    /// Local subnets are more specific than the capture routes. Two halves one bit longer route them through the tunnel
    /// while relay sockets, pinned to the physical interface, still reach the subnet on-link.
    /// </summary>
    private void SyncSplits(NetworkSnapshot network)
    {
        var wanted = new HashSet<(IPAddress Network, int Prefix)>();
        foreach (var nic in network.Interfaces.Where(i => i.Luid != tunnel!.Luid))
        foreach (var subnet in nic.Subnets)
        {
            if (!IpNetwork.TryParse(subnet, out var parsed)) continue;
            var v6 = parsed.Address.AddressFamily == AddressFamily.InterNetworkV6;
            var bits = v6 ? 128 : 32;
            if (v6 && !ipv6 || parsed.Prefix < 2 || parsed.Prefix > bits - 2) continue;
            var address = NetAddress.From(parsed.Address);
            if (!address.IsRoutableUnicast || TunnelNetworks.Any(t => IpNetwork.TryParse(t, out var tunnelNetwork) && tunnelNetwork.Contains(parsed.Address)) ||
                !v6 && address.Within(NetAddress.Parse("169.254.0.0"), 16)) continue;
            var size = bits - parsed.Prefix;
            var low = address.Value >> size << size;
            var high = low | (UInt128.One << (size - 1));
            wanted.Add((new NetAddress(low, v6).ToIPAddress(), parsed.Prefix + 1));
            wanted.Add((new NetAddress(high, v6).ToIPAddress(), parsed.Prefix + 1));
        }
        foreach (var stale in splits.Except(wanted).ToArray())
        {
            try { TunnelNetwork.DeleteRoute(tunnel!.Luid, stale.Network, stale.Prefix); splits.Remove(stale); }
            catch (System.ComponentModel.Win32Exception error) { ServiceHost.Log("A stale subnet route could not be removed: " + error.Message); }
        }
        foreach (var route in wanted.Except(splits).ToArray())
        {
            TunnelNetwork.AddRoute(tunnel!.Luid, route.Network, route.Prefix);
            splits.Add(route);
        }
    }

    private static Socket Bind(IPAddress address)
    {
        // A freshly assigned address can take a moment to become bindable.
        for (var attempt = 0; ; attempt++)
        {
            try { return RouterRelay.Listen(address); }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.AddressNotAvailable && attempt < 50) { Thread.Sleep(100); }
        }
    }

    private void StopCore()
    {
        sweeper?.Dispose(); sweeper = null;
        // Windows would keep the resolver for the next adapter with this GUID. While the plan confines the DNS client, its
        // physical servers stay blocked whatever the adapter names.
        if (tunnel is not null && resolving != false)
        {
            try { SetResolver(false); }
            catch (Exception error) when (error is System.ComponentModel.Win32Exception or EntryPointNotFoundException)
            { ServiceHost.Log("The Darkwire adapter's DNS servers could not be cleared: " + error.Message); }
        }
        resolving = null;
        if (relay is not null) relay.Forwarder = null;
        dns?.Dispose(); dns = null; physicalEgress = null;
        // VPN tunnels and their routes go first: without Darkwire's capture routes, nothing may prefer a tunnel's.
        try { tunnels?.DisposeAsync().AsTask().Wait(TunnelSupervisor.StopTimeout + TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        // Routes to servers of backends that did not stop in time go too.
        peers?.Clear(); peers = null; peerNetwork = null;
        lifetime?.Cancel();
        evaluations?.Writer.TryComplete();
        var stopped = receiver is null || receiver.Join(TimeSpan.FromSeconds(10));
        try { decisions?.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        try { relay?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        // The receive thread uses the session; never free it underneath a thread that did not stop.
        if (stopped) tunnel?.Dispose();
        else ServiceHost.Log("The router thread did not stop; its adapter stays until the service exits.");
        lifetime?.Dispose();
        splits.Clear();
        // Answers the filter gave may still sit in the Windows DNS cache.
        if (names is not null || loopbackNames is not null) FlushDnsCache();
        names = null; loopbackNames = null;
        tunnel = null; router = null; relay = null; decider = null; tunnels = null; receiver = null; decisions = null; lifetime = null; evaluations = null;
        backends = null; lookup = null; latestNetwork = null;
        lock (ownGate) ownUp = null;
    }

    /// <summary>A router without a vault cannot read credentials; any profile it is asked to run fails closed.</summary>
    private sealed class UnavailableVault : IVpnProfileVault
    {
        public StoredVpnProfile Save(Guid id, string kind, string configuration) => throw new InvalidOperationException("The service VPN vault is unavailable.");
        public IReadOnlyList<StoredVpnProfile> List() => throw new InvalidOperationException("The service VPN vault is unavailable.");
        public ParsedVpnConfiguration Read(Guid id, Guid revision) => throw new InvalidOperationException("The service VPN vault is unavailable.");
        public void Delete(Guid id) => throw new InvalidOperationException("The service VPN vault is unavailable.");
    }
}
