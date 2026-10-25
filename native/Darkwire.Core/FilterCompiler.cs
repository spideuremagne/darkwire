namespace Darkwire.Core;

public sealed record PortRange(ushort Low, ushort High);
/// <summary>One native WFP filter. Service, Users and Package hold selectors; the engine converts them to SIDs.</summary>
public sealed record NativeFilter(string Name, Guid? RuleId, bool Ipv6, TrafficDirection Direction, RuleAction Action,
    ulong Weight, string? ApplicationPath = null, byte? Protocol = null, PortRange? LocalPort = null,
    PortRange? RemotePort = null, string? RemoteNetwork = null, string? LocalNetwork = null,
    byte? IcmpType = null, byte? IcmpCode = null, ulong? LocalInterfaceLuid = null, uint? CurrentProfileId = null,
    string? Service = null, string? Users = null, string? Package = null, uint? RequiredFlags = null, uint? TunnelType = null);
public sealed record FilterPlan(IReadOnlyList<NativeFilter> Filters, IReadOnlyList<string> Errors)
{
    public bool CanApply => Errors.Count == 0;
    /// <summary>Parts of the policy the plan leaves out without failing, such as a downloaded list that no longer fits.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
    /// <summary>The startup lock's filters, which go in a sublayer of their own above the policy (<see cref="FilterCompiler.StartupLock"/>).</summary>
    public IReadOnlyList<NativeFilter> StartupLock { get; init; } = [];
}

/// <summary>
/// A VPN backend's own traffic to one of its peers: the backend executable, the service whose SID its token carries, the
/// transport, and the peer's address when the profile names one rather than a host name.
/// </summary>
public sealed record TunnelEndpoint(string ApplicationPath, string? Service, byte Protocol, string? RemoteNetwork, ushort Port);

/// <summary>The running tunnel router: the service executable that relays flows and the networks assigned to the tunnel.</summary>
public sealed record RouterPlan(string ServicePath, IReadOnlyList<string> TunnelNetworks)
{
    /// <summary>Unicast destinations the leak guard covers: everything except link-local, multicast and broadcast, which stay with rules.</summary>
    public static IReadOnlyList<string> GuardedNetworks { get; } = new[] { "0.0.0.0-169.253.255.255", "169.255.0.0-223.255.255.255", "::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
        .SelectMany(range => { IpAddressRange.TryParse(range, out var parsed); return parsed.ToNetworks(); }).Select(n => n.Address + "/" + n.Prefix).ToArray();

    /// <summary>Executables a VPN profile carries. Their traffic may leave only through Darkwire's tunnel, whatever rules allow.</summary>
    public IReadOnlyList<string> TunneledApplications { get; init; } = [];
    /// <summary>A default VPN profile carries every application, so nothing may leave around Darkwire's tunnel.</summary>
    public bool TunnelAll { get; init; }
    /// <summary>The VPN backends' own traffic to their peers, which leaves through the physical network.</summary>
    public IReadOnlyList<TunnelEndpoint> Endpoints { get; init; } = [];
    /// <summary>Blocks unicast around the tunnel unless a rule allows it. Open mode routes only for VPN profiles and has none.</summary>
    public bool LeakGuard { get; init; } = true;
    /// <summary>
    /// Domain lists or blocked names are enforced, or encrypted DNS answers: the router answers lookups itself, so the Windows
    /// DNS client is confined to Darkwire's adapter, as with a default profile, and its lookups cannot leave around it.
    /// </summary>
    public bool FiltersDns { get; init; }
    /// <summary>The local networks traffic stays on instead of a VPN tunnel; empty when every route goes through the tunnel.</summary>
    public IReadOnlyList<string> LocalNetworks { get; init; } = [];
    /// <summary>Darkwire's own programs whose connections go through the router, its DNS proxy: the startup lock lets them out as it does the service.</summary>
    public IReadOnlyList<string> OwnApplications { get; init; } = [];
}

/// <summary>Fail-closed lowering for supported WFP conditions.</summary>
public static class FilterCompiler
{
    public const int MaximumFilters = 20_000;
    // The highest matching weight in the Darkwire sublayer decides. Explicit, geographic and list denies outrank every allow.
    public const ulong DenyWeight = 300, EdgeAllowWeight = 295, EdgeGuardWeight = 290, CoreWeight = 250, AllowWeight = 200, DefaultWeight = 1;
    // Router mode: the relay, its listener and the VPN backends' peer traffic, then tunnel-bound flows (the router decides
    // them), then the guard around VPN-carried applications, then explicit allows, then a block on every other unicast
    // egress. A flow that bypasses the tunnel therefore leaves only under a rule that allows it anyway, and never for an
    // application a VPN profile carries; without a rule it is blocked and reported for learning. Explicit denies stay above everything.
    // Edge-traversal allows would outrank that guard, so while it guards applications they keep the edge weight only for
    // Teredo traffic, and the VPN edge guard above them keeps guarded applications out of it.
    public const ulong VpnEdgeGuardWeight = 297, RouterServiceWeight = 245, TunnelWeight = 242, VpnGuardWeight = 220, LeakGuardWeight = 150;
    // A default VPN profile carries the Windows DNS client's lookups too, and domain lists filter them: core networking admits
    // its DNS to any server, so a guard above core networking denies it every server, and a permit above the guard admits only
    // Darkwire's adapter and loopback.
    public const ulong DnsClientWeight = 265, DnsClientGuardWeight = 260;
    // Blocked internal networks sit beneath explicit allows, so a rule still opens one host, and above the leak guard.
    public const ulong InternalBlockWeight = 190;
    // The startup lock's own sublayer: its block, the exceptions the restore needs above it, and the service's release above both.
    public const ulong LockWeight = 1, LockExceptionWeight = 10, LockReleaseWeight = 100;
    public const uint LoopbackFlag = 0x1, TeredoTunnelType = 14;
    private const string ServiceHost = @"%SystemRoot%\system32\svchost.exe";

    /// <param name="lists">The service's downloaded catalog lists; without it, catalog network lists are not enforced yet.</param>
    public static FilterPlan Compile(AppState state, bool learningNotificationsReady = false, IGeoLookup? geoDatabase = null, NetworkSnapshot? network = null,
        IBlocklistContents? lists = null)
    {
        List<string> errors = []; List<NativeFilter> filters = [];
        var admissionErrors = PolicyValidation.Validate(state);
        if (admissionErrors.Count > 0) return new([], admissionErrors);
        if (!Enum.IsDefined(state.Mode)) return new([], ["Unknown firewall mode."]);
        // VPN tunnels run in the connection router, in every mode, Open included. Without it assignments would silently use
        // the physical network, and a connected profile would have nowhere to run.
        if ((VpnAssignments.Routed(state) || VpnAssignments.Connected(state).Any()) && !state.RouteConnections)
            return new([], ["VPN profiles need connection routing. Turn routing on, or disconnect the profiles and remove their assignments and the default VPN route."]);
        // Darkwire's resolver sends lookups to them through the router, so they too need it.
        if (state.DnsServers.Count > 0 && !state.RouteConnections)
            return new([], ["Encrypted DNS servers answer through Darkwire's connection router. Turn routing on, or go back to the network's DNS servers."]);
        // Open allows everything, yet VPN-carried applications stay guarded and the Windows DNS client stays with Darkwire's
        // resolver; loopback and core networking stay above those guards.
        if (state.Mode == FirewallMode.Open) return RoutesInOpen(state) ? new(Essentials(state, lockdown: false).ToList(), []) : new([], []);
        if (state.Mode == FirewallMode.Learning && !learningNotificationsReady) errors.Add("Learning requires a live blocked-connection subscription and an authenticated decision channel.");
        var fixedFilters = FixedFilters(state);
        if (state.Mode == FirewallMode.Lockdown) return new(fixedFilters, []);
        var limit = MaximumFilters - fixedFilters.Count;
        // An allow list names what may be reached, which no budget of kernel filters can hold for most countries: the router
        // refuses everything else as it decides each connection.
        if (state.CountryAllowList)
        {
            if (!state.RouteConnections) errors.Add("A country allow list is enforced by Darkwire's connection router. Turn on connection routing, or block countries instead.");
            if (geoDatabase is null) errors.Add("Country and ASN restrictions require a verified GeoIP database before kernel installation.");
        }
        var blockedCountries = state.CountryAllowList ? [] : state.BlockedCountries;
        if (blockedCountries.Count > 0 || state.BlockedAsns.Count > 0)
        {
            if (geoDatabase is null) errors.Add("Country and ASN restrictions require a verified GeoIP database before kernel installation.");
            else
            {
                try
                {
                    foreach (var restricted in geoDatabase.RestrictedNetworks(blockedCountries, state.BlockedAsns, limit / 2))
                    {
                        IpNetwork.TryParse(restricted, out var parsed);
                        foreach (var direction in new[] { TrafficDirection.Outbound, TrafficDirection.Inbound })
                            filters.Add(new("Geographic restriction", null, parsed.Address.GetAddressBytes().Length == 16, direction, RuleAction.Deny, DenyWeight, RemoteNetwork: restricted));
                    }
                }
                catch (InvalidDataException ex) { errors.Add(ex.Message); }
            }
        }
        // Counted before the rules, so they share the filter budget.
        filters.AddRange(InternalFilters(state));
        foreach (var rule in state.Rules)
        {
            if (!rule.Enabled) continue;
            if (!RuleEnforcement.Installs(rule))
            {
                if (RuleEnforcement.NeedsConsent(rule)) errors.Add($"{rule.ApplicationName}: accept the broader block or disable this imported rule. {rule.ImportWarning}");
                continue;
            }
            var invalid = RuleValidator.Validate(rule);
            IpProtocol.TryParse(rule.Protocol, out var protocol);
            if (rule.Direction == TrafficDirection.Unknown) invalid.Add("Unknown is a telemetry state, not a rule direction.");
            if ((!RuleValidator.IsAny(rule.LocalPorts) || !RuleValidator.IsAny(rule.RemotePorts)) && protocol is not (6 or 17)) invalid.Add("Port restrictions require TCP or UDP.");
            if (invalid.Count > 0) { errors.AddRange(invalid.Select(e => $"{rule.ApplicationName}: {e}")); continue; }
            (string? Network, ulong? Luid)[] addresses, localAddresses;
            try
            {
                // Allow rules pair each resolved keyword with its interface; deny rules use the union. Either reading never widens what Windows allowed.
                addresses = ExpandAddresses(rule.RemoteAddresses, network, keywords: true, pairWithInterface: rule.Action == RuleAction.Allow);
                localAddresses = ExpandAddresses(rule.LocalAddresses, network, keywords: false, pairWithInterface: false);
            }
            catch (InvalidDataException ex) { errors.Add(rule.ApplicationName + ": " + ex.Message); continue; }
            // A dynamic keyword that currently resolves to nothing matches nothing; the service recompiles when interfaces change.
            if (addresses.Length == 0) continue;
            var local = Ports(rule.LocalPorts); var remote = Ports(rule.RemotePorts);
            // WFP profile IDs: None=0, Public=1, Private=2, Domain=3.
            // These are neither NL_NETWORK_CATEGORY values nor NET_FW_PROFILE_TYPE2 masks.
            // See NtCoreLib/Net/Firewall/FirewallProfileId.cs and FirewallValue.SpecializeValue.
            uint?[] profiles = rule.Location == "Any" ? [null] : RuleValidator.Tokens(rule.Location)
                .Select(p => (uint?)(p switch { "Public" => 1u, "Private" => 2u, "Domain" => 3u, _ => throw new InvalidDataException("Invalid network profile.") })).Distinct().ToArray();
            IcmpSelectors.TryParse(rule.IcmpTypesAndCodes, out var icmpSelectors);
            var directions = rule.Direction == TrafficDirection.Any ? new[] { TrafficDirection.Inbound, TrafficDirection.Outbound } : [rule.Direction];
            long AddressCount((string? Network, ulong? Luid)[] values, bool ipv6) => values.LongCount(a => a.Network is null || IpNetwork.TryParse(a.Network, out var net) && (net.Address.GetAddressBytes().Length == 16) == ipv6);
            var families = (protocol == 58 ? 0 : AddressCount(addresses, false) * AddressCount(localAddresses, false)) +
                (protocol == 1 ? 0 : AddressCount(addresses, true) * AddressCount(localAddresses, true));
            var expansion = families;
            var budget = limit - filters.Count;
            foreach (var factor in new[] { local.Length, remote.Length, directions.Length, icmpSelectors.Count, profiles.Length })
            {
                if (factor == 0) { expansion = 0; break; }
                if (expansion > budget / factor) { expansion = (long)budget + 1; break; }
                expansion *= factor;
            }
            if (expansion > budget) { errors.Add($"The policy expands beyond the {MaximumFilters:N0}-filter limit, including Darkwire's built-in filters."); continue; }
            if (expansion == 0) { errors.Add(rule.ApplicationName + ": address families and protocol have no compatible combination."); continue; }
            string? Selector(string value) => RuleValidator.IsAny(value) ? null : value;
            foreach (var ipv6 in new[] { false, true })
            {
                if (protocol == 1 && ipv6 || protocol == 58 && !ipv6) continue;
                foreach (var address in addresses)
                {
                    if (address.Network is not null && IpNetwork.TryParse(address.Network, out var remoteNetwork) && (remoteNetwork.Address.GetAddressBytes().Length == 16) != ipv6) continue;
                    foreach (var localAddress in localAddresses)
                    {
                        if (localAddress.Network is not null && IpNetwork.TryParse(localAddress.Network, out var localNetwork) && (localNetwork.Address.GetAddressBytes().Length == 16) != ipv6) continue;
                        foreach (var localPort in local)
                        foreach (var remotePort in remote)
                        foreach (var direction in directions)
                        foreach (var icmp in icmpSelectors)
                        foreach (var profile in profiles)
                            filters.Add(new(rule.ApplicationName, rule.Id, ipv6, direction, rule.Action, Weight(rule, direction),
                                Selector(rule.Path), protocol, localPort, remotePort, address.Network, localAddress.Network, icmp?.Type, icmp?.Code,
                                address.Luid, profile, Selector(rule.Service), Selector(rule.User), Selector(rule.Package)));
                    }
                }
            }
        }
        List<string> warnings = [];
        var domainLists = Blocklists(state, lists, filters, limit, errors, warnings) || state.BlockedNames.Count > 0;
        if (domainLists && !state.RouteConnections)
            errors.Add("Domain blocklists and blocked names are enforced by DNS filtering in Darkwire's connection router. Turn on connection routing, or turn them off.");
        // The router answers the DNS it relays, but plain DNS to a link-local server goes around it on-link. While domain lists
        // or blocked names are enforced, or encrypted DNS answers, that DNS is refused, and Windows asks its other servers.
        else if (domainLists || state.DnsServers.Count > 0)
            foreach (var (server, ipv6) in new[] { ("169.254.0.0/16", false), ("fe80::/10", true) })
            foreach (var protocol in new byte[] { 17, 6 })
                filters.Add(new("DNS filtering: unrouted server", null, ipv6, TrafficDirection.Outbound, RuleAction.Deny, DenyWeight, Protocol: protocol, RemotePort: new(53, 53), RemoteNetwork: server));
        filters.AddRange(fixedFilters);
        return errors.Count > 0 ? new([], errors.Distinct().ToArray()) : new(filters, []) { Warnings = warnings };
    }

    /// <summary>Open mode routes only to carry VPN profiles and to send lookups to encrypted DNS servers.</summary>
    public static bool RoutesInOpen(AppState state) => VpnAssignments.Routed(state) || VpnAssignments.Connected(state).Any() || state.DnsServers.Count > 0;

    /// <summary>
    /// Network lists deny their CIDRs in both directions at the list weight; returns whether a domain list is enabled. A custom
    /// list's networks are policy data and must fit. A catalog list changes underneath the policy, so one that no longer fits
    /// is left out and reported instead of failing the plan, with room kept for the filters routing adds.
    /// </summary>
    private static bool Blocklists(AppState state, IBlocklistContents? lists, List<NativeFilter> filters, int limit, List<string> errors, List<string> warnings)
    {
        var domains = false;
        void Deny(string name, IReadOnlyList<string> networks)
        {
            foreach (var network in networks)
            foreach (var direction in new[] { TrafficDirection.Outbound, TrafficDirection.Inbound })
                filters.Add(new(name, null, network.Contains(':'), direction, RuleAction.Deny, DenyWeight, RemoteNetwork: network));
        }
        foreach (var source in state.Blocklists.Where(l => l.Enabled && l.CatalogId is null))
        {
            List<IpNetwork> listed = [];
            foreach (var entry in source.Entries)
                if (IpNetwork.TryParse(entry, out var network)) listed.Add(network); else domains = true;
            var networks = AddressRanges.Normalize(listed);
            if (filters.Count + 2L * networks.Count > limit) { errors.Add($"The policy expands beyond the {MaximumFilters:N0}-filter limit, including Darkwire's built-in filters."); break; }
            Deny(source.Name, networks);
        }
        var room = limit - RouterReserve(state, filters);
        foreach (var source in state.Blocklists.Where(l => l.Enabled && l.CatalogId is not null))
        {
            // Validation refuses unknown catalog IDs; a list not downloaded yet is applied when the service has it.
            if (BlocklistCatalog.Find(source.CatalogId) is not { } entry) continue;
            if (entry.Domains) { domains = true; continue; }
            if (lists?.Networks(entry.Id) is not { } networks) continue;
            if (filters.Count + 2L * networks.Count > room) { warnings.Add($"{entry.Name} is not enforced: its {networks.Count:N0} networks no longer fit the kernel filter limit."); continue; }
            Deny(entry.Name, networks);
        }
        return domains;
    }

    /// <summary>
    /// Internal access as filters (<see cref="InternalNetworks.Decide"/>): allowed out to internal hosts, multicast and
    /// broadcast, and in from internal hosts on private and domain networks, at the allow weight; or refused both ways beneath
    /// explicit allows. Core networking keeps DHCP, DNS and discovery working above either.
    /// </summary>
    private static IEnumerable<NativeFilter> InternalFilters(AppState state)
    {
        if (state.InternalNetworks == InternalAccess.Rules) yield break;
        var allow = state.InternalNetworks == InternalAccess.Allow;
        var (action, weight) = allow ? (RuleAction.Allow, AllowWeight) : (RuleAction.Deny, InternalBlockWeight);
        foreach (var network in InternalNetworks.Unicast.Concat(InternalNetworks.Groups))
        {
            var ipv6 = network.Contains(':');
            yield return new("Internal networks", null, ipv6, TrafficDirection.Outbound, action, weight, RemoteNetwork: network);
            // Multicast and broadcast are never where a connection comes from.
            if (InternalNetworks.Groups.Contains(network)) continue;
            if (!allow) { yield return new("Internal networks", null, ipv6, TrafficDirection.Inbound, action, weight, RemoteNetwork: network); continue; }
            foreach (var profile in new uint[] { 2, 3 })
                yield return new("Internal networks", null, ipv6, TrafficDirection.Inbound, action, weight, RemoteNetwork: network, CurrentProfileId: profile);
        }
    }

    /// <summary>
    /// Room routing adds after compilation: relay, listener, tunnel, leak guard and DNS client filters, VPN endpoints and guards,
    /// and the Teredo part that IPv6 edge-traversal allows keep while applications are guarded.
    /// </summary>
    private static int RouterReserve(AppState state, List<NativeFilter> filters) => state.RouteConnections
        ? 256 + 8 * state.VpnProfiles.Count + 5 * (state.VpnProfiles.Sum(p => p.Applications.Count) + 1) + filters.Count(f => f.Weight == EdgeAllowWeight && f.Ipv6) +
            (state.DefaultOutboundVpnProfileId is not null && state.LocalNetworkBypassesVpn ? LocalGuardReserve : 0) : 0;

    /// <summary>Room for a default profile's guard around the local networks: every unicast range outside them, in both directions.</summary>
    public const int LocalGuardReserve = 1024;

    private static ulong Weight(FirewallRule rule, TrafficDirection direction) =>
        rule.Action == RuleAction.Deny ? DenyWeight : direction == TrafficDirection.Inbound && rule.EdgeTraversal ? EdgeAllowWeight : AllowWeight;

    /// <summary>
    /// The plan the router evaluates: the decision plan plus the VPN backends' own traffic to their peers, which Darkwire
    /// permits for its tunnels in every mode except where an explicit deny says otherwise.
    /// </summary>
    public static FilterPlan Endpoints(FilterPlan plan, RouterPlan router)
    {
        if (!plan.CanApply || router.Endpoints.Count == 0) return plan;
        if (!Valid(router)) return new([], ["The tunnel router plan is invalid."]);
        return Limited(plan.Filters.Concat(EndpointFilters(router)).ToArray()) with { Warnings = plan.Warnings };
    }

    /// <summary>
    /// The kernel plan for router mode: the decision plan plus the VPN backends' peer traffic, relay, tunnel, DNS client and
    /// guard filters. The router evaluates the decision plan itself, as if each flow left directly; the added filters only steer
    /// flows into it and keep VPN-carried applications, and with a default profile or domain lists the Windows DNS client, from
    /// leaving any other way. Edge-traversal allows, which would outrank the VPN guard, drop beneath it here (<see cref="EdgeAllows"/>);
    /// the router evaluates only outbound flows.
    /// </summary>
    public static FilterPlan Route(FilterPlan plan, RouterPlan router)
    {
        if (!plan.CanApply) return plan;
        if (!Valid(router)) return new([], ["The tunnel router plan is invalid."]);
        var filters = EdgeAllows(plan.Filters, router).ToArray();
        var edge = filters.Any(f => f.Weight == EdgeAllowWeight);
        return Limited(filters.Concat(EndpointFilters(router)).Concat(RouterFilters(router)).Concat(DnsClientFilters(router)).Concat(TunnelGuards(router, edge)).ToArray())
            with { Warnings = plan.Warnings };
    }

    private static bool Valid(RouterPlan router) =>
        Path.IsPathFullyQualified(router.ServicePath) && router.TunnelNetworks.Count > 0 &&
        router.TunnelNetworks.All(n => IpNetwork.TryParse(n, out var parsed) && parsed.Prefix > 0) &&
        router.TunneledApplications.All(Path.IsPathFullyQualified) && router.OwnApplications.All(Path.IsPathFullyQualified) &&
        router.LocalNetworks.All(n => IpNetwork.TryParse(n, out var local) && local.Prefix > 0) &&
        router.Endpoints.All(e => Path.IsPathFullyQualified(e.ApplicationPath) && e.Protocol is 6 or 17 && e.Port > 0 &&
            (e.Service is null || IdentitySelectors.ValidService(e.Service) && !RuleValidator.IsAny(e.Service)) &&
            (e.RemoteNetwork is null || IpNetwork.TryParse(e.RemoteNetwork, out var peer) && peer.Prefix == (peer.Address.GetAddressBytes().Length == 16 ? 128 : 32)));

    private static FilterPlan Limited(NativeFilter[] filters) =>
        filters.Length > MaximumFilters ? new([], [$"The policy expands beyond the {MaximumFilters:N0}-filter limit, including Darkwire's built-in filters."]) : new(filters, []);

    /// <summary>Loopback, core networking, the Teredo edge guard and the four default filters. Lockdown keeps only loopback and link essentials.</summary>
    private static List<NativeFilter> FixedFilters(AppState state)
    {
        var lockdown = state.Mode == FirewallMode.Lockdown;
        var list = Essentials(state, lockdown).ToList();
        // Inbound allow rules exclude Teredo edge traffic unless they opt into edge traversal (EdgeAllowWeight), as in Windows.
        if (!lockdown) list.Add(new("Edge traversal guard", null, true, TrafficDirection.Inbound, RuleAction.Deny, EdgeGuardWeight, TunnelType: TeredoTunnelType));
        foreach (var ipv6 in new[] { false, true })
        foreach (var direction in new[] { TrafficDirection.Inbound, TrafficDirection.Outbound })
            list.Add(new("Default policy", null, ipv6, direction, RuleAction.Deny, DefaultWeight));
        return list;
    }

    /// <summary>Loopback, which Windows Firewall never filters (AppContainer loopback isolation remains with Windows), and the optional core networking set.</summary>
    private static IEnumerable<NativeFilter> Essentials(AppState state, bool lockdown)
    {
        foreach (var ipv6 in new[] { false, true })
        foreach (var direction in new[] { TrafficDirection.Inbound, TrafficDirection.Outbound })
            yield return new("Loopback", null, ipv6, direction, RuleAction.Allow, CoreWeight, RequiredFlags: LoopbackFlag);
        if (!state.CoreNetworking) yield break;
        foreach (var filter in CoreNetworking(lockdown)) yield return filter;
    }

    private static IEnumerable<NativeFilter> CoreNetworking(bool lockdown)
    {
        var both = new[] { TrafficDirection.Inbound, TrafficDirection.Outbound };
        foreach (var direction in both)
        {
            yield return new("Core networking: DHCP", null, false, direction, RuleAction.Allow, CoreWeight, ServiceHost, 17, new(68, 68), new(67, 67), Service: "Dhcp");
            yield return new("Core networking: DHCPv6", null, true, direction, RuleAction.Allow, CoreWeight, ServiceHost, 17, new(546, 546), new(547, 547), Service: "Dhcp");
            // Router and neighbor discovery, then multicast listener discovery, scoped as Windows' Core Networking rules scope them:
            // router advertisements and listener messages arrive only from link-local senders, and redirects are not allowed at all.
            foreach (var type in new byte[] { 133, 134, 135, 136, 130, 131, 132, 143 })
                yield return new("Core networking: IPv6 discovery", null, true, direction, RuleAction.Allow, CoreWeight, IdentitySelectors.SystemApplication, 58, IcmpType: type,
                    RemoteNetwork: direction == TrafficDirection.Inbound && type is not (133 or 135 or 136) ? "fe80::/64" : null);
        }
        if (lockdown) yield break;
        foreach (var ipv6 in new[] { false, true })
        foreach (var protocol in new byte[] { 17, 6 })
            yield return new("Core networking: DNS client", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, CoreWeight, ServiceHost, protocol, RemotePort: new(53, 53), Service: "Dnscache");
        // Path MTU discovery and ICMP errors that keep existing connections healthy.
        foreach (var type in new byte[] { 1, 2, 3, 4 })
            yield return new("Core networking: ICMPv6 errors", null, true, TrafficDirection.Inbound, RuleAction.Allow, CoreWeight, IdentitySelectors.SystemApplication, 58, IcmpType: type);
        yield return new("Core networking: fragmentation needed", null, false, TrafficDirection.Inbound, RuleAction.Allow, CoreWeight, IdentitySelectors.SystemApplication, 1, IcmpType: 3, IcmpCode: 4);
        foreach (var direction in both)
            yield return new("Core networking: IGMP", null, false, direction, RuleAction.Allow, CoreWeight, IdentitySelectors.SystemApplication, 2);
    }

    /// <summary>
    /// The startup lock (<see cref="AppState.StartupLock"/>), for a sublayer of its own evaluated before the policy's: a block on
    /// everything in both directions, and above it the exceptions restoring needs: loopback, DHCP and IPv6 discovery, the Windows
    /// DNS client, Darkwire's service, which relays, resolves VPN servers and probes its own learning events, and with routing
    /// its VPN backends' traffic to their peers, its DNS proxy's, which answers the DNS client with encrypted DNS, and the
    /// relay's listener, which takes in the TCP connections the router translates for what passes the lock into Darkwire's
    /// adapter. An exception only passes the lock; the policy beneath still decides it. The service lifts the lock with a release above both
    /// once it has restored its state, and the release ends with the service. None for a plan that installs nothing or with the
    /// lock off.
    /// </summary>
    public static IReadOnlyList<NativeFilter> StartupLock(AppState state, FilterPlan plan, string servicePath, RouterPlan? router)
    {
        if (!state.StartupLock || !plan.CanApply || plan.Filters.Count == 0) return [];
        List<NativeFilter> filters = [];
        foreach (var ipv6 in new[] { false, true })
        foreach (var direction in new[] { TrafficDirection.Inbound, TrafficDirection.Outbound })
        {
            filters.Add(new("Darkwire startup lock", null, ipv6, direction, RuleAction.Deny, LockWeight));
            filters.Add(new("Darkwire startup lock: loopback", null, ipv6, direction, RuleAction.Allow, LockExceptionWeight, RequiredFlags: LoopbackFlag));
        }
        static NativeFilter Exception(NativeFilter filter) => filter with { Name = "Darkwire startup lock: " + filter.Name, Weight = LockExceptionWeight };
        filters.AddRange(CoreNetworking(lockdown: true).Select(Exception));
        foreach (var ipv6 in new[] { false, true })
        foreach (var protocol in new byte[] { 17, 6 })
            filters.Add(Exception(new("DNS client", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, CoreWeight, ServiceHost, protocol, RemotePort: new(53, 53), Service: "Dnscache")));
        if (Path.IsPathFullyQualified(servicePath))
            foreach (var ipv6 in new[] { false, true })
                filters.Add(Exception(new("Darkwire service", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, RouterServiceWeight, servicePath)));
        if (router is not null && Valid(router))
        {
            filters.AddRange(EndpointFilters(router).Select(Exception));
            foreach (var network in router.TunnelNetworks)
                filters.Add(Exception(new("Router: listener", null, network.Contains(':'), TrafficDirection.Inbound, RuleAction.Allow, RouterServiceWeight, router.ServicePath, LocalNetwork: network)));
            foreach (var own in router.OwnApplications.Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (var ipv6 in new[] { false, true })
                filters.Add(Exception(new("Darkwire " + Path.GetFileNameWithoutExtension(own), null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, RouterServiceWeight, own)));
        }
        return filters;
    }

    /// <summary>
    /// Flows leaving through the tunnel are permitted here and decided by the router, which holds unknown ones. Besides
    /// the relay's own sockets, unicast that goes around the tunnel leaves only under an explicit allow. The relay's
    /// sockets are pinned to their egress, physical or a VPN tunnel's, so the relay permit also carries tunneled flows.
    /// </summary>
    private static IEnumerable<NativeFilter> RouterFilters(RouterPlan router)
    {
        foreach (var ipv6 in new[] { false, true })
        {
            yield return new("Router: relay", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, RouterServiceWeight, router.ServicePath);
            foreach (var network in router.TunnelNetworks.Where(n => IpNetwork.TryParse(n, out var parsed) && (parsed.Address.GetAddressBytes().Length == 16) == ipv6))
            {
                yield return new("Router: listener", null, ipv6, TrafficDirection.Inbound, RuleAction.Allow, RouterServiceWeight, router.ServicePath, LocalNetwork: network);
                yield return new("Router: tunnel", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, TunnelWeight, LocalNetwork: network);
            }
            if (!router.LeakGuard) continue;
            foreach (var guarded in RouterPlan.GuardedNetworks.Where(n => n.Contains(':') == ipv6))
                yield return new("Router: leak guard", null, ipv6, TrafficDirection.Outbound, RuleAction.Deny, LeakGuardWeight, RemoteNetwork: guarded);
        }
    }

    /// <summary>
    /// With a default profile, DNS filtering or encrypted DNS, the Windows DNS client (Dnscache) may send DNS only into Darkwire's
    /// adapter, from the tunnel addresses, where the router filters it and sends it to the encrypted DNS servers, to the profile's
    /// resolver through its tunnel or to the network's own servers, or over loopback to a local resolver, whose own lookups the
    /// router sees as any application's.
    /// The guard denies its DNS to every other server, link-local ones included, above the core-networking exception; explicit
    /// denies still outrank the permits.
    /// </summary>
    private static IEnumerable<NativeFilter> DnsClientFilters(RouterPlan router)
    {
        if (!router.TunnelAll && !router.FiltersDns) yield break;
        foreach (var ipv6 in new[] { false, true })
        foreach (var protocol in new byte[] { 17, 6 })
        {
            yield return new("Router: DNS client guard", null, ipv6, TrafficDirection.Outbound, RuleAction.Deny, DnsClientGuardWeight, ServiceHost, protocol, RemotePort: new(53, 53), Service: "Dnscache");
            foreach (var network in router.TunnelNetworks.Where(n => IpNetwork.TryParse(n, out var parsed) && (parsed.Address.GetAddressBytes().Length == 16) == ipv6))
                yield return new("Router: DNS client tunnel", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, DnsClientWeight, ServiceHost, protocol, RemotePort: new(53, 53),
                    LocalNetwork: network, Service: "Dnscache");
            yield return new("Router: DNS client loopback", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, DnsClientWeight, ServiceHost, protocol, RemotePort: new(53, 53),
                Service: "Dnscache", RequiredFlags: LoopbackFlag);
        }
    }

    /// <summary>
    /// A VPN backend reaches its peers directly: the router routes each peer address over the physical network, so
    /// WireGuard's driver never sends its transport into Darkwire's adapter. Only the backend executable (and its
    /// service identity) may use these permits, only toward the peer's port and, when the profile names one, its address.
    /// </summary>
    private static IEnumerable<NativeFilter> EndpointFilters(RouterPlan router)
    {
        foreach (var endpoint in router.Endpoints.Distinct())
        foreach (var ipv6 in new[] { false, true })
        {
            if (endpoint.RemoteNetwork is { } peer && IpNetwork.TryParse(peer, out var parsed) && (parsed.Address.GetAddressBytes().Length == 16) != ipv6) continue;
            yield return new("Router: VPN endpoint", null, ipv6, TrafficDirection.Outbound, RuleAction.Allow, RouterServiceWeight, endpoint.ApplicationPath,
                endpoint.Protocol, RemotePort: new(endpoint.Port, endpoint.Port), RemoteNetwork: endpoint.RemoteNetwork, Service: endpoint.Service);
        }
    }

    /// <summary>
    /// Applications a VPN profile carries may exchange traffic only through Darkwire's tunnel, where the router sends it into
    /// their profile's tunnel and nowhere else. The guard outranks explicit allows, so no rule lets them around it in either
    /// direction; loopback and core networking stay above it. A default profile guards every application. Where edge-traversal
    /// allows keep Teredo traffic above the guard, the VPN edge guard denies it to guarded applications. Loopback is never
    /// edge traffic, and core networking gets none past the edge traversal guard, so both still stay above the guards.
    /// A default profile that leaves the local networks to them guards only the unicast space outside them, so rules decide
    /// local traffic in both directions; applications a profile carries stay guarded everywhere.
    /// </summary>
    private static IEnumerable<NativeFilter> TunnelGuards(RouterPlan router, bool edge)
    {
        string?[] applications = router.TunnelAll ? [null] : [.. router.TunneledApplications.Distinct(StringComparer.OrdinalIgnoreCase)];
        string?[] remotes = router.TunnelAll && router.LocalNetworks.Count > 0 ? [.. AddressRanges.Without(RouterPlan.GuardedNetworks, router.LocalNetworks)] : [null];
        foreach (var application in applications)
        {
            foreach (var ipv6 in new[] { false, true })
            foreach (var direction in new[] { TrafficDirection.Outbound, TrafficDirection.Inbound })
            foreach (var remote in remotes.Where(r => r is null || r.Contains(':') == ipv6))
                yield return new("Router: VPN guard", null, ipv6, direction, RuleAction.Deny, VpnGuardWeight, application, RemoteNetwork: remote);
            if (edge) yield return new("Router: VPN edge guard", null, true, TrafficDirection.Inbound, RuleAction.Deny, VpnEdgeGuardWeight, application, TunnelType: TeredoTunnelType);
        }
    }

    /// <summary>
    /// Edge-traversal allows outrank the VPN guard, so while it guards applications they drop to the allow weight beneath it.
    /// Their Teredo traffic, which the edge traversal guard blocks otherwise, keeps the edge weight in a copy of each IPv6
    /// allow, and the VPN edge guard denies that copy to guarded applications; with a default profile no application is
    /// left to copy it for. Every edge-traversal allow is treated this way: one for any program, or one naming a guarded
    /// executable by another path, reaches guarded applications too.
    /// </summary>
    private static IEnumerable<NativeFilter> EdgeAllows(IReadOnlyList<NativeFilter> filters, RouterPlan router)
    {
        var guarded = router.TunnelAll || router.TunneledApplications.Count > 0;
        foreach (var filter in filters)
        {
            if (!guarded || filter.Weight != EdgeAllowWeight) { yield return filter; continue; }
            yield return filter with { Weight = AllowWeight };
            if (filter.Ipv6 && !router.TunnelAll) yield return filter with { TunnelType = TeredoTunnelType };
        }
    }

    private static (string? Network, ulong? Luid)[] ExpandAddresses(string selector, NetworkSnapshot? network, bool keywords, bool pairWithInterface)
    {
        if (RuleValidator.IsAny(selector)) return [(null, null)];
        List<(string? Network, ulong? Luid)> addresses = [];
        foreach (var token in RuleValidator.Tokens(selector))
        {
            if (keywords && AddressKeywords.TryParse(token, out var keyword, out var family))
            {
                if (network is null) throw new InvalidDataException(keyword + " is resolved by the filtering service from current interface addresses.");
                foreach (var (luid, cidr) in AddressKeywords.Expand(keyword, family, network)) addresses.Add((cidr, pairWithInterface ? luid : null));
            }
            else
            {
                IReadOnlyList<IpNetwork> networks;
                var isRange = IpAddressRange.TryParse(token, out var range);
                if (isRange) networks = range.ToNetworks();
                else if (IpNetwork.TryParse(token, out var parsedNetwork)) networks = [parsedNetwork];
                else throw new InvalidDataException("Invalid address selector.");
                foreach (var item in networks) addresses.Add((isRange ? item.Address + "/" + item.Prefix : token, null));
            }
            if (addresses.Count >= MaximumFilters) throw new InvalidDataException("Address selectors exceed the native filter limit.");
        }
        return addresses.Distinct().ToArray();
    }
    private static PortRange?[] Ports(string value) => RuleValidator.IsAny(value) ? new PortRange?[] { null } : RuleValidator.Tokens(value).Select(t =>
    { var p = t.Split('-'); var low = ushort.Parse(p[0]); return new PortRange(low, p.Length == 1 ? low : ushort.Parse(p[1])); }).ToArray();
}
