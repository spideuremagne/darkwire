using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Darkwire.Vpn;

/// <summary>
/// Where a relayed flow leaves the host: a physical interface and the source address the stack would choose on it, or a
/// VPN tunnel's interface and its address. A shared source belongs to another tunnel's interface; this one sends from it
/// over Windows' weak host model.
/// </summary>
public sealed record Egress(ulong Luid, uint Index, IPAddress Source, int PrefixLength, uint Metric, bool Shared = false);

/// <summary>The interface that holds an address: its GUID and name, and whether it is up.</summary>
public sealed record AddressHolder(Guid Interface, string Name, bool Up);

public interface IEgressSelector
{
    Egress? Select(IPAddress destination);
}

/// <summary>Chooses, among non-tunnel interfaces, the route Windows would use if the tunnel routes did not exist.</summary>
public sealed class EgressSelector(Func<IReadOnlyList<ulong>> interfaces) : IEgressSelector
{
    public Egress? Select(IPAddress destination) => Hop(destination)?.Egress;

    /// <summary>The route <see cref="Select"/> chooses, with its next hop.</summary>
    public (Egress Egress, IPAddress NextHop)? Hop(IPAddress destination)
    {
        (Egress Egress, IPAddress NextHop)? best = null;
        foreach (var luid in interfaces())
        {
            if (TunnelNetwork.BestHop(luid, destination) is not { } candidate) continue;
            // Longest prefix first, then the lowest route plus interface metric, as Windows routes.
            if (best is not { } current || candidate.Egress.PrefixLength > current.Egress.PrefixLength ||
                candidate.Egress.PrefixLength == current.Egress.PrefixLength && candidate.Egress.Metric < current.Egress.Metric) best = candidate;
        }
        return best;
    }
}

/// <summary>
/// A VPN tunnel's interface as an egress. It carries only the families it has addresses for and the networks its profile
/// routes, and nothing once closed, so a flow assigned to it can never leave through another interface.
/// </summary>
public sealed class TunnelEgress : IEgressSelector
{
    private readonly IPAddress[] sources, resolvers, shared;
    private readonly NetPrefix[] networks;
    private volatile bool closed;

    /// <param name="shared">Sources another tunnel's interface holds, which this one sends from over the weak host model.</param>
    public TunnelEgress(ulong luid, uint index, IEnumerable<IPAddress> sources, IEnumerable<NetPrefix> networks, IEnumerable<IPAddress> resolvers, IEnumerable<IPAddress>? shared = null)
    {
        this.sources = sources.ToArray(); this.networks = networks.ToArray();
        if (luid == 0 || index == 0 || this.sources.Length == 0 || this.sources.Any(s => !NetAddress.From(s).IsRoutableUnicast) ||
            this.sources.GroupBy(s => s.AddressFamily).Any(g => g.Count() > 1))
            throw new ArgumentException("A tunnel egress needs its interface and one unicast source address per family.");
        Luid = luid; Index = index;
        this.shared = [.. this.sources.Intersect(shared ?? [])];
        // A resolver the tunnel does not carry could never answer through it.
        this.resolvers = resolvers.Where(r => Carry(r) is not null).ToArray();
    }

    public ulong Luid { get; }
    public uint Index { get; }
    public IReadOnlyList<IPAddress> Sources => sources;
    /// <summary>The sources another tunnel's interface holds.</summary>
    public IReadOnlyList<IPAddress> Shared => shared;
    /// <summary>The profile's resolvers this tunnel carries.</summary>
    public IReadOnlyList<IPAddress> Resolvers => resolvers;
    public bool Closed => closed;

    /// <summary>The tunnel went down: from now on it carries nothing, including flows already routed to it.</summary>
    public void Close() => closed = true;

    public Egress? Select(IPAddress destination) => closed ? null : Carry(destination);

    /// <summary>
    /// Whether the profile routes the destination through a network of its own inside the given private space, such as an
    /// office or home network behind the tunnel, rather than only through its default route.
    /// </summary>
    public bool RoutesPrivately(NetAddress destination, IReadOnlyList<NetPrefix> privateSpace) =>
        !closed && networks.Any(n => n.Contains(destination) && privateSpace.Any(p => p.Length <= n.Length && p.Contains(n.Network)));

    private Egress? Carry(IPAddress destination)
    {
        if (destination.AddressFamily == AddressFamily.InterNetworkV6 && destination.ScopeId != 0) return null;
        var target = NetAddress.From(destination);
        if (!target.IsRoutableUnicast || !networks.Any(n => n.Contains(target))) return null;
        var source = sources.FirstOrDefault(s => s.AddressFamily == destination.AddressFamily);
        return source is null ? null : new(Luid, Index, source, 0, 0, shared.Contains(source));
    }

    /// <summary>
    /// The route for a flow through this tunnel, or null when the tunnel cannot carry it. DNS goes to the profile's own
    /// resolver, preferring the flow's family, so a name server the physical network handed out is never asked through it.
    /// DNS addressed to Darkwire's resolver has no server but the profile's: without one it is refused. Echo requests leave
    /// through the interface holding their source address, which no socket option can pin, so a shared source refuses them
    /// rather than send them through another tunnel.
    /// </summary>
    /// <param name="redirectDns">False for Darkwire's own flows, whose port 53 may carry DNSCrypt to the server they name.</param>
    public FlowRoute? Route(byte protocol, NetEndpoint remote, bool redirectDns = true)
    {
        if (protocol is 1 or 58) return Select(remote.Address.ToIPAddress()) is { Shared: false } echo ? new(echo, null, true) : null;
        if (protocol is 6 or 17 && remote.Port == 53 && redirectDns)
        {
            foreach (var resolver in resolvers.OrderBy(r => (r.AddressFamily == AddressFamily.InterNetworkV6) == remote.Address.V6 ? 0 : 1))
                if (Select(resolver) is { } via) return new(via, new(NetAddress.From(resolver), 53), true);
            if (RouterAddresses.IsResolver(remote)) return null;
        }
        return Select(remote.Address.ToIPAddress()) is { } egress ? new(egress, null, true) : null;
    }
}

/// <summary>IP Helper operations for the tunnel adapter: interface settings, addresses, DNS servers, routes and per-interface route lookup.</summary>
public static class TunnelNetwork
{
    private const uint ObjectExists = 5010, NotFound = 1168;
    private const ushort Inet = 2, Inet6 = 23;
    // netioapi.h: DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6 and DNS_SETTING_NAMESERVER.
    private const uint DnsSettingsVersion1 = 1;
    private const ulong DnsSettingIpv6 = 0x1, DnsSettingNameServer = 0x2;

    /// <summary>Fixed metric, the given MTU, and on IPv6 no router discovery or duplicate address probes. Returns false when IPv6 is disabled.</summary>
    public static bool Configure(ulong luid, int mtu)
    {
        var ipv6 = true;
        foreach (var family in new[] { Inet, Inet6 })
        {
            var row = new InterfaceRow(); InitializeIpInterfaceEntry(ref row);
            row.Family = family; row.InterfaceLuid = luid;
            var error = GetIpInterfaceEntry(ref row);
            if (error == NotFound && family == Inet6) { ipv6 = false; continue; }
            Check(error, "read tunnel interface settings");
            row.UseAutomaticMetric = 0; row.Metric = 0; row.NlMtu = (uint)mtu;
            if (family == Inet6) { row.RouterDiscoveryBehavior = 0; row.DadTransmits = 0; row.ManagedAddressConfigurationSupported = 0; row.OtherStatefulConfigurationSupported = 0; }
            // SetIpInterfaceEntry rejects IPv4 rows that carry a site prefix length.
            else row.SitePrefixLength = 0;
            Check(SetIpInterfaceEntry(ref row), "configure the tunnel interface");
        }
        return ipv6;
    }

    /// <summary>
    /// Lets an interface send from addresses other interfaces hold, and accept traffic for them, in one family: Windows'
    /// weak host model. An interface that already does is left alone.
    /// </summary>
    public static void ShareAddresses(ulong luid, AddressFamily family)
    {
        var row = new InterfaceRow(); InitializeIpInterfaceEntry(ref row);
        row.Family = family == AddressFamily.InterNetworkV6 ? Inet6 : Inet; row.InterfaceLuid = luid;
        Check(GetIpInterfaceEntry(ref row), "read tunnel interface settings");
        if (row.WeakHostSend != 0 && row.WeakHostReceive != 0) return;
        row.WeakHostSend = row.WeakHostReceive = 1;
        // SetIpInterfaceEntry rejects IPv4 rows that carry a site prefix length.
        if (row.Family == Inet) row.SitePrefixLength = 0;
        Check(SetIpInterfaceEntry(ref row), "let the tunnel interface use a shared address");
    }

    /// <summary>An interface's MTU in one family, or null when the family is not enabled on it.</summary>
    public static int? Mtu(ulong luid, AddressFamily family)
    {
        var row = new InterfaceRow(); InitializeIpInterfaceEntry(ref row);
        row.Family = family == AddressFamily.InterNetworkV6 ? Inet6 : Inet; row.InterfaceLuid = luid;
        var error = GetIpInterfaceEntry(ref row);
        if (error == NotFound) return null;
        Check(error, "read tunnel interface settings");
        return (int)row.NlMtu;
    }

    public static void SetMtu(ulong luid, AddressFamily family, int mtu)
    {
        var row = new InterfaceRow(); InitializeIpInterfaceEntry(ref row);
        row.Family = family == AddressFamily.InterNetworkV6 ? Inet6 : Inet; row.InterfaceLuid = luid;
        Check(GetIpInterfaceEntry(ref row), "read tunnel interface settings");
        row.NlMtu = (uint)mtu;
        if (row.Family == Inet) row.SitePrefixLength = 0;
        Check(SetIpInterfaceEntry(ref row), "set the tunnel interface's MTU");
    }

    /// <summary>The interface holding an address now, or null when none does. Windows gives a unicast address to one interface only.</summary>
    public static AddressHolder? Holder(IPAddress address)
    {
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
            if (Guid.TryParse(network.Id, out var id) && network.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(address)))
                return new(id, network.Name, network.OperationalStatus == OperationalStatus.Up);
        return null;
    }

    /// <summary>Assigns an address already in the preferred state, so sockets can bind before duplicate detection would finish.</summary>
    public static void AddAddress(ulong luid, IPAddress address, int prefix)
    {
        var row = new UnicastRow(); InitializeUnicastIpAddressEntry(ref row);
        row.Address = SockAddr.From(address); row.InterfaceLuid = luid; row.OnLinkPrefixLength = (byte)prefix; row.DadState = 4;
        var error = CreateUnicastIpAddressEntry(ref row);
        if (error != ObjectExists) Check(error, "assign a tunnel address");
    }

    /// <summary>Takes an address off an interface, ending every connection bound to it; one already gone is left alone.</summary>
    public static void DeleteAddress(ulong luid, IPAddress address)
    {
        var row = new UnicastRow(); InitializeUnicastIpAddressEntry(ref row);
        row.Address = SockAddr.From(address); row.InterfaceLuid = luid;
        var error = DeleteUnicastIpAddressEntry(ref row);
        if (error != NotFound) Check(error, "remove a tunnel address");
    }

    /// <summary>An on-link route through the interface. The route metric adds to the interface metric when routes tie on prefix length.</summary>
    public static void AddRoute(ulong luid, IPAddress network, int prefix, uint metric = 0)
    {
        var row = Route(luid, network, prefix);
        row.Metric = metric;
        var error = CreateIpForwardEntry2(ref row);
        if (error != ObjectExists) Check(error, "add a tunnel route");
    }

    /// <summary>The LUID and index of an interface by its GUID; throws once the interface is gone.</summary>
    public static (ulong Luid, uint Index) Interface(Guid id)
    {
        Check(ConvertInterfaceGuidToLuid(ref id, out var luid), "find the tunnel interface");
        Check(ConvertInterfaceLuidToIndex(ref luid, out var index), "find the tunnel interface index");
        if (luid == 0 || index == 0) throw new Win32Exception(unchecked((int)NotFound), "Could not find the tunnel interface.");
        return (luid, index);
    }

    /// <summary>
    /// Replaces the DNS servers the Windows DNS client uses on an interface for one family; none clears them. Windows keeps
    /// the setting under the interface GUID, so an adapter removed and created again with that GUID gets it back.
    /// </summary>
    public static void SetDnsServers(ulong luid, bool ipv6, IEnumerable<IPAddress> servers)
    {
        var list = servers.ToArray();
        if (list.Any(s => (s.AddressFamily == AddressFamily.InterNetworkV6) != ipv6 || !NetAddress.From(s).IsRoutableUnicast))
            throw new ArgumentException("DNS servers must be unicast addresses of the family being set.", nameof(servers));
        Check(ConvertInterfaceLuidToGuid(ref luid, out var interfaceId), "find the tunnel interface GUID");
        var text = Marshal.StringToHGlobalUni(string.Join(",", list.Select(s => s.ToString())));
        try
        {
            var settings = new DnsInterfaceSettings { Version = DnsSettingsVersion1, Flags = DnsSettingNameServer | (ipv6 ? DnsSettingIpv6 : 0), NameServer = text };
            Check(SetInterfaceDnsSettings(interfaceId, ref settings), "set the tunnel interface's DNS servers");
        }
        finally { Marshal.FreeHGlobal(text); }
    }

    public static void DeleteRoute(ulong luid, IPAddress network, int prefix)
    {
        var row = Route(luid, network, prefix);
        var error = DeleteIpForwardEntry2(ref row);
        if (error != NotFound) Check(error, "remove a tunnel route");
    }

    /// <summary>The best route to the destination through one interface, or null when that interface cannot reach it.</summary>
    public static Egress? BestRoute(ulong luid, IPAddress destination) => BestHop(luid, destination)?.Egress;

    /// <summary>The best route through one interface with its next hop, which is unspecified for an on-link destination.</summary>
    public static (Egress Egress, IPAddress NextHop)? BestHop(ulong luid, IPAddress destination)
    {
        var target = SockAddr.From(destination);
        if (GetBestRoute2(ref luid, 0, IntPtr.Zero, ref target, 0, out var route, out var source) != 0) return null;
        var row = new InterfaceRow(); InitializeIpInterfaceEntry(ref row);
        row.Family = target.Family; row.InterfaceLuid = luid;
        var interfaceMetric = GetIpInterfaceEntry(ref row) == 0 ? row.Metric : 0;
        return (new(luid, route.InterfaceIndex, source.ToAddress(), route.Destination.Length, route.Metric + interfaceMetric), route.NextHop.ToAddress());
    }

    /// <summary>A route to one address through an interface and its next hop; an unspecified next hop makes it on-link.</summary>
    public static void AddHostRoute(ulong luid, IPAddress destination, IPAddress nextHop)
    {
        var row = HostRoute(luid, destination, nextHop);
        var error = CreateIpForwardEntry2(ref row);
        if (error != ObjectExists) Check(error, "add a route to a VPN server");
    }

    public static void DeleteHostRoute(ulong luid, IPAddress destination, IPAddress nextHop)
    {
        var row = HostRoute(luid, destination, nextHop);
        var error = DeleteIpForwardEntry2(ref row);
        if (error != NotFound) Check(error, "remove a route to a VPN server");
    }

    private static ForwardRow HostRoute(ulong luid, IPAddress destination, IPAddress nextHop)
    {
        if (destination.AddressFamily != nextHop.AddressFamily) throw new ArgumentException("The next hop must be of the destination's family.", nameof(nextHop));
        var row = Route(luid, destination, destination.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
        row.NextHop = SockAddr.From(nextHop);
        return row;
    }

    /// <summary>Struct sizes the x64 IP Helper ABI requires; a mismatch would corrupt every call.</summary>
    public static bool LayoutMatches() => Marshal.SizeOf<SockAddr>() == 28 && Marshal.SizeOf<AddressPrefix>() == 32 && Marshal.SizeOf<ForwardRow>() == 104 &&
        Marshal.SizeOf<UnicastRow>() == 80 && Marshal.SizeOf<InterfaceRow>() == 168 && Marshal.SizeOf<DnsInterfaceSettings>() == 64 &&
        Marshal.OffsetOf<DnsInterfaceSettings>(nameof(DnsInterfaceSettings.NameServer)) == 24;

    private static ForwardRow Route(ulong luid, IPAddress network, int prefix)
    {
        var row = new ForwardRow(); InitializeIpForwardEntry(ref row);
        row.InterfaceLuid = luid;
        row.Destination = new() { Prefix = SockAddr.From(network), Length = (byte)prefix };
        // An unspecified next hop of the same family makes the route on-link through the tunnel.
        row.NextHop = SockAddr.From(network.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
        row.Metric = 0;
        return row;
    }

    private static void Check(uint error, string action)
    {
        if (error != 0) throw new Win32Exception(unchecked((int)error), "Could not " + action + ".");
    }

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    internal unsafe struct SockAddr
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(2)] public ushort Port;
        [FieldOffset(4)] public fixed byte V4[4];
        [FieldOffset(8)] public fixed byte V6[16];
        [FieldOffset(24)] public uint ScopeId;

        public static SockAddr From(IPAddress address)
        {
            var result = new SockAddr();
            var bytes = address.GetAddressBytes();
            if (bytes.Length == 4) { result.Family = Inet; for (var i = 0; i < 4; i++) result.V4[i] = bytes[i]; }
            else { result.Family = Inet6; for (var i = 0; i < 16; i++) result.V6[i] = bytes[i]; result.ScopeId = (uint)address.ScopeId; }
            return result;
        }

        public IPAddress ToAddress()
        {
            if (Family == Inet) { var bytes = new byte[4]; for (var i = 0; i < 4; i++) bytes[i] = V4[i]; return new(bytes); }
            var wide = new byte[16]; for (var i = 0; i < 16; i++) wide[i] = V6[i];
            return new(wide, ScopeId);
        }
    }

    [StructLayout(LayoutKind.Sequential)] internal struct AddressPrefix { public SockAddr Prefix; public byte Length; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ForwardRow
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public AddressPrefix Destination;
        public SockAddr NextHop;
        public byte SitePrefixLength;
        public uint ValidLifetime, PreferredLifetime, Metric;
        public int Protocol;
        public byte Loopback, AutoconfigureAddress, Publish, Immortal;
        public uint Age;
        public int Origin;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicastRow
    {
        public SockAddr Address;
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public int PrefixOrigin, SuffixOrigin;
        public uint ValidLifetime, PreferredLifetime;
        public byte OnLinkPrefixLength, SkipAsSource;
        public int DadState;
        public uint ScopeId;
        public long CreationTimeStamp;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct InterfaceRow
    {
        public ushort Family;
        public ulong InterfaceLuid;
        public uint InterfaceIndex, MaxReassemblySize;
        public ulong InterfaceIdentifier;
        public uint MinRouterAdvertisementInterval, MaxRouterAdvertisementInterval;
        public byte AdvertisingEnabled, ForwardingEnabled, WeakHostSend, WeakHostReceive, UseAutomaticMetric, UseNeighborUnreachabilityDetection,
            ManagedAddressConfigurationSupported, OtherStatefulConfigurationSupported, AdvertiseDefaultRoute;
        public int RouterDiscoveryBehavior;
        public uint DadTransmits, BaseReachableTime, RetransmitTime, PathMtuDiscoveryTimeout;
        public int LinkLocalAddressBehavior;
        public uint LinkLocalAddressTimeout;
        public fixed uint ZoneIndices[16];
        public uint SitePrefixLength, Metric, NlMtu;
        public byte Connected, SupportsWakeUpPatterns, SupportsNeighborDiscovery, SupportsRouterDiscovery;
        public uint ReachableTime;
        public byte TransmitOffload, ReceiveOffload, DisableDefaultRoutes;
    }

    /// <summary>DNS_INTERFACE_SETTINGS (version 1); only the fields named in Flags are applied.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct DnsInterfaceSettings
    {
        public uint Version;
        public ulong Flags;
        public IntPtr Domain, NameServer, SearchList;
        public uint RegistrationEnabled, RegisterAdapterName, EnableLlmnr, QueryAdapterName;
        public IntPtr ProfileNameServer;
    }

    [DllImport("iphlpapi.dll")] private static extern void InitializeIpForwardEntry(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint CreateIpForwardEntry2(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint DeleteIpForwardEntry2(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern void InitializeUnicastIpAddressEntry(ref UnicastRow row);
    [DllImport("iphlpapi.dll")] private static extern uint CreateUnicastIpAddressEntry(ref UnicastRow row);
    [DllImport("iphlpapi.dll")] private static extern uint DeleteUnicastIpAddressEntry(ref UnicastRow row);
    [DllImport("iphlpapi.dll")] private static extern void InitializeIpInterfaceEntry(ref InterfaceRow row);
    [DllImport("iphlpapi.dll")] private static extern uint GetIpInterfaceEntry(ref InterfaceRow row);
    [DllImport("iphlpapi.dll")] private static extern uint SetIpInterfaceEntry(ref InterfaceRow row);
    [DllImport("iphlpapi.dll")] private static extern uint GetBestRoute2(ref ulong luid, uint index, IntPtr source, ref SockAddr destination, uint options, out ForwardRow route, out SockAddr bestSource);
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceGuidToLuid(ref Guid id, out ulong luid);
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceLuidToGuid(ref ulong luid, out Guid id);
    [DllImport("iphlpapi.dll")] private static extern uint SetInterfaceDnsSettings(Guid interfaceId, ref DnsInterfaceSettings settings);
}
