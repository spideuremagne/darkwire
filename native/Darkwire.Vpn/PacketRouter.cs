namespace Darkwire.Vpn;

public enum RouterFlowState : byte { Pending, Connecting, Open, Blocked, Closing }
public enum RouterFailure : byte { Refused, Unreachable, TimedOut }

/// <summary>One routed conversation. Public members never change; the router owns everything else.</summary>
public sealed class RouterFlow
{
    internal RouterFlow(long id, byte protocol, NetEndpoint local, NetEndpoint remote, DateTimeOffset created)
    { Id = id; Protocol = protocol; Local = local; Remote = remote; Created = created; Changed = created; LastActive = created; }
    public long Id { get; }
    /// <summary>6 (TCP), 17 (UDP), 1 (ICMP) or 58 (ICMPv6). An ICMP flow's local port is its echo identifier.</summary>
    public byte Protocol { get; }
    /// <summary>The application's endpoint as it appears on the tunnel interface.</summary>
    public NetEndpoint Local { get; }
    /// <summary>The destination the application asked for.</summary>
    public NetEndpoint Remote { get; }
    public DateTimeOffset Created { get; }
    internal RouterFlowState State;
    internal DateTimeOffset Changed, LastActive;
    internal byte[]? Held;
    internal ushort HeldSequence;
    internal Queue<byte[]>? Queued;
    internal int QueuedBytes;
    internal NetEndpoint Fake;
    internal bool LocalFin, RemoteFin;
}

public sealed record RouterFlowInfo(long Id, byte Protocol, NetEndpoint Local, NetEndpoint Remote, RouterFlowState State, DateTimeOffset Created);
public sealed record RouterStatistics(long Malformed, long Unsupported, long Refused, long Stray, long Overflow, long Blocked, long Unsolicited);

/// <summary>
/// Side effects the router requests. Every call arrives while the router lock is held: implementations must
/// queue work and return, never call the router synchronously, and copy spans before returning.
/// </summary>
public interface IRouterHost
{
    /// <summary>Writes a packet into the tunnel, toward the host stack.</summary>
    void Inject(ReadOnlySpan<byte> packet);
    /// <summary>A new flow is held; answer with <see cref="PacketRouter.Decide"/>.</summary>
    void Evaluate(RouterFlow flow);
    /// <summary>An allowed TCP flow needs its outbound connection; answer with Connected or Failed.</summary>
    void Connect(RouterFlow flow);
    /// <summary>A datagram on an allowed UDP flow. Flows sharing a local endpoint share one outbound socket.</summary>
    void Send(RouterFlow flow, byte[] payload);
    /// <summary>An echo request on an allowed ICMP flow; answer with <see cref="PacketRouter.DeliverEcho"/>.</summary>
    void Echo(RouterFlow flow, ushort sequence, byte[] data);
    /// <summary>
    /// The flow stopped carrying traffic; called exactly once per flow. With abort, tear its relay down now (revocation,
    /// expiry); otherwise the connection is ending by itself and its relay may finish delivering what it holds.
    /// </summary>
    void Closed(RouterFlow flow, bool abort);
    /// <summary>No UDP flow remains for this local endpoint: close its outbound socket.</summary>
    void Released(NetEndpoint local);
}

/// <summary>Tunnel addressing. Fake pools are a /16 (IPv4) and a /96 (IPv6) inside the tunnel networks.</summary>
public sealed record RouterAddresses(NetAddress Network4, int Prefix4, NetAddress Network6, int Prefix6,
    NetAddress Pool4, NetAddress Pool6, NetEndpoint Listener4, NetEndpoint Listener6, int Mtu)
{
    public static readonly NetAddress Tunnel4 = NetAddress.Parse("198.18.0.1"), Tunnel6 = NetAddress.Parse("fd5a:9c33:21e7::1");
    /// <summary>
    /// The DNS server Darkwire's adapter names for the Windows DNS client while a default VPN profile is in use. Nothing
    /// listens there: the router sends DNS addressed to it to a profile's resolver through that profile's tunnel.
    /// </summary>
    public static readonly NetAddress Resolver4 = NetAddress.Parse("198.18.0.2"), Resolver6 = NetAddress.Parse("fd5a:9c33:21e7::2");

    /// <summary>DNS addressed to Darkwire's resolver: the one destination inside the tunnel networks that the router relays.</summary>
    public static bool IsResolver(NetEndpoint destination) =>
        destination.Port == DnsAnswers.Port && destination.Address == (destination.Address.V6 ? Resolver6 : Resolver4);

    /// <summary>198.18.0.0/15 (RFC 2544 benchmarking space) and a fixed ULA /64; listeners bind the tunnel addresses.</summary>
    public static RouterAddresses Default(ushort port4, ushort port6, int mtu) => new(
        NetAddress.Parse("198.18.0.0"), 15, NetAddress.Parse("fd5a:9c33:21e7::"), 64,
        NetAddress.Parse("198.19.0.0"), NetAddress.Parse("fd5a:9c33:21e7::1:0:0"), new(Tunnel4, port4), new(Tunnel6, port6), mtu);

    public void Validate()
    {
        var families = !Network4.V6 && Network6.V6 && !Pool4.V6 && Pool6.V6 && !Listener4.Address.V6 && Listener6.Address.V6;
        var networks = families && Prefix4 is >= 8 and <= 16 && Prefix6 is >= 32 and <= 96 &&
            (uint)Network4.Value % (1u << (32 - Prefix4)) == 0 && Network6.Value % ((UInt128)1 << (128 - Prefix6)) == UInt128.Zero;
        // Pools are whole /16 and /96 blocks inside the networks; listeners sit outside them.
        var pools = networks && Pool4.Within(Network4, Prefix4) && Pool6.Within(Network6, Prefix6) &&
            (uint)Pool4.Value % 0x10000 == 0 && (ulong)Pool6.Value % 0x1_0000_0000 == 0;
        var listeners = pools && Listener4.Address.Within(Network4, Prefix4) && Listener6.Address.Within(Network6, Prefix6) &&
            !Listener4.Address.Within(Pool4, 16) && !Listener6.Address.Within(Pool6, 96) && Listener4.Port != 0 && Listener6.Port != 0;
        // The resolver address is in the networks but neither in a pool nor the adapter's own address, so its DNS reaches the router.
        var resolvers = listeners && Resolver4.Within(Network4, Prefix4) && Resolver6.Within(Network6, Prefix6) && !Resolver4.Within(Pool4, 16) &&
            !Resolver6.Within(Pool6, 96) && Resolver4 != Listener4.Address && Resolver6 != Listener6.Address;
        if (!resolvers || Mtu is < 1280 or > 0xFFFF) throw new InvalidDataException("Invalid tunnel router addressing.");
    }
}

/// <summary>
/// User-mode router for packets captured from a TUN adapter. Nothing leaves without a decision: new flows are
/// held (TCP SYNs, queued datagrams, echo requests) until <see cref="Decide"/>. Allowed TCP is translated to a local
/// listener that the host's own stack terminates; the SYN reaches it only after the outbound connection succeeded,
/// so applications see real refusals. UDP and ICMP echo terminate here and are relayed by the host.
/// </summary>
public sealed class PacketRouter
{
    public const int MaximumFlows = 65_536, MaximumPending = 4_096, MaximumAssociations = 16_384, MaximumAssociationFlows = 4_096;
    public const int MaximumQueuedDatagrams = 8, MaximumQueuedBytes = 4 * 1024 * 1024;
    public static readonly TimeSpan DecisionTimeout = TimeSpan.FromSeconds(60), ConnectTimeout = TimeSpan.FromSeconds(30),
        TcpIdle = TimeSpan.FromMinutes(124), Linger = TimeSpan.FromSeconds(30), UdpIdle = TimeSpan.FromMinutes(5), IcmpIdle = TimeSpan.FromSeconds(60);
    private const int FakePorts = 64_512, FakeAddresses = 65_534;
    private readonly object gate = new();
    private readonly IRouterHost host;
    private readonly RouterAddresses addresses;
    private readonly TimeProvider clock;
    private readonly FragmentReassembler fragments = new();
    private readonly Dictionary<long, RouterFlow> flows = [];
    private readonly Dictionary<FlowKey, RouterFlow> tuples = [];
    private readonly Dictionary<NetEndpoint, RouterFlow> fakes = [];
    private readonly Dictionary<NetEndpoint, Association> associations = [];
    private readonly List<RouterFlow> expired = [];
    private long nextFlow, malformed, unsupported, refused, stray, overflow, blocked, unsolicited;
    private ulong nextFake;
    private uint nextFragment;
    private ushort nextIdentification;
    private int pending, queuedBytes;

    public PacketRouter(IRouterHost host, RouterAddresses addresses, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(host); ArgumentNullException.ThrowIfNull(addresses);
        addresses.Validate();
        this.host = host; this.addresses = addresses; this.clock = clock ?? TimeProvider.System;
    }

    public RouterStatistics Statistics { get { lock (gate) return new(malformed, unsupported, refused, stray, overflow, blocked, unsolicited); } }

    public IReadOnlyList<RouterFlowInfo> Flows()
    {
        lock (gate) return flows.Values.Select(f => new RouterFlowInfo(f.Id, f.Protocol, f.Local, f.Remote, f.State, f.Created)).ToArray();
    }

    /// <summary>The open TCP flow a listener connection came from, by its fake remote endpoint.</summary>
    public RouterFlow? Accepting(NetEndpoint remote)
    {
        Enter();
        lock (gate) return fakes.TryGetValue(remote, out var flow) && flow.State == RouterFlowState.Open ? flow : null;
    }

    /// <summary>Routes one packet read from the tunnel; it may be rewritten in place and injected back.</summary>
    public void Process(Span<byte> packet)
    {
        Enter();
        lock (gate)
        {
            var now = clock.GetUtcNow();
            if (!IpPacket.TryParse(packet, out var header)) { malformed++; return; }
            if (!header.IsFragment) { Route(packet[..header.Length], header, now); return; }
            var whole = fragments.Add(packet, header, now);
            if (whole is null) return;
            if (!IpPacket.TryParse(whole, out header) || header.IsFragment) { malformed++; return; }
            Route(whole, header, now);
        }
    }

    public void Decide(long id, bool allow)
    {
        Enter();
        lock (gate)
        {
            if (!flows.TryGetValue(id, out var flow) || flow.State != RouterFlowState.Pending) return;
            var now = clock.GetUtcNow();
            if (flow.Protocol == 6)
            {
                if (!allow) { ResetHeld(flow); Remove(flow); return; }
                Move(flow, RouterFlowState.Connecting, now);
                host.Connect(flow);
                return;
            }
            Move(flow, allow ? RouterFlowState.Open : RouterFlowState.Blocked, now);
            flow.LastActive = now;
            if (flow.Protocol == 17)
            {
                var queued = flow.Queued; flow.Queued = null; queuedBytes -= flow.QueuedBytes; flow.QueuedBytes = 0;
                if (!allow || queued is null) return;
                associations[flow.Local].Used = true;
                foreach (var payload in queued) host.Send(flow, payload);
                return;
            }
            var held = flow.Held; flow.Held = null;
            if (allow && held is not null) host.Echo(flow, flow.HeldSequence, held);
        }
    }

    /// <summary>The outbound connection for an allowed TCP flow is up: release the held SYN to the listener.</summary>
    public void Connected(long id)
    {
        Enter();
        lock (gate)
        {
            if (!flows.TryGetValue(id, out var flow) || flow.State != RouterFlowState.Connecting || flow.Held is not { } syn) return;
            var now = clock.GetUtcNow();
            if (AllocateFake(flow.Local.Address.V6) is not { } fake) { overflow++; ResetHeld(flow); Remove(flow); return; }
            flow.Fake = fake; fakes.Add(fake, flow); flow.Held = null;
            Move(flow, RouterFlowState.Open, now); flow.LastActive = now;
            IpPacket.TryParse(syn, out var header);
            PacketBuilder.Rewrite(syn, header, fake, Listener(fake.Address.V6));
            host.Inject(syn);
        }
    }

    public void Failed(long id, RouterFailure failure)
    {
        Enter();
        lock (gate)
        {
            if (!flows.TryGetValue(id, out var flow) || flow.State != RouterFlowState.Connecting) return;
            if (failure == RouterFailure.Refused) ResetHeld(flow);
            else if (failure == RouterFailure.Unreachable && flow.Held is { } syn && IpPacket.TryParse(syn, out var header))
                InjectBuilt(PacketBuilder.Unreachable(header.Destination, syn, header, UnreachableCode.Host));
            Remove(flow);
        }
    }

    /// <summary>The relay for an open TCP flow ended; translation lingers so final segments still arrive.</summary>
    public void Release(long id)
    {
        Enter();
        lock (gate)
            if (flows.TryGetValue(id, out var flow) && flow.Protocol == 6 && flow.State == RouterFlowState.Open) Close(flow, clock.GetUtcNow(), false);
    }

    /// <summary>Withdraws a decision after a policy change. Blocked and open datagram flows are forgotten and re-evaluated on their next packet.</summary>
    public void Revoke(long id)
    {
        Enter();
        lock (gate)
        {
            if (!flows.TryGetValue(id, out var flow) || flow.State == RouterFlowState.Closing) return;
            if (flow.Protocol == 6 && flow.State == RouterFlowState.Open) { Close(flow, clock.GetUtcNow(), true); return; }
            if (flow.Protocol == 6) ResetHeld(flow);
            Remove(flow);
        }
    }

    /// <summary>A datagram from <paramref name="remote"/> reached the socket serving <paramref name="local"/>.</summary>
    public void DeliverDatagram(NetEndpoint local, NetEndpoint remote, ReadOnlySpan<byte> payload)
    {
        Enter();
        lock (gate)
        {
            // Address- and port-dependent filtering: only destinations the application reached may answer.
            if (!associations.TryGetValue(local, out var association) || !association.Flows.TryGetValue(remote, out var flow) ||
                flow.State != RouterFlowState.Open || remote.Address.V6 != local.Address.V6 || payload.Length > (local.Address.V6 ? 0xFFFF - 8 : 0xFFFF - 28))
            { unsolicited++; return; }
            flow.LastActive = association.LastActive = clock.GetUtcNow();
            InjectBuilt(PacketBuilder.Udp(remote, local, payload, ++nextIdentification));
        }
    }

    public void DeliverEcho(long id, ushort sequence, ReadOnlySpan<byte> data)
    {
        Enter();
        lock (gate)
        {
            if (!flows.TryGetValue(id, out var flow) || flow.Protocol is not (1 or 58) || flow.State != RouterFlowState.Open ||
                data.Length > (flow.Local.Address.V6 ? 0xFFFF - 8 : 0xFFFF - 28)) { unsolicited++; return; }
            flow.LastActive = clock.GetUtcNow();
            InjectBuilt(PacketBuilder.Echo(flow.Remote.Address, flow.Local.Address, true, flow.Local.Port, sequence, data, ++nextIdentification));
        }
    }

    /// <summary>Expires undecided, idle and lingering flows and stale fragments; call about once a second.</summary>
    public void Sweep()
    {
        Enter();
        lock (gate)
        {
            var now = clock.GetUtcNow();
            fragments.Expire(now);
            expired.Clear();
            foreach (var flow in flows.Values)
            {
                var due = flow.State switch
                {
                    RouterFlowState.Pending => now - flow.Changed >= DecisionTimeout,
                    RouterFlowState.Connecting => now - flow.Changed >= ConnectTimeout,
                    RouterFlowState.Closing => now - flow.Changed >= Linger,
                    _ when flow.Protocol == 6 => now - flow.LastActive >= TcpIdle,
                    _ when flow.Protocol == 17 => now - associations[flow.Local].LastActive >= UdpIdle,
                    _ => now - flow.LastActive >= IcmpIdle
                };
                if (due) expired.Add(flow);
            }
            foreach (var flow in expired)
                if (flow.Protocol == 6 && flow.State == RouterFlowState.Open) Close(flow, now, true); else Remove(flow);
            expired.Clear();
        }
    }

    private void Route(Span<byte> packet, in IpPacket header, DateTimeOffset now)
    {
        switch (header.Protocol)
        {
            case 6: RouteTcp(packet, header, now); return;
            case 17: RouteUdp(packet, header, now); return;
            case 1 when !header.V6:
            case 58 when header.V6: RouteEcho(packet, header, now); return;
            // Other protocols have no relay; they stop here rather than leave unexamined.
            default: unsupported++; return;
        }
    }

    private void RouteTcp(Span<byte> packet, in IpPacket header, DateTimeOffset now)
    {
        var listener = Listener(header.V6);
        var source = new NetEndpoint(header.Source, header.SourcePort);
        var destination = new NetEndpoint(header.Destination, header.DestinationPort);
        if (source == listener)
        {
            if (!fakes.TryGetValue(destination, out var reply)) { stray++; return; }
            Observe(reply, header.TcpFlags, false, now);
            PacketBuilder.Rewrite(packet, header, reply.Remote, reply.Local);
            host.Inject(packet);
            return;
        }
        if (!InTunnel(header.Source)) { refused++; return; }
        if (!Relayed(destination) || header.SourcePort == 0 || header.DestinationPort == 0) { refused++; Reset(header); return; }
        var opening = (header.TcpFlags & (IpPacket.Syn | IpPacket.Ack | IpPacket.Rst | IpPacket.Fin)) == IpPacket.Syn;
        var key = new FlowKey(6, source, destination);
        if (tuples.TryGetValue(key, out var flow))
        {
            // A fresh SYN on a lingering tuple is a new connection; the old translation has nothing left to carry.
            if (flow.State == RouterFlowState.Closing && opening) Remove(flow);
            else if (flow.State is RouterFlowState.Pending or RouterFlowState.Connecting)
            {
                // Retransmitted SYNs refresh the held copy; nothing passes before the decision.
                if (opening) flow.Held = packet.ToArray();
                return;
            }
            else
            {
                Observe(flow, header.TcpFlags, true, now);
                PacketBuilder.Rewrite(packet, header, flow.Fake, listener);
                host.Inject(packet);
                return;
            }
        }
        if (!opening) { stray++; Reset(header); return; }
        if (Create(6, source, destination, now) is not { } created) return;
        created.Held = packet.ToArray();
        tuples.Add(key, created);
        host.Evaluate(created);
    }

    private void RouteUdp(Span<byte> packet, in IpPacket header, DateTimeOffset now)
    {
        var local = new NetEndpoint(header.Source, header.SourcePort);
        var remote = new NetEndpoint(header.Destination, header.DestinationPort);
        if (!InTunnel(header.Source) || !Relayed(remote) || header.SourcePort == 0 || header.DestinationPort == 0) { refused++; return; }
        var payload = packet.Slice(header.PayloadOffset, header.PayloadLength);
        if (!associations.TryGetValue(local, out var association))
        {
            if (associations.Count >= MaximumAssociations) { overflow++; return; }
            association = new();
            associations.Add(local, association);
        }
        association.LastActive = now;
        if (!association.Flows.TryGetValue(remote, out var flow))
        {
            if (association.Flows.Count >= MaximumAssociationFlows || Create(17, local, remote, now) is not { } created)
            {
                if (association.Flows.Count >= MaximumAssociationFlows) overflow++;
                if (association.Flows.Count == 0) associations.Remove(local);
                return;
            }
            association.Flows.Add(remote, created);
            Enqueue(created, payload);
            host.Evaluate(created);
            return;
        }
        flow.LastActive = now;
        switch (flow.State)
        {
            case RouterFlowState.Pending: Enqueue(flow, payload); return;
            case RouterFlowState.Open: association.Used = true; host.Send(flow, payload.ToArray()); return;
            default: blocked++; return;
        }
    }

    private void RouteEcho(Span<byte> packet, in IpPacket header, DateTimeOffset now)
    {
        // Only echo requests leave the host; errors, discovery and multicast listener traffic stay local.
        if (header.IcmpType != (header.V6 ? 128 : 8) || header.IcmpCode != 0) { unsupported++; return; }
        if (!InTunnel(header.Source) || !Routable(header.Destination)) { refused++; return; }
        var local = new NetEndpoint(header.Source, header.IcmpIdentifier);
        var key = new FlowKey(header.Protocol, local, new(header.Destination, 0));
        var data = packet.Slice(header.PayloadOffset, header.PayloadLength);
        if (!tuples.TryGetValue(key, out var flow))
        {
            if (Create(header.Protocol, local, key.Remote, now) is not { } created) return;
            created.Held = data.ToArray(); created.HeldSequence = header.IcmpSequence;
            tuples.Add(key, created);
            host.Evaluate(created);
            return;
        }
        flow.LastActive = now;
        switch (flow.State)
        {
            case RouterFlowState.Pending: flow.Held = data.ToArray(); flow.HeldSequence = header.IcmpSequence; return;
            case RouterFlowState.Open: host.Echo(flow, header.IcmpSequence, data.ToArray()); return;
            default: blocked++; return;
        }
    }

    private void Observe(RouterFlow flow, byte flags, bool local, DateTimeOffset now)
    {
        flow.LastActive = now;
        if (flow.State != RouterFlowState.Open) return;
        if ((flags & IpPacket.Rst) != 0) { Close(flow, now, false); return; }
        if ((flags & IpPacket.Fin) == 0) return;
        if (local) flow.LocalFin = true; else flow.RemoteFin = true;
        if (flow.LocalFin && flow.RemoteFin) Close(flow, now, false);
    }

    private RouterFlow? Create(byte protocol, NetEndpoint local, NetEndpoint remote, DateTimeOffset now)
    {
        if (flows.Count >= MaximumFlows || pending >= MaximumPending) { overflow++; return null; }
        var flow = new RouterFlow(++nextFlow, protocol, local, remote, now) { State = RouterFlowState.Pending };
        flows.Add(flow.Id, flow); pending++;
        return flow;
    }

    private void Enqueue(RouterFlow flow, ReadOnlySpan<byte> payload)
    {
        flow.Queued ??= new();
        if (flow.Queued.Count >= MaximumQueuedDatagrams || queuedBytes + payload.Length > MaximumQueuedBytes) { overflow++; return; }
        flow.Queued.Enqueue(payload.ToArray());
        flow.QueuedBytes += payload.Length; queuedBytes += payload.Length;
    }

    private void Move(RouterFlow flow, RouterFlowState state, DateTimeOffset now)
    {
        if (flow.State == RouterFlowState.Pending) pending--;
        if (state == RouterFlowState.Pending) pending++;
        flow.State = state; flow.Changed = now;
    }

    /// <summary>Stops an open TCP flow; translation lingers so the final segments, including the relay's own reset, still arrive.</summary>
    private void Close(RouterFlow flow, DateTimeOffset now, bool abort)
    {
        Move(flow, RouterFlowState.Closing, now);
        host.Closed(flow, abort);
    }

    private void Remove(RouterFlow flow)
    {
        if (!flows.Remove(flow.Id)) return;
        var state = flow.State;
        Move(flow, RouterFlowState.Closing, flow.Changed);
        queuedBytes -= flow.QueuedBytes; flow.Queued = null; flow.QueuedBytes = 0; flow.Held = null;
        if (flow.Fake != default && fakes.TryGetValue(flow.Fake, out var translated) && ReferenceEquals(translated, flow)) fakes.Remove(flow.Fake);
        if (flow.Protocol == 17)
        {
            var association = associations[flow.Local];
            association.Flows.Remove(flow.Remote);
            if (association.Flows.Count == 0)
            {
                associations.Remove(flow.Local);
                if (association.Used) host.Released(flow.Local);
            }
        }
        else
        {
            var key = new FlowKey(flow.Protocol, flow.Local, flow.Remote);
            if (tuples.TryGetValue(key, out var mapped) && ReferenceEquals(mapped, flow)) tuples.Remove(key);
        }
        if (state != RouterFlowState.Closing) host.Closed(flow, true);
    }

    private void ResetHeld(RouterFlow flow)
    {
        if (flow.Held is { } syn && IpPacket.TryParse(syn, out var header)) Reset(header);
    }

    private void Reset(in IpPacket header)
    {
        if (PacketBuilder.Reset(header) is { } reset) host.Inject(reset);
    }

    private void InjectBuilt(byte[] packet)
    {
        if (packet.Length <= addresses.Mtu) { host.Inject(packet); return; }
        foreach (var fragment in PacketBuilder.Fragment(packet, addresses.Mtu, ++nextFragment)) host.Inject(fragment);
    }

    private NetEndpoint? AllocateFake(bool v6)
    {
        var pool = v6 ? addresses.Pool6 : addresses.Pool4;
        // Slots advance monotonically, so a translation is not reused until the pool wraps, long after TIME_WAIT.
        for (var attempt = 0; attempt <= MaximumFlows; attempt++)
        {
            var slot = nextFake++;
            var candidate = new NetEndpoint(new(pool.Value + (ulong)(1 + slot / FakePorts % FakeAddresses), v6), (ushort)(1024 + slot % FakePorts));
            if (!fakes.ContainsKey(candidate)) return candidate;
        }
        return null;
    }

    private NetEndpoint Listener(bool v6) => v6 ? addresses.Listener6 : addresses.Listener4;
    private bool InTunnel(NetAddress address) => address.V6 ? address.Within(addresses.Network6, addresses.Prefix6) : address.Within(addresses.Network4, addresses.Prefix4);
    private bool Routable(NetAddress address) => address.IsRoutableUnicast && !InTunnel(address);
    // DNS to Darkwire's resolver address is the one destination inside the tunnel networks; decisions send it to a profile's resolver.
    private bool Relayed(NetEndpoint destination) => Routable(destination.Address) || RouterAddresses.IsResolver(destination);

    private void Enter()
    {
        if (Monitor.IsEntered(gate)) throw new InvalidOperationException("Router host callbacks must not call the router.");
    }

    private readonly record struct FlowKey(byte Protocol, NetEndpoint Local, NetEndpoint Remote);
    private sealed class Association
    {
        public Dictionary<NetEndpoint, RouterFlow> Flows { get; } = [];
        public DateTimeOffset LastActive;
        public bool Used;
    }
}
