using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Vpn;

public delegate bool PacketSink(ReadOnlySpan<byte> packet);

/// <summary>
/// An allowed flow's way out: the egress its socket is pinned to and, for redirected DNS, the server that answers in place
/// of the destination. A tunneled route shares sockets only with flows pinned to the same tunnel interface.
/// </summary>
public sealed record FlowRoute(Egress Egress, NetEndpoint? Target = null, bool Tunneled = false)
{
    /// <summary>A flow of Darkwire's own, such as its DNS proxy's: its DNS goes out as sent, never read, filtered or forwarded.</summary>
    public bool Own { get; init; }
}

/// <summary>
/// Chooses where each allowed flow leaves as its relay opens, and again for every datagram; null refuses the flow. A
/// tunnel's route never falls back to another interface. Calls may arrive while the router lock is held: implementations
/// must not call the router.
/// </summary>
public interface IFlowRoutes
{
    FlowRoute? Select(RouterFlow flow);
}

/// <summary>
/// The socket side of the tunnel router. An allowed TCP flow is dialed from its egress before its held SYN reaches the
/// local listener, then relayed; UDP flows share one socket per application endpoint; echo requests go through the IP
/// Helper API. Every socket is pinned to the interface its flow's route names, a physical one or a VPN tunnel's, so
/// relayed traffic never re-enters the router and a tunnel's flows never leave anywhere else. Router callbacks only queue
/// work here; nothing calls the router while its lock is held.
/// </summary>
public sealed class RouterRelay : IRouterHost, IAsyncDisposable
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15), AcceptTimeout = TimeSpan.FromSeconds(10), EchoTimeout = TimeSpan.FromSeconds(4);
    public const int MaximumEchoes = 32, MaximumLookups = 256;
    private readonly PacketSink inject;
    private readonly IFlowRoutes routes;
    private readonly Action<RouterFlow> evaluate;
    private readonly Action<RouterFlow>? closed;
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentDictionary<long, TcpRelay> tcp = new();
    private readonly ConcurrentDictionary<NetEndpoint, Association> udp = new();
    // A redirected flow has a socket of its own, so every reply maps back to the destination the application asked.
    private readonly ConcurrentDictionary<long, Association> redirected = new();
    private readonly SemaphoreSlim echoes = new(MaximumEchoes), lookups = new(MaximumLookups);
    private readonly List<Socket> listeners = [];
    private readonly List<Task> loops = [];
    private PacketRouter? router;
    private Func<string, bool>? blockedNames, loopbackNames;
    private IDnsForwarder? forwarder;

    /// <param name="routes">Each allowed flow's route; null refuses it.</param>
    /// <param name="evaluate">Receives each new flow; it must only queue work.</param>
    /// <param name="closed">Notified when the router forgets a flow; it must only update bookkeeping.</param>
    public RouterRelay(PacketSink inject, IFlowRoutes routes, Action<RouterFlow> evaluate, Action<RouterFlow>? closed = null)
    { this.inject = inject; this.routes = routes; this.evaluate = evaluate; this.closed = closed; }

    /// <summary>A listener on a tunnel address for translated connections; nothing else can reach it.</summary>
    public static Socket Listen(IPAddress address)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.ExclusiveAddressUse = true;
            if (address.AddressFamily == AddressFamily.InterNetworkV6) socket.DualMode = false;
            socket.Bind(new IPEndPoint(address, 0));
            socket.Listen(1024);
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    /// <summary>Takes ownership of the listeners and starts accepting translated connections.</summary>
    public void Attach(PacketRouter router, IEnumerable<Socket> owned)
    {
        if (Interlocked.CompareExchange(ref this.router, router, null) is not null) throw new InvalidOperationException("The relay already serves a router.");
        foreach (var listener in owned) { listeners.Add(listener); loops.Add(Task.Run(() => AcceptAsync(listener))); }
    }

    public int OpenConnections => tcp.Count;
    public int Associations => udp.Count + redirected.Count;

    /// <summary>
    /// Closes at once everything relayed through an interface that is going away, connections still ending by themselves
    /// included: Windows removes an interface only once nothing uses it, and a tunnel restarting needs its interface's name.
    /// </summary>
    public void Abandon(ulong luid)
    {
        foreach (var (id, relay) in tcp)
            if (relay.Route?.Egress.Luid == luid && tcp.TryRemove(new KeyValuePair<long, TcpRelay>(id, relay))) relay.Close(true);
        foreach (var (local, association) in udp)
            if (association.Through(luid) && udp.TryRemove(new KeyValuePair<NetEndpoint, Association>(local, association))) association.Dispose();
        foreach (var (id, association) in redirected)
            if (association.Through(luid) && redirected.TryRemove(new KeyValuePair<long, Association>(id, association))) association.Dispose();
    }

    /// <summary>
    /// Names whose plain DNS lookups the relay answers itself as nonexistent, over UDP and TCP; null relays every lookup
    /// unread. The test runs while the router lock is held, so it must be quick and must not call the router.
    /// </summary>
    public Func<string, bool>? BlockedNames { get => Volatile.Read(ref blockedNames); set => Volatile.Write(ref blockedNames, value); }

    /// <summary>Names the relay answers with the loopback address, over UDP and TCP; the same rules apply as for <see cref="BlockedNames"/>.</summary>
    public Func<string, bool>? LoopbackNames { get => Volatile.Read(ref loopbackNames); set => Volatile.Write(ref loopbackNames, value); }

    /// <summary>
    /// Answers lookups bound for the internet: every one sent to Darkwire's resolver, and plain DNS that leaves physically for
    /// any server. A tunnel's own DNS stays in its tunnel, and Darkwire's own flows are never read. Null sends lookups on.
    /// </summary>
    public IDnsForwarder? Forwarder { get => Volatile.Read(ref forwarder); set => Volatile.Write(ref forwarder, value); }

    void IRouterHost.Inject(ReadOnlySpan<byte> packet) => inject(packet);
    void IRouterHost.Evaluate(RouterFlow flow) => evaluate(flow);

    void IRouterHost.Connect(RouterFlow flow)
    {
        var relay = new TcpRelay(flow);
        if (tcp.TryAdd(flow.Id, relay)) _ = Task.Run(() => DialAsync(relay));
    }

    void IRouterHost.Send(RouterFlow flow, byte[] payload)
    {
        // Every datagram follows its flow's current route: a tunnel that went down carries nothing more.
        var route = routes.Select(flow);
        // Filtered and forwarded DNS is answered here, so nothing of a blocked lookup leaves.
        if (flow.Remote.Port == DnsAnswers.Port && route is not { Own: true } && Lookup(flow, payload, route)) return;
        if (route is null) return;
        if (route.Target is { } target && target != flow.Remote)
        {
            if (!redirected.TryGetValue(flow.Id, out var redirect) || !redirect.Carries(route))
            {
                if (Open(flow.Local, route, (target, flow.Remote)) is not { } created) return;
                var replaced = redirect;
                redirected[flow.Id] = redirect = created;
                if (replaced is not null) ThreadPool.QueueUserWorkItem(_ => replaced.Dispose());
            }
            redirect.Send(payload, target);
            return;
        }
        if (!udp.TryGetValue(flow.Local, out var association) || !association.Carries(route))
        {
            // The first datagram picks the association's egress. A flow routed into or out of a tunnel gets a new socket rather
            // than borrowing one pinned elsewhere; flows still on the old route are withdrawn by the router.
            if (Open(flow.Local, route) is not { } created) return;
            var replaced = association;
            udp[flow.Local] = association = created;
            if (replaced is not null) ThreadPool.QueueUserWorkItem(_ => replaced.Dispose());
        }
        association.Send(payload, flow.Remote);
    }

    /// <summary>
    /// Answers a datagram lookup here when filtering or forwarding applies: a blocked or loopback name at once, a name bound for
    /// the internet through the forwarder. False sends it along the flow's route. A local name sent to Darkwire's resolver
    /// with no route to a server for it fails here.
    /// </summary>
    private bool Lookup(RouterFlow flow, byte[] query, FlowRoute? route)
    {
        var forwarding = Forwarding(flow, route);
        var blocks = BlockedNames; var loopback = LoopbackNames;
        if (blocks is null && loopback is null && forwarding is null) return false;
        var answer = DnsAnswers.Filter(query, blocks, loopback);
        if (answer is null && forwarding is not null && DnsAnswers.QuestionName(query) is { } name && forwarding.Answers(name))
        {
            Forward(flow, query, forwarding);
            return true;
        }
        if (answer is null && route is null && forwarding is not null && RouterAddresses.IsResolver(flow.Remote)) answer = DnsAnswers.Failure(query);
        if (answer is null) return false;
        if (answer.Length > 0) ThreadPool.QueueUserWorkItem(_ => router!.DeliverDatagram(flow.Local, flow.Remote, answer));
        return true;
    }

    /// <summary>
    /// The forwarder for a flow's lookups: those sent to Darkwire's resolver, and plain DNS leaving physically. A tunnel's DNS
    /// stays in its tunnel, and a flow whose route is gone sends nothing anywhere else.
    /// </summary>
    private IDnsForwarder? Forwarding(RouterFlow flow, FlowRoute? route) => RouterAddresses.IsResolver(flow.Remote) || route is { Tunneled: false } ? Forwarder : null;

    private void Forward(RouterFlow flow, byte[] query, IDnsForwarder forwarding)
    {
        // Too many lookups in flight drop the next one, as a congested link would.
        if (!lookups.Wait(0)) return;
        var cancellation = stop.Token;
        _ = Task.Run(async () =>
        {
            try { router!.DeliverDatagram(flow.Local, flow.Remote, await forwarding.AskAsync(query, false, cancellation).ConfigureAwait(false)); }
            catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException) { }
            finally { lookups.Release(); }
        });
    }

    /// <summary>How a DNS stream's queries are answered here; null relays the stream unread.</summary>
    private Func<byte[], ValueTask<byte[]?>>? Answering(RouterFlow flow, FlowRoute? route)
    {
        var forwarding = Forwarding(flow, route);
        if (BlockedNames is null && LoopbackNames is null && forwarding is null) return null;
        var cancellation = stop.Token;
        return async query =>
        {
            // The names are read for each query, so a change reaches open streams too.
            if (DnsAnswers.Filter(query, BlockedNames, LoopbackNames) is { } answer) return answer;
            return forwarding is not null && DnsAnswers.QuestionName(query) is { } name && forwarding.Answers(name)
                ? await forwarding.AskAsync(query, true, cancellation).ConfigureAwait(false) : null;
        };
    }

    void IRouterHost.Echo(RouterFlow flow, ushort sequence, byte[] data)
    {
        if (!echoes.Wait(0)) return;
        _ = Task.Run(() =>
        {
            try
            {
                var destination = flow.Remote.Address.ToIPAddress();
                // The explicit source address selects the route's interface under the strong host model; a shared one would
                // select the interface holding it instead, so tunnels never route echoes from one.
                if (routes.Select(flow) is { Egress.Shared: false } route && IcmpEcho.Send(route.Egress.Source, destination, data, EchoTimeout) is { } reply)
                    router!.DeliverEcho(flow.Id, sequence, reply);
            }
            finally { echoes.Release(); }
        });
    }

    void IRouterHost.Closed(RouterFlow flow, bool abort)
    {
        closed?.Invoke(flow);
        if (redirected.TryRemove(flow.Id, out var redirect)) ThreadPool.QueueUserWorkItem(_ => redirect.Dispose());
        if (flow.Protocol != 6 || !tcp.TryRemove(flow.Id, out var relay)) return;
        // A connection ending by itself may still be delivering its last bytes; give it the router's linger to finish.
        if (abort || Volatile.Read(ref relay.Accepted) is null) ThreadPool.QueueUserWorkItem(_ => relay.Close(true));
        else relay.Expire(PacketRouter.Linger);
    }

    void IRouterHost.Released(NetEndpoint local)
    {
        if (udp.TryRemove(local, out var association)) ThreadPool.QueueUserWorkItem(_ => association.Dispose());
    }

    private async Task DialAsync(TcpRelay relay)
    {
        var flow = relay.Flow;
        try
        {
            var route = relay.Route = routes.Select(flow);
            // Darkwire's resolver answers a stream through the forwarder even with no server for local names.
            if (route is null && Forwarder is not null && RouterAddresses.IsResolver(flow.Remote))
            {
                relay.Answered = true;
                router!.Connected(flow.Id);
                _ = WatchAcceptAsync(relay);
                return;
            }
            // No route refuses the flow: a tunnel that is down has no fallback.
            if (route is null) { Fail(relay, RouterFailure.Unreachable); return; }
            var remote = (route.Target ?? flow.Remote).ToIPEndPoint();
            var socket = Pinned(route.Egress, SocketType.Stream, ProtocolType.Tcp);
            relay.Outbound = socket;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(relay.Lifetime.Token))
            {
                timeout.CancelAfter(ConnectTimeout);
                try { await socket.ConnectAsync(remote, timeout.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!relay.Lifetime.IsCancellationRequested) { Fail(relay, RouterFailure.TimedOut); return; }
            }
            socket.NoDelay = true;
            router!.Connected(flow.Id);
            _ = WatchAcceptAsync(relay);
        }
        catch (SocketException error)
        {
            Fail(relay, error.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => RouterFailure.Refused,
                SocketError.TimedOut => RouterFailure.TimedOut,
                _ => RouterFailure.Unreachable
            });
        }
        catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException) { relay.Close(true); }
    }

    private void Fail(TcpRelay relay, RouterFailure failure)
    {
        tcp.TryRemove(relay.Flow.Id, out _);
        relay.Close(true);
        router!.Failed(relay.Flow.Id, failure);
    }

    /// <summary>The translated SYN reaches the listener at once unless the application already gave up.</summary>
    private async Task WatchAcceptAsync(TcpRelay relay)
    {
        try { await Task.Delay(AcceptTimeout, relay.Lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }
        if (Volatile.Read(ref relay.Accepted) is not null || !tcp.TryRemove(relay.Flow.Id, out _)) return;
        relay.Close(true);
        router!.Release(relay.Flow.Id);
    }

    private async Task AcceptAsync(Socket listener)
    {
        while (!stop.IsCancellationRequested)
        {
            Socket accepted;
            try { accepted = await listener.AcceptAsync(stop.Token).ConfigureAwait(false); }
            catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException) { return; }
            catch (SocketException) { continue; }
            RouterFlow? flow = null;
            try { if (accepted.RemoteEndPoint is IPEndPoint remote) flow = router!.Accepting(NetEndpoint.From(remote)); }
            catch (ArgumentException) { }
            // Only connections the router translated, for a flow whose outbound side is up or answered here, are relayed.
            if (flow is null || !tcp.TryGetValue(flow.Id, out var relay) || relay.Outbound is null && !relay.Answered || Interlocked.CompareExchange(ref relay.Accepted, accepted, null) is not null)
            {
                Abort(accepted);
                continue;
            }
            accepted.NoDelay = true;
            _ = Task.Run(() => RunAsync(relay));
        }
    }

    private async Task RunAsync(TcpRelay relay)
    {
        try
        {
            var flow = relay.Flow;
            // A stream answered here has no server: what nothing answers locally fails.
            var answer = flow.Remote.Port != DnsAnswers.Port || relay.Route is { Own: true } ? null : Answering(flow, relay.Route) ?? (relay.Outbound is null ? DnsAnswers.Filtering(null, null) : null);
            if (answer is not null) await DnsAnswers.RelayTcpAsync(relay.Accepted!, relay.Outbound, answer, PacketRouter.TcpIdle, relay.Lifetime.Token).ConfigureAwait(false);
            else await ProxyTransport.RelayTcpAsync(relay.Accepted!, relay.Outbound!, PacketRouter.TcpIdle, relay.Lifetime.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        finally
        {
            relay.Close(relay.Lifetime.IsCancellationRequested);
            tcp.TryRemove(new KeyValuePair<long, TcpRelay>(relay.Flow.Id, relay));
            router!.Release(relay.Flow.Id);
        }
    }

    /// <param name="redirect">For a redirected flow: the server it is sent to and the destination its replies appear to come from.</param>
    private Association? Open(NetEndpoint local, FlowRoute route, (NetEndpoint Server, NetEndpoint Shown)? redirect = null)
    {
        Socket? socket = null;
        try
        {
            socket = Pinned(route.Egress, SocketType.Dgram, ProtocolType.Udp);
            // SIO_UDP_CONNRESET off: an ICMP port unreachable must not fail the next receive for every flow on this socket.
            socket.IOControl(unchecked((int)0x9800000C), new byte[4], null);
            socket.Blocking = false;
            return new(router!, local, socket, route, redirect, stop.Token);
        }
        catch (SocketException) { socket?.Dispose(); return null; }
    }

    /// <summary>A socket bound to the egress source and pinned to its interface with IP_UNICAST_IF.</summary>
    internal static Socket Pinned(Egress route, SocketType type, ProtocolType protocol)
    {
        var v4 = route.Source.AddressFamily == AddressFamily.InterNetwork;
        var socket = new Socket(route.Source.AddressFamily, type, protocol);
        try
        {
            // IP_UNICAST_IF: IPv4 takes the interface index in network byte order, IPv6 in host order.
            socket.SetSocketOption(v4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, (SocketOptionName)31, v4 ? IPAddress.HostToNetworkOrder((int)route.Index) : (int)route.Index);
            socket.Bind(new IPEndPoint(route.Source, 0));
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    private static void Abort(Socket socket)
    {
        try { socket.LingerState = new(true, 0); } catch (SocketException) { } catch (ObjectDisposedException) { }
        socket.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync().ConfigureAwait(false);
        foreach (var listener in listeners) listener.Dispose();
        foreach (var relay in tcp.Values) relay.Close(true);
        tcp.Clear();
        foreach (var association in udp.Values.Concat(redirected.Values)) association.Dispose();
        udp.Clear(); redirected.Clear();
        try { await Task.WhenAll(loops).ConfigureAwait(false); } catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException) { }
        stop.Dispose();
    }

    private sealed class TcpRelay(RouterFlow flow)
    {
        public RouterFlow Flow { get; } = flow;
        public CancellationTokenSource Lifetime { get; } = new();
        public FlowRoute? Route;
        public Socket? Outbound;
        public Socket? Accepted;
        /// <summary>A DNS stream the relay answers itself, with no server behind it.</summary>
        public volatile bool Answered;
        private int closed;

        public void Expire(TimeSpan grace)
        {
            try { Lifetime.CancelAfter(grace); } catch (ObjectDisposedException) { }
        }

        public void Close(bool abort)
        {
            if (Interlocked.Exchange(ref closed, 1) != 0) return;
            try { Lifetime.Cancel(); } catch (ObjectDisposedException) { }
            foreach (var socket in new[] { Volatile.Read(ref Accepted), Outbound })
            {
                if (socket is null) continue;
                if (abort) Abort(socket); else socket.Dispose();
            }
        }
    }

    private sealed class Association : IDisposable
    {
        private readonly Socket socket;
        private readonly FlowRoute route;
        private readonly CancellationTokenSource lifetime;

        public Association(PacketRouter router, NetEndpoint local, Socket socket, FlowRoute route, (NetEndpoint Server, NetEndpoint Shown)? redirect, CancellationToken stop)
        {
            this.socket = socket; this.route = route; lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
            _ = Task.Run(() => ReceiveAsync(router, local, redirect, lifetime.Token));
        }

        /// <summary>Physical flows share whichever interface the first one picked; a tunnel's flows need that tunnel's socket.</summary>
        public bool Carries(FlowRoute next) => next.Tunneled == route.Tunneled &&
            (!next.Tunneled || next.Egress.Index == route.Egress.Index && next.Egress.Source.Equals(route.Egress.Source));

        public bool Through(ulong luid) => route.Egress.Luid == luid;

        public void Send(byte[] payload, NetEndpoint remote)
        {
            // Non-blocking: a full send buffer drops the datagram, as a congested link would.
            try { socket.SendTo(payload, SocketFlags.None, remote.ToIPEndPoint()); }
            catch (Exception error) when (error is SocketException or ObjectDisposedException) { }
        }

        private async Task ReceiveAsync(PacketRouter router, NetEndpoint local, (NetEndpoint Server, NetEndpoint Shown)? redirect, CancellationToken cancellation)
        {
            var buffer = new byte[65_536];
            EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            while (!cancellation.IsCancellationRequested)
            {
                SocketReceiveFromResult result;
                try { result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellation).ConfigureAwait(false); }
                catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException) { return; }
                catch (SocketException) { continue; }
                if (result.RemoteEndPoint is not IPEndPoint from) continue;
                NetEndpoint remote;
                try { remote = NetEndpoint.From(from); } catch (ArgumentException) { continue; }
                if (redirect is { } answered)
                {
                    // Only the server the query went to may answer it, and the answer comes from the destination the application asked.
                    if (remote != answered.Server) continue;
                    remote = answered.Shown;
                }
                router.DeliverDatagram(local, remote, buffer.AsSpan(0, result.ReceivedBytes));
            }
        }

        public void Dispose()
        {
            try { lifetime.Cancel(); } catch (ObjectDisposedException) { }
            socket.Dispose(); lifetime.Dispose();
        }
    }
}
