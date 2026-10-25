using Darkwire.Vpn;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

/// <summary>Per-flow egress: tunnel selection, DNS redirection, configuration metadata and the relay's refusal without a route.</summary>
internal static class VpnRouteChecks
{
    private static readonly NetEndpoint App4 = new(RouterAddresses.Tunnel4, 50_000), Remote4 = new(NetAddress.Parse("203.0.113.8"), 443);
    private static readonly IPAddress Source4 = IPAddress.Parse("10.64.0.2"), Source6 = IPAddress.Parse("fd00:64::2");

    public static void Run(Action<string, Action> check, bool native)
    {
        static void Expect(bool value, string message = "VPN route invariant failed.") { if (!value) throw new Exception(message); }
        static void Reject(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Expected rejection."); }
        static TunnelEgress Tunnel(string[] networks, string[] resolvers, params IPAddress[] sources) =>
            new(900, 9, sources.Length == 0 ? [Source4] : sources, networks.Select(NetPrefix.Parse), resolvers.Select(IPAddress.Parse));
        var key = Convert.ToBase64String(Enumerable.Repeat((byte)0x41, 32).ToArray());
        var wg = $"[Interface]\nPrivateKey = {key}\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\n[Peer]\nPublicKey = {key}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 10.0.0.0/8, 192.168.50.0/24\n" +
            $"[Peer]\nPublicKey = {key}\nEndpoint = [2001:db8::7]:51821\nAllowedIPs = 10.0.0.0/8, fd00::/8\n";

        check("Network prefixes contain their own family and ignore host bits", () =>
        {
            var prefix = NetPrefix.Parse("10.1.2.3/8");
            Expect(prefix.Contains(NetAddress.Parse("10.200.0.1")) && !prefix.Contains(NetAddress.Parse("11.0.0.1")) && !prefix.Contains(NetAddress.Parse("::a01:203")));
            Expect(NetPrefix.Parse("::/0").Contains(NetAddress.Parse("2001:db8::1")) && !NetPrefix.Parse("::/0").Contains(NetAddress.Parse("1.2.3.4")));
            Expect(NetPrefix.Parse("192.0.2.1").Length == 32);
            foreach (var bad in new[] { "10.0.0.0/33", "::/129", "10.0.0.0/-1", "10.0.0.0/8/8", "host/8" })
                try { NetPrefix.Parse(bad); throw new Exception("Accepted " + bad); } catch (FormatException) { }
        });
        check("WireGuard carries its peers' AllowedIPs", () =>
        {
            var parsed = VpnConfiguration.Parse("WireGuard", wg);
            Expect(parsed.Networks.Select(n => n.ToString()).SequenceEqual(["10.0.0.0/8", "192.168.50.0/24", "fd00::/8"]));
        });
        check("Endpoint summaries split into hosts and ports, IPv6 literals included", () =>
        {
            var endpoints = VpnConfiguration.Endpoints(VpnConfiguration.Parse("WireGuard", wg).Endpoint);
            Expect(endpoints.SequenceEqual([("198.51.100.7", (ushort)51820), ("2001:db8::7", (ushort)51821)]));
            Expect(VpnConfiguration.Endpoints("vpn.example.com:51820, 198.51.100.9:443").SequenceEqual([("vpn.example.com", (ushort)51820), ("198.51.100.9", (ushort)443)]));
            foreach (var bad in new[] { "", "host", "host:0", "2001:db8::7:51820", "host:51820,other:1", "bad host:1" }) Reject(() => VpnConfiguration.Endpoints(bad));
        });
        check("A tunnel egress carries only its own families and networks, pinned to its interface", () =>
        {
            var tunnel = Tunnel(["10.0.0.0/8", "0.0.0.0/0"], []);
            var egress = tunnel.Select(IPAddress.Parse("203.0.113.8"));
            Expect(egress is { Luid: 900, Index: 9 } && egress.Source.Equals(Source4));
            Expect(tunnel.Select(IPAddress.Parse("2001:db8::8")) is null);
            foreach (var unroutable in new[] { "224.0.0.251", "255.255.255.255", "127.0.0.1", "0.0.0.0" }) Expect(tunnel.Select(IPAddress.Parse(unroutable)) is null, unroutable);
            var split = Tunnel(["10.0.0.0/8"], []);
            Expect(split.Select(IPAddress.Parse("10.20.30.40")) is not null && split.Select(IPAddress.Parse("203.0.113.8")) is null);
            var dual = Tunnel(["0.0.0.0/0", "::/0"], [], Source4, Source6);
            Expect(dual.Select(IPAddress.Parse("2001:db8::8"))?.Source.Equals(Source6) == true);
        });
        check("A tunnel egress marks the sources another tunnel's interface holds, and refuses echo requests from them", () =>
        {
            var tunnel = new TunnelEgress(900, 9, [Source4, Source6], [NetPrefix.Parse("0.0.0.0/0"), NetPrefix.Parse("::/0")], [], [Source4, IPAddress.Parse("10.99.0.2")]);
            Expect(tunnel.Shared.SequenceEqual([Source4]));
            Expect(tunnel.Route(6, Remote4) is { Tunneled: true, Egress.Shared: true } && tunnel.Route(17, Remote4) is { Egress.Shared: true });
            // Windows sends an echo from its source address's interface, which would be the other tunnel's.
            Expect(tunnel.Route(1, Remote4) is null);
            Expect(tunnel.Route(58, new(NetAddress.Parse("2001:db8::8"), 0)) is { Tunneled: true, Egress.Shared: false });
            Expect(Tunnel(["0.0.0.0/0"], []).Route(1, Remote4) is { Tunneled: true, Egress.Shared: false });
        });
        check("A closed tunnel carries nothing, even routes chosen before it closed", () =>
        {
            var tunnel = Tunnel(["0.0.0.0/0"], ["10.64.0.1"]);
            Expect(tunnel.Route(6, Remote4) is { Tunneled: true });
            tunnel.Close();
            Expect(tunnel.Closed && tunnel.Select(IPAddress.Parse("203.0.113.8")) is null && tunnel.Route(6, Remote4) is null && tunnel.Route(17, new(Remote4.Address, 53)) is null);
        });
        check("Tunneled DNS goes to the profile's resolver, same family first, whatever server the application asked", () =>
        {
            var tunnel = Tunnel(["0.0.0.0/0", "::/0"], ["fd00:64::1", "10.64.0.1"], Source4, Source6);
            foreach (var protocol in new byte[] { 17, 6 })
            {
                var lan = tunnel.Route(protocol, new(NetAddress.Parse("192.168.1.1"), 53))!;
                Expect(lan.Target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53) && lan.Egress.Source.Equals(Source4) && lan.Tunneled);
                var v6 = tunnel.Route(protocol, new(NetAddress.Parse("2001:4860:4860::8888"), 53))!;
                Expect(v6.Target == new NetEndpoint(NetAddress.Parse("fd00:64::1"), 53) && v6.Egress.Source.Equals(Source6));
            }
            // A v4-only tunnel answers an IPv6 query through its IPv4 resolver.
            var v4Only = Tunnel(["0.0.0.0/0", "::/0"], ["10.64.0.1"]);
            Expect(v4Only.Route(17, new(NetAddress.Parse("2001:4860:4860::8888"), 53))?.Target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53));
            Expect(v4Only.Route(17, new(NetAddress.Parse("2001:4860:4860::8888"), 443)) is null);
            Expect(tunnel.Route(17, new(NetAddress.Parse("192.168.1.1"), 5353))?.Target is null);
        });
        check("Without a usable resolver tunneled DNS keeps its destination, and only if the tunnel carries it", () =>
        {
            var none = Tunnel(["0.0.0.0/0"], []);
            Expect(none.Route(17, new(NetAddress.Parse("1.1.1.1"), 53)) is { Target: null } route && route.Egress.Source.Equals(Source4));
            var outside = Tunnel(["10.0.0.0/8"], ["9.9.9.9"]);
            Expect(outside.Route(17, new(NetAddress.Parse("10.1.1.1"), 53)) is { Target: null });
            Expect(outside.Route(17, new(NetAddress.Parse("192.168.1.1"), 53)) is null);
        });
        check("DNS addressed to Darkwire's resolver goes only to a profile resolver the tunnel carries, never on to that address", () =>
        {
            NetEndpoint resolver4 = new(RouterAddresses.Resolver4, 53), resolver6 = new(RouterAddresses.Resolver6, 53);
            var dual = Tunnel(["0.0.0.0/0", "::/0"], ["fd00:64::1", "10.64.0.1"], Source4, Source6);
            Expect(dual.Resolvers.Select(a => a.ToString()).SequenceEqual(["fd00:64::1", "10.64.0.1"]));
            foreach (var protocol in new byte[] { 17, 6 })
            {
                Expect(dual.Route(protocol, resolver4) is { Tunneled: true, Target: var target } route && target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53) && route.Egress.Source.Equals(Source4));
                Expect(dual.Route(protocol, resolver6)?.Target == new NetEndpoint(NetAddress.Parse("fd00:64::1"), 53));
            }
            // An IPv4-only tunnel answers the IPv6 resolver address through its IPv4 resolver.
            Expect(Tunnel(["0.0.0.0/0", "::/0"], ["10.64.0.1"]).Route(17, resolver6)?.Target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53));
            // No resolver, or none the tunnel carries (outside its networks, or of a family it has no address for): refused.
            var none = Tunnel(["0.0.0.0/0", "::/0"], [], Source4, Source6);
            var outside = Tunnel(["10.0.0.0/8"], ["9.9.9.9", "fd00:64::1"]);
            foreach (var tunnel in new[] { none, outside })
                Expect(tunnel.Resolvers.Count == 0 && tunnel.Route(17, resolver4) is null && tunnel.Route(6, resolver4) is null && tunnel.Route(17, resolver6) is null);
            Expect(none.Route(17, new(NetAddress.Parse("1.1.1.1"), 53)) is { Target: null });
            dual.Close();
            Expect(dual.Route(17, resolver4) is null);
        });
        check("Endpoint host names become the addresses looked up for them, IPv4 first, and nothing else changes", () =>
        {
            static string[] Lines(string text) => text.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
            IPAddress[] found = [IPAddress.Parse("2001:db8::9"), IPAddress.Parse("203.0.113.9"), IPAddress.Parse("127.0.0.1"), IPAddress.Parse("fe80::9"), IPAddress.Parse("203.0.113.10")];
            List<string> asked = [];
            IReadOnlyList<IPAddress> Lookup(string host) { asked.Add(host); return found; }
            var named = VpnConfiguration.Parse("WireGuard", wg.Replace("198.51.100.7:51820", "VPN.Example.net:51820"));
            var resolved = VpnConfiguration.ResolveEndpoints("WireGuard", named.NormalizedConfiguration, Lookup);
            Expect(asked.SequenceEqual(["vpn.example.net"]) && Lines(resolved).Count(l => l == "Endpoint = 203.0.113.9:51820") == 1 && Lines(resolved).Contains("Endpoint = [2001:db8::7]:51821"));
            Expect(resolved.Replace("203.0.113.9:51820", "VPN.Example.net:51820") == named.NormalizedConfiguration);
            found = [IPAddress.Parse("2001:db8::9")];
            Expect(Lines(VpnConfiguration.ResolveEndpoints("WireGuard", named.NormalizedConfiguration, Lookup)).Contains("Endpoint = [2001:db8::9]:51820"));
            // A name with no usable address refuses the configuration.
            foreach (var unusable in new IPAddress[][] { [], [IPAddress.Parse("127.0.0.1"), IPAddress.Parse("fe80::1"), IPAddress.Parse("224.0.0.1")] })
            {
                found = unusable;
                Reject(() => VpnConfiguration.ResolveEndpoints("WireGuard", named.NormalizedConfiguration, Lookup));
            }
            // Address endpoints are never looked up.
            asked.Clear();
            var literal = VpnConfiguration.Parse("WireGuard", wg).NormalizedConfiguration;
            Expect(VpnConfiguration.ResolveEndpoints("WireGuard", literal, Lookup) == literal && asked.Count == 0);
        });
        check("A tunnel egress refuses scoped, duplicate-family and missing interfaces", () =>
        {
            foreach (var build in new Action[]
            {
                () => new TunnelEgress(0, 9, [Source4], [], []),
                () => new TunnelEgress(900, 0, [Source4], [], []),
                () => new TunnelEgress(900, 9, [], [], []),
                () => new TunnelEgress(900, 9, [Source4, IPAddress.Parse("10.64.0.3")], [], []),
                () => new TunnelEgress(900, 9, [IPAddress.Parse("224.0.0.1")], [], [])
            })
                try { build(); throw new Exception("Invalid tunnel egress accepted."); } catch (ArgumentException) { }
        });
        check("The relay refuses a connection without a route and never opens a socket for it", () =>
        {
            using var rig = new RelayRig(_ => null);
            rig.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1000, 0, IpPacket.Syn, 64240, [], []));
            var flow = rig.Next();
            rig.Router.Decide(flow.Id, true);
            var answer = rig.Injected(packet => packet.Protocol == 1);
            Expect(answer.IcmpType == 3 && answer.IcmpCode == 1 && answer.Destination == App4.Address && rig.Relay.OpenConnections == 0);
            Expect(rig.Router.Flows().Count == 0);
        });
        check("The relay drops datagrams without a route and opens no association", () =>
        {
            using var rig = new RelayRig(_ => null);
            rig.Router.Process(PacketBuilder.Udp(App4, new(NetAddress.Parse("198.51.100.1"), 53), [1, 2, 3]));
            rig.Router.Decide(rig.Next().Id, true);
            rig.Router.Process(PacketBuilder.Udp(App4, new(NetAddress.Parse("198.51.100.1"), 53), [4]));
            Expect(rig.Relay.Associations == 0);
        });
        if (!native) return;
        var loopback = new Egress(1, (uint)NetworkInterface.LoopbackInterfaceIndex, IPAddress.Loopback, 8, 0);
        check("Native relay dials the route's target pinned to its egress, not the destination the application asked", () =>
        {
            using var server = new TcpListener(IPAddress.Loopback, 0); server.Start();
            var target = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)server.LocalEndpoint).Port);
            using var rig = new RelayRig(_ => new(loopback, target, true));
            var accepting = server.AcceptSocketAsync();
            rig.Router.Process(PacketBuilder.Tcp(App4, new(NetAddress.Parse("192.168.1.1"), 53), 1000, 0, IpPacket.Syn, 64240, [], []));
            rig.Router.Decide(rig.Next().Id, true);
            Expect(accepting.Wait(TimeSpan.FromSeconds(5)), "The relay did not reach its target.");
            using var accepted = accepting.Result;
            Expect(((IPEndPoint)accepted.RemoteEndPoint!).Address.Equals(IPAddress.Loopback));
            // The held SYN is released toward the listener only once the outbound side is up.
            var syn = rig.Injected(packet => packet.Protocol == 6);
            Expect(syn.TcpFlags == IpPacket.Syn && syn.Destination == RouterAddresses.Tunnel4 && syn.DestinationPort == 7100);
        });
        check("Native relay redirects a datagram flow to its resolver and answers as the destination the application asked", () =>
        {
            using var resolver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            resolver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var target = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)resolver.LocalEndPoint!).Port);
            var asked = new NetEndpoint(NetAddress.Parse("192.168.1.1"), 53);
            using var rig = new RelayRig(_ => new(loopback, target, true));
            rig.Router.Process(PacketBuilder.Udp(App4, asked, [7, 7, 7]));
            rig.Router.Decide(rig.Next().Id, true);
            var buffer = new byte[64]; EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            resolver.ReceiveTimeout = 5000;
            var count = resolver.ReceiveFrom(buffer, ref from);
            Expect(count == 3 && buffer[0] == 7);
            // A stranger writing to the relay's socket is not an answer; the resolver is.
            using (var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            { stranger.Bind(new IPEndPoint(IPAddress.Loopback, 0)); stranger.SendTo([9], from); }
            resolver.SendTo([42, 43], from);
            var reply = rig.Injected(packet => packet.Protocol == 17);
            Expect(reply.Source == asked.Address && reply.SourcePort == 53 && reply.Destination == App4.Address && reply.DestinationPort == App4.Port && reply.PayloadLength == 2);
            Thread.Sleep(200);
            Expect(rig.Count(packet => packet.Protocol == 17) == 1, "A stranger's datagram was delivered.");
        });
        check("Native relay abandons at once what it relays through an interface going away, and nothing through another", () =>
        {
            using var server = new TcpListener(IPAddress.Loopback, 0); server.Start();
            var target = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)server.LocalEndpoint).Port);
            using var resolver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            resolver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var answering = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)resolver.LocalEndPoint!).Port);
            using var rig = new RelayRig(flow => new(loopback, flow.Protocol == 6 ? target : answering, true));
            var accepting = server.AcceptSocketAsync();
            rig.Router.Process(PacketBuilder.Tcp(App4, new(NetAddress.Parse("192.168.1.1"), 53), 1000, 0, IpPacket.Syn, 64240, [], []));
            rig.Router.Decide(rig.Next().Id, true);
            Expect(accepting.Wait(TimeSpan.FromSeconds(5)), "The relay did not reach its target.");
            using var accepted = accepting.Result;
            rig.Router.Process(PacketBuilder.Udp(App4, new(NetAddress.Parse("198.51.100.1"), 53), [1]));
            rig.Router.Decide(rig.Next().Id, true);
            Expect(rig.Relay.OpenConnections == 1 && rig.Relay.Associations == 1, "Nothing was relayed.");
            rig.Relay.Abandon(loopback.Luid + 1);
            Expect(rig.Relay.OpenConnections == 1 && rig.Relay.Associations == 1, "Another interface going away closed them.");
            rig.Relay.Abandon(loopback.Luid);
            Expect(rig.Relay.OpenConnections == 0 && rig.Relay.Associations == 0, "What went through the interface stayed open.");
            // Reset rather than closed, so nothing of the connection lingers on the interface.
            accepted.ReceiveTimeout = 5000;
            try { var read = accepted.Receive(new byte[1]); throw new Exception(read == 0 ? "The connection was closed, not reset." : "Data arrived."); }
            catch (SocketException error) { Expect(error.SocketErrorCode == SocketError.ConnectionReset, error.SocketErrorCode.ToString()); }
        });
        check("Native relay gives a flow moved into a tunnel its own socket instead of the one pinned elsewhere", () =>
        {
            using var server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            server.Bind(new IPEndPoint(IPAddress.Loopback, 0)); server.ReceiveTimeout = 5000;
            // The router never relays to loopback itself, so the server stands in as the redirect target of a routable destination.
            var target = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)server.LocalEndPoint!).Port);
            var destination = new NetEndpoint(NetAddress.Parse("198.51.100.1"), 53);
            var tunneled = false;
            using var rig = new RelayRig(_ => new(loopback, target, tunneled));
            rig.Router.Process(PacketBuilder.Udp(App4, destination, [1]));
            rig.Router.Decide(rig.Next().Id, true);
            var buffer = new byte[16]; EndPoint first = new IPEndPoint(IPAddress.Any, 0), second = new IPEndPoint(IPAddress.Any, 0);
            server.ReceiveFrom(buffer, ref first);
            rig.Router.Process(PacketBuilder.Udp(App4, destination, [2]));
            server.ReceiveFrom(buffer, ref second);
            Expect(first.Equals(second), "Physical datagrams of one association should share a socket.");
            tunneled = true;
            rig.Router.Process(PacketBuilder.Udp(App4, destination, [3]));
            server.ReceiveFrom(buffer, ref second);
            Expect(!first.Equals(second) && buffer[0] == 3 && rig.Relay.Associations == 1);
        });
        check("Native relay carries a large TCP stream whole and keeps the response after a half-close", () =>
        {
            // The relay's TCP leg between the application's accepted socket and the outbound one.
            using var applications = new TcpListener(IPAddress.Loopback, 0); applications.Start();
            using var servers = new TcpListener(IPAddress.Loopback, 0); servers.Start();
            using var application = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5000 };
            application.Connect(applications.LocalEndpoint); using var accepted = applications.AcceptSocket();
            using var outbound = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            outbound.Connect(servers.LocalEndpoint); using var server = servers.AcceptSocket(); server.ReceiveTimeout = 5000;
            var relay = ProxyTransport.RelayTcpAsync(accepted, outbound, TimeSpan.FromSeconds(30), CancellationToken.None);
            static byte[] ReadToEnd(Socket socket)
            {
                using var output = new MemoryStream(); var buffer = new byte[4096];
                for (int count; (count = socket.Receive(buffer)) > 0;) output.Write(buffer, 0, count);
                return output.ToArray();
            }
            var payload = new byte[1024 * 1024 + 123]; new Random(42).NextBytes(payload);
            var received = Task.Run(() => ReadToEnd(server));
            Expect(application.Send(payload) == payload.Length); application.Shutdown(SocketShutdown.Send);
            Expect(received.Wait(TimeSpan.FromSeconds(10)) && received.Result.SequenceEqual(payload), "The TCP stream changed.");
            byte[] response = [1, 7, 9, 0, 255]; server.Send(response); server.Shutdown(SocketShutdown.Send);
            Expect(ReadToEnd(application).SequenceEqual(response), "The half-close discarded the response.");
            Expect(relay.Wait(TimeSpan.FromSeconds(5)), "The relay outlived both directions closing.");
        });
        check("Native relay ends mid-stream as soon as its connection is closed", () =>
        {
            using var applications = new TcpListener(IPAddress.Loopback, 0); applications.Start();
            using var servers = new TcpListener(IPAddress.Loopback, 0); servers.Start();
            using var application = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            application.Connect(applications.LocalEndpoint); using var accepted = applications.AcceptSocket();
            using var outbound = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            outbound.Connect(servers.LocalEndpoint); using var server = servers.AcceptSocket(); server.ReceiveTimeout = 5000;
            // RouterRelay closes a connection by canceling the token it relays under.
            using var close = new CancellationTokenSource();
            var relay = ProxyTransport.RelayTcpAsync(accepted, outbound, TimeSpan.FromSeconds(30), close.Token);
            application.Send([1, 2, 3]);
            Expect(server.Receive(new byte[3]) > 0, "The relay carried nothing before it was closed.");
            close.Cancel();
            try { relay.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
            Expect(relay.IsCompleted, "The relay kept running after its connection was closed.");
        });
    }

    /// <summary>A packet router served by a real relay whose routes come from the check; injected packets are collected.</summary>
    internal sealed class RelayRig : IDisposable, IFlowRoutes
    {
        private readonly Func<RouterFlow, FlowRoute?> routes;
        private readonly ConcurrentQueue<RouterFlow> evaluated = new();
        private readonly List<byte[]> injected = [];
        public readonly RouterRelay Relay;
        public readonly PacketRouter Router;

        public RelayRig(Func<RouterFlow, FlowRoute?> routes)
        {
            this.routes = routes;
            Relay = new(packet => { lock (injected) injected.Add(packet.ToArray()); return true; }, this, evaluated.Enqueue);
            Router = new(Relay, RouterAddresses.Default(7100, 7100, 1500));
            Relay.Attach(Router, []);
        }

        public FlowRoute? Select(RouterFlow flow) => routes(flow);

        public RouterFlow Next() => evaluated.TryDequeue(out var flow) ? flow : throw new Exception("No flow was evaluated.");

        public IpPacket Injected(Func<IpPacket, bool> match)
        {
            IpPacket found = default; var seen = false;
            SpinWait.SpinUntil(() =>
            {
                lock (injected)
                    foreach (var packet in injected)
                        if (IpPacket.TryParse(packet, out var header) && match(header)) { found = header; return seen = true; }
                return false;
            }, TimeSpan.FromSeconds(5));
            return seen ? found : throw new Exception("The expected packet was not injected.");
        }

        /// <summary>The payload of the first injected packet the match accepts.</summary>
        public byte[] Payload(Func<IpPacket, bool> match)
        {
            var header = Injected(match);
            lock (injected)
                foreach (var packet in injected)
                    if (IpPacket.TryParse(packet, out var parsed) && match(parsed)) return packet.AsSpan(header.PayloadOffset, header.PayloadLength).ToArray();
            throw new Exception("The expected packet was not injected.");
        }

        public int Count(Func<IpPacket, bool> match)
        {
            lock (injected) return injected.Count(packet => IpPacket.TryParse(packet, out var header) && match(header));
        }

        public void Dispose() => Relay.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(5));
    }
}
