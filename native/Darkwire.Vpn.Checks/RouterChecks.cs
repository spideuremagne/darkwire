using Darkwire.Vpn;
using System.Buffers.Binary;

internal static class RouterChecks
{
    private static readonly NetEndpoint App4 = new(RouterAddresses.Tunnel4, 50_000), Remote4 = new(NetAddress.Parse("203.0.113.8"), 443);
    private static readonly NetEndpoint App6 = new(RouterAddresses.Tunnel6, 50_000), Remote6 = new(NetAddress.Parse("2001:db8::8"), 443);
    private static readonly NetEndpoint Listener4 = new(RouterAddresses.Tunnel4, 7100), Listener6 = new(RouterAddresses.Tunnel6, 7100);

    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string message = "Router invariant failed.") { if (!value) throw new Exception(message); }

        check("Checksum matches the RFC 1071 example", () => Assert(Checksum.Fold(Checksum.Add(0, [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])) == 0x220d));
        check("IPv4 header checksum matches a known header", () => Assert(Checksum.Fold(Checksum.Add(0, Convert.FromHexString("450000730000400040110000c0a80001c0a800c7"))) == 0xb861));
        check("Translation keeps TCP and UDP checksums valid in both families", () =>
        {
            var random = new Random(7);
            for (var i = 0; i < 400; i++)
            {
                var v6 = i % 2 == 0; var udp = i % 4 < 2;
                NetEndpoint Endpoint() { var bytes = new byte[v6 ? 16 : 4]; random.NextBytes(bytes); return new(NetAddress.Read(bytes), (ushort)random.Next(1, 65536)); }
                var payload = new byte[random.Next(0, 1400)]; random.NextBytes(payload);
                var packet = udp ? PacketBuilder.Udp(Endpoint(), Endpoint(), payload)
                    : PacketBuilder.Tcp(Endpoint(), Endpoint(), (uint)random.Next(), (uint)random.Next(), IpPacket.Ack, 1000, [], payload);
                Assert(Valid(packet), "Builder produced an invalid packet at iteration " + i);
                IpPacket.TryParse(packet, out var header);
                var source = Endpoint(); var destination = Endpoint();
                PacketBuilder.Rewrite(packet, header, source, destination);
                Assert(Valid(packet), "Translation broke a checksum at iteration " + i);
                IpPacket.TryParse(packet, out header);
                Assert(header.Source == source.Address && header.SourcePort == source.Port && header.Destination == destination.Address && header.DestinationPort == destination.Port);
                Assert(packet.AsSpan(header.PayloadOffset, header.PayloadLength).SequenceEqual(payload));
            }
        });
        check("IPv4 UDP without a checksum stays without one", () =>
        {
            var packet = PacketBuilder.Udp(App4, Remote4, [1, 2, 3]);
            packet[26] = 0; packet[27] = 0;
            IpPacket.TryParse(packet, out var header);
            PacketBuilder.Rewrite(packet, header, Remote4, App4);
            Assert(packet[26] == 0 && packet[27] == 0 && Valid(packet));
        });
        check("Parser rejects truncated and contradictory headers", () =>
        {
            var tcp = PacketBuilder.Tcp(App4, Remote4, 1, 0, IpPacket.Syn, 1000, [], []);
            Assert(IpPacket.TryParse(tcp, out _) && !IpPacket.TryParse(tcp.AsSpan(0, 39), out _));
            foreach (var (at, value) in new[] { (0, (byte)0x44), (0, (byte)0x55), (6, (byte)0x80), (32, (byte)0x40), (32, (byte)0x60) })
            {
                var broken = (byte[])tcp.Clone(); broken[at] = value;
                Assert(!IpPacket.TryParse(broken, out _), "Accepted a corrupt byte at " + at);
            }
            var udp = PacketBuilder.Udp(App4, Remote4, [1, 2, 3]); udp[25] = 200;
            Assert(!IpPacket.TryParse(udp, out _));
            var jumbo = PacketBuilder.Tcp(App6, Remote6, 1, 0, IpPacket.Syn, 1000, [], []); jumbo[4] = 0; jumbo[5] = 0;
            Assert(!IpPacket.TryParse(jumbo, out _));
        });
        check("IPv6 extension headers are walked to the transport header", () =>
        {
            var packet = Extend(PacketBuilder.Tcp(App6, Remote6, 1, 0, IpPacket.Syn, 1000, [], [5]), 0, 60, 44);
            Assert(IpPacket.TryParse(packet, out var header) && !header.IsFragment && header.Protocol == 6 && header.TransportOffset == 64);
            Assert(header.SourcePort == 50_000 && header.DestinationPort == 443 && header.PayloadLength == 1 && Valid(packet));
        });
        foreach (var (name, chain) in new[] { ("misplaced Hop-by-Hop options", new byte[] { 60, 0 }), ("a pending source route", new byte[] { 43 }), ("nine extension headers", Enumerable.Repeat((byte)60, 9).ToArray()) })
            check("IPv6 parser rejects " + name, () =>
            {
                var packet = Extend(PacketBuilder.Tcp(App6, Remote6, 1, 0, IpPacket.Syn, 1000, [], []), chain);
                if (chain[0] == 43) packet[43] = 1;
                Assert(!IpPacket.TryParse(packet, out _));
            });
        foreach (var v6 in new[] { false, true })
            check((v6 ? "IPv6" : "IPv4") + " fragments reassemble in any order", () =>
            {
                var payload = Enumerable.Range(0, 3000).Select(i => (byte)i).ToArray();
                var whole = PacketBuilder.Udp(v6 ? App6 : App4, v6 ? Remote6 : Remote4, payload, 77);
                var parts = PacketBuilder.Fragment(whole, 1280, 0x1234);
                Assert(parts.Count == 3 && parts.All(p => p.Length <= 1280));
                var reassembler = new FragmentReassembler(); byte[]? result = null;
                foreach (var part in new[] { parts[2], parts[0], parts[1] })
                {
                    Assert(result is null);
                    result = Add(reassembler, part);
                }
                Assert(result is not null && result.AsSpan().SequenceEqual(whole) && reassembler.Pending == 0);
            });
        check("Overlapping fragments discard the whole datagram", () =>
        {
            var parts = PacketBuilder.Fragment(PacketBuilder.Udp(App4, Remote4, new byte[3000], 78), 1280, 0);
            var reassembler = new FragmentReassembler();
            Assert(Add(reassembler, parts[0]) is null);
            var overlap = (byte[])parts[1].Clone();
            BinaryPrimitives.WriteUInt16BigEndian(overlap.AsSpan(6), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(overlap.AsSpan(6)) - 1));
            Checksum.RefreshIPv4Header(overlap);
            Assert(Add(reassembler, overlap) is null && reassembler.Pending == 0);
            Assert(Add(reassembler, parts[1]) is null && Add(reassembler, parts[2]) is null);
        });
        check("Duplicate fragments are ignored", () =>
        {
            var whole = PacketBuilder.Udp(App4, Remote4, new byte[3000], 79);
            var parts = PacketBuilder.Fragment(whole, 1280, 0);
            var reassembler = new FragmentReassembler();
            Assert(Add(reassembler, parts[0]) is null && Add(reassembler, parts[0]) is null && Add(reassembler, parts[1]) is null);
            Assert(Add(reassembler, parts[2]) is { } result && result.AsSpan().SequenceEqual(whole));
        });
        check("Unaligned and expired fragments never complete", () =>
        {
            var parts = PacketBuilder.Fragment(PacketBuilder.Udp(App4, Remote4, new byte[3000], 80), 1280, 0);
            var reassembler = new FragmentReassembler();
            var unaligned = parts[0][..^1];
            BinaryPrimitives.WriteUInt16BigEndian(unaligned.AsSpan(2), (ushort)unaligned.Length);
            Checksum.RefreshIPv4Header(unaligned);
            Assert(Add(reassembler, unaligned) is null && reassembler.Pending == 0);
            Assert(Add(reassembler, parts[0]) is null && reassembler.Pending == 1);
            reassembler.Expire(DateTimeOffset.UnixEpoch + FragmentReassembler.Lifetime);
            Assert(reassembler.Pending == 0 && Add(reassembler, parts[1]) is null && Add(reassembler, parts[2]) is null);
        });
        check("Reset answers a SYN with RST|ACK acknowledging it", () =>
        {
            IpPacket.TryParse(PacketBuilder.Tcp(App4, Remote4, 1000, 0, IpPacket.Syn, 1000, [], [1, 2, 3]), out var header);
            var reset = PacketBuilder.Reset(header)!;
            IpPacket.TryParse(reset, out var r);
            Assert(Valid(reset) && r.Source == Remote4.Address && r.SourcePort == 443 && r.Destination == App4.Address && r.DestinationPort == 50_000);
            Assert(r.TcpFlags == (IpPacket.Rst | IpPacket.Ack) && r.Sequence == 0 && r.Acknowledgment == 1004);
        });
        check("Reset answers an ACK at its acknowledgment and never answers a reset", () =>
        {
            IpPacket.TryParse(PacketBuilder.Tcp(App6, Remote6, 1000, 777, IpPacket.Ack, 1000, [], []), out var header);
            IpPacket.TryParse(PacketBuilder.Reset(header)!, out var r);
            Assert(r.TcpFlags == IpPacket.Rst && r.Sequence == 777);
            IpPacket.TryParse(PacketBuilder.Tcp(App4, Remote4, 1000, 0, IpPacket.Rst, 0, [], []), out header);
            Assert(PacketBuilder.Reset(header) is null);
        });
        check("Unreachable quotes the original within the RFC size limits", () =>
        {
            foreach (var v6 in new[] { false, true })
            {
                var original = PacketBuilder.Tcp(v6 ? App6 : App4, v6 ? Remote6 : Remote4, 1, 0, IpPacket.Syn, 1000, [], new byte[2000]);
                IpPacket.TryParse(original, out var header);
                var error = PacketBuilder.Unreachable(header.Destination, original, header, UnreachableCode.Port);
                IpPacket.TryParse(error, out var e);
                Assert(Valid(error) && e.Destination == header.Source && e.IcmpType == (v6 ? 1 : 3) && e.IcmpCode == (v6 ? 4 : 3));
                Assert(error.Length == (v6 ? 1280 : 576) && error.AsSpan(e.PayloadOffset).SequenceEqual(original.AsSpan(0, error.Length - e.PayloadOffset)));
            }
        });
        check("Router addressing rejects overlapping pools, listeners and resolver", () =>
        {
            var good = RouterAddresses.Default(7100, 7100, 1500);
            good.Validate();
            foreach (var bad in new[] { good with { Mtu = 1000 }, good with { Listener4 = new(NetAddress.Parse("198.19.0.7"), 7100) },
                good with { Pool4 = NetAddress.Parse("10.0.0.0") }, good with { Listener6 = new(RouterAddresses.Tunnel6, 0) }, good with { Prefix4 = 24 },
                good with { Listener4 = new(RouterAddresses.Resolver4, 7100) }, good with { Listener6 = new(RouterAddresses.Resolver6, 7100) } })
            {
                try { bad.Validate(); throw new Exception("Invalid addressing accepted."); }
                catch (InvalidDataException) { }
            }
        });

        check("TCP SYN is held until the decision and the outbound connection", () =>
        {
            var r = new Rig();
            var syn = PacketBuilder.Tcp(App4, Remote4, 1000, 0, IpPacket.Syn, 64240, [], []);
            r.Router.Process(syn.ToArray());
            Assert(r.Host.Evaluated.Count == 1 && r.Host.Injected.Count == 0);
            var flow = r.Host.Evaluated[0];
            Assert(flow.Protocol == 6 && flow.Local == App4 && flow.Remote == Remote4);
            r.Router.Process(syn.ToArray());
            Assert(r.Host.Evaluated.Count == 1 && r.Host.Injected.Count == 0);
            r.Router.Decide(flow.Id, true);
            Assert(r.Host.Connecting.Count == 1 && r.Host.Connecting[0] == flow && r.Host.Injected.Count == 0);
            r.Router.Connected(flow.Id);
            var injected = r.Last(out var packet);
            Assert(Valid(packet) && injected.Destination == RouterAddresses.Tunnel4 && injected.DestinationPort == 7100 && injected.TcpFlags == IpPacket.Syn && injected.Sequence == 1000);
            var fake = new NetEndpoint(injected.Source, injected.SourcePort);
            Assert(injected.Source.Within(NetAddress.Parse("198.19.0.0"), 16) && r.Router.Accepting(fake)?.Id == flow.Id);
            r.Router.Process(PacketBuilder.Tcp(Listener4, fake, 5000, 1001, IpPacket.Syn | IpPacket.Ack, 64240, [], []));
            var reply = r.Last(out packet);
            Assert(Valid(packet) && reply.Source == Remote4.Address && reply.SourcePort == 443 && reply.Destination == App4.Address && reply.DestinationPort == 50_000 && reply.Sequence == 5000);
            r.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1001, 5001, IpPacket.Ack | IpPacket.Psh, 64240, [], [9, 9, 9]));
            var data = r.Last(out packet);
            Assert(Valid(packet) && data.Source == fake.Address && data.SourcePort == fake.Port && data.DestinationPort == 7100 && data.PayloadLength == 3);
        });
        check("Blocked TCP SYN is refused with a reset and forgotten", () =>
        {
            var r = new Rig();
            r.Router.Process(Syn());
            r.Router.Decide(r.Host.Evaluated[0].Id, false);
            var reset = r.Last(out var packet);
            Assert(Valid(packet) && reset.TcpFlags == (IpPacket.Rst | IpPacket.Ack) && reset.Acknowledgment == 1001 && reset.Destination == App4.Address);
            Assert(r.Host.ClosedFlows.Count == 1 && r.Router.Flows().Count == 0 && r.Host.Connecting.Count == 0);
        });
        foreach (var failure in new[] { RouterFailure.Refused, RouterFailure.Unreachable, RouterFailure.TimedOut })
            check("Failed TCP connection reports " + failure + " to the application", () =>
            {
                var r = new Rig();
                r.Router.Process(Syn());
                var flow = r.Host.Evaluated[0];
                r.Router.Decide(flow.Id, true); r.Router.Failed(flow.Id, failure);
                Assert(r.Host.ClosedFlows.Count == 1 && r.Router.Flows().Count == 0);
                if (failure == RouterFailure.TimedOut) { Assert(r.Host.Injected.Count == 0); return; }
                var answer = r.Last(out var packet);
                Assert(Valid(packet) && r.Host.Injected.Count == 1);
                Assert(failure == RouterFailure.Refused ? answer.TcpFlags == (IpPacket.Rst | IpPacket.Ack) : answer.Protocol == 1 && answer.IcmpType == 3 && answer.IcmpCode == 1);
            });
        check("Segments of unknown connections are reset; resets are not answered", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1, 777, IpPacket.Ack, 1000, [], [1]));
            var reset = r.Last(out var packet);
            Assert(Valid(packet) && reset.TcpFlags == IpPacket.Rst && reset.Sequence == 777 && r.Host.Evaluated.Count == 0);
            r.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1, 777, IpPacket.Rst, 1000, [], []));
            Assert(r.Host.Injected.Count == 1);
        });
        foreach (var destination in new[] { "198.19.0.5", "198.18.0.1", "224.0.0.251", "127.0.0.1", "255.255.255.255", "0.0.0.0", "fe80::1", "ff02::1", "::1", "::ffff:1.2.3.4", "fd5a:9c33:21e7::99" })
            check("TCP to " + destination + " is refused without evaluation", () =>
            {
                var r = new Rig(); var target = NetAddress.Parse(destination);
                r.Router.Process(PacketBuilder.Tcp(target.V6 ? App6 : App4, new(target, 80), 1, 0, IpPacket.Syn, 1000, [], []));
                Assert(r.Host.Evaluated.Count == 0 && r.Host.Injected.Count == 1 && r.Last(out _).TcpFlags == (IpPacket.Rst | IpPacket.Ack));
            });
        check("DNS to Darkwire's resolver address is evaluated; other ports there and other tunnel addresses are refused", () =>
        {
            var r = new Rig();
            foreach (var (app, resolver) in new[] { (App4, RouterAddresses.Resolver4), (App6, RouterAddresses.Resolver6) })
            {
                r.Router.Process(PacketBuilder.Udp(app, new(resolver, 53), [1]));
                r.Router.Process(PacketBuilder.Tcp(app, new(resolver, 53), 1, 0, IpPacket.Syn, 1000, [], []));
            }
            Assert(r.Host.Evaluated.Count == 4 && r.Host.Evaluated.All(f => RouterAddresses.IsResolver(f.Remote)) && r.Host.Injected.Count == 0);
            r.Router.Process(PacketBuilder.Udp(App4, new(RouterAddresses.Resolver4, 5353), [1]));
            r.Router.Process(PacketBuilder.Udp(App6, new(NetAddress.Parse("fd5a:9c33:21e7::3"), 53), [1]));
            r.Router.Process(PacketBuilder.Echo(App4.Address, RouterAddresses.Resolver4, false, 7, 1, [1]));
            r.Router.Process(PacketBuilder.Tcp(App4, new(RouterAddresses.Resolver4, 80), 1, 0, IpPacket.Syn, 1000, [], []));
            Assert(r.Host.Evaluated.Count == 4 && r.Router.Statistics.Refused == 4 && r.Host.Injected.Count == 1 && r.Last(out _).TcpFlags == (IpPacket.Rst | IpPacket.Ack));
        });
        check("Packets from outside the tunnel network are dropped", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Tcp(new(NetAddress.Parse("192.168.1.5"), 5000), Remote4, 1, 0, IpPacket.Syn, 1000, [], []));
            r.Router.Process(PacketBuilder.Udp(new(NetAddress.Parse("fe80::5"), 5000), Remote6, [1]));
            Assert(r.Host.Evaluated.Count == 0 && r.Host.Injected.Count == 0 && r.Router.Statistics.Refused == 2);
        });
        check("Undecided flows are bounded", () =>
        {
            var r = new Rig();
            for (var i = 0; i <= PacketRouter.MaximumPending; i++)
                r.Router.Process(PacketBuilder.Tcp(new(RouterAddresses.Tunnel4, (ushort)(1024 + i)), Remote4, 1, 0, IpPacket.Syn, 1000, [], []));
            Assert(r.Host.Evaluated.Count == PacketRouter.MaximumPending && r.Router.Statistics.Overflow == 1);
        });
        check("Undecided flows expire and the next SYN asks again", () =>
        {
            var r = new Rig();
            r.Router.Process(Syn());
            r.Clock.Now += PacketRouter.DecisionTimeout; r.Router.Sweep();
            Assert(r.Host.ClosedFlows.Count == 1 && r.Router.Flows().Count == 0);
            r.Router.Process(Syn());
            Assert(r.Host.Evaluated.Count == 2 && r.Host.Evaluated[1].Id != r.Host.Evaluated[0].Id);
            r.Router.Decide(r.Host.Evaluated[0].Id, true);
            Assert(r.Host.Connecting.Count == 0);
        });
        check("Both FINs close the flow once while translation lingers", () =>
        {
            var (r, _, fake) = OpenTcp();
            r.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1001, 5001, IpPacket.Fin | IpPacket.Ack, 1000, [], []));
            Assert(r.Host.ClosedFlows.Count == 0);
            r.Router.Process(PacketBuilder.Tcp(Listener4, fake, 5001, 1002, IpPacket.Fin | IpPacket.Ack, 1000, [], []));
            Assert(r.Host.ClosedFlows.Count == 1 && !r.Host.Aborts[0] && r.Router.Accepting(fake) is null);
            var count = r.Host.Injected.Count;
            r.Router.Process(PacketBuilder.Tcp(App4, Remote4, 1002, 5002, IpPacket.Ack, 1000, [], []));
            Assert(r.Host.Injected.Count == count + 1 && r.Last(out _).DestinationPort == 7100);
            r.Clock.Now += PacketRouter.Linger; r.Router.Sweep();
            Assert(r.Router.Flows().Count == 0 && r.Host.ClosedFlows.Count == 1);
            r.Router.Process(PacketBuilder.Tcp(Listener4, fake, 5002, 1002, IpPacket.Ack, 1000, [], []));
            Assert(r.Host.Injected.Count == count + 1 && r.Router.Statistics.Stray == 1);
        });
        check("A reset from the listener closes the flow and still reaches the application", () =>
        {
            var (r, _, fake) = OpenTcp();
            r.Router.Process(PacketBuilder.Tcp(Listener4, fake, 5001, 0, IpPacket.Rst, 0, [], []));
            var reset = r.Last(out var packet);
            Assert(Valid(packet) && reset.TcpFlags == IpPacket.Rst && reset.Destination == App4.Address && r.Host.ClosedFlows.Count == 1);
        });
        foreach (var revoke in new[] { false, true })
            check((revoke ? "Revoked" : "Released") + " TCP flows keep translating their final segments", () =>
            {
                var (r, flow, fake) = OpenTcp();
                if (revoke) r.Router.Revoke(flow.Id); else r.Router.Release(flow.Id);
                Assert(r.Host.ClosedFlows.Count == 1 && r.Host.Aborts[0] == revoke);
                r.Router.Process(PacketBuilder.Tcp(Listener4, fake, 5001, 1001, IpPacket.Rst | IpPacket.Ack, 0, [], []));
                Assert(r.Last(out _).Destination == App4.Address && r.Host.ClosedFlows.Count == 1);
            });
        check("A new SYN on a lingering tuple starts a new decision", () =>
        {
            var (r, flow, _) = OpenTcp();
            r.Router.Release(flow.Id);
            r.Router.Process(Syn());
            var flows = r.Router.Flows();
            Assert(r.Host.Evaluated.Count == 2 && flows.Count == 1 && flows[0].State == RouterFlowState.Pending);
        });
        check("Open TCP flows idle out after two hours", () =>
        {
            var (r, _, _) = OpenTcp();
            r.Clock.Now += PacketRouter.TcpIdle - TimeSpan.FromSeconds(1); r.Router.Sweep();
            Assert(r.Host.ClosedFlows.Count == 0);
            r.Clock.Now += TimeSpan.FromSeconds(1); r.Router.Sweep();
            Assert(r.Host.ClosedFlows.Count == 1);
        });
        check("IPv6 TCP translates through the IPv6 listener with distinct fake endpoints", () =>
        {
            var r = new Rig(); var seen = new HashSet<NetEndpoint>();
            for (var port = 1; port <= 50; port++)
            {
                r.Router.Process(PacketBuilder.Tcp(new(RouterAddresses.Tunnel6, (ushort)(40_000 + port)), Remote6, 1, 0, IpPacket.Syn, 1000, [], []));
                var flow = r.Host.Evaluated[^1];
                r.Router.Decide(flow.Id, true); r.Router.Connected(flow.Id);
                var syn = r.Last(out var packet);
                Assert(Valid(packet) && syn.Destination == RouterAddresses.Tunnel6 && syn.DestinationPort == 7100 && syn.Source.Within(NetAddress.Parse("fd5a:9c33:21e7::1:0:0"), 96));
                Assert(seen.Add(new(syn.Source, syn.SourcePort)));
            }
        });

        check("UDP datagrams queue until allowed, then flow in order", () =>
        {
            var r = new Rig();
            for (byte i = 0; i < 10; i++) r.Router.Process(PacketBuilder.Udp(App4, Remote4, [i]));
            Assert(r.Host.Evaluated.Count == 1 && r.Host.Sent.Count == 0);
            var flow = r.Host.Evaluated[0];
            r.Router.Decide(flow.Id, true);
            Assert(r.Host.Sent.Count == PacketRouter.MaximumQueuedDatagrams && r.Host.Sent.Select(s => s.Payload[0]).SequenceEqual(Enumerable.Range(0, 8).Select(i => (byte)i)));
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [42]));
            Assert(r.Host.Sent.Count == 9 && r.Host.Sent[^1].Payload[0] == 42 && r.Host.Sent[^1].Flow == flow);
        });
        check("UDP replies come only from destinations the application reached", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [1]));
            r.Router.Decide(r.Host.Evaluated[0].Id, true);
            r.Router.DeliverDatagram(App4, Remote4, [7, 7]);
            var reply = r.Last(out var packet);
            Assert(Valid(packet) && reply.Source == Remote4.Address && reply.SourcePort == 443 && reply.DestinationPort == 50_000 && reply.PayloadLength == 2);
            r.Router.DeliverDatagram(App4, new(Remote4.Address, 444), [7]);
            r.Router.DeliverDatagram(App4, new(NetAddress.Parse("203.0.113.9"), 443), [7]);
            Assert(r.Host.Injected.Count == 1 && r.Router.Statistics.Unsolicited == 2);
        });
        check("Blocked UDP is dropped without asking again until revoked", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [1]));
            var flow = r.Host.Evaluated[0];
            r.Router.Decide(flow.Id, false);
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [2]));
            Assert(r.Host.Sent.Count == 0 && r.Host.Evaluated.Count == 1 && r.Router.Statistics.Blocked == 1);
            r.Router.Revoke(flow.Id);
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [3]));
            Assert(r.Host.Evaluated.Count == 2 && r.Host.ClosedFlows.Count == 1);
        });
        check("Each UDP destination is decided separately on one association", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [1]));
            r.Router.Process(PacketBuilder.Udp(App4, new(NetAddress.Parse("198.51.100.1"), 53), [2]));
            Assert(r.Host.Evaluated.Count == 2 && r.Host.Evaluated.All(f => f.Local == App4));
        });
        check("Idle UDP associations release their socket once", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Udp(App4, Remote4, [1]));
            r.Router.Decide(r.Host.Evaluated[0].Id, true);
            r.Clock.Now += PacketRouter.UdpIdle - TimeSpan.FromSeconds(1); r.Router.Sweep();
            Assert(r.Host.ReleasedLocals.Count == 0);
            r.Clock.Now += TimeSpan.FromSeconds(1); r.Router.Sweep();
            Assert(r.Host.ReleasedLocals.Count == 1 && r.Host.ReleasedLocals[0] == App4 && r.Host.ClosedFlows.Count == 1 && r.Router.Flows().Count == 0);
        });
        check("Large UDP replies are fragmented to the tunnel MTU and reassemble", () =>
        {
            var r = new Rig();
            r.Router.Process(PacketBuilder.Udp(App6, Remote6, [1]));
            r.Router.Decide(r.Host.Evaluated[0].Id, true);
            var payload = Enumerable.Range(0, 5000).Select(i => (byte)(i * 7)).ToArray();
            r.Router.DeliverDatagram(App6, Remote6, payload);
            Assert(r.Host.Injected.Count == 4 && r.Host.Injected.All(p => p.Length <= 1500));
            var reassembler = new FragmentReassembler(); byte[]? whole = null;
            foreach (var part in r.Host.Injected) whole = Add(reassembler, part);
            Assert(whole is not null && Valid(whole));
            IpPacket.TryParse(whole, out var header);
            Assert(whole.AsSpan(header.PayloadOffset, header.PayloadLength).SequenceEqual(payload));
        });
        check("Fragmented application datagrams are reassembled before evaluation", () =>
        {
            var r = new Rig();
            var payload = new byte[4000]; new Random(3).NextBytes(payload);
            var parts = PacketBuilder.Fragment(PacketBuilder.Udp(App4, Remote4, payload, 9), 1500, 0);
            for (var i = parts.Count - 1; i >= 0; i--) r.Router.Process(parts[i]);
            Assert(r.Host.Evaluated.Count == 1);
            r.Router.Decide(r.Host.Evaluated[0].Id, true);
            Assert(r.Host.Sent.Count == 1 && r.Host.Sent[0].Payload.AsSpan().SequenceEqual(payload));
        });

        foreach (var v6 in new[] { false, true })
            check((v6 ? "ICMPv6" : "ICMP") + " echo is held, relayed and answered", () =>
            {
                var r = new Rig(); var app = v6 ? App6 : App4; var remote = v6 ? Remote6 : Remote4;
                r.Router.Process(PacketBuilder.Echo(app.Address, remote.Address, false, 0x1234, 1, [1, 2, 3]));
                r.Router.Process(PacketBuilder.Echo(app.Address, remote.Address, false, 0x1234, 2, [1, 2, 3]));
                Assert(r.Host.Evaluated.Count == 1 && r.Host.Echoes.Count == 0);
                var flow = r.Host.Evaluated[0];
                Assert(flow.Protocol == (v6 ? 58 : 1) && flow.Local.Port == 0x1234);
                r.Router.Decide(flow.Id, true);
                Assert(r.Host.Echoes.Count == 1 && r.Host.Echoes[0].Sequence == 2);
                r.Router.DeliverEcho(flow.Id, 2, [1, 2, 3]);
                var reply = r.Last(out var packet);
                Assert(Valid(packet) && reply.IcmpType == (v6 ? 129 : 0) && reply.IcmpIdentifier == 0x1234 && reply.IcmpSequence == 2);
                Assert(reply.Source == remote.Address && reply.Destination == app.Address);
            });
        check("ICMP errors from the host never leave", () =>
        {
            var r = new Rig();
            var original = PacketBuilder.Udp(new(Remote4.Address, 53), App4, [1]);
            IpPacket.TryParse(original, out var header);
            r.Router.Process(PacketBuilder.Unreachable(App4.Address, original, header, UnreachableCode.Port));
            Assert(r.Host.Evaluated.Count == 0 && r.Host.Injected.Count == 0 && r.Router.Statistics.Unsupported == 1);
        });
        check("Protocols without a relay are dropped without evaluation", () =>
        {
            var r = new Rig();
            var gre = PacketBuilder.Udp(App4, Remote4, [1, 2, 3]); gre[9] = 47; Checksum.RefreshIPv4Header(gre);
            r.Router.Process(gre);
            Assert(r.Host.Evaluated.Count == 0 && r.Host.Injected.Count == 0 && r.Router.Statistics.Unsupported == 1);
        });
        check("Host callbacks cannot re-enter the router", () =>
        {
            var r = new Rig(); r.Host.Reenter = true;
            try { r.Router.Process(Syn()); throw new Exception("Re-entry accepted."); }
            catch (InvalidOperationException) { }
        });
    }

    private static byte[] Syn() => PacketBuilder.Tcp(App4, Remote4, 1000, 0, IpPacket.Syn, 64240, [], []);

    private static (Rig Rig, RouterFlow Flow, NetEndpoint Fake) OpenTcp()
    {
        var r = new Rig();
        r.Router.Process(Syn());
        var flow = r.Host.Evaluated[^1];
        r.Router.Decide(flow.Id, true); r.Router.Connected(flow.Id);
        var syn = r.Last(out _);
        return (r, flow, new(syn.Source, syn.SourcePort));
    }

    private static byte[]? Add(FragmentReassembler reassembler, byte[] fragment)
    {
        if (!IpPacket.TryParse(fragment, out var header) || !header.IsFragment) throw new Exception("Not a fragment.");
        return reassembler.Add(fragment, header, DateTimeOffset.UnixEpoch);
    }

    /// <summary>Inserts 8-byte extension headers after the fixed IPv6 header; fragment headers are atomic.</summary>
    private static byte[] Extend(byte[] packet, params byte[] types)
    {
        var result = new byte[packet.Length + 8 * types.Length];
        packet.AsSpan(0, 40).CopyTo(result);
        var upper = packet[6];
        result[6] = types.Length > 0 ? types[0] : upper;
        for (var i = 0; i < types.Length; i++)
        {
            var at = 40 + 8 * i;
            result[at] = i + 1 < types.Length ? types[i + 1] : upper;
            if (types[i] is not (43 or 44)) { result[at + 2] = 1; result[at + 3] = 4; }
        }
        packet.AsSpan(40).CopyTo(result.AsSpan(40 + 8 * types.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)(result.Length - 40));
        return result;
    }

    /// <summary>Verifies the IPv4 header checksum and the transport or ICMP checksum of a whole packet.</summary>
    private static bool Valid(ReadOnlySpan<byte> packet)
    {
        if (!IpPacket.TryParse(packet, out var header) || header.IsFragment) return false;
        if (!header.V6 && Checksum.Fold(Checksum.Add(0, packet[..header.TransportOffset])) != 0) return false;
        var segment = packet[header.TransportOffset..header.Length];
        if (header.Protocol == 17 && !header.V6 && BinaryPrimitives.ReadUInt16BigEndian(segment[6..]) == 0) return true;
        return header.Protocol switch
        {
            6 or 17 or 58 => Checksum.Fold(Checksum.Add(Checksum.Pseudo(header.Source, header.Destination, header.Protocol, segment.Length), segment)) == 0,
            1 => Checksum.Fold(Checksum.Add(0, segment)) == 0,
            _ => true
        };
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Rig
    {
        public readonly Host Host = new();
        public readonly Clock Clock = new();
        public readonly PacketRouter Router;
        public Rig() { Router = new(Host, RouterAddresses.Default(7100, 7100, 1500), Clock); Host.Router = Router; }
        public IpPacket Last(out byte[] packet)
        {
            packet = Host.Injected[^1];
            if (!IpPacket.TryParse(packet, out var header)) throw new Exception("The router injected a malformed packet.");
            return header;
        }
    }

    private sealed class Host : IRouterHost
    {
        public readonly List<byte[]> Injected = [];
        public readonly List<RouterFlow> Evaluated = [], Connecting = [], ClosedFlows = [];
        public readonly List<(RouterFlow Flow, byte[] Payload)> Sent = [];
        public readonly List<(RouterFlow Flow, ushort Sequence, byte[] Data)> Echoes = [];
        public readonly List<NetEndpoint> ReleasedLocals = [];
        public PacketRouter? Router;
        public bool Reenter;
        public void Inject(ReadOnlySpan<byte> packet) => Injected.Add(packet.ToArray());
        public void Evaluate(RouterFlow flow) { Evaluated.Add(flow); if (Reenter) Router!.Decide(flow.Id, true); }
        public void Connect(RouterFlow flow) => Connecting.Add(flow);
        public void Send(RouterFlow flow, byte[] payload) => Sent.Add((flow, payload));
        public void Echo(RouterFlow flow, ushort sequence, byte[] data) => Echoes.Add((flow, sequence, data));
        public readonly List<bool> Aborts = [];
        public void Closed(RouterFlow flow, bool abort) { ClosedFlows.Add(flow); Aborts.Add(abort); }
        public void Released(NetEndpoint local) => ReleasedLocals.Add(local);
    }
}
