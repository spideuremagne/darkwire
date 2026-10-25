using Darkwire.Vpn;
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

/// <summary>DNS filtering in the router: which messages are answered locally, what the answer says, and that blocked lookups never leave.</summary>
internal static class DnsChecks
{
    private static readonly NetEndpoint App4 = new(RouterAddresses.Tunnel4, 50_000), Server = new(NetAddress.Parse("198.51.100.53"), 53);
    private static void Expect(bool value, string message = "DNS filtering invariant failed.") { if (!value) throw new Exception(message); }
    private static ushort Word(byte[] message, int offset) => BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset));

    /// <summary>A recursive query for one name, optionally with an EDNS OPT record as stub resolvers send.</summary>
    private static byte[] Query(string name, ushort id = 0x1234, ushort type = 1, bool edns = false)
    {
        List<byte> bytes = [(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, (byte)(edns ? 1 : 0)];
        foreach (var label in name.Split('.')) { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.AddRange([0, (byte)(type >> 8), (byte)type, 0, 1]);
        if (edns) bytes.AddRange([0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        return [.. bytes];
    }

    public static void Run(Action<string, Action> check, bool native)
    {
        check("A blocked lookup is answered as nonexistent, echoing its ID, flags and question", () =>
        {
            var query = Query("Ads.Example.com", edns: true); string? asked = null;
            var answer = DnsAnswers.Filter(query, name => (asked = name) == "ads.example.com")!;
            Expect(asked == "ads.example.com" && answer.Length == 33 && Word(answer, 0) == 0x1234 && Word(answer, 2) == 0x8183, "Unexpected header.");
            Expect(Word(answer, 4) == 1 && Word(answer, 6) == 0 && Word(answer, 8) == 0 && Word(answer, 10) == 0 && answer.AsSpan(12).SequenceEqual(query.AsSpan(12, 21)));
            var plain = Query("ads.example.com"); plain[2] = 0; plain[3] = 0x10;
            Expect(Word(DnsAnswers.Filter(plain, _ => true)!, 2) == 0x8093, "Recursion and checking flags were not carried as asked.");
        });
        check("Allowed lookups, responses and other opcodes pass unread", () =>
        {
            Expect(DnsAnswers.Filter(Query("example.org"), _ => false) is null);
            var response = Query("ads.example.com"); response[2] |= 0x80;
            var update = Query("ads.example.com"); update[2] = 5 << 3;
            Expect(DnsAnswers.Filter(response, _ => true) is null && DnsAnswers.Filter(update, _ => true) is null);
        });
        check("Queries the filter cannot read are refused, and runts dropped", () =>
        {
            var compressed = Query("a.b"); compressed = [.. compressed[..12], 0xC0, 0x0C, 0, 1, 0, 1];
            var two = Query("ads.example.com"); two[5] = 2;
            var answered = Query("ads.example.com"); answered[7] = 1;
            var truncated = Query("ads.example.com")[..^3];
            var wide = Query("ads.example.com"); wide[12] = 64;
            var lengthy = Query(string.Join('.', Enumerable.Repeat(new string('a', 63), 4)) + ".com");
            foreach (var malformed in new[] { compressed, two, answered, truncated, wide, lengthy })
            {
                var refusal = DnsAnswers.Filter(malformed, _ => false)!;
                Expect(refusal is { Length: 12 } && Word(refusal, 0) == 0x1234 && Word(refusal, 2) == 0x8181 && Word(refusal, 4) == 0, "A malformed query was not refused.");
            }
            Expect(DnsAnswers.Filter(new byte[5], _ => true) is { Length: 0 });
        });
        check("The relay answers a blocked lookup itself and opens no socket for it", () =>
        {
            using var rig = new VpnRouteChecks.RelayRig(_ => new(new Egress(1, 1, IPAddress.Parse("192.0.2.10"), 24, 0)));
            rig.Relay.BlockedNames = name => name.EndsWith("ads.example.com", StringComparison.Ordinal);
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("x.ads.example.com", id: 77)));
            rig.Router.Decide(rig.Next().Id, true);
            bool Reply(IpPacket packet) => packet.Protocol == 17 && packet.Source == Server.Address && packet.SourcePort == 53 && packet.Destination == App4.Address && packet.DestinationPort == App4.Port;
            var answer = rig.Payload(Reply);
            Expect(Word(answer, 0) == 77 && (Word(answer, 2) & 0xF) == 3 && rig.Relay.Associations == 0);
        });
        check("A blocked lookup sent to Darkwire's resolver is answered from it, never relayed to the server behind it", () =>
        {
            var resolver = new NetEndpoint(RouterAddresses.Resolver4, 53);
            using var rig = new VpnRouteChecks.RelayRig(_ => new(new Egress(1, 1, IPAddress.Parse("192.0.2.10"), 24, 0), new(NetAddress.Parse("192.0.2.53"), 53)));
            rig.Relay.BlockedNames = name => name == "ads.example.com";
            rig.Router.Process(PacketBuilder.Udp(App4, resolver, Query("ads.example.com", id: 9)));
            rig.Router.Decide(rig.Next().Id, true);
            var answer = rig.Payload(p => p.Protocol == 17 && p.Source == resolver.Address && p.SourcePort == 53 && p.Destination == App4.Address && p.DestinationPort == App4.Port);
            Expect(Word(answer, 0) == 9 && (Word(answer, 2) & 0xF) == 3 && rig.Relay.Associations == 0);
        });
        check("A name answered locally gets the loopback address for A, AAAA and ANY, and an empty answer for other types", () =>
        {
            static bool Local(string name) => name == "blocked.example";
            var a = DnsAnswers.Filter(Query("Blocked.Example", id: 5, edns: true), name => true, Local)!;
            // One A record owned by the question's name, five minutes, 127.0.0.1; the loopback answer wins over a list's block.
            Expect(Word(a, 0) == 5 && Word(a, 2) == 0x8180 && Word(a, 4) == 1 && Word(a, 6) == 1 && Word(a, 8) == 0 && Word(a, 10) == 0, "Unexpected A header.");
            var record = a.AsSpan(12 + 17 + 4);
            Expect(Word(record.ToArray(), 0) == 0xC00C && Word(record.ToArray(), 2) == 1 && Word(record.ToArray(), 4) == 1 && BinaryPrimitives.ReadUInt32BigEndian(record[6..]) == DnsAnswers.LoopbackTtl &&
                Word(record.ToArray(), 10) == 4 && record.Slice(12, 4).SequenceEqual(IPAddress.Loopback.GetAddressBytes()) && record.Length == 16);
            var six = DnsAnswers.Filter(Query("blocked.example", type: 28), null, Local)!;
            Expect(Word(six, 6) == 1 && six.AsSpan(six.Length - 16).SequenceEqual(IPAddress.IPv6Loopback.GetAddressBytes()) && Word(six, six.Length - 18) == 16);
            Expect(DnsAnswers.Filter(Query("blocked.example", type: 255), null, Local) is { } any && Word(any, 6) == 2 && any.Length == 12 + 21 + 16 + 28);
            Expect(DnsAnswers.Filter(Query("blocked.example", type: 15), null, Local) is { } mx && Word(mx, 2) == 0x8180 && Word(mx, 6) == 0 && mx.Length == 12 + 21);
            Expect(DnsAnswers.Filter(Query("other.example"), null, Local) is null && DnsAnswers.Filter(Query("x.blocked.example"), null, Local) is null);
        });
        check("Queries are read for their name, failed with a server failure, sent on validating, and matched to their answers", () =>
        {
            Expect(DnsAnswers.QuestionName(Query("WWW.Example.org")) == "www.example.org");
            var response = Query("example.org"); response[2] |= 0x80;
            Expect(DnsAnswers.QuestionName(response) is null && DnsAnswers.QuestionName(new byte[4]) is null);
            var failure = DnsAnswers.Failure(Query("example.org", id: 77, edns: true))!;
            Expect(Word(failure, 0) == 77 && Word(failure, 2) == 0x8182 && Word(failure, 4) == 1 && failure.Length == 12 + 17);
            var unchecked_ = Query("example.org"); unchecked_[3] |= 0x10;
            var validating = DnsAnswers.Validating(unchecked_);
            Expect((validating[3] & 0x10) == 0 && (unchecked_[3] & 0x10) != 0 && validating.AsSpan(4).SequenceEqual(unchecked_.AsSpan(4)));
            var query = Query("Example.org", id: 3); var answer = Query("eXAMPLE.ORG", id: 3); answer[2] |= 0x80;
            Expect(DnsAnswers.Answers(query, answer) && !DnsAnswers.Answers(query, Query("example.org", id: 3)));
            var other = Query("example.org", id: 4); other[2] |= 0x80; var aaaa = Query("example.org", id: 3, type: 28); aaaa[2] |= 0x80; var elsewhere = Query("example.net", id: 3); elsewhere[2] |= 0x80;
            Expect(!DnsAnswers.Answers(query, other) && !DnsAnswers.Answers(query, aaaa) && !DnsAnswers.Answers(query, elsewhere));
        });
        check("Lookups for Darkwire's resolver bound for the internet go to the forwarder; local ones fail without a server for them", () =>
        {
            var resolver = new NetEndpoint(RouterAddresses.Resolver4, 53);
            var forwarder = new Forwarder(name => !name.EndsWith(".lan", StringComparison.Ordinal));
            using var rig = new VpnRouteChecks.RelayRig(_ => null);
            rig.Relay.Forwarder = forwarder;
            rig.Router.Process(PacketBuilder.Udp(App4, resolver, Query("example.org", id: 21)));
            rig.Router.Decide(rig.Next().Id, true);
            bool Reply(IpPacket p) => p.Protocol == 17 && p.Source == resolver.Address && p.SourcePort == 53 && p.Destination == App4.Address;
            var answer = rig.Payload(Reply);
            Expect(Word(answer, 0) == 21 && (Word(answer, 2) & 0x8000) != 0 && forwarder.Asked.Count == 1 && rig.Relay.Associations == 0, "The forwarder did not answer.");
            rig.Router.Process(PacketBuilder.Udp(App4, resolver, Query("printer.lan", id: 22)));
            SpinWait.SpinUntil(() => rig.Count(Reply) == 2, TimeSpan.FromSeconds(5));
            Expect(rig.Count(Reply) == 2 && forwarder.Asked.Count == 1, "A local name reached the forwarder.");
        });
        check("Plain DNS leaving physically is forwarded too, from the server asked; a tunnel's DNS and Darkwire's own are not", () =>
        {
            var egress = new Egress(1, 1, IPAddress.Parse("192.0.2.10"), 24, 0);
            var forwarder = new Forwarder(_ => true);
            FlowRoute route = new(egress);
            using var rig = new VpnRouteChecks.RelayRig(_ => route);
            rig.Relay.Forwarder = forwarder;
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("example.org", id: 31)));
            rig.Router.Decide(rig.Next().Id, true);
            var answer = rig.Payload(p => p.Protocol == 17 && p.Source == Server.Address && p.SourcePort == 53 && p.Destination == App4.Address);
            Expect(Word(answer, 0) == 31 && forwarder.Asked.Count == 1);
            // Routes are asked again for each datagram: a tunnel's lookup and Darkwire's own leave unread.
            route = new(egress, null, true);
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("example.org", id: 32)));
            route = new(egress) { Own = true };
            rig.Relay.BlockedNames = _ => true;
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("example.org", id: 33)));
            Thread.Sleep(300);
            Expect(forwarder.Asked.Count == 1 && rig.Count(p => p.Protocol == 17 && p.Destination == App4.Address) == 1, "A tunnel's or Darkwire's own lookup was answered here.");
        });
        if (!native) return;
        var loopback = new Egress(1, (uint)NetworkInterface.LoopbackInterfaceIndex, IPAddress.Loopback, 8, 0);
        check("Native relay sends allowed lookups on and keeps blocked ones from the resolver", () =>
        {
            using var resolver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            resolver.Bind(new IPEndPoint(IPAddress.Loopback, 0)); resolver.ReceiveTimeout = 2000;
            var target = new NetEndpoint(NetAddress.Parse("127.0.0.1"), (ushort)((IPEndPoint)resolver.LocalEndPoint!).Port);
            using var rig = new VpnRouteChecks.RelayRig(_ => new(loopback, target, true));
            rig.Relay.BlockedNames = name => name == "ads.example.com";
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("ads.example.com", id: 1)));
            rig.Router.Decide(rig.Next().Id, true);
            rig.Router.Process(PacketBuilder.Udp(App4, Server, Query("example.org", id: 2)));
            var buffer = new byte[512]; EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var count = resolver.ReceiveFrom(buffer, ref from);
            Expect(count == Query("example.org").Length && Word(buffer, 0) == 2, "The allowed lookup did not reach the resolver.");
            Expect(Word(rig.Payload(p => p.Protocol == 17), 0) == 1);
            try { resolver.ReceiveFrom(buffer, ref from); throw new Exception("A blocked lookup reached the resolver."); }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.TimedOut) { }
        });
        check("Native DNS over TCP is filtered message by message, answers and responses each whole", () =>
        {
            using var applications = new TcpListener(IPAddress.Loopback, 0); applications.Start();
            using var servers = new TcpListener(IPAddress.Loopback, 0); servers.Start();
            using var application = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5000 };
            application.Connect(applications.LocalEndpoint); using var accepted = applications.AcceptSocket();
            using var outbound = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            outbound.Connect(servers.LocalEndpoint); using var server = servers.AcceptSocket(); server.ReceiveTimeout = 5000;
            var relay = DnsAnswers.RelayTcpAsync(accepted, outbound, DnsAnswers.Filtering(name => name == "ads.example.com", null), TimeSpan.FromSeconds(30), CancellationToken.None);
            static byte[] Framed(byte[] message) { var framed = new byte[message.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length); message.CopyTo(framed, 2); return framed; }
            static byte[] Read(Socket socket)
            {
                var prefix = new byte[2]; for (var read = 0; read < 2;) read += socket.Receive(prefix, read, 2 - read, SocketFlags.None) is > 0 and var n ? n : throw new IOException("Closed.");
                var message = new byte[Word(prefix, 0)]; for (var read = 0; read < message.Length;) read += socket.Receive(message, read, message.Length - read, SocketFlags.None) is > 0 and var n ? n : throw new IOException("Closed.");
                return message;
            }
            application.Send([.. Framed(Query("ads.example.com", id: 1)), .. Framed(Query("example.org", id: 2))]);
            var forwarded = Read(server);
            Expect(Word(forwarded, 0) == 2, "The server saw a blocked query.");
            forwarded[2] |= 0x80; server.Send(Framed(forwarded));
            var replies = new[] { Read(application), Read(application) }.ToDictionary(m => Word(m, 0));
            Expect(replies.Count == 2 && (Word(replies[1], 2) & 0xF) == 3 && replies[2].SequenceEqual(forwarded));
            application.Shutdown(SocketShutdown.Send);
            Expect(server.Receive(new byte[1]) == 0, "The application's close did not reach the server.");
            server.Shutdown(SocketShutdown.Send);
            Expect(relay.Wait(TimeSpan.FromSeconds(5)) && application.Receive(new byte[1]) == 0);
        });
        check("Native DNS over TCP with no server behind it answers locally, through the forwarder, or with a server failure", () =>
        {
            using var applications = new TcpListener(IPAddress.Loopback, 0); applications.Start();
            using var application = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5000 };
            application.Connect(applications.LocalEndpoint); using var accepted = applications.AcceptSocket();
            var forwarder = new Forwarder(name => name != "printer.lan");
            async ValueTask<byte[]?> Answer(byte[] query) => DnsAnswers.Filter(query, name => name == "ads.example.com") ??
                (DnsAnswers.QuestionName(query) is { } name && forwarder.Answers(name) ? await forwarder.AskAsync(query, true, CancellationToken.None) : null);
            var relay = DnsAnswers.RelayTcpAsync(accepted, null, Answer, TimeSpan.FromSeconds(30), CancellationToken.None);
            static byte[] Framed(byte[] message) { var framed = new byte[message.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length); message.CopyTo(framed, 2); return framed; }
            static byte[] Read(Socket socket)
            {
                var prefix = new byte[2]; for (var read = 0; read < 2;) read += socket.Receive(prefix, read, 2 - read, SocketFlags.None) is > 0 and var n ? n : throw new IOException("Closed.");
                var message = new byte[Word(prefix, 0)]; for (var read = 0; read < message.Length;) read += socket.Receive(message, read, message.Length - read, SocketFlags.None) is > 0 and var n ? n : throw new IOException("Closed.");
                return message;
            }
            application.Send([.. Framed(Query("ads.example.com", id: 1)), .. Framed(Query("example.org", id: 2)), .. Framed(Query("printer.lan", id: 3))]);
            var replies = new[] { Read(application), Read(application), Read(application) }.ToDictionary(m => Word(m, 0));
            Expect((Word(replies[1], 2) & 0xF) == 3 && (Word(replies[2], 2) & 0x8000) != 0 && (Word(replies[2], 2) & 0xF) == 0 && (Word(replies[3], 2) & 0xF) == 2 && forwarder.Asked.Count == 1);
            application.Shutdown(SocketShutdown.Send);
            Expect(relay.Wait(TimeSpan.FromSeconds(5)) && application.Receive(new byte[1]) == 0, "The local stream did not close with the application.");
        });
    }

    /// <summary>A forwarder answering what it is told to with the query echoed back as a response.</summary>
    private sealed class Forwarder(Func<string, bool> answers) : IDnsForwarder
    {
        public readonly System.Collections.Concurrent.ConcurrentQueue<byte[]> Asked = new();
        public bool Answers(string name) => answers(name);
        public Task<byte[]> AskAsync(byte[] query, bool stream, CancellationToken cancellation)
        {
            Asked.Enqueue(query);
            var answer = query.ToArray(); answer[2] |= 0x80; answer[3] |= 0x80;
            return Task.FromResult(answer);
        }
    }
}
