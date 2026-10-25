using Darkwire.Vpn;
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

/// <summary>The service's own lookups of VPN endpoint names: the questions it asks and which answers it accepts.</summary>
internal static class DnsLookupChecks
{
    private const string Host = "vpn.example.net";
    private static readonly byte[] Asked = [0xC0, 12];
    private static void Expect(bool value, string message = "DNS lookup invariant failed.") { if (!value) throw new Exception(message); }
    private static ushort Word(byte[] message, int offset) => BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset));

    private static byte[] Labels(string name)
    {
        List<byte> bytes = [];
        foreach (var label in name.Split('.')) { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.Add(0);
        return [.. bytes];
    }

    /// <summary>A response echoing the query's ID and question, with the given flags (the response bit added) and answer records.</summary>
    private static byte[] Response(byte[] query, ushort flags, params byte[][] records)
    {
        var response = new List<byte>(query);
        response[2] = (byte)(0x80 | flags >> 8); response[3] = (byte)flags;
        response[6] = (byte)(records.Length >> 8); response[7] = (byte)records.Length;
        foreach (var record in records) response.AddRange(record);
        return [.. response];
    }

    private static byte[] Record(byte[] owner, ushort type, byte[] data) =>
        [.. owner, (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length, .. data];

    private static (DnsReply Reply, List<IPAddress> Found) Read(byte[] message, ushort id = 7, string name = Host, ushort type = DnsLookup.A)
    {
        List<IPAddress> found = [];
        return (DnsLookup.Read(message, id, name, type, found), found);
    }

    public static void Run(Action<string, Action> check, bool native)
    {
        var query = DnsLookup.Query(7, Host, DnsLookup.A);
        check("Endpoint lookups ask one recursive question per address type", () =>
        {
            var aaaa = DnsLookup.Query(0xBEEF, Host, DnsLookup.Aaaa);
            Expect(aaaa.Length == 33 && Word(aaaa, 0) == 0xBEEF && Word(aaaa, 2) == 0x0100 && Word(aaaa, 4) == 1 && Word(aaaa, 6) == 0 && Word(aaaa, 8) == 0 && Word(aaaa, 10) == 0);
            Expect(DnsAnswers.Question(aaaa) is (Host, 33) && Word(aaaa, 29) == DnsLookup.Aaaa && Word(aaaa, 31) == 1 && Word(query, 29) == DnsLookup.A);
            foreach (var bad in new[] { "", "a..b", new string('a', 64) + ".com", "bad host.com", "trailing.", "café.example" })
                try { DnsLookup.Query(1, bad, DnsLookup.A); throw new Exception("Accepted " + bad); } catch (ArgumentException) { }
        });
        check("An answer gives the asked name's addresses, following its aliases, and nothing about other names", () =>
        {
            // The CNAME's owner points at the question; the A record's owner points into the CNAME's data at offset 45.
            var response = Response(query, 0x0180, Record(Asked, 5, Labels("edge.example.net")), Record([0xC0, 45], DnsLookup.A, [203, 0, 113, 9]),
                Record(Labels("other.example.org"), DnsLookup.A, [198, 51, 100, 66]), Record(Labels("edge.example.net"), DnsLookup.Aaaa, new byte[16]));
            Expect(Read(response) is (DnsReply.Answered, [var address]) && address.Equals(IPAddress.Parse("203.0.113.9")));
            var six = DnsLookup.Query(9, "VPN.example.net", DnsLookup.Aaaa);
            Expect(Read(Response(six, 0x0180, Record(Asked, DnsLookup.Aaaa, IPAddress.Parse("2001:db8::9").GetAddressBytes())), 9, Host, DnsLookup.Aaaa) is (DnsReply.Answered, [var v6]) &&
                v6.Equals(IPAddress.Parse("2001:db8::9")));
        });
        check("No address and no such name are answers; errors and truncation leave the question to another server", () =>
        {
            Expect(Read(Response(query, 0x0180)) is (DnsReply.Answered, []));
            Expect(Read(Response(query, 0x0183)) is (DnsReply.Answered, []));
            Expect(Read(Response(query, 0x0180, Record(Asked, DnsLookup.Aaaa, new byte[16]))) is (DnsReply.Answered, []));
            foreach (var flags in new ushort[] { 0x0182, 0x0185, 0x0380 })
                Expect(Read(Response(query, flags, Record(Asked, DnsLookup.A, [203, 0, 113, 9]))) is (DnsReply.Failed, []), $"Flags {flags:X4} were accepted.");
        });
        check("Messages answering another question are not the answer", () =>
        {
            var answer = Response(query, 0x0180, Record(Asked, DnsLookup.A, [203, 0, 113, 9]));
            Expect(Read(answer, id: 8).Reply == DnsReply.Unrelated && Read(answer, name: "other.example.net").Reply == DnsReply.Unrelated && Read(answer, type: DnsLookup.Aaaa).Reply == DnsReply.Unrelated);
            var unanswered = (byte[])answer.Clone(); unanswered[2] &= 0x7F;
            var notify = (byte[])answer.Clone(); notify[2] |= 4 << 3;
            Expect(Read(unanswered).Reply == DnsReply.Unrelated && Read(notify).Reply == DnsReply.Unrelated && Read(answer[..11]).Reply == DnsReply.Unrelated);
        });
        check("Unreadable answers fail the server", () =>
        {
            var cut = Response(query, 0x0180, Record(Asked, DnsLookup.A, [203, 0, 113, 9]));
            var wide = Response(query, 0x0180, Record(Asked, DnsLookup.A, [203, 0, 113, 9, 1]));
            var looped = Response(query, 0x0180, Record([0xC0, 33], DnsLookup.A, [203, 0, 113, 9]));
            var aliases = Response(query, 0x0180, Record(Asked, 5, Labels("edge.example.net")), Record(Labels("edge.example.net"), 5, Labels(Host)));
            var extended = Response(query, 0x0180, Record([0x41, 0], DnsLookup.A, [203, 0, 113, 9]));
            var questionless = Response(query, 0x0180); questionless[5] = 0;
            foreach (var (name, message) in new[] { ("cut", cut[..^1]), ("wide", wide), ("looped", looped), ("aliases", aliases), ("extended", extended), ("questionless", questionless) })
                Expect(Read(message) is (DnsReply.Failed, []), "The " + name + " answer was accepted.");
        });
        if (!native) return;
        var loopback = new Egress(1, (uint)NetworkInterface.LoopbackInterfaceIndex, IPAddress.Loopback, 8, 0);
        static Socket Server()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 5000 };
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return socket;
        }
        static (byte[] Query, EndPoint From) Receive(Socket server)
        {
            var buffer = new byte[512]; EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var count = server.ReceiveFrom(buffer, ref from);
            return (buffer[..count], from);
        }
        static byte[] Answer(byte[] query, IPAddress v4, IPAddress v6)
        {
            var type = Word(query, query.Length - 4);
            return Response(query, 0x0180, Record(Asked, type, (type == DnsLookup.A ? v4 : v6).GetAddressBytes()));
        }
        check("Native lookup asks each server from a socket connected to it, passes failing and silent servers, and ignores strangers", () =>
        {
            using Socket failing = Server(), silent = Server(), answering = Server(), stranger = Server();
            var serving = new[]
            {
                Task.Run(() => { for (var i = 0; i < 2; i++) { var (asked, from) = Receive(failing); failing.SendTo(Response(asked, 0x0182), from); } }),
                Task.Run(() =>
                {
                    for (var i = 0; i < 2; i++)
                    {
                        var (asked, from) = Receive(answering);
                        stranger.SendTo(Answer(asked, IPAddress.Parse("192.0.2.99"), IPAddress.Parse("2001:db8::99")), from);
                        answering.SendTo(Answer(asked, IPAddress.Parse("203.0.113.9"), IPAddress.Parse("2001:db8::9")), from);
                    }
                })
            };
            IPEndPoint[] servers = [.. new[] { failing, silent, answering }.Select(s => (IPEndPoint)s.LocalEndPoint!)];
            var found = DnsLookup.ResolveAsync(Host, servers, _ => loopback, TimeSpan.FromMilliseconds(500), CancellationToken.None).GetAwaiter().GetResult();
            Expect(found.Select(a => a.ToString()).SequenceEqual(["203.0.113.9", "2001:db8::9"]), string.Join(", ", found));
            Expect(Task.WaitAll(serving, TimeSpan.FromSeconds(5)), "A fake server did not finish.");
        });
        check("Native lookup without a server that gives an address fails", () =>
        {
            using var silent = Server();
            try
            {
                DnsLookup.ResolveAsync(Host, [(IPEndPoint)silent.LocalEndPoint!], _ => loopback, TimeSpan.FromMilliseconds(200), CancellationToken.None).GetAwaiter().GetResult();
                throw new Exception("A lookup without an answer succeeded.");
            }
            catch (IOException) { }
            try { DnsLookup.ResolveAsync(Host, [], _ => loopback, TimeSpan.FromMilliseconds(200), CancellationToken.None).GetAwaiter().GetResult(); throw new Exception("A lookup without servers succeeded."); }
            catch (IOException) { }
        });
    }
}
