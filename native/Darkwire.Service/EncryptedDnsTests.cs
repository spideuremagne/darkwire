using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Darkwire.Service;

/// <summary>The DNS proxy's configuration and log, the resolver list the service keeps, and the record of refused connections.</summary>
internal static class EncryptedDnsTests
{
    private static readonly byte[] Seed = [.. Enumerable.Range(1, 32).Select(i => (byte)i)], KeyId = [9, 9, 9, 9, 1, 2, 3, 4];

    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string reason = "Encrypted DNS invariant failed.") { if (!value) throw new Exception(reason); }
        var quad9 = DnsStamp.FromUrl("https://dns.quad9.net/dns-query", 3); var second = DnsStamp.FromUrl("https://dns11.quad9.net/dns-query", 3);
        var own = DnsStamp.FromUrl("https://dns.example/dns-query");

        check("dnscrypt-proxy runs the policy's servers as static stamps on one loopback port, downloading and logging nothing else", () =>
        {
            var text = DnsCryptProxy.Configuration([new("quad9-doh-ip4-port443-filter-pri", [quad9, second]), new("own-dns.example", [own])], 54321, @"C:\ProgramData\Darkwire\Service\DnsCrypt\dnscrypt-proxy.log");
            var lines = text.Split('\n');
            Assert(lines.Contains("listen_addresses = ['127.0.0.1:54321']") && lines.Contains("server_names = ['quad9-doh-ip4-port443-filter-pri', 'quad9-doh-ip4-port443-filter-pri+2', 'own-dns.example']"));
            Assert(lines.Contains("[static.'quad9-doh-ip4-port443-filter-pri+2']") && lines.Contains($"stamp = '{second}'") && lines.Contains("[static.'own-dns.example']") && lines.Contains($"stamp = '{own}'"));
            // No lists to fetch, no query log, no system DNS and no network probe: everything it does is a lookup it was asked for.
            Assert(!text.Contains("[sources", StringComparison.Ordinal) && !text.Contains("query_log", StringComparison.Ordinal) && lines.Contains("ignore_system_dns = true") && lines.Contains("netprobe_timeout = 0"));
            Assert(lines.Contains("[monitoring_ui]") && lines.Contains("enabled = false") && lines.Contains("odoh_servers = false") && lines.Contains("log_file = 'C:\\ProgramData\\Darkwire\\Service\\DnsCrypt\\dnscrypt-proxy.log'"));
        });
        check("Nothing that could break out of the configuration's quotes is written into it", () =>
        {
            static void Refused(Action action) { try { action(); } catch (Exception error) when (error is InvalidDataException or ArgumentException) { return; } throw new Exception("Unsafe configuration was written."); }
            Refused(() => DnsCryptProxy.Configuration([new("bad'name", [quad9])], 1, "log"));
            Refused(() => DnsCryptProxy.Configuration([new("ok", ["sdns://'injected"])], 1, "log"));
            Refused(() => DnsCryptProxy.Configuration([new("ok", [quad9])], 1, "it's.log"));
            Assert(DnsCryptProxy.Statics([new("a", [quad9, second, own])]).Select(s => s.Name).SequenceEqual(["a", "a+2", "a+3"]));
        });
        check("dnscrypt-proxy's log tells the fastest server, how many answer, a wait for one, and a fatal error", () =>
        {
            var log = "[2026-10-16 12:00:00] [NOTICE] dnscrypt-proxy 2.1.18\n[2026-10-16 12:00:01] [NOTICE] dnscrypt-proxy is waiting for at least one server to be reachable\n" +
                "[2026-10-16 12:00:05] [NOTICE] Server with the lowest initial latency: quad9-doh-ip4-port443-filter-pri+2 (rtt: 14ms), live servers: 3\n";
            Assert(DnsCryptProxy.ReadLog(log) is { Fastest: "quad9-doh-ip4-port443-filter-pri", FastestMs: 14, Live: 3, Waiting: false, Fatal: null });
            Assert(DnsCryptProxy.ReadLog("[2026-10-16 12:00:01] [NOTICE] dnscrypt-proxy is waiting for at least one server to be reachable\n") is { Waiting: true, Fastest: null });
            Assert(DnsCryptProxy.ReadLog("[2026-10-16 12:00:01] [FATAL] listen udp 127.0.0.1:53: bind: address already in use\n").Fatal == "listen udp 127.0.0.1:53: bind: address already in use");
        });
        check("The log tells when the proxy's test of its servers has ended, however many answered, and when it still runs", () =>
        {
            // As dnscrypt-proxy logs them when the tunnel carrying its servers comes up after it started: the DNSCrypt servers
            // time out, leaving the DoH one whose connection waited for it; or they answer only as it comes up, measured slower.
            var missed = "[2026-10-20 11:55:19] [NOTICE] Now listening to 127.0.0.1:58898 [UDP]\n[2026-10-20 11:55:25] [NOTICE] [quad9-dnscrypt-ip4-filter-pri] TIMEOUT\n" +
                "[2026-10-20 11:55:29] [NOTICE] [quad9-doh-ip4-port443-filter-ecs-pri+2] OK (DoH) - rtt: 1162ms\n" +
                "[2026-10-20 11:55:29] [NOTICE] Server with the lowest initial latency: quad9-doh-ip4-port443-filter-ecs-pri+2 (rtt: 1162ms), live servers: 1\n";
            var slow = "[2026-10-20 15:50:29] [NOTICE] -   107ms quad9-doh-ip4-port443-filter-ecs-pri\n[2026-10-20 15:50:29] [NOTICE] -  4776ms quad9-dnscrypt-ip4-filter-pri+3\n" +
                "[2026-10-20 15:50:29] [NOTICE] Server with the lowest initial latency: quad9-doh-ip4-port443-filter-ecs-pri (rtt: 107ms), live servers: 9\n";
            Assert(DnsCryptProxy.TestEnded(DnsCryptProxy.ReadLog(missed)) && DnsCryptProxy.ReadLog(missed).Live == 1);
            Assert(DnsCryptProxy.TestEnded(DnsCryptProxy.ReadLog(slow)) && DnsCryptProxy.ReadLog(slow).Live == 9);
            // Still testing, there is nothing to go on yet; waiting for any server to answer ends a test too.
            Assert(!DnsCryptProxy.TestEnded(DnsCryptProxy.ReadLog("[2026-10-20 11:55:19] [NOTICE] Now listening to 127.0.0.1:58898 [UDP]\n")) && !DnsCryptProxy.TestEnded(null));
            Assert(DnsCryptProxy.TestEnded(DnsCryptProxy.ReadLog("[2026-10-20 11:55:29] [NOTICE] dnscrypt-proxy is waiting for at least one server to be reachable\n")));
        });
        var query = DnsLookup.Query(0x2222, "cdn.jsdelivr.net", DnsLookup.A);
        static int Code(byte[] answer) => answer[3] & 0x0F;
        check("A lookup waits for the DNS proxy to start, and is asked again while the proxy still measures its servers", () =>
        {
            using var proxy = new DnsCryptProxy(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30), supervise: false);
            using var server = new WarmingServer(failures: 2);
            var pending = proxy.AskAsync(query, stream: false, CancellationToken.None);
            Thread.Sleep(300);
            Assert(!pending.IsCompleted, "A lookup failed while the proxy was starting.");
            proxy.UseListener(server.Endpoint);
            Assert(pending.Wait(TimeSpan.FromSeconds(4)) && Code(pending.Result) == 0 && server.Asked == 3, "A lookup failed while the proxy warmed up.");
            Assert(proxy.Status() is { Answered: 1, Failed: 0 });
        });
        check("Once warmed up a server failure is the answer, and a lookup no proxy answers in time fails", () =>
        {
            using var proxy = new DnsCryptProxy(TimeSpan.FromMilliseconds(800), TimeSpan.Zero, supervise: false);
            using var server = new WarmingServer(failures: int.MaxValue);
            proxy.UseListener(server.Endpoint);
            Assert(Code(proxy.AskAsync(query, false, CancellationToken.None).GetAwaiter().GetResult()) == 2 && server.Asked == 1, "A warmed-up proxy's failure was asked again.");
            proxy.UseListener(null);
            var waited = Stopwatch.StartNew();
            var failure = proxy.AskAsync(query, false, CancellationToken.None).GetAwaiter().GetResult();
            Assert(Code(failure) == 2 && DnsAnswers.Answers(query, failure) && waited.Elapsed >= TimeSpan.FromMilliseconds(700), "A lookup without a proxy did not wait its time, or did not fail.");
            Assert(proxy.Status() is { Answered: 0, Failed: 2 });
            // A proxy still warming up when the time runs out fails it too.
            using var warming = new DnsCryptProxy(TimeSpan.FromMilliseconds(800), TimeSpan.FromSeconds(30), supervise: false);
            warming.UseListener(server.Endpoint);
            var before = server.Asked;
            Assert(Code(warming.AskAsync(query, false, CancellationToken.None).GetAwaiter().GetResult()) == 2 && server.Asked - before >= 2 && warming.Status().Failed == 1);
        });
        check("The resolver list is kept only when signed by the project's key for this list, and never replaced by an older one", () =>
        {
            var directory = Path.Combine(Path.GetTempPath(), "darkwire-resolvers-" + Guid.NewGuid().ToString("N"));
            try
            {
                var key = Minisign.PublicKey(Seed, KeyId);
                var served = new Dictionary<string, byte[]>();
                Task Download(Uri uri, string destination, long limit, CancellationToken cancellation)
                {
                    if (!served.TryGetValue(uri.AbsoluteUri, out var data)) throw new HttpRequestException("Not found.");
                    File.WriteAllBytes(destination, data);
                    return Task.CompletedTask;
                }
                void Serve(string url, string list, string comment, byte[]? seed = null)
                {
                    var bytes = Encoding.UTF8.GetBytes(list);
                    served[url] = bytes; served[url + ".minisig"] = Encoding.UTF8.GetBytes(Minisign.Sign(seed ?? Seed, KeyId, bytes, comment));
                }
                var clock = new ManualClock();
                var store = new ResolverListStore(Download, directory, clock, key);
                var changes = 0; store.Changed = () => changes++;
                // The first mirror is down; the second serves the list.
                Serve(ResolverList.Urls[1], List(12, "first"), "timestamp:1790000000\tfile:public-resolvers.md");
                store.CheckAsync(CancellationToken.None).GetAwaiter().GetResult();
                Assert(store.Servers.Count == 12 && store.Catalog() is { Error: null, SignedAt: { } signed } && signed.ToUnixTimeSeconds() == 1790000000 && changes == 1, "The verified list was not kept.");
                // Another key, another file's signature, and an older list are each refused, and the copy held stays.
                Serve(ResolverList.Urls[1], List(13, "forged"), "timestamp:1795000000\tfile:public-resolvers.md", new byte[32]);
                Serve(ResolverList.Urls[2], List(13, "relays"), "timestamp:1795000000\tfile:relays.md");
                Serve(ResolverList.Urls[0], List(13, "older"), "timestamp:1780000000\tfile:public-resolvers.md");
                store.CheckAsync(CancellationToken.None).GetAwaiter().GetResult();
                Assert(store.Servers.Count == 12 && store.Servers[0].Description == "first 0" && store.Catalog().Error is { } error && error.Contains("older") && changes == 1, "A list that should be refused was kept.");
                // A newer signed list replaces it, and a restarted service verifies what it kept before using it.
                Serve(ResolverList.Urls[0], List(14, "newer"), "timestamp:1799000000\tfile:public-resolvers.md");
                store.CheckAsync(CancellationToken.None).GetAwaiter().GetResult();
                Assert(store.Servers.Count == 14 && changes == 2 && new ResolverListStore(Download, directory, clock, key).Servers.Count == 14);
                File.AppendAllText(Path.Combine(directory, ResolverList.FileName), "\n## tampered\n\nx\n\n" + quad9 + "\n");
                Assert(new ResolverListStore(Download, directory, clock, key).Servers.Count == 0, "A tampered stored list was used.");
                Assert(new ResolverListStore(Download, directory, clock).Servers.Count == 0, "A list signed by another key passed for the project's.");
            }
            finally { Directory.Delete(directory, true); }
        });
        check("Refusals are kept once for each program, destination and reason, newest first, the oldest let go", () =>
        {
            var log = new BlockedFlowLog(); var start = DateTimeOffset.UnixEpoch;
            BlockedFlow Flow(int i, string reason = "No rule allows it") => new(start.AddSeconds(i), @"C:\Apps\game.exe", "203.0.113." + (i % 250), 443, "TCP", TrafficDirection.Outbound, reason);
            log.Record(Flow(1)); log.Record(Flow(2) with { RemoteAddress = "203.0.113.1", Time = start.AddSeconds(5) });
            Assert(log.Snapshot() is [{ Count: 2 } only] && only.Time == start.AddSeconds(5));
            log.Record(Flow(1, "FireHOL Level 1"));
            Assert(log.Snapshot().Count == 2 && log.Snapshot()[0].Reason == "No rule allows it");
            for (var i = 10; i < 400; i++) log.Record(Flow(i));
            var kept = log.Snapshot();
            Assert(kept.Count == BlockedFlowLog.Capacity && kept[0].Time == start.AddSeconds(399) && kept.Zip(kept.Skip(1)).All(p => p.First.Time >= p.Second.Time));
        });
    }

    /// <summary>A resolver list of DoH servers named alpha-0, alpha-1 and so on, each described by a word and its number.</summary>
    private static string List(int count, string word) => "# public-resolvers\n\nTest list.\n\n" +
        string.Concat(Enumerable.Range(0, count).Select(i => $"## alpha-{i}\n\n{word} {i}\n\n{DnsStamp.FromUrl($"https://alpha{i}.example/dns-query", 1)}\n\n"));

    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>A loopback DNS server failing the first lookups it is asked, as dnscrypt-proxy does until it has measured its servers.</summary>
    private sealed class WarmingServer : IDisposable
    {
        private readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly int failures;
        private int asked;

        public WarmingServer(int failures)
        {
            this.failures = failures;
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _ = Task.Run(ServeAsync);
        }

        public IPEndPoint Endpoint => (IPEndPoint)socket.LocalEndPoint!;
        public int Asked => Volatile.Read(ref asked);

        private async Task ServeAsync()
        {
            var buffer = new byte[512];
            while (true)
            {
                SocketReceiveFromResult received;
                try { received = await socket.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0)); }
                // A client gone before its answer arrived.
                catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionReset) { continue; }
                catch (Exception error) when (error is SocketException or ObjectDisposedException) { return; }
                var answer = buffer[..received.ReceivedBytes];
                answer[2] |= 0x80;
                answer[3] = (byte)(answer[3] & 0xF0 | (Interlocked.Increment(ref asked) <= failures ? 2 : 0));
                try { await socket.SendToAsync(answer, received.RemoteEndPoint); }
                catch (Exception error) when (error is SocketException or ObjectDisposedException) { return; }
            }
        }

        public void Dispose() => socket.Dispose();
    }
}
