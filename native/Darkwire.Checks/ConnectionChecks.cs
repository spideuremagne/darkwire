using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Host;
using System.Net;

internal static class ConnectionChecks
{
    internal static void Run(Action<string, Action> check)
    {
        static void Expect(bool value) { if (!value) throw new Exception("Assertion failed"); }
        var connection = new Connection("App", @"C:\App.exe", 42, "203.0.113.8", 443, 53001, "TCP", TrafficDirection.Unknown, LocalAddress: "192.0.2.1");
        check("Known DNS name includes actual remote IP", () => Expect((connection with { Hostname = "example.com" }).Destination == "example.com (203.0.113.8)"));
        check("IP-only destination stays IP-only by default", () => Expect(connection.Destination == "203.0.113.8" && !new AppState().ReverseDnsEnabled));
        check("Reverse DNS follows IP in parentheses", () => Expect((connection with { ReverseHostname = "ptr.example.com" }).Destination == "203.0.113.8 (ptr.example.com)"));
        check("Known DNS name takes precedence over reverse DNS", () => Expect((connection with { Hostname = "example.com", ReverseHostname = "ptr.example.com" }).Destination == "example.com (203.0.113.8)"));
        check("Reverse DNS cannot satisfy domain blocklist policy", () => Expect(!BlocklistParser.Matches("example.com", connection with { ReverseHostname = "ptr.example.com" })));
        check("IPv6 endpoint uses brackets", () => Expect((connection with { RemoteAddress = "2001:db8::8" }).Endpoint == "[2001:db8::8]:443"));
        check("Established TCP direction is never guessed", () => Expect(new ConnectionDirectionTracker().Apply([connection])[0].Direction == TrafficDirection.Unknown));
        check("Native TCP states use Windows SDK SYN_SENT and SYN_RCVD values", () =>
        {
            Expect(WindowsTelemetry.DirectionForTcpState(3) == TrafficDirection.Outbound);
            Expect(WindowsTelemetry.DirectionForTcpState(4) == TrafficDirection.Inbound);
            Expect(new[] { 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 99 }.All(s => WindowsTelemetry.DirectionForTcpState(s) == TrafficDirection.Unknown));
        });
        check("Inbound handshake direction survives established snapshot", () =>
        {
            var tracker = new ConnectionDirectionTracker(); tracker.Apply([connection with { Direction = TrafficDirection.Inbound }]);
            Expect(tracker.Apply([connection])[0].Direction == TrafficDirection.Inbound);
        });
        check("Direction never crosses process or endpoint identities", () =>
        {
            var tracker = new ConnectionDirectionTracker(); tracker.Apply([connection with { Direction = TrafficDirection.Inbound }]);
            Expect(tracker.Apply([connection with { ProcessId = 43 }, connection with { RemotePort = 80 }]).All(c => c.Direction == TrafficDirection.Unknown));
        });
        check("Direction expires after tuple disappears", () =>
        {
            var tracker = new ConnectionDirectionTracker(); tracker.Apply([connection with { Direction = TrafficDirection.Outbound }]); tracker.Apply([]);
            Expect(tracker.Apply([connection])[0].Direction == TrafficDirection.Unknown);
        });
        check("PTR cache coalesces duplicate concurrent requests", () =>
        {
            var calls = 0; var answer = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var resolver = new ReverseDnsResolver((_, _) => { Interlocked.Increment(ref calls); return answer.Task; });
            var first = resolver.ResolveAsync("203.0.113.8"); var second = resolver.ResolveAsync("203.0.113.8"); answer.SetResult("ptr.example.com.");
            Expect(Task.WhenAll(first, second).GetAwaiter().GetResult().All(v => v == "ptr.example.com") && calls == 1);
        });
        check("Negative PTR answers are cached and retried after expiry", () =>
        {
            var calls = 0; var time = DateTimeOffset.UtcNow;
            var resolver = new ReverseDnsResolver((_, _) => { calls++; return Task.FromResult<string?>(null); }, () => time);
            resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); Expect(calls == 1);
            time = time.AddMinutes(3); resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); Expect(calls == 2);
        });
        check("PTR cache capacity stays bounded", () =>
        {
            var resolver = new ReverseDnsResolver((_, _) => Task.FromResult<string?>("ptr.example.com"), capacity: 2);
            foreach (var ip in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" }) resolver.ResolveAsync(ip).GetAwaiter().GetResult();
            Expect(new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" }.Count(ip => resolver.TryGet(ip, out _)) == 2);
        });
        check("Positive PTR answers expire after fifteen minutes", () =>
        {
            var calls = 0; var time = DateTimeOffset.UtcNow;
            var resolver = new ReverseDnsResolver((_, _) => { calls++; return Task.FromResult<string?>("ptr.example.com"); }, () => time);
            resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); time = time.AddMinutes(14);
            resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); Expect(calls == 1);
            time = time.AddMinutes(2); resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult(); Expect(calls == 2);
        });
        check("Canceled PTR request is not cached and can be retried", () =>
        {
            var calls = 0; var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var resolver = new ReverseDnsResolver(async (_, token) => { calls++; started.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return "never.example"; });
            using var cancellation = new CancellationTokenSource(); var request = resolver.ResolveAsync("203.0.113.8", cancellation.Token);
            started.Task.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult(); cancellation.Cancel();
            Expect(request.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult() is null && !resolver.TryGet("203.0.113.8", out _));
            using var secondCancellation = new CancellationTokenSource(); var second = resolver.ResolveAsync("203.0.113.8", secondCancellation.Token); secondCancellation.Cancel();
            second.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult(); Expect(calls == 2);
        });
        check("PTR lookup rejects invalid display hostnames", () =>
        {
            var resolver = new ReverseDnsResolver((_, _) => Task.FromResult<string?>("bad\nname.example"));
            Expect(resolver.ResolveAsync("203.0.113.8").GetAwaiter().GetResult() is null);
        });
        check("PTR timeouts return without blocking indefinitely", () =>
        {
            var resolver = new ReverseDnsResolver(async (_, token) => { await Task.Delay(Timeout.Infinite, token); return "never.example"; }, timeout: TimeSpan.FromMilliseconds(25));
            Expect(resolver.ResolveAsync("203.0.113.8").WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult() is null);
        });
        check("PTR resolver does not accept hostname input as an address", () =>
        {
            var resolver = new ReverseDnsResolver((_, _) => throw new Exception("Must not query"));
            Expect(resolver.ResolveAsync("example.com").GetAwaiter().GetResult() is null);
        });
        check("PTR requests run with at most four concurrent lookups", () =>
        {
            var active = 0; var maximum = 0;
            var resolver = new ReverseDnsResolver(async (_, token) =>
            {
                var count = Interlocked.Increment(ref active);
                int previous;
                do { previous = maximum; if (previous >= count) break; } while (Interlocked.CompareExchange(ref maximum, count, previous) != previous);
                await Task.Delay(10, token); Interlocked.Decrement(ref active); return "ptr.example.com";
            });
            Task.WhenAll(Enumerable.Range(1, 16).Select(i => resolver.ResolveAsync("203.0.113." + i))).GetAwaiter().GetResult();
            Expect(maximum is > 0 and <= 4);
        });
        check("Timed-out DNS providers retain bounded native work slots", () =>
        {
            var calls = 0; var answer = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var resolver = new ReverseDnsResolver((_, _) => { Interlocked.Increment(ref calls); return answer.Task; }, timeout: TimeSpan.FromMilliseconds(25));
            try
            {
                Task.WhenAll(Enumerable.Range(1, 16).Select(i => resolver.ResolveAsync("203.0.113." + i))).WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                Expect(calls == 4);
            }
            finally { answer.TrySetResult(null); }
        });
        const string service = @"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", proxy = @"C:\Program Files\Darkwire\Service\Backends\DnsCrypt\dnscrypt-proxy.exe";
        var own = new OwnConnections(@"C:\Program Files\Darkwire\Service");
        static Connection Tcp(string path, string local, string remote, int port, int localPort = 50_000) =>
            new(Path.GetFileNameWithoutExtension(path), path, 7, remote, port, localPort, "TCP", TrafficDirection.Unknown, LocalAddress: local);
        check("The router's relay sockets are no connections of their own; routed and Darkwire's own connections are outbound", () =>
        {
            var made = own.Made(
            [
                Tcp(@"C:\Apps\browser.exe", "198.18.0.1", "52.123.129.14", 443),
                // Its relay, and the translated connection's accepted end, in both families.
                Tcp(service, "192.168.1.20", "52.123.129.14", 443, 61_000), Tcp(service, "198.18.0.1", "198.19.0.1", 1097, 7100),
                Tcp(service, "fd5a:9c33:21e7::1", "fd5a:9c33:21e7::1:0:5", 1029, 7101),
                // The DNS proxy's connection and its relay; a download of the service's own.
                Tcp(proxy, "198.18.0.1", "9.9.9.9", 443, 50_001), Tcp(service, "192.168.1.20", "9.9.9.9", 443, 61_001), Tcp(service, "192.168.1.20", "151.101.1.229", 443, 61_002),
                // Not routed; and one to the adapter's address that no relay carries, which could have come in.
                Tcp(@"C:\Apps\mail.exe", "192.168.1.20", "203.0.113.5", 993), Tcp(@"C:\Apps\server.exe", "198.18.0.1", "192.168.1.50", 50_123, 8080)
            ]);
            Expect(made.Count == 5 && made.Single(c => c.Path == service).RemoteAddress == "151.101.1.229");
            Expect(made.Where(c => c.Application is "browser" or "dnscrypt-proxy" or "Darkwire.Service").All(c => c.Direction == TrafficDirection.Outbound));
            Expect(made.Where(c => c.Application is "mail" or "server").All(c => c.Direction == TrafficDirection.Unknown));
            // Only the installed programs are Darkwire's: one of the same name elsewhere neither hides sockets nor counts as its own.
            var impostor = Tcp(@"C:\Users\Public\Darkwire.Service.exe", "198.18.0.1", "198.19.0.1", 80);
            Expect(own.Own(made.Single(c => c.Path == proxy)) && !own.Own(impostor) && own.Made([impostor]).Count == 1);
        });
        check("Darkwire's own connections need no rule while routed; explicit denies still refuse them, a country allow list does not", () =>
        {
            var engine = new PolicyEngine();
            var download = Tcp(service, "192.168.1.20", "151.101.1.229", 443) with { Direction = TrafficDirection.Outbound, Country = "US" };
            AppState Policy(FirewallMode mode) => new() { Mode = mode };
            Expect(engine.Evaluate(Policy(FirewallMode.Learning), download).Kind == DecisionKind.Prompt);
            Expect(engine.EvaluateOwn(Policy(FirewallMode.Learning), download) is { Kind: DecisionKind.Allow, Reason: "Darkwire's own connection" });
            Expect(engine.EvaluateOwn(Policy(FirewallMode.Lockdown), download).Kind == DecisionKind.Allow && engine.EvaluateOwn(Policy(FirewallMode.Open), download).Reason == "Open mode");
            var allowList = Policy(FirewallMode.BlockNew); allowList.CountryAllowList = true; allowList.AllowedCountries = ["CH"];
            var blocked = Policy(FirewallMode.BlockNew); blocked.BlockedCountries = ["US"];
            Expect(engine.EvaluateOwn(allowList, download).Kind == DecisionKind.Allow && engine.EvaluateOwn(blocked, download).Reason == "Country policy");
            var denied = Policy(FirewallMode.BlockNew); denied.Rules = [new() { ApplicationName = "No downloads", Path = service, Action = RuleAction.Deny }];
            Expect(engine.EvaluateOwn(denied, download) is { Kind: DecisionKind.Deny, Reason: "No downloads" });
            // Without routing they are decided like any program's.
            var unrouted = Policy(FirewallMode.BlockNew); unrouted.RouteConnections = false;
            Expect(engine.EvaluateOwn(unrouted, download) is { Kind: DecisionKind.Deny, Reason: "Block new" });
        });
        check("Each connection shows the VPN profile whose tunnel carries it, else the Windows route; loopback shows none", () =>
        {
            Guid work = Guid.NewGuid(), home = Guid.NewGuid(), gone = Guid.NewGuid();
            var routes = new ConnectionRoutes(
                [new("198.18.0.1", 50_000, "203.0.113.8", 443, work), new("fd5a:9c33:21e7::1", 50_001, "2001:db8::8", 443), new("198.18.0.1", 50_002, "203.0.113.9", 443, gone)],
                [new(home, "WireGuard", "Up", DateTimeOffset.UtcNow, 9, ["10.64.0.2"]), new(Guid.NewGuid(), "WireGuard", "Starting", DateTimeOffset.UtcNow)],
                id => id == work ? "Work" : id == home ? "Home" : "VPN profile");
            static Connection From(string local, int localPort, string remote, int port, string path = @"C:\Apps\browser.exe") =>
                new(Path.GetFileNameWithoutExtension(path), path, 7, remote, port, localPort, "TCP", TrafficDirection.Outbound, LocalAddress: local);
            // As the router reports them, whatever way the addresses are written.
            Expect(routes.Of(From("198.18.0.1", 50_000, "203.0.113.8", 443)) == "Work" && routes.Of(From("fd5a:9c33:21e7:0::1", 50_001, "2001:0db8::0008", 443)) == ConnectionRoutes.WindowsRoute);
            Expect(routes.Of(From("198.18.0.1", 50_002, "203.0.113.9", 443)) == "VPN profile");
            // One of Darkwire's downloads through a running tunnel; one from the adapter the router did not report; loopback; one not routed.
            Expect(routes.Of(From("10.64.0.2", 61_000, "151.101.1.229", 443, service)) == "Home" && routes.Of(From("198.18.0.1", 50_009, "203.0.113.10", 443)) == ConnectionRoutes.Unknown);
            Expect(routes.Of(From("127.0.0.1", 50_010, "127.0.0.1", 5353)) == ConnectionRoutes.Loopback && routes.Of(From("192.168.1.20", 50_011, "203.0.113.11", 443)) == ConnectionRoutes.WindowsRoute);
            // While Darkwire routes nothing, everything takes the Windows route.
            Expect(ConnectionRoutes.None.Of(From("192.168.1.20", 50_011, "203.0.113.11", 443)) == ConnectionRoutes.WindowsRoute);
            // The demo's report sends its applications through their profiles, for captures.
            var demo = Demo.State(); var demoRoutes = new ConnectionRoutes(Demo.Routed(demo), [], id => demo.VpnProfiles.Single(p => p.Id == id).Name);
            Expect(Demo.Connections().Select(demoRoutes.Of).Distinct().Order().SequenceEqual(["Private / Stockholm", ConnectionRoutes.WindowsRoute, "Work / Amsterdam"]));
        });
    }
}
