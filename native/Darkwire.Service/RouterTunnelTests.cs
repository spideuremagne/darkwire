using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Net;

namespace Darkwire.Service;

/// <summary>
/// Per-application VPN routing through the real packet router, decisions and tunnel supervisor, with fake backends,
/// interfaces and socket tables: flows wait for their tunnel, leave only through it, and are refused or withdrawn without it.
/// </summary>
internal static class RouterTunnelTests
{
    private const string Browser = @"C:\Apps\browser.exe", Game = @"C:\Apps\game.exe", DnsClient = @"%SystemRoot%\system32\svchost.exe";
    private const string Service = @"C:\Program Files\Darkwire\Service\Darkwire.Service.exe", WireGuard = @"C:\Program Files\Darkwire\Service\Backends\WireGuard\wireguard.exe";
    private static readonly string Dnscache = IdentitySelectors.ServiceSid("Dnscache");
    private static readonly NetEndpoint Resolver4 = new(RouterAddresses.Resolver4, 53), Resolver6 = new(RouterAddresses.Resolver6, 53), ProfileResolver = new(NetAddress.Parse("10.64.0.1"), 53);
    private static readonly Guid Profile = new("2f0c9a5e-3d41-4b6f-9a07-5c1d8e2b7f10"), Fallback = new("8a4e1c3b-6f27-4d95-b0e8-1f3a5c7d9e21"), Interface = new("c3b2a1f0-1234-4cde-8f00-aabbccddeeff");
    private static readonly TunnelDemand Demand = new(Profile, "WireGuard", new("11111111-2222-3333-4444-555555555555"));
    private static readonly Egress Lan = new(42, 7, IPAddress.Parse("192.168.1.20"), 0, 25), Lan6 = new(42, 7, IPAddress.Parse("2001:db8:1::20"), 0, 25);
    private static readonly NetEndpoint Remote = new(NetAddress.Parse("203.0.113.8"), 443);
    private static readonly IPAddress TunnelSource = IPAddress.Parse("10.64.0.2");

    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string reason = "Tunnel routing invariant failed.") { if (!value) throw new Exception(reason); }
        static void Until(Func<bool> condition, string reason) { if (!SpinWait.SpinUntil(condition, TimeSpan.FromSeconds(5))) throw new Exception(reason); }
        static FirewallRule Allow(string path = "*") => new() { ApplicationName = path == "*" ? "Anything" : Path.GetFileNameWithoutExtension(path), Path = path };

        check("An assigned application's connection waits for its starting tunnel, then leaves only through it", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Backends.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Tunnels.Sync([Demand]);
            Assert(r.Tunnels.Find(Profile)?.State == TunnelState.Starting);
            var flow = r.Connect(Browser, Remote);
            Assert(r.Host.Count(h => h.Connecting) == 0 && r.Router.Flows().Single().State == RouterFlowState.Pending, "The flow did not wait for its tunnel.");
            r.Backends.Gate.SetResult();
            Until(() => r.Host.Count(h => h.Connecting) == 1, "The flow was not released through its tunnel.");
            var route = r.Decisions.Select(flow)!;
            Assert(route.Tunneled && route.Egress is { Luid: 900, Index: 9 } && route.Egress.Source.Equals(TunnelSource) && route.Target is null);
            Assert(r.Interfaces.Read(c => c.Contains("add 900 0.0.0.0/1 4096") && c.Contains("add 900 128.0.0.0/1 4096") && !c.Any(x => x.Contains("::/1"))));
        });
        check("A tunnel sharing its address with another gets only a default route, says so, refuses pings and is maintained before each health check", () =>
        {
            var decisions = Decisions(FirewallMode.BlockNew, Allow()) with { DefaultTunnel = Profile };
            using (var own = new Rig(decisions))
            {
                // A tunnel holding its own address takes the echo requests the default route carries.
                own.StartTunnel();
                var echo = own.Ping(Remote.Address);
                Assert(own.Host.Read(h => h.Echoes.Contains(echo)) && own.Decisions.Select(echo) is { Tunneled: true, Egress.Shared: false });
            }
            using var r = new Rig(decisions);
            r.Backends.Shared = [TunnelSource];
            r.StartTunnel();
            // Under the weak host model the halves would outrank the physical default route for sockets bound to its addresses.
            Assert(r.Interfaces.Read(c => c.Contains("add 900 0.0.0.0/0 4096") && !c.Any(x => x.Contains("/1 "))), "A tunnel sharing its address got the halves.");
            Assert(r.Decisions.Select(r.Connect(Browser, Remote)) is { Tunneled: true, Egress: { Shared: true } egress } && egress.Source.Equals(TunnelSource));
            Assert(r.Tunnels.Status().Single().Shared!.SequenceEqual(["10.64.0.2"]));
            // An echo request would leave through the interface holding the address, another tunnel's, so it is refused.
            var ping = r.Ping(Remote.Address);
            Assert(!r.Host.Read(h => h.Echoes.Contains(ping)) && r.Decisions.Select(ping) is null);
            var instance = r.Backends.Read(b => b.Instances.Single());
            r.Tunnels.Tick();
            Assert(instance.Maintained == 1 && r.Tunnels.Find(Profile)?.State == TunnelState.Up);
        });
        check("Unassigned applications keep the physical egress", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Game)));
            r.StartTunnel();
            var flow = r.Connect(Game, Remote);
            Assert(r.Host.Count(h => h.Connecting) == 1 && r.Decisions.Select(flow) is { Tunneled: false } route && route.Egress == Lan);
        });
        check("Kept local, local network traffic leaves physically under a default profile, while DNS to a local server still goes through the tunnel", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Game), Allow(Browser)) with { DefaultTunnel = Profile, Local = [NetPrefix.Parse("192.168.1.0/24")] });
            r.StartTunnel();
            var share = r.Connect(Game, new(NetAddress.Parse("192.168.1.50"), 445));
            Assert(r.Decisions.Select(share) is { Tunneled: false } local && local.Egress == Lan, "Local traffic entered the tunnel.");
            // An application a profile carries reaches the local network directly too.
            Assert(r.Decisions.Select(r.Connect(Browser, new(NetAddress.Parse("192.168.1.1"), 80), 50_001)) is { Tunneled: false });
            Assert(r.Decisions.Select(r.Connect(Game, Remote, 50_002)) is { Tunneled: true });
            var lookup = r.Datagram(Game, new(NetAddress.Parse("192.168.1.1"), 53), 50_003);
            Assert(r.Decisions.Select(lookup) is { Tunneled: true, Target: var target } && target == ProfileResolver, "A local DNS server answered around the tunnel.");
        });
        check("A running tunnel counts what its interface sends and receives, and when it last received anything", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (1_000, 5_000);
            r.StartTunnel();
            Assert(r.Tunnels.Status().Single() is { SentBytes: 0, ReceivedBytes: 0, LastReceived: null, InRates: null, OutRates: null });
            r.Interfaces.Traffic = (3_000, 5_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick();
            Assert(r.Tunnels.Status().Single() is { SentBytes: 2_000, ReceivedBytes: 0, LastReceived: null }, "Sending alone counted as an answer.");
            r.Interfaces.Traffic = (3_500, 9_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick();
            Assert(r.Tunnels.Status().Single() is { SentBytes: 2_500, ReceivedBytes: 4_000, LastReceived: var last } && last == r.Clock.Now);
            // Bits per second between counts chart its throughput: 2,000 bytes out over two seconds, then 4,000 in and 500 out.
            Assert(r.Tunnels.Status().Single() is { InRates: [0, 16_000], OutRates: [8_000, 2_000] }, "The rates between counts were wrong.");
            // The first flow the router sends through the tunnel is recorded, so a tunnel whose server never answers shows it was tried.
            Assert(r.Tunnels.Status().Single().Routed is null);
            var routedAt = r.Clock.Now;
            r.Decisions.Select(r.Connect(Browser, Remote));
            r.Clock.Now += TimeSpan.FromSeconds(5);
            r.Decisions.Select(r.Connect(Browser, Remote, 50_001));
            Assert(r.Tunnels.Status().Single().Routed == routedAt);
        });
        check("A tunnel whose server answered and then falls silent while it keeps sending is silent from its first unanswered send until anything comes back", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            void Count(long sent, long received) { r.Interfaces.Traffic = (sent, received); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick(); }
            Count(1_000, 2_000);
            // A lone send, such as the last acknowledgment of a closed connection, is no silence however long nothing follows it.
            Count(1_100, 2_000);
            for (var i = 0; i < 10; i++) Count(1_100, 2_000);
            Assert(r.Tunnels.Status().Single() is { Silent: null, Unanswered: null }, "A lone unanswered send counted as silence.");
            // Sending again after a long pause starts afresh, and is silence once it has gone on for four seconds.
            Count(1_200, 2_000); var first = r.Clock.Now;
            Count(1_300, 2_000);
            Assert(r.Tunnels.Status().Single().Silent is null, "Two seconds of unanswered sending counted as silence.");
            Count(1_400, 2_000);
            Assert(r.Tunnels.Status().Single() is { Silent: var silent, Unanswered: var unanswered } && silent == first && unanswered == first, "Sending unanswered for four seconds was no silence.");
            // It stays silent while nothing comes back, sending or not, and any answer ends it.
            for (var i = 0; i < 10; i++) Count(1_400, 2_000);
            Count(1_500, 2_000);
            Assert(r.Tunnels.Status().Single().Silent == first);
            Count(1_500, 2_100);
            Assert(r.Tunnels.Status().Single() is { Silent: null, Unanswered: null, LastReceived: var heard } && heard == r.Clock.Now, "An answer did not end the silence.");
        });
        check("A tunnel whose server answered falls silent too when WireGuard, waiting for a handshake, counts nothing sent while the router keeps sending connections through it, and is reconnected", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            ushort port = 50_000;
            // The router sends one more connection through the tunnel each round; WireGuard counts nothing either way.
            void Route() { r.Clock.Now += TimeSpan.FromSeconds(1); r.Decisions.Select(r.Connect(Browser, Remote, port++)); r.Clock.Now += TimeSpan.FromSeconds(1); r.Tunnels.Tick(); }
            void Idle() { r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick(); }
            r.Interfaces.Traffic = (1_000, 2_000); Idle();
            // One connection after a long pause is no silence, however long nothing follows it.
            Route();
            for (var i = 0; i < 10; i++) Idle();
            Assert(r.Tunnels.Status().Single() is { Silent: null, Unanswered: null }, "A lone unanswered connection counted as silence.");
            // Connections going on unanswered for four seconds are silence, from the first of them.
            Route(); var first = r.Clock.Now;
            Route();
            Assert(r.Tunnels.Status().Single().Silent is null, "Two seconds of unanswered connections counted as silence.");
            Route();
            Assert(r.Tunnels.Status().Single() is { Silent: var silent, Unanswered: var unanswered } && silent == first && unanswered == first, "Connections sent on unanswered were no silence.");
            // Reconnected 45 seconds after it fell silent.
            while (r.Clock.Now - first < TunnelSupervisor.FirstReconnect - TimeSpan.FromSeconds(1)) Route();
            Assert(r.Backends.Read(b => b.Started.Count) == 1, "Reconnected before 45 seconds of silence.");
            Route();
            Until(() => r.Backends.Read(b => b.Started.Count) == 2 && r.Tunnels.Find(Profile)?.State == TunnelState.Up, "A tunnel whose connections went unanswered was not reconnected.");
            Assert(r.Tunnels.Status().Single() is { Reconnects: 1, Silent: null }, "The reconnect was not counted, or the new backend started out silent.");
        });
        check("A tunnel sharing another's address is not called silent for connections the router sends it, whose answers can come in through the other", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.Backends.Shared = [TunnelSource];
            r.StartTunnel();
            Assert(r.Tunnels.Status().Single().Shared is { Count: > 0 }, "The tunnel did not share its address.");
            ushort port = 50_000;
            void Route() { r.Clock.Now += TimeSpan.FromSeconds(1); r.Decisions.Select(r.Connect(Browser, Remote, port++)); r.Clock.Now += TimeSpan.FromSeconds(1); r.Tunnels.Tick(); }
            r.Interfaces.Traffic = (1_000, 2_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick();
            for (var i = 0; i < 30; i++) Route();
            Assert(r.Backends.Read(b => b.Started.Count) == 1 && r.Tunnels.Status().Single() is { Silent: null, Reconnects: 0 }, "A sharing tunnel was called silent for the router's connections.");
            // What it sends itself unanswered still counts.
            long sent = 1_000;
            for (var i = 0; i < 3; i++) { r.Interfaces.Traffic = (sent += 100, 2_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick(); }
            Assert(r.Tunnels.Status().Single().Silent is not null, "A sharing tunnel sending unanswered was no longer called silent.");
        });
        check("A tunnel whose server stops completing WireGuard's handshakes falls silent while WireGuard sends on, one sharing another's address and counting nothing on its interface included, and is reconnected", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.Backends.Shared = [TunnelSource];
            r.StartTunnel();
            var instance = r.Backends.Read(b => b.Instances.Single());
            long wireGuard = 0;
            void Count(Instance tunnel, DateTimeOffset? handshake) { tunnel.Peers = new(wireGuard += 148, 2_000, handshake); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick(); }
            // Its server answered: bytes came back through it, then WireGuard completed a handshake, which dates the last answer.
            r.Interfaces.Traffic = (1_000, 2_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick();
            var handshake = r.Clock.Now + TimeSpan.FromSeconds(1);
            Count(instance, handshake);
            Assert(r.Tunnels.Status().Single() is { LastReceived: var heard, Silent: null } && heard == handshake, "A completed handshake did not date the server's last answer.");
            // Then none completes while WireGuard goes on trying, and the interface counts nothing: unanswered after three minutes.
            while (r.Clock.Now + TimeSpan.FromSeconds(2) - handshake < TunnelSupervisor.HandshakeSilence) Count(instance, handshake);
            Assert(r.Tunnels.Status().Single().Silent is null, "A tunnel was silent before its handshakes had gone unanswered for three minutes.");
            Count(instance, handshake); var first = r.Clock.Now;
            Count(instance, handshake); Count(instance, handshake);
            Assert(r.Tunnels.Status().Single() is { Silent: var silent, Unanswered: var unanswered } && silent == first && unanswered == first, "Unanswered handshakes were no silence.");
            while (r.Clock.Now - first < TunnelSupervisor.FirstReconnect - TimeSpan.FromSeconds(1)) Count(instance, handshake);
            Assert(r.Backends.Read(b => b.Started.Count) == 1, "Reconnected before 45 seconds of silence.");
            Count(instance, handshake);
            Until(() => r.Backends.Read(b => b.Started.Count) == 2 && r.Tunnels.Find(Profile)?.State == TunnelState.Up, "A tunnel whose handshakes went unanswered was not reconnected.");
            Assert(r.Tunnels.Status().Single() is { Reconnects: 1, Silent: null }, "The reconnect was not counted, or the new backend started out silent.");
            // The next backend's server never completes one, and nothing comes back on its interface: unanswered three minutes
            // after it came up, and reconnected 90 seconds after that.
            var next = r.Backends.Read(b => b.Instances[1]); var up = r.Clock.Now;
            while (r.Clock.Now + TimeSpan.FromSeconds(2) - up < TunnelSupervisor.HandshakeSilence) Count(next, null);
            Assert(r.Tunnels.Status().Single() is { Silent: null, Unanswered: null }, "A new backend was silent before three minutes.");
            Count(next, null); var again = r.Clock.Now;
            Count(next, null); Count(next, null);
            Assert(r.Tunnels.Status().Single() is { ReceivedBytes: 0, Silent: var quiet, Unanswered: var since } && quiet == again && since == again, "A backend whose server never completed a handshake was not unanswered.");
            while (r.Clock.Now - again < TunnelSupervisor.FirstReconnect * 2 - TimeSpan.FromSeconds(2)) Count(next, null);
            Assert(r.Backends.Read(b => b.Started.Count) == 2, "The second reconnect did not wait 90 seconds.");
            Count(next, null);
            Until(() => r.Backends.Read(b => b.Started.Count) == 3 && r.Tunnels.Find(Profile)?.State == TunnelState.Up, "A backend whose server never completed a handshake was not reconnected.");
        });
        check("WireGuard's counts call no tunnel silent while handshakes complete or its server's packets come back, while WireGuard sends nothing, or for a handshake answered after a long pause", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            var instance = r.Backends.Read(b => b.Instances.Single());
            long wireGuard = 0, back = 1_000; var handshake = r.Clock.Now + TimeSpan.FromSeconds(1);
            void Count(long sent, bool renew = false, long received = 0) { if (renew) handshake = r.Clock.Now; instance.Peers = new(wireGuard += sent, back += received, handshake); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick(); }
            r.Interfaces.Traffic = (1_000, 2_000); r.Clock.Now += TimeSpan.FromSeconds(2); r.Tunnels.Tick();
            // A keepalive every 24 seconds and a handshake every two minutes, for twenty minutes.
            for (var i = 1; i <= 600; i++) Count(i % 12 == 0 ? 32 : 0, renew: i % 60 == 0);
            // Ten minutes with no new handshake reported while the server's packets keep coming back.
            for (var i = 1; i <= 300; i++) Count(i % 12 == 0 ? 32 : 0, received: i % 12 == 0 ? 32 : 0);
            // Ten idle minutes: the last handshake grows old while WireGuard sends nothing.
            for (var i = 0; i < 300; i++) Count(0);
            // Traffic again: WireGuard's handshake is lost once and its retry answered, then what it carries is answered too.
            Count(148); Count(0); Count(148, renew: true);
            r.Interfaces.Traffic = (1_100, 2_100); Count(32);
            Assert(r.Backends.Read(b => b.Started.Count) == 1 && r.Tunnels.Status().Single() is { Silent: null, Reconnects: 0 }, "Handshakes that completed made a tunnel silent.");
        });
        // One try of the tunnels' end-to-end checks: due once the wait between tries is over, asked in the background, and done.
        static void Try(Rig r) { r.Clock.Now += TunnelSupervisor.CheckRetry; r.Tunnels.Tick(); Until(() => !r.Tunnels.CheckInFlight(Profile) && !r.Tunnels.CheckInFlight(Fallback), "A check's try did not finish."); }
        check("A tunnel that comes up is checking until its DNS server answers through it, tried again after a miss, and checked again when asked", () =>
        {
            var answers = new Queue<bool?>([false, true, true]);
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)), (_, _) => { lock (answers) return answers.Dequeue(); });
            r.StartTunnel();
            Assert(r.Tunnels.Status().Single() is { Checking: true, Checked: null, CheckFailed: null }, "A tunnel just up was not checking.");
            Try(r);
            Assert(r.Tunnels.Status().Single() is { Checking: true, Checked: null }, "A missed answer ended the check.");
            Try(r);
            Assert(r.Tunnels.Status().Single() is { Checking: false, Checked: var passed, CheckFailed: null, CheckRestarts: 0 } && passed == r.Clock.Now, "An answer did not pass the check.");
            r.Tunnels.Recheck();
            Assert(r.Tunnels.Status().Single() is { Checking: true, Checked: not null }, "A recheck did not check the tunnel again.");
            Try(r);
            Assert(r.Tunnels.Status().Single() is { Checking: false } && r.Backends.Read(b => b.Started.Count) == 1, "The recheck's answer did not end it.");
        });
        check("A check passes on traffic coming back while it goes on, though the DNS server asked never answers, and at once without one to ask", () =>
        {
            using (var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)), (_, _) => false))
            {
                r.Interfaces.Traffic = (0, 0);
                r.StartTunnel();
                r.Interfaces.Traffic = (1_000, 1_000); Try(r);
                Assert(r.Tunnels.Status().Single().Checking, "A first missed answer ended the check.");
                r.Interfaces.Traffic = (2_000, 1_000 + TunnelSupervisor.CheckReceived); Try(r);
                Assert(r.Tunnels.Status().Single() is { Checking: false, Checked: not null }, "Traffic coming back did not pass the check.");
            }
            using var none = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)), (_, _) => null);
            none.StartTunnel();
            Try(none);
            Assert(none.Tunnels.Status().Single() is { Checking: false, Checked: not null }, "A tunnel naming no DNS server stayed checking.");
        });
        check("A tunnel whose DNS server never answers through it is restarted with every tunnel sharing its address, all gone before any starts again, and its next restart waits", () =>
        {
            // The sharing profile's server never answers; the other's does.
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)), (profile, _) => profile != Fallback);
            var sharing = new TunnelDemand(Fallback, "WireGuard", new("99999999-8888-7777-6666-555555555555"));
            r.StartTunnel();
            r.Backends.Shared = [TunnelSource];
            r.Tunnels.Sync([Demand, sharing]);
            Until(() => r.Tunnels.Find(Fallback)?.State == TunnelState.Up, "The sharing tunnel did not come up.");
            TunnelStatus Of(Guid profile) => r.Tunnels.Status().Single(t => t.ProfileId == profile);
            int Starts() => r.Backends.Read(b => b.Started.Count);
            // The first tunnel is checked again as the second comes up beside it, and passes.
            Assert(Of(Profile).Checking && Of(Fallback).Checking, "A tunnel was not checked as another came up sharing its address.");
            Try(r);
            Assert(Of(Profile) is { Checking: false, Checked: not null } && Of(Fallback).Checking, "The answering tunnel's check did not pass.");
            for (var i = 2; i < TunnelSupervisor.CheckTries; i++) Try(r);
            Assert(Of(Fallback).Checking && Starts() == 2, "A tunnel was restarted before its check's last try.");
            r.Backends.Record("mark");
            Try(r);
            Until(() => Starts() == 4 && r.Tunnels.Status().All(t => t.State == "Up"), "The tunnels sharing an address were not both restarted.");
            var events = r.Backends.Read(b => b.Events.SkipWhile(e => e != "mark").ToArray());
            Assert(Array.FindLastIndex(events, e => e.StartsWith("dispose", StringComparison.Ordinal)) is var gone and >= 0 && Array.FindIndex(events, e => e.StartsWith("start", StringComparison.Ordinal)) > gone,
                "A tunnel started again before every old backend was gone: " + string.Join(", ", events));
            Assert(Of(Fallback) is { CheckRestarts: 1, Checking: true } && Of(Profile).CheckRestarts == 0, "The failed check's restart was not counted to its own tunnel.");
            // Still nothing back: its check fails again, but the next restart waits 45 seconds after the last.
            var restarted = r.Clock.Now;
            for (var i = 0; i < TunnelSupervisor.CheckTries; i++) Try(r);
            Assert(Of(Fallback) is { Checking: false, CheckFailed: not null } && Starts() == 4, "A failed check restarted the tunnels again at once.");
            while (r.Clock.Now - restarted < TunnelSupervisor.FirstReconnect) Try(r);
            Assert(Starts() == 4, "The tunnels were restarted before the wait was over.");
            // Once it is over, a failed check restarts them again.
            for (var i = 1; i < TunnelSupervisor.CheckTries; i++) Try(r);
            Until(() => Starts() == 6 && Of(Fallback).CheckRestarts == 2, "A tunnel still carrying nothing back was not restarted after the wait.");
        });
        check("A tunnel whose server stays silent is reconnected with a new backend, each further reconnect waiting twice as long until the server answers", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            long sent = 0, received = 0;
            void Count(long send, long receive = 0) { r.Interfaces.Traffic = (sent += send, received += receive); r.Clock.Now += TimeSpan.FromSeconds(5); r.Tunnels.Tick(); }
            int Starts() => r.Backends.Read(b => b.Started.Count);
            void Reconnected(int starts, int reconnects, string reason)
            {
                Until(() => Starts() == starts && r.Tunnels.Find(Profile)?.State == TunnelState.Up, reason);
                Assert(r.Tunnels.Status().Single().Reconnects == reconnects && r.Backends.Read(b => b.Instances.Take(starts - 1).All(i => i.Disposed)), reason);
            }
            Count(1_000, 2_000);
            // Silent from its first unanswered send, five seconds later; reconnected 45 seconds after that.
            for (var i = 0; i < 9; i++) Count(100);
            Assert(r.Tunnels.Find(Profile)?.State == TunnelState.Up && Starts() == 1, "Reconnected before 45 seconds of silence.");
            Count(100);
            Reconnected(2, 1, "A silent tunnel was not reconnected.");
            // The new backend sends unanswered too: the next reconnect waits 90 seconds.
            for (var i = 0; i < 17; i++) Count(100);
            Assert(Starts() == 2, "The second reconnect did not wait twice as long.");
            Count(100);
            Reconnected(3, 2, "A tunnel still silent was not reconnected again.");
            // An answer ends it all: the next silence is reconnected after 45 seconds again.
            Count(100, 500);
            Assert(r.Tunnels.Status().Single().Reconnects == 0, "An answer did not reset the reconnects.");
            for (var i = 0; i < 9; i++) Count(100);
            Assert(Starts() == 3);
            Count(100);
            Reconnected(4, 1, "The wait did not start over after the server answered.");
        });
        check("Reconnect from a card starts a running tunnel again at once and a failed one without waiting, counting no silence; a starting one is left alone", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            Assert(r.Tunnels.Reconnect(Profile), "A running tunnel was not reconnected.");
            Until(() => r.Backends.Read(b => b.Started.Count) == 2 && r.Tunnels.Find(Profile)?.State == TunnelState.Up, "A running tunnel did not start again.");
            Assert(r.Backends.Read(b => b.Instances[0].Disposed) && r.Tunnels.Status().Single().Reconnects == 0, "The old backend remained, or the reconnect counted as one for silence.");
            // Failed: started again at once, before its retry is due.
            r.Backends.Read(b => b.Instances[1]).Up = false; r.Tunnels.Tick();
            Assert(r.Tunnels.Find(Profile)?.State == TunnelState.Failed && r.Tunnels.Reconnect(Profile), "A failed tunnel was not reconnected.");
            Until(() => r.Backends.Read(b => b.Started.Count) == 3 && r.Tunnels.Find(Profile)?.State == TunnelState.Up, "A failed tunnel did not start again at once.");
            // Starting already, or no tunnel at all: nothing to do.
            r.Backends.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Assert(r.Tunnels.Reconnect(Profile) && r.Tunnels.Find(Profile)?.State == TunnelState.Starting);
            Assert(!r.Tunnels.Reconnect(Profile) && !r.Tunnels.Reconnect(Guid.NewGuid()), "A starting tunnel, or a profile with none, was reconnected.");
            r.Backends.Gate.SetResult();
            Until(() => r.Tunnels.Find(Profile)?.State == TunnelState.Up, "The reconnect did not finish.");
        });
        check("A tunnel going away first releases what Darkwire has open through it, then takes its own addresses off for a tunnel sharing them to take over, then stops", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            var sharing = new TunnelDemand(Fallback, "WireGuard", new("99999999-8888-7777-6666-555555555555"));
            r.StartTunnel();
            // The second holds none of its addresses itself: the first's interface holds them.
            r.Backends.Shared = [TunnelSource];
            r.Tunnels.Sync([Demand, sharing]);
            Until(() => r.Tunnels.Find(Fallback)?.State == TunnelState.Up, "The sharing tunnel did not come up.");
            var (holder, sharer) = r.Backends.Read(b => (b.Instances[0], b.Instances[1]));
            var maintained = sharer.Maintained;
            Assert(r.Tunnels.Reconnect(Profile));
            Until(() => holder.Disposed, "The old backend remained.");
            var events = r.Backends.Read(b => b.Events.ToArray());
            int At(string text) => Array.IndexOf(events, text);
            Assert(At("release 900") >= 0 && At("release 900") < At($"unassign 900 {TunnelSource}") && At($"unassign 900 {TunnelSource}") < At($"dispose {Demand.Revision}"), string.Join(", ", events));
            Assert(sharer.Maintained > maintained, "The sharing tunnel was not maintained at once to take the address over.");
            // A tunnel holding none of its addresses takes none off as it goes.
            r.Backends.Record("mark");
            Assert(r.Tunnels.Reconnect(Fallback));
            Until(() => sharer.Disposed, "The sharing tunnel's old backend remained.");
            var later = r.Backends.Read(b => b.Events.SkipWhile(e => e != "mark").ToArray());
            Assert(later.Contains("release 900") && !later.Any(e => e.StartsWith("unassign", StringComparison.Ordinal)), string.Join(", ", later));
        });
        check("An idle tunnel, one whose sends are answered, and one that sent a last unanswered packet are never reconnected", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            long sent = 0, received = 0;
            void Count(long send, long receive) { r.Interfaces.Traffic = (sent += send, received += receive); r.Clock.Now += TimeSpan.FromSeconds(10); r.Tunnels.Tick(); }
            for (var i = 0; i < 60; i++) Count(0, 0);
            for (var i = 0; i < 60; i++) Count(100, 100);
            Count(100, 0);
            for (var i = 0; i < 60; i++) Count(0, 0);
            Assert(r.Backends.Read(b => b.Started.Count) == 1 && r.Tunnels.Status().Single() is { State: "Up", Reconnects: 0 }, "A tunnel with nothing unanswered was reconnected.");
        });
        check("A reconnect withdraws the tunnel's connections at once and holds new ones until the new backend is up", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Interfaces.Traffic = (0, 0);
            r.StartTunnel();
            var tunneled = r.Connect(Browser, Remote);
            Assert(r.Decisions.Select(tunneled) is { Tunneled: true });
            r.Router.Connected(tunneled.Id);
            // Routed into it with nothing back for 45 seconds: its handshake never came back, so WireGuard counts nothing sent.
            r.Backends.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Clock.Now += TunnelSupervisor.FirstReconnect; r.Tunnels.Tick();
            Assert(r.Tunnels.Find(Profile)?.State == TunnelState.Starting && r.Tunnels.Status().Single().Reconnects == 1, "The silent tunnel was not reconnecting.");
            Assert(r.Host.Read(h => h.Closed.Single()) is var (closed, abort) && closed == tunneled && abort, "The tunnel's connection was not withdrawn.");
            var held = r.Connect(Browser, Remote, 50_001);
            Assert(r.Host.Resets(50_001) == 0 && r.Router.Flows().Single(f => f.Id == held.Id).State == RouterFlowState.Pending, "A new connection did not wait for the reconnect.");
            r.Backends.Gate.SetResult();
            Until(() => r.Host.Read(h => h.Connecting.Contains(held)), "The held connection was not released through the new backend.");
            Assert(r.Decisions.Select(held) is { Tunneled: true } && r.Backends.Read(b => b.Started.Count) == 2);
        });
        check("A tunnel that cannot start refuses its applications' connections", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Backends.Failure = new IOException("The handshake never completed.");
            r.Tunnels.Sync([Demand]);
            Until(() => r.Tunnels.Find(Profile)?.State == TunnelState.Failed, "The failed start was not recorded.");
            var flow = r.Connect(Browser, Remote);
            Assert(r.Host.Resets(50_000) == 1 && r.Host.Count(h => h.Connecting) == 0 && r.Decisions.Select(flow) is null && r.Router.Flows().Count == 0);
            Assert(r.Tunnels.Status().Single() is { State: "Failed", Error: "The handshake never completed." });
        });
        check("Kill switch: with a default profile, other applications reach nothing around its failed or lost tunnel, while local networks stay reachable", () =>
        {
            var decisions = Decisions(FirewallMode.BlockNew, Allow(Game)) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Profile, Local = [NetPrefix.Parse("192.168.1.0/24")] };
            using (var failed = new Rig(decisions))
            {
                failed.Backends.Failure = new IOException("The handshake never completed.");
                failed.Tunnels.Sync([Demand]);
                Until(() => failed.Tunnels.Find(Profile)?.State == TunnelState.Failed, "The failed start was not recorded.");
                var flow = failed.Connect(Game, Remote);
                Assert(failed.Host.Resets(50_000) == 1 && failed.Host.Count(h => h.Connecting) == 0 && failed.Decisions.Select(flow) is null, "A connection left around the failed default tunnel.");
                Assert(failed.Decisions.Select(failed.Connect(Game, new(NetAddress.Parse("192.168.1.50"), 445), 50_001)) is { Tunneled: false } local && local.Egress == Lan, "The local network was cut off.");
            }
            using var r = new Rig(decisions);
            r.StartTunnel();
            var tunneled = r.Connect(Game, Remote);
            r.Router.Connected(tunneled.Id);
            Assert(r.Decisions.Select(tunneled) is { Tunneled: true });
            r.Backends.Read(b => b.Instances.Single()).Up = false;
            r.Tunnels.Tick();
            Assert(r.Decisions.Select(tunneled) is null, "The lost tunnel's connection was not withdrawn.");
            r.Connect(Game, Remote, 50_002);
            Assert(r.Host.Resets(50_002) == 1, "A new connection left while the default tunnel was down.");
        });
        check("Losing a tunnel withdraws its connections at once and refuses new ones until it restarts", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser), Allow(Game)));
            r.StartTunnel();
            var tunneled = r.Connect(Browser, Remote);
            var physical = r.Connect(Game, Remote, 50_001);
            r.Router.Connected(tunneled.Id); r.Router.Connected(physical.Id);
            var instance = r.Backends.Read(b => b.Instances.Single());
            instance.Up = false;
            r.Tunnels.Tick();
            Assert(r.Host.Read(h => h.Closed.Single()) is var (closed, abort) && closed == tunneled && abort, "The tunnel's connection was not withdrawn.");
            Assert(r.Tunnels.Find(Profile)?.State == TunnelState.Failed && r.Decisions.Select(tunneled) is null && r.Decisions.Select(physical) is not null);
            Until(() => instance.Disposed && r.Interfaces.Read(c => c.Count(x => x.StartsWith("delete 900", StringComparison.Ordinal))) == 2, "The lost tunnel's routes and backend remain.");
            r.Connect(Browser, Remote, 50_002);
            Assert(r.Host.Resets(50_002) == 1, "A new connection was not refused while the tunnel is down.");
            // The retry waits for its backoff, then the new instance carries new connections.
            r.Tunnels.Tick();
            Assert(r.Backends.Read(b => b.Started.Count) == 1);
            r.Clock.Now += TunnelSupervisor.FirstRetry; r.Tunnels.Tick();
            Until(() => r.Tunnels.Find(Profile)?.State == TunnelState.Up, "The tunnel did not restart.");
            var again = r.Connect(Browser, Remote, 50_003);
            Assert(r.Decisions.Select(again) is { Tunneled: true } && r.Backends.Read(b => b.Started.Count) == 2);
        });
        check("DNS from an assigned application goes to its profile's resolver through the tunnel", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.StartTunnel();
            var lookup = r.Datagram(Browser, new(NetAddress.Parse("192.168.1.1"), 53), 50_010);
            Assert(r.Host.Read(h => h.Sent.Contains(lookup)), "The query was not relayed.");
            Assert(r.Decisions.Select(lookup) is { Tunneled: true, Target: { } target } route && target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53) && route.Egress.Source.Equals(TunnelSource));
            var stream = r.Connect(Browser, new(NetAddress.Parse("8.8.8.8"), 53), 50_011);
            Assert(r.Decisions.Select(stream)?.Target == new NetEndpoint(NetAddress.Parse("10.64.0.1"), 53));
        });
        check("With a default profile, Windows DNS client lookups sent to Darkwire's resolver wait for its tunnel and go to its resolver", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback });
            r.Backends.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Tunnels.Sync([Demand with { ProfileId = Fallback }]);
            var lookup = r.Datagram(DnsClient, Resolver4, 50_020, Dnscache);
            Assert(r.Router.Flows().Single().State == RouterFlowState.Pending && !r.Host.Read(h => h.Sent.Contains(lookup)), "The lookup did not wait for the tunnel.");
            r.Backends.Gate.SetResult();
            Until(() => r.Host.Read(h => h.Sent.Contains(lookup)), "The lookup was not released through the tunnel.");
            Assert(r.Decisions.Select(lookup) is { Tunneled: true, Target: var target } route && target == ProfileResolver && route.Egress.Source.Equals(TunnelSource));
            // Over TCP and IPv6 too; an IPv4-only tunnel answers the IPv6 resolver address through its IPv4 resolver.
            var stream = r.Connect(DnsClient, Resolver6, 50_021, v6: true, sid: Dnscache);
            Assert(r.Host.Count(h => h.Connecting) == 1 && r.Decisions.Select(stream) is { Tunneled: true, Target: var streamed } && streamed == ProfileResolver);
            Assert(r.Decisions.Select(r.Datagram(DnsClient, Resolver6, 50_022, Dnscache))?.Target == ProfileResolver);
        });
        check("An assigned application asking Darkwire's resolver gets its own profile's resolver, not the default profile's", () =>
        {
            // The default profile's tunnel is not even running: only the browser's own can answer.
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)) with { DefaultTunnel = Fallback });
            r.StartTunnel();
            Assert(r.Decisions.Select(r.Datagram(Browser, Resolver4, 50_023)) is { Tunneled: true, Target: var target } && target == ProfileResolver);
        });
        check("Lookups sent to Darkwire's resolver are refused without a profile resolver, and never leave physically", () =>
        {
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback }))
            {
                r.Backends.Resolvers = [];
                r.StartTunnel(Demand with { ProfileId = Fallback });
                var lookup = r.Datagram(DnsClient, Resolver4, 50_030, Dnscache);
                r.Connect(DnsClient, Resolver4, 50_031, sid: Dnscache);
                Assert(r.Decisions.Select(lookup) is null && !r.Host.Read(h => h.Sent.Contains(lookup)) && r.Host.Resets(50_031) == 1 && r.Host.Count(h => h.Connecting) == 0);
                Assert(r.Tunnels.Status().Single() is { State: "Up", Resolvers.Count: 0 }, "The status did not report the missing resolver.");
                // Darkwire's own service has no tunnel to ask through; DNS to a server the client chose still uses the tunnel.
                r.Connect(Service, Resolver4, 50_032);
                Assert(r.Host.Resets(50_032) == 1);
                Assert(r.Decisions.Select(r.Datagram(DnsClient, new(NetAddress.Parse("192.168.1.1"), 53), 50_033, Dnscache)) is { Tunneled: true, Target: null });
            }
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>() }))
            {
                // Without a default profile the address has no server at all.
                var lookup = r.Datagram(DnsClient, Resolver4, 50_034, Dnscache);
                r.Connect(Game, Resolver4, 50_035);
                Assert(r.Decisions.Select(lookup) is null && !r.Host.Read(h => h.Sent.Contains(lookup)) && r.Host.Resets(50_035) == 1 && r.Host.Count(h => h.Connecting) == 0);
            }
        });
        check("While domain lists are enforced, Windows lookups sent to Darkwire's resolver go to the network's own server physically", () =>
        {
            IPAddress[] servers = [IPAddress.Parse("192.168.1.1"), IPAddress.Parse("2001:db8:1::1"), IPAddress.Parse("192.168.1.2")];
            NetEndpoint Server(string address) => new(NetAddress.Parse(address), 53);
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), SystemDns = servers }))
            {
                var lookup = r.Datagram(DnsClient, Resolver4, 50_050, Dnscache);
                Assert(r.Host.Read(h => h.Sent.Contains(lookup)), "The lookup was not relayed.");
                Assert(r.Decisions.Select(lookup) is { Tunneled: false, Target: var target } route && target == Server("192.168.1.1") && route.Egress == Lan);
                // Each family asks its own first server, over TCP too.
                Assert(r.Decisions.Select(r.Datagram(DnsClient, Resolver6, 50_051, Dnscache)) is { Tunneled: false, Target: var six } routed && six == Server("2001:db8:1::1") && routed.Egress == Lan6);
                var stream = r.Connect(DnsClient, Resolver4, 50_052, sid: Dnscache);
                Assert(r.Host.Count(h => h.Connecting) == 1 && r.Decisions.Select(stream)?.Target == Server("192.168.1.1"));
            }
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), SystemDns = [IPAddress.Parse("192.168.1.1")] }))
                // Without an IPv6 server, an IPv4 one answers the IPv6 resolver address.
                Assert(r.Decisions.Select(r.Datagram(DnsClient, Resolver6, 50_053, Dnscache))?.Target == Server("192.168.1.1"));
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback, SystemDns = servers }))
            {
                // A default profile still carries the lookups it takes, to its own resolver.
                r.StartTunnel(Demand with { ProfileId = Fallback });
                Assert(r.Decisions.Select(r.Datagram(DnsClient, Resolver4, 50_054, Dnscache)) is { Tunneled: true, Target: var resolver } && resolver == ProfileResolver);
            }
        });
        check("Turning domain lists off withdraws the lookups sent to the network's servers", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), SystemDns = [IPAddress.Parse("192.168.1.1")] });
            var stream = r.Connect(DnsClient, Resolver4, 50_060, sid: Dnscache);
            r.Router.Connected(stream.Id);
            r.Decisions.Update(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>() });
            Assert(r.Host.Read(h => h.Closed.Single()) is var (closed, abort) && closed == stream && abort && r.Decisions.Select(stream) is null);
            r.Connect(DnsClient, Resolver4, 50_061, sid: Dnscache);
            Assert(r.Host.Resets(50_061) == 1, "A new lookup was not refused once the lists were off.");
        });
        check("Removing the default profile withdraws the lookups it carried", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback });
            r.StartTunnel(Demand with { ProfileId = Fallback });
            var stream = r.Connect(DnsClient, Resolver4, 50_040, sid: Dnscache);
            r.Router.Connected(stream.Id);
            r.Decisions.Update(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>() });
            Assert(r.Host.Read(h => h.Closed.Single()) is var (closed, abort) && closed == stream && abort && r.Decisions.Select(stream) is null);
        });
        check("A tunnel refuses destinations and address families it does not carry", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.Backends.Networks = [NetPrefix.Parse("10.0.0.0/8")];
            r.StartTunnel();
            r.Connect(Browser, Remote);
            Assert(r.Host.Resets(50_000) == 1, "A destination outside the tunnel's networks was not refused.");
            var inside = r.Connect(Browser, new(NetAddress.Parse("10.1.2.3"), 443), 50_001);
            Assert(r.Decisions.Select(inside) is { Tunneled: true });
            r.Connect(Browser, new(NetAddress.Parse("2001:db8::8"), 443), 50_002, v6: true);
            Assert(r.Host.Resets(50_002) == 1 && r.Host.Count(h => h.Connecting) == 1, "IPv6 left without an IPv6 tunnel address.");
        });
        check("A default profile carries unassigned applications, but never Darkwire's service or backends", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow()) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback });
            r.StartTunnel(Demand with { ProfileId = Fallback });
            Assert(r.Decisions.Select(r.Connect(Game, Remote)) is { Tunneled: true });
            Assert(r.Decisions.Select(r.Connect(WireGuard, new(NetAddress.Parse("198.51.100.7"), 51820), 50_001)) is { Tunneled: false } backend && backend.Egress == Lan);
            Assert(r.Decisions.Select(r.Connect(Service, Remote, 50_002)) is { Tunneled: false });
            // Unidentified flows follow the default profile when no application has its own.
            Assert(r.Decisions.Select(r.Connect(null, Remote, 50_003)) is { Tunneled: true });
        });
        check("Unidentified connections are refused while applications have VPN assignments; ICMP follows the default route", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow()));
            r.StartTunnel();
            r.Connect(null, Remote);
            Assert(r.Host.Resets(50_000) == 1 && r.Host.Count(h => h.Connecting) == 0);
            var ping = r.Ping(Remote.Address);
            Assert(r.Host.Read(h => h.Echoes.Contains(ping)) && r.Decisions.Select(ping) is { Tunneled: false } echo && echo.Egress == Lan);
        });
        check("An executable two profiles claim leaves through neither", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)) with { Assigned = new Dictionary<string, Guid> { [Key(Browser)] = Guid.Empty } });
            r.StartTunnel();
            r.Connect(Browser, Remote);
            Assert(r.Host.Resets(50_000) == 1);
        });
        check("Policy refusals win: a tunnel never carries what the plan blocks", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew));
            r.StartTunnel();
            r.Connect(Browser, Remote);
            Assert(r.Host.Resets(50_000) == 1 && r.Host.Count(h => h.Connecting) == 0);
        });
        check("Moving an application into a tunnel withdraws its physical connections", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)) with { Assigned = new Dictionary<string, Guid>() });
            var flow = r.Connect(Browser, Remote);
            r.Router.Connected(flow.Id);
            Assert(r.Decisions.Select(flow) is { Tunneled: false });
            r.StartTunnel();
            r.Decisions.Update(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            Assert(r.Host.Read(h => h.Closed.Single()) is var (closed, abort) && closed == flow && abort);
            Assert(r.Decisions.Select(r.Connect(Browser, Remote, 50_001)) is { Tunneled: true });
        });
        check("Learning asks about a tunneled connection on the tunnel's interface and releases it through the tunnel once allowed", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.Learning));
            r.StartTunnel();
            var flow = r.Connect(Browser, Remote);
            var prompt = r.Asked.Single();
            Assert(prompt.Path == Browser && prompt.LocalAddress == "10.64.0.2" && prompt.Location == "Public" && r.Host.Count(h => h.Connecting) == 0);
            r.Decisions.Update(Decisions(FirewallMode.Learning, Allow(Browser)));
            Assert(r.Host.Count(h => h.Connecting) == 1 && r.Decisions.Select(flow) is { Tunneled: true });
        });
        check("Replaced credentials restart a profile only after the old backend and its routes are gone", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.StartTunnel();
            var revised = Demand with { Revision = Guid.NewGuid() };
            r.Tunnels.Sync([revised]);
            Until(() => r.Tunnels.Find(Profile)?.State == TunnelState.Up && r.Backends.Read(b => b.Started.Count) == 2, "The revised profile did not start.");
            var events = r.Backends.Read(b => b.Events.ToArray());
            Assert(events.SequenceEqual([$"start {Demand.Revision}", "release 900", $"unassign 900 {TunnelSource}", $"dispose {Demand.Revision}", $"start {revised.Revision}"]), string.Join(", ", events));
            r.Tunnels.Sync([]);
            Assert(r.Tunnels.Find(Profile) is null && r.Tunnels.Status().Count == 0);
            Until(() => r.Backends.Read(b => b.Instances.All(i => i.Disposed)), "An unwanted profile kept running.");
        });
        check("Status reports each profile's state, interface and addresses", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew));
            r.StartTunnel();
            Assert(r.Tunnels.Status().Single() is { State: "Up", Interface: 9, Error: null, Shared: null } up && up.Addresses!.SequenceEqual(["10.64.0.2"]) && up.ProfileId == Profile);
            Assert(r.Tunnels.Owns(900) && !r.Tunnels.Owns(42));
        });
        check("Stopping the supervisor withdraws every tunneled connection before the backends go away", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser)));
            r.StartTunnel();
            var flow = r.Connect(Browser, Remote);
            r.Router.Connected(flow.Id);
            r.Tunnels.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(5));
            Assert(r.Host.Read(h => h.Closed.Single()).Flow == flow && r.Tunnels.Find(Profile) is null && r.Decisions.Select(flow) is null);
            Assert(r.Backends.Read(b => b.Instances.Single()).Disposed && !r.Tunnels.Owns(900));
            r.Tunnels.Sync([Demand]);
            Assert(r.Backends.Read(b => b.Started.Count) == 1, "A stopped supervisor started a tunnel.");
        });
        check("Darkwire's DNS proxy takes its own route, needs no rule, and reaches the servers it names, DNSCrypt on port 53 included", () =>
        {
            var own = new HashSet<string>([Key(Proxy)], StringComparer.OrdinalIgnoreCase);
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Own = own, OwnTunnel = Profile }))
            {
                r.StartTunnel();
                Assert(r.Decisions.Select(r.Connect(Proxy, Remote)) is { Tunneled: true, Own: true }, "The proxy did not take its profile's tunnel.");
                var crypt = r.Datagram(Proxy, new(NetAddress.Parse("198.51.100.53"), 53), 50_100);
                Assert(r.Decisions.Select(crypt) is { Tunneled: true, Target: null, Own: true }, "The proxy's DNSCrypt went to the profile's resolver.");
            }
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Own = own }))
                Assert(r.Decisions.Select(r.Connect(Proxy, Remote)) is { Tunneled: false, Own: true } physical && physical.Egress == Lan);
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Own = own, OwnRefused = true }))
            {
                r.Connect(Proxy, Remote);
                Assert(r.Host.Resets(50_000) == 1, "The proxy left while its route could not run.");
            }
            // An explicit deny still refuses it.
            var deny = new FirewallRule { ApplicationName = "No quad", RemoteAddresses = "203.0.113.8", Action = RuleAction.Deny };
            using (var r = new Rig(Decisions(FirewallMode.BlockNew, deny) with { Own = own }))
            {
                r.Connect(Proxy, Remote);
                Assert(r.Host.Resets(50_000) == 1, "An explicit deny let the proxy through.");
            }
        });
        check("With encrypted DNS, lookups sent to Darkwire's resolver pass with no network or tunnel server for them", () =>
        {
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), Forwards = true }))
            {
                var lookup = r.Datagram(DnsClient, Resolver4, 50_200, Dnscache);
                Assert(r.Host.Read(h => h.Sent.Contains(lookup)) && r.Decisions.Select(lookup) is null, "The lookup was not let through to the forwarder.");
                r.Connect(DnsClient, Resolver4, 50_201, sid: Dnscache);
                Assert(r.Host.Count(h => h.Connecting) == 1 && r.Host.Resets(50_201) == 0, "A lookup over TCP was refused.");
            }
            using (var r = new Rig(Decisions(FirewallMode.BlockNew) with { Assigned = new Dictionary<string, Guid>(), DefaultTunnel = Fallback, Forwards = true }))
            {
                // A default profile's tunnel naming no resolver no longer refuses them.
                r.Backends.Resolvers = [];
                r.StartTunnel(Demand with { ProfileId = Fallback });
                var lookup = r.Datagram(DnsClient, Resolver4, 50_202, Dnscache);
                Assert(r.Host.Read(h => h.Sent.Contains(lookup)) && r.Decisions.Select(lookup) is null);
            }
        });
        check("The router reports the TCP connections it carries or holds, each with the profile it takes or none, and not those it refused", () =>
        {
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser), Allow(Game)));
            r.Backends.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Tunnels.Sync([Demand]);
            r.Connect(Browser, Remote);
            r.Connect(Game, Remote, 50_001);
            r.Connect(Game, new(NetAddress.Parse("2001:db8::8"), 443), 50_002, v6: true);
            r.Connect(@"C:\Apps\editor.exe", Remote, 50_003);
            r.Datagram(Game, new(NetAddress.Parse("198.51.100.9"), 443), 50_004);
            // The browser's connection waits for its starting tunnel and already shows the profile it takes.
            var routed = r.Decisions.Connections();
            Assert(routed.Count == 3 && routed.Single(c => c.LocalPort == 50_000) is { LocalAddress: "198.18.0.1", RemoteAddress: "203.0.113.8", RemotePort: 443 } held && held.ProfileId == Profile);
            Assert(routed.Single(c => c.LocalPort == 50_001).ProfileId is null && routed.Single(c => c.LocalPort == 50_002) is { LocalAddress: "fd5a:9c33:21e7::1", RemoteAddress: "2001:db8::8", ProfileId: null });
            r.Backends.Gate.SetResult();
            Until(() => r.Host.Count(h => h.Connecting) == 3, "The held flow was not released through its tunnel.");
            Assert(r.Decisions.Connections().Single(c => c.LocalPort == 50_000).ProfileId == Profile);
        });
        check("Each refused flow is told once, with why it was refused", () =>
        {
            List<BlockedFlow> refused = [];
            var deny = new FirewallRule { ApplicationName = "Block the game", Path = Game, Action = RuleAction.Deny };
            using var r = new Rig(Decisions(FirewallMode.BlockNew, Allow(Browser), deny) with { Refused = refused.Add });
            r.Connect(Game, Remote);
            r.Connect(Browser, Remote, 50_001);
            r.Connect(null, Remote, 50_002);
            r.Connect(@"C:\Apps\editor.exe", Remote, 50_003);
            Assert(refused.Select(f => f.Reason).SequenceEqual(["Block the game", "Its VPN tunnel is down", "Its program could not be identified, and VPN profiles carry programs", "No rule allows it"]),
                string.Join(" | ", refused.Select(f => f.Reason)));
            Assert(refused[0] is { Application: Game, RemoteAddress: "203.0.113.8", RemotePort: 443, Protocol: "TCP", Direction: TrafficDirection.Outbound, Count: 1 } && refused[2].Application == "Unidentified program");
        });
    }

    private const string Proxy = @"C:\Program Files\Darkwire\Service\Backends\DnsCrypt\dnscrypt-proxy.exe";

    private static string Key(string path) => Environment.ExpandEnvironmentVariables(path).ToLowerInvariant();

    /// <summary>Decisions where the browser is assigned to the profile; network profiles: LAN Private, tunnel Public.</summary>
    private static RouterDecisions Decisions(FirewallMode mode, params FirewallRule[] rules)
    {
        var plan = FilterCompiler.Compile(new() { Mode = mode, Rules = [.. rules] }, true);
        if (!plan.CanApply) throw new Exception(string.Join("; ", plan.Errors));
        return new(new PlanMatcher(plan, Key, a => a), mode, new Dictionary<ulong, uint> { [42] = 2, [900] = 1 }, [42])
        {
            Assigned = new Dictionary<string, Guid> { [Key(Browser)] = Profile },
            Exempt = new HashSet<string>([Key(Service), Key(WireGuard)], StringComparer.OrdinalIgnoreCase)
        };
    }

    private sealed class Rig : IDisposable
    {
        public readonly Host Host = new();
        public readonly Clock Clock = new();
        public readonly Backends Backends = new();
        public readonly Interfaces Interfaces = new();
        public readonly PacketRouter Router;
        public readonly TunnelSupervisor Tunnels;
        public readonly FlowDecisions Decisions;
        public readonly List<Connection> Asked = [];
        private readonly Dictionary<int, (string Path, string? Sid)> processes = [];
        private readonly List<(bool Udp, SocketRow Row)> sockets = [];
        private int nextProcess = 100;

        /// <param name="check">Asks a profile's DNS server through its tunnel, for the supervisor's end-to-end checks; none without it.</param>
        public Rig(RouterDecisions decisions, Func<Guid, TunnelEgress, bool?>? check = null)
        {
            FlowDecisions? current = null;
            Interfaces.Log = Backends.Record;
            Tunnels = new(Backends, Interfaces, profile => Volatile.Read(ref current)?.TunnelChanged(profile), true, Clock, luid => Backends.Record("release " + luid), check);
            var attribution = new FlowAttribution((udp, v6) => sockets.Where(s => s.Udp == udp && (s.Row.LocalAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) == v6).Select(s => s.Row).ToArray(),
                (id, _) => processes.TryGetValue(id, out var owner) ? new FlowProcess(id, 1, owner.Path, new(Key(owner.Path),
                    new HashSet<string>(owner.Sid is { } sid ? ["S-1-5-21-1-2-3-1001", sid] : ["S-1-5-21-1-2-3-1001"], StringComparer.OrdinalIgnoreCase), null)) : null);
            current = Decisions = new(decisions, connection => { Asked.Add(connection); return true; }, Tunnels, new Physical(), attribution);
            Router = new(Host, RouterAddresses.Default(7100, 7100, 1500), Clock);
            Host.Forget = Decisions.Forget;
            Decisions.Attach(Router);
        }

        public void StartTunnel(TunnelDemand? demand = null)
        {
            var profile = (demand ?? Demand).ProfileId;
            Tunnels.Sync([demand ?? Demand]);
            if (!SpinWait.SpinUntil(() => Tunnels.Find(profile)?.State == TunnelState.Up, TimeSpan.FromSeconds(5))) throw new Exception("The fake tunnel did not come up.");
        }

        /// <param name="sid">A service SID the process token carries besides the user's.</param>
        public RouterFlow Connect(string? path, NetEndpoint remote, ushort port = 50_000, bool v6 = false, string? sid = null)
        {
            var local = new NetEndpoint(v6 ? RouterAddresses.Tunnel6 : RouterAddresses.Tunnel4, port);
            if (path is not null) Own(path, sid, false, local, remote);
            Router.Process(PacketBuilder.Tcp(local, remote, 1000, 0, IpPacket.Syn, 64240, [], []));
            return Evaluate();
        }

        public RouterFlow Datagram(string path, NetEndpoint remote, ushort port, string? sid = null)
        {
            var local = new NetEndpoint(remote.Address.V6 ? RouterAddresses.Tunnel6 : RouterAddresses.Tunnel4, port);
            Own(path, sid, true, local, null);
            Router.Process(PacketBuilder.Udp(local, remote, [1, 2, 3]));
            return Evaluate();
        }

        public RouterFlow Ping(NetAddress remote)
        {
            Router.Process(PacketBuilder.Echo(RouterAddresses.Tunnel4, remote, false, 0x4242, 1, [1, 2, 3]));
            return Evaluate();
        }

        private RouterFlow Evaluate()
        {
            var flow = Host.Read(h => h.Evaluated[^1]);
            Decisions.Evaluate([flow]);
            return flow;
        }

        private void Own(string path, string? sid, bool udp, NetEndpoint local, NetEndpoint? remote)
        {
            var process = nextProcess++;
            processes[process] = (path, sid);
            // SYN_SENT for a connecting TCP socket; UDP rows carry no remote.
            sockets.Add((udp, new(local.Address.ToIPAddress(), local.Port, remote?.Address.ToIPAddress(), remote?.Port ?? 0, udp ? 0 : 3, process, 0)));
        }

        public void Dispose() => Tunnels.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(5));
    }

    private sealed class Physical : IEgressSelector
    {
        public Egress? Select(IPAddress destination) => destination.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? Lan6 : Lan;
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Host : IRouterHost
    {
        private readonly object gate = new();
        private readonly List<byte[]> injected = [];
        public readonly List<RouterFlow> Evaluated = [], Connecting = [], Sent = [], Echoes = [];
        public readonly List<(RouterFlow Flow, bool Abort)> Closed = [];
        public Action<RouterFlow>? Forget;
        public T Read<T>(Func<Host, T> read) { lock (gate) return read(this); }
        public int Count(Func<Host, List<RouterFlow>> list) { lock (gate) return list(this).Count; }
        /// <summary>Resets the router sent to the application's port: refused connections.</summary>
        public int Resets(ushort port)
        {
            lock (gate) return injected.Count(p => IpPacket.TryParse(p, out var h) && h.Protocol == 6 && (h.TcpFlags & IpPacket.Rst) != 0 && h.DestinationPort == port);
        }
        public void Inject(ReadOnlySpan<byte> packet) { lock (gate) injected.Add(packet.ToArray()); }
        public void Evaluate(RouterFlow flow) { lock (gate) Evaluated.Add(flow); }
        public void Connect(RouterFlow flow) { lock (gate) Connecting.Add(flow); }
        public void Send(RouterFlow flow, byte[] payload) { lock (gate) Sent.Add(flow); }
        public void Echo(RouterFlow flow, ushort sequence, byte[] data) { lock (gate) Echoes.Add(flow); }
        void IRouterHost.Closed(RouterFlow flow, bool abort) { lock (gate) Closed.Add((flow, abort)); Forget?.Invoke(flow); }
        public void Released(NetEndpoint local) { }
    }

    private sealed class Backends : ITunnelBackends
    {
        private readonly object gate = new();
        public readonly List<TunnelDemand> Started = [];
        public readonly List<Instance> Instances = [];
        public readonly List<string> Events = [];
        public TaskCompletionSource? Gate;
        public Exception? Failure;
        public IReadOnlyList<NetPrefix> Networks = [NetPrefix.Parse("0.0.0.0/0"), NetPrefix.Parse("::/0")];
        public IReadOnlyList<IPAddress> Resolvers = [IPAddress.Parse("10.64.0.1")];
        /// <summary>The addresses new instances share with another tunnel.</summary>
        public IReadOnlyList<IPAddress> Shared = [];
        public T Read<T>(Func<Backends, T> read) { lock (gate) return read(this); }

        public async Task<ITunnelInstance> StartAsync(TunnelDemand demand, CancellationToken cancellation)
        {
            lock (gate) { Started.Add(demand); Events.Add("start " + demand.Revision); }
            if (Gate is { } wait) await wait.Task.WaitAsync(cancellation).ConfigureAwait(false);
            if (Failure is { } failure) throw failure;
            var instance = new Instance(this, demand, Networks, Resolvers, Shared);
            lock (gate) Instances.Add(instance);
            return instance;
        }

        public void Record(string text) { lock (gate) Events.Add(text); }
    }

    private sealed class Instance(Backends owner, TunnelDemand demand, IReadOnlyList<NetPrefix> networks, IReadOnlyList<IPAddress> resolvers, IReadOnlyList<IPAddress> shared) : ITunnelInstance
    {
        public volatile bool Up = true, Disposed;
        public int Maintained;
        public Guid ProfileId => demand.ProfileId;
        public IReadOnlyList<TunnelRoute> Routes { get; } = [new(Interface, TunnelSource)];
        public IReadOnlyList<IPAddress> Shared => shared;
        public IReadOnlyList<NetPrefix> Networks => networks;
        public IReadOnlyList<IPAddress> Resolvers => resolvers;
        public bool Healthy => Up && !Disposed;
        public void Maintain() => Interlocked.Increment(ref Maintained);
        /// <summary>What WireGuard counts for the tunnel's servers; none until a check sets it.</summary>
        public PeerTraffic? Peers { get; set; }
        public ValueTask DisposeAsync() { owner.Record("dispose " + demand.Revision); Disposed = true; return ValueTask.CompletedTask; }
    }

    private sealed class Interfaces : ITunnelInterfaces
    {
        private readonly List<string> calls = [];
        /// <summary>The tunnel interface's sent and received byte counters.</summary>
        public (long Sent, long Received)? Traffic;
        public (long Sent, long Received)? Counters(Guid interfaceId) => interfaceId == Interface ? Traffic : null;
        public T Read<T>(Func<List<string>, T> read) { lock (calls) return read(calls); }
        public (ulong Luid, uint Index) Resolve(Guid interfaceId) => interfaceId == Interface ? (900UL, 9U) : throw new System.ComponentModel.Win32Exception(1168);
        public void AddRoute(ulong luid, IPAddress network, int prefix, uint metric) { lock (calls) calls.Add($"add {luid} {network}/{prefix} {metric}"); }
        public void DeleteRoute(ulong luid, IPAddress network, int prefix) { lock (calls) calls.Add($"delete {luid} {network}/{prefix}"); }
        /// <summary>Told of each address taken off, in order with what the backends record.</summary>
        public Action<string>? Log;
        public void DeleteAddress(ulong luid, IPAddress address) => Log?.Invoke($"unassign {luid} {address}");
    }
}
