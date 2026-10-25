using Darkwire.Core;
using Darkwire.Engine;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;

internal static class AttributionChecks
{
    private static readonly IPAddress Tunnel = IPAddress.Parse("198.18.0.1"), Remote = IPAddress.Parse("203.0.113.8");

    public static void Run(Action<string, Action> check, bool native)
    {
        static void Expect(bool condition, string reason = "Attribution invariant failed.") { if (!condition) throw new Exception(reason); }
        static SocketRow Tcp(int pid, int state = 3, int port = 50_000, long created = 1000) => new(Tunnel, port, Remote, 443, state, pid, created);
        static SocketRow Udp(IPAddress address, int pid, int port = 50_000) => new(address, port, null, 0, 0, pid, 1000);
        static FlowAttribution Attribution(SocketRow[] tcp4, SocketRow[] udp4, SocketRow[]? tcp6 = null, SocketRow[]? udp6 = null, List<string>? reads = null, long started = 500) =>
            new((udp, v6) => { reads?.Add((udp ? "udp" : "tcp") + (v6 ? "6" : "4")); return (udp ? v6 ? udp6 : udp4 : v6 ? tcp6 : tcp4) ?? []; },
                (pid, created) => started > created && created > 0 ? null : new(pid, started, $@"C:\Apps\{pid}.exe", new($@"\device\harddiskvolume1\apps\{pid}.exe", new HashSet<string>(), null)));
        var local = new IPEndPoint(Tunnel, 50_000); var remote = new IPEndPoint(Remote, 443);

        check("Connecting TCP socket is attributed by its exact tuple", () =>
            Expect(Attribution([Tcp(7, port: 50_001), Tcp(42)], []).Begin().Tcp(local, remote)?.ProcessId == 42));
        check("Closed tuples never attribute a new connection", () =>
        {
            Expect(Attribution([Tcp(0, 11), Tcp(9, 11)], []).Begin().Tcp(local, remote) is null);
            Expect(Attribution([Tcp(9, 11), Tcp(42)], []).Begin().Tcp(local, remote)?.ProcessId == 42);
        });
        check("Dual-mode TCP sockets are found under IPv4-mapped addresses", () =>
        {
            var mapped = new SocketRow(Tunnel.MapToIPv6(), 50_000, Remote.MapToIPv6(), 443, 3, 77, 1000);
            Expect(Attribution([], [], [mapped]).Begin().Tcp(local, remote)?.ProcessId == 77);
        });
        check("An exact UDP bind wins over a wildcard socket on the same port", () =>
            Expect(Attribution([], [Udp(IPAddress.Any, 5), Udp(Tunnel, 6)]).Begin().Udp(local)?.ProcessId == 6));
        check("UDP sockets of two processes sharing a port stay unattributed", () =>
            Expect(Attribution([], [Udp(IPAddress.Any, 5), Udp(IPAddress.Any, 6)]).Begin().Udp(local) is null));
        check("Dual-mode UDP sockets are found under the IPv6 wildcard", () =>
            Expect(Attribution([], [], udp6: [Udp(IPAddress.IPv6Any, 8)]).Begin().Udp(local)?.ProcessId == 8));
        check("An inbound attempt is attributed to the socket listening on its port, never to a connection's", () =>
        {
            var any = new SocketRow(IPAddress.Any, 50_000, IPAddress.Any, 0, 2, 31, 1000);
            var exact = new SocketRow(Tunnel, 50_000, IPAddress.Any, 0, 2, 32, 1000);
            Expect(Attribution([any, Tcp(42)], []).Begin().Listener(local)?.ProcessId == 31);
            Expect(Attribution([any, exact], []).Begin().Listener(local)?.ProcessId == 32, "A wildcard listener outranked an exact bind.");
            Expect(Attribution([Tcp(42)], []).Begin().Listener(local) is null, "A connecting socket answered for a listener.");
            Expect(Attribution([], [], [new(IPAddress.IPv6Any, 50_000, IPAddress.IPv6Any, 0, 2, 33, 1000)]).Begin().Listener(local)?.ProcessId == 33);
        });
        check("Service hosts are named by the service behind the connection, else by every service they run", () =>
        {
            static Connection Host(string service, string hosted) => new("svchost", @"C:\Windows\System32\svchost.exe", 7, "203.0.113.8", 443, 50_000, "TCP", TrafficDirection.Outbound, Service: service, HostedServices: hosted);
            Expect(Host("Dnscache", "Dnscache") is { ProcessDisplay: "svchost · Dnscache" } single && single.SharedServices().Length == 0);
            Expect(Host("", "BITS, wuauserv") is { ProcessDisplay: "svchost · BITS, wuauserv" } untagged && untagged.SharedServices().Length == 0);
            Expect(Host("wuauserv", "BITS, wuauserv") is { ProcessDisplay: "svchost · wuauserv" } tagged && tagged.SharedServices() is ["BITS"], "A tagged connection was not named by its service.");
            Expect(new Connection("browser", @"C:\Apps\browser.exe", 7, "203.0.113.8", 443, 50_000, "TCP", TrafficDirection.Outbound).ProcessDisplay == "browser");
        });
        check("A socket in a process running several services is named by the service Windows tagged it with, when the token names it", () =>
        {
            var asked = 0;
            FlowAttribution Hosting(string[] sids, Func<SocketRow, string?> module, SocketRow[]? tcp4 = null, SocketRow[]? udp4 = null) =>
                new((udp, v6) => !v6 && (udp ? udp4 : tcp4) is { } rows ? rows : [],
                    (pid, _) => new(pid, 500, @"C:\Windows\System32\svchost.exe", new(@"\device\harddiskvolume1\windows\system32\svchost.exe", new HashSet<string>(sids, StringComparer.OrdinalIgnoreCase), null)),
                    row => { asked++; return module(row); });
            string[] shared = [IdentitySelectors.ServiceSid("BITS"), IdentitySelectors.ServiceSid("wuauserv")];
            FlowProcess Tagged(string? tag) => Hosting(shared, _ => tag, [Tcp(42)]).Begin().Tcp(local, remote)!;
            Expect(Tagged("WUAUSERV") is { TaggedService: "wuauserv" } process && ServiceNames.Of(process) is ({ Count: 2 }, "wuauserv"), "The tag did not name its service.");
            foreach (var other in new[] { null, "", "Dnscache", "svchost.exe" })
                Expect(Tagged(other) is { TaggedService: null } untagged && ServiceNames.Of(untagged).Service is null, "A tag outside the token named a service: " + other);
            // Sockets of the process sharing a UDP port name a service only when their tags agree.
            SocketRow[] pair = [Udp(IPAddress.Any, 42), Udp(IPAddress.Any, 42)];
            Expect(Hosting(shared, _ => "BITS", udp4: pair).Begin().Udp(local) is { TaggedService: "BITS" });
            var turn = 0;
            Expect(Hosting(shared, _ => turn++ == 0 ? "BITS" : "wuauserv", udp4: pair).Begin().Udp(local) is { TaggedService: null }, "Disagreeing tags named a service.");
            // A process running one service, or none, is named by its token alone; Windows is not asked.
            asked = 0;
            Expect(ServiceNames.Of(Hosting([IdentitySelectors.ServiceSid("Dnscache")], _ => "BITS", [Tcp(42)]).Begin().Tcp(local, remote)!) is (_, "Dnscache"));
            Expect(Hosting(["S-1-5-21-1-2-3-1001"], _ => "BITS", [Tcp(42)]).Begin().Tcp(local, remote) is { TaggedService: null });
            Expect(asked == 0, "Windows was asked about the socket of a process running at most one service.");
        });
        check("Windows is asked about a socket's owner only for a whole owner-module row that carries owner information", () =>
        {
            var row = Tcp(42, state: 5);
            Expect(FlowAttribution.OwnerModule(row) is null && FlowAttribution.OwnerModule(row with { Entry = new byte[160] }) is null);
            Expect(FlowAttribution.OwnerModule(row with { Entry = new byte[192] }) is null, "A row of another table's size was read.");
        });
        check("A PID that started after its socket is not trusted", () =>
            Expect(Attribution([Tcp(42, created: 400)], [], started: 500).Begin().Tcp(local, remote) is null));
        check("A snapshot reads each socket table once", () =>
        {
            var reads = new List<string>(); var snapshot = Attribution([Tcp(42)], [Udp(Tunnel, 6)], reads: reads).Begin();
            snapshot.Tcp(local, remote); snapshot.Tcp(local, remote); snapshot.Udp(local); snapshot.Udp(local);
            Expect(string.Join(",", reads) == "tcp4,udp4");
            var again = new List<string>(); var attribution = Attribution([Tcp(42)], [], reads: again);
            attribution.Begin().Tcp(local, remote); attribution.Begin().Tcp(local, remote);
            Expect(again.Count == 2, "A new batch reused an older socket table.");
        });
        check("The kernel is attributed as System", () =>
        {
            var system = FlowAttribution.ReadProcess(FlowAttribution.SystemProcessId, 0)!;
            Expect(system.Owner.ApplicationId == IdentitySelectors.SystemApplication && system.Owner.Sids!.Contains("S-1-5-18"));
        });
        if (!native) return;
        var applicationId = System.Text.Encoding.Unicode.GetString(WfpConditions.ApplicationId(Environment.ProcessPath!)).TrimEnd('\0');
        var user = WindowsIdentity.GetCurrent().User!.Value;
        void Mine(FlowProcess? process)
        {
            Expect(process is not null, "The socket was not attributed.");
            Expect(process!.ProcessId == Environment.ProcessId && process.ImagePath.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase), "Wrong process.");
            Expect(process.Owner.ApplicationId == applicationId, "Application ID differs from WFP's: " + process.Owner.ApplicationId);
            Expect(process.Owner.Sids?.Contains(user) == true && process.Owner.PackageSid is null, "Token identity is incomplete.");
        }
        foreach (var loopback in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
            check("Live " + loopback.AddressFamily + " TCP connection is attributed to this process", () =>
            {
                using var listener = new Socket(loopback.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(new IPEndPoint(loopback, 0)); listener.Listen(1);
                using var client = new Socket(loopback.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                client.Connect(listener.LocalEndPoint!);
                using var accepted = listener.Accept();
                Mine(new FlowAttribution().Begin().Tcp((IPEndPoint)client.LocalEndPoint!, (IPEndPoint)client.RemoteEndPoint!));
            });
        check("Live listener is attributed to this process, and running services to their hosts", () =>
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0)); listener.Listen(1);
            Mine(new FlowAttribution().Begin().Listener((IPEndPoint)listener.LocalEndPoint!));
            // The DNS client always runs; any user may see which process hosts it.
            Expect(ServiceProcesses.Read().Values.Any(services => services.Contains("Dnscache", StringComparer.OrdinalIgnoreCase)), "No process hosts the DNS client.");
        });
        check("Live: Windows names the service that opened the RPC endpoint mapper's socket", () =>
        {
            // Port 135 always listens, opened by a thread of the RPC service, whose socket Windows tags with that service.
            var listener = FlowAttribution.ReadTcp(false).FirstOrDefault(r => r.LocalPort == 135 && r.State == 2);
            Expect(listener.Entry.Length > 0, "Nothing listens on port 135.");
            var services = ServiceProcesses.Read().GetValueOrDefault(listener.ProcessId) ?? [];
            Expect(FlowAttribution.OwnerModule(listener) is { } module && services.Contains(module, StringComparer.OrdinalIgnoreCase), "Windows named none of the process's services for its socket.");
            Expect(services.Count < 2 || FlowAttribution.TaggedService(listener, services) is not null, "The tag did not name a service of a shared process.");
        });
        check("Live UDP sockets are attributed, including dual-mode ones", () =>
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            Mine(new FlowAttribution().Begin().Udp((IPEndPoint)udp.LocalEndPoint!));
            using var dual = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
            dual.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
            Mine(new FlowAttribution().Begin().Udp(new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)dual.LocalEndPoint!).Port)));
        });
    }
}
