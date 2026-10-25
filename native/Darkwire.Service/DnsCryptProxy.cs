using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Vpn;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Darkwire.Service;

/// <summary>An encrypted DNS server Darkwire's DNS proxy runs: its name and its stamps.</summary>
public sealed record DnsUpstream(string Name, IReadOnlyList<string> Stamps);

/// <summary>
/// Runs dnscrypt-proxy (https://github.com/DNSCrypt/dnscrypt-proxy, ISC) as Darkwire's DNS proxy for the encrypted DNS servers
/// the policy names, and forwards to it the lookups the router sends to the internet. The service writes its whole
/// configuration: the servers as static stamps, one loopback listener on a free port, nothing to download, and its log in
/// the service's protected state. Its own connections leave through the router like an application's, along the route set
/// for Darkwire's own connections. Names a local network answers never reach it, and a lookup it cannot answer in time fails
/// rather than going anywhere else.
/// </summary>
internal sealed partial class DnsCryptProxy : IDnsForwarder, IDisposable
{
    public static string Executable(string serviceDirectory) => Path.Combine(serviceDirectory, "Backends", "DnsCrypt", "dnscrypt-proxy.exe");
    public static bool Installed => File.Exists(Executable(AppContext.BaseDirectory));
    private static string RuntimeDirectory => Path.Combine(ServiceHost.StateDirectory, "DnsCrypt");
    private static string LogPath => Path.Combine(RuntimeDirectory, "dnscrypt-proxy.log");
    /// <summary>A lookup's time to answer; dnscrypt-proxy gives each server five seconds.</summary>
    public static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(6);
    /// <summary>How long after it starts listening dnscrypt-proxy may still be measuring its servers, failing lookups meanwhile.</summary>
    public static readonly TimeSpan WarmUp = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ListenTimeout = TimeSpan.FromSeconds(30), OwnershipCheck = TimeSpan.FromSeconds(30), AskAgain = TimeSpan.FromMilliseconds(250),
        TestCheck = TimeSpan.FromSeconds(1), TestTimeout = TimeSpan.FromMinutes(2);
    private readonly object gate = new();
    // Completed, and replaced, whenever the wanted servers change.
    private TaskCompletionSource changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource stop = new();
    private readonly Task supervision;
    private readonly TimeSpan queryTimeout, warmUp;
    private IReadOnlyList<DnsUpstream>? wanted;
    private IReadOnlyList<string> domains = [];
    // The running proxy's listener and process, and when it began listening; null while none answers.
    private (IPEndPoint Endpoint, int ProcessId, long Since)? listener;
    // Completed once a proxy listens, and replaced when it stops, so lookups wait for the next one.
    private TaskCompletionSource listening = new(TaskCreationOptions.RunContinuationsAsynchronously);
    // When the route to the servers last came up, and a task completed then, and replaced, for the run to hear of it.
    private long routeReady;
    private TaskCompletionSource routed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private string state = "Starting";
    private string? error;
    private DateTimeOffset? errorAt;
    private long answered, failed;
    private int latency = -1;
    private (DateTime Written, long Length, LogSummary Summary)? log;

    public DnsCryptProxy() : this(QueryTimeout, WarmUp, supervise: true) { }

    /// <param name="supervise">False for checks, which give it a listener of their own (<see cref="UseListener"/>) rather than a process.</param>
    internal DnsCryptProxy(TimeSpan queryTimeout, TimeSpan warmUp, bool supervise)
    {
        this.queryTimeout = queryTimeout; this.warmUp = warmUp;
        supervision = supervise ? Task.Run(() => SuperviseAsync(stop.Token)) : Task.CompletedTask;
    }

    /// <summary>Answers lookups from a listener a check runs, as if a proxy had just started on it; null stops it.</summary>
    internal void UseListener(IPEndPoint? endpoint, int processId = 0)
    {
        if (endpoint is null) Unlisten(); else Listen(endpoint, processId);
    }

    private void Listen(IPEndPoint endpoint, int processId)
    {
        lock (gate) { listener = (endpoint, processId, Stopwatch.GetTimestamp()); listening.TrySetResult(); }
    }

    private void Unlisten()
    {
        lock (gate)
        {
            listener = null;
            if (listening.Task.IsCompleted) listening = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    /// <summary>Runs the servers given, restarting the proxy only when they change; the domains are those the local networks answer.</summary>
    public void Sync(IReadOnlyList<DnsUpstream> servers, IReadOnlyList<string> localDomains)
    {
        Volatile.Write(ref domains, localDomains);
        lock (gate)
        {
            if (wanted is not null && wanted.Count == servers.Count && wanted.Zip(servers).All(p => p.First.Name == p.Second.Name && p.First.Stamps.SequenceEqual(p.Second.Stamps))) return;
            wanted = servers;
            var previous = changed; changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
            previous.TrySetResult();
        }
    }

    /// <summary>
    /// The route to the servers came up, as the tunnel carrying Darkwire's own connections does after a start. A run that
    /// began before then tested its servers without it, or only after waiting for it, so it may have left some out or measured
    /// them slow, and dnscrypt-proxy keeps what it found until its next test, hours later: once its test has ended, such a run
    /// starts again.
    /// </summary>
    public void RouteReady()
    {
        lock (gate)
        {
            routeReady = Stopwatch.GetTimestamp();
            var previous = routed; routed = new(TaskCreationOptions.RunContinuationsAsynchronously);
            previous.TrySetResult();
        }
    }

    public bool Answers(string name) => !LocalNames.Contains(name, Volatile.Read(ref domains));

    /// <summary>
    /// The answer to a lookup, through dnscrypt-proxy. While it starts the lookup waits for it, and while it is still measuring
    /// its servers, failing every lookup, it is asked again, so the first lookups after a start, a server change or a boot
    /// are answered once it can, within the lookup's time. Once that runs out, or once the proxy fails after warming up, the
    /// answer is a server failure.
    /// </summary>
    public async Task<byte[]> AskAsync(byte[] query, bool stream, CancellationToken cancellation)
    {
        var failure = DnsAnswers.Failure(query) ?? [];
        // The servers validate DNSSEC themselves, unless the query asks them not to; it never does here.
        var asked = DnsAnswers.Validating(query);
        var started = Stopwatch.GetTimestamp();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(queryTimeout);
        try
        {
            while (true)
            {
                var current = await ListenerAsync(timeout.Token).ConfigureAwait(false);
                byte[] answer;
                try { answer = stream ? await AskStreamAsync(current.Endpoint, current.ProcessId, asked, timeout.Token).ConfigureAwait(false) : await AskDatagramAsync(current.Endpoint, asked, timeout.Token).ConfigureAwait(false); }
                // A proxy stopping or restarting under the lookup: ask whichever runs next.
                catch (Exception error) when (error is SocketException or IOException or InvalidDataException) { await Task.Delay(AskAgain, timeout.Token).ConfigureAwait(false); continue; }
                var serverFailure = answer.Length >= 4 && (answer[3] & 0x0F) == 2;
                if (serverFailure && Stopwatch.GetElapsedTime(current.Since) < warmUp) { await Task.Delay(AskAgain, timeout.Token).ConfigureAwait(false); continue; }
                Volatile.Write(ref latency, (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
                if (serverFailure) Interlocked.Increment(ref failed); else Interlocked.Increment(ref answered);
                return answer;
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            Interlocked.Increment(ref failed);
            return failure;
        }
    }

    /// <summary>The running proxy's listener, waiting for one while none listens.</summary>
    private async Task<(IPEndPoint Endpoint, int ProcessId, long Since)> ListenerAsync(CancellationToken cancellation)
    {
        while (true)
        {
            Task started;
            lock (gate) { if (listener is { } current) return current; started = listening.Task; }
            await started.WaitAsync(cancellation).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> AskDatagramAsync(IPEndPoint endpoint, byte[] query, CancellationToken cancellation)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Connect(endpoint);
        await socket.SendAsync(query, SocketFlags.None, cancellation).ConfigureAwait(false);
        var buffer = new byte[65_535];
        while (true)
        {
            var count = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellation).ConfigureAwait(false);
            if (DnsAnswers.Answers(query, buffer.AsSpan(0, count))) return buffer[..count];
        }
    }

    /// <summary>One query over TCP, to the proxy's own listener: the connection must reach its process, not one that took its port.</summary>
    private static async Task<byte[]> AskStreamAsync(IPEndPoint endpoint, int processId, byte[] query, CancellationToken cancellation)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        await socket.ConnectAsync(endpoint, cancellation).ConfigureAwait(false);
        if (!LoopbackPeerIdentity.Matches(socket, processId)) throw new IOException("Another process holds the DNS proxy's port.");
        var framed = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length); query.CopyTo(framed, 2);
        await socket.SendAsync(framed, SocketFlags.None, cancellation).ConfigureAwait(false);
        var prefix = new byte[2];
        await ReadAsync(socket, prefix, cancellation).ConfigureAwait(false);
        var answer = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        await ReadAsync(socket, answer, cancellation).ConfigureAwait(false);
        return DnsAnswers.Answers(query, answer) ? answer : throw new InvalidDataException("The DNS proxy answered another query.");
    }

    private static async Task ReadAsync(Socket socket, byte[] buffer, CancellationToken cancellation)
    {
        for (var read = 0; read < buffer.Length;)
        {
            var count = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, cancellation).ConfigureAwait(false);
            if (count == 0) throw new IOException("The DNS proxy closed the connection.");
            read += count;
        }
    }

    /// <summary>
    /// Keeps a proxy running the wanted servers: starts one, restarts it when the servers change, when it exits, when its
    /// port turns out to be held by another process, or, once its test of them has ended, when the route to its servers came
    /// up after it started; backing off while starts keep failing.
    /// </summary>
    private async Task SuperviseAsync(CancellationToken cancellation)
    {
        var failures = 0;
        try
        {
            while (!cancellation.IsCancellationRequested)
            {
                IReadOnlyList<DnsUpstream>? servers; Task next;
                lock (gate) { servers = wanted; next = changed.Task; }
                if (servers is null || servers.Count == 0) { await next.WaitAsync(cancellation).ConfigureAwait(false); continue; }
                ContainedProcess? process = null;
                var restart = false;
                try
                {
                    SetState("Starting", null);
                    // It tests its servers from the moment it starts; a route that comes up later may have missed that test.
                    var tested = Stopwatch.GetTimestamp();
                    (process, var endpoint) = await StartAsync(servers, cancellation).ConfigureAwait(false);
                    Listen(endpoint, process.Id);
                    SetState("Ready", null);
                    failures = 0;
                    var exited = process.WaitForExitAsync(cancellation);
                    var entries = Statics(servers).Count;
                    while (true)
                    {
                        Task ready; long readyAt;
                        lock (gate) { ready = routed.Task; readyAt = routeReady; }
                        // The route came up after this run began, so its servers were tested without it, or only after waiting for
                        // it: once that test has ended, or has taken longer than any test takes, the run starts again to test them
                        // through the route.
                        if (readyAt > tested && ReadLogFile() is var summary && (TestEnded(summary) || Stopwatch.GetElapsedTime(readyAt) > TestTimeout))
                        {
                            var found = summary?.Live is { } live ? $"its test found {live} of {entries} servers answering"
                                : summary?.Waiting == true ? "it waited for any server to answer" : "its test had not ended";
                            ServiceHost.Log($"DNS proxy: the tunnel carrying it came up after it started, and {found}; testing its servers again through it.");
                            restart = true; break;
                        }
                        var done = await Task.WhenAny(exited, next, ready, Task.Delay(readyAt > tested ? TestCheck : OwnershipCheck, cancellation)).ConfigureAwait(false);
                        if (done == next) { restart = true; break; }
                        // Canceled, the wait only means the service is stopping: the proxy is still running, with no exit code.
                        if (done == exited) { cancellation.ThrowIfCancellationRequested(); throw new IOException($"dnscrypt-proxy stopped (exit code {process.ExitCode})."); }
                        if (done == ready) continue;
                        // Its port could only be taken once it let go of it; that ends this run too.
                        if (!Listening(endpoint.Port, process.Id)) throw new IOException("dnscrypt-proxy no longer holds its port alone.");
                    }
                }
                catch (Exception failure) when (failure is not OperationCanceledException || !cancellation.IsCancellationRequested)
                {
                    failures++;
                    SetState("Failed", failure.Message);
                    ServiceHost.Log("DNS proxy: " + failure.Message);
                }
                finally
                {
                    Unlisten();
                    if (process is not null)
                    {
                        // The next run starts once this one has let go of its files.
                        process.Stop();
                        try { await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } catch (TimeoutException) { }
                        process.Dispose();
                    }
                }
                if (!restart) await Task.WhenAny(next, Task.Delay(TimeSpan.FromSeconds(Math.Min(30, 1 << Math.Min(failures, 5))), cancellation)).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
    }

    /// <summary>Writes the configuration for a free loopback port and starts the proxy, returning once it alone listens there.</summary>
    private static async Task<(ContainedProcess Process, IPEndPoint Endpoint)> StartAsync(IReadOnlyList<DnsUpstream> servers, CancellationToken cancellation)
    {
        var executable = Executable(AppContext.BaseDirectory);
        if (!File.Exists(executable)) throw new IOException(@"dnscrypt-proxy is not installed in Service\Backends\DnsCrypt.");
        // The proxy runs as LocalSystem from the protected installation, with its configuration in protected state.
        ProtectedStorage.Verify();
        Directory.CreateDirectory(RuntimeDirectory);
        var port = FreePort();
        var configuration = Path.Combine(RuntimeDirectory, "dnscrypt-proxy.toml");
        File.WriteAllText(configuration, Configuration(servers, port, LogPath), new UTF8Encoding(false));
        var process = ContainedProcess.Start(executable, "-config " + Quote(configuration));
        try
        {
            var deadline = Stopwatch.GetTimestamp() + (long)(ListenTimeout.TotalSeconds * Stopwatch.Frequency);
            while (!Listening(port, process.Id))
            {
                if (process.HasExited) throw new IOException($"dnscrypt-proxy stopped while starting (exit code {process.ExitCode}); see {LogPath}.");
                if (Stopwatch.GetTimestamp() > deadline) throw new IOException("dnscrypt-proxy did not start listening.");
                await Task.Delay(100, cancellation).ConfigureAwait(false);
            }
            return (process, new(IPAddress.Loopback, port));
        }
        catch { process.Dispose(); throw; }
    }

    private static string Quote(string path) => path.Contains('"') ? throw new ArgumentException("Invalid path.") : '"' + path + '"';

    /// <summary>A loopback port free for both UDP and TCP at this moment.</summary>
    private static int FreePort()
    {
        for (var attempt = 0; ; attempt++)
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var port = ((IPEndPoint)udp.LocalEndPoint!).Port;
            try
            {
                using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
                tcp.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch (SocketException) when (attempt < 20) { }
        }
    }

    /// <summary>
    /// The proxy's process listens on the loopback port for UDP and TCP, and no other process holds that port on loopback or
    /// every address, which could take its lookups.
    /// </summary>
    internal static bool Listening(int port, int processId)
    {
        static bool Claims(SocketRow row) => IPAddress.IsLoopback(row.LocalAddress) || row.LocalAddress.Equals(IPAddress.Any);
        var udp = FlowAttribution.ReadUdp(false).Where(r => r.LocalPort == port && Claims(r)).ToArray();
        // MIB_TCP_STATE_LISTEN; established connections on the port are the proxy's own clients.
        var tcp = FlowAttribution.ReadTcp(false).Where(r => r.LocalPort == port && r.State == 2 && Claims(r)).ToArray();
        return udp.Length > 0 && tcp.Length > 0 && udp.Concat(tcp).All(r => r.ProcessId == processId);
    }

    /// <summary>
    /// dnscrypt-proxy's configuration: the servers as static entries, a listener on the loopback port, no lists or sources of its
    /// own, nothing logged but its own progress, and plain bootstrap resolvers only for finding a DoH server by name.
    /// </summary>
    internal static string Configuration(IReadOnlyList<DnsUpstream> servers, int port, string logFile)
    {
        if (logFile.IndexOfAny(['\'', '\r', '\n']) >= 0) throw new ArgumentException("The log path cannot be written into the configuration.");
        var statics = Statics(servers);
        var text = new StringBuilder();
        void Line(string value) => text.Append(value).Append('\n');
        Line("# Written by the Darkwire service each time it starts dnscrypt-proxy; changes here are overwritten.");
        Line($"listen_addresses = ['127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}']");
        Line("max_clients = 250");
        Line($"server_names = [{string.Join(", ", statics.Select(s => $"'{s.Name}'"))}]");
        foreach (var setting in new[]
        {
            "ipv4_servers = true", "ipv6_servers = true", "dnscrypt_servers = true", "doh_servers = true", "odoh_servers = false",
            "require_dnssec = false", "require_nolog = false", "require_nofilter = false", "force_tcp = false", "http3 = false",
            "timeout = 5000", "keepalive = 30", "log_level = 2", $"log_file = '{logFile}'", "log_file_latest = true", "use_syslog = false",
            "cert_refresh_delay = 240", "bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']", "ignore_system_dns = true", "netprobe_timeout = 0",
            "block_ipv6 = false", "block_unqualified = true", "block_undelegated = true", "reject_ttl = 10",
            "cache = true", "cache_size = 4096", "cache_min_ttl = 0", "cache_max_ttl = 86400", "cache_neg_min_ttl = 0", "cache_neg_max_ttl = 600"
        }) Line(setting);
        Line("");
        Line("[monitoring_ui]");
        Line("enabled = false");
        Line("");
        Line("[static]");
        foreach (var (name, stamp) in statics)
        {
            Line($"[static.'{name}']");
            Line($"stamp = '{stamp}'");
        }
        return text.ToString();
    }

    /// <summary>One static entry for each stamp: a server's first under its name, the others as name+2, name+3 and so on.</summary>
    internal static IReadOnlyList<(string Name, string Stamp)> Statics(IReadOnlyList<DnsUpstream> servers)
    {
        List<(string, string)> statics = [];
        foreach (var server in servers)
        {
            if (!ResolverList.ValidName(server.Name)) throw new InvalidDataException("A DNS server's name cannot be written into the configuration.");
            for (var i = 0; i < server.Stamps.Count; i++)
            {
                var stamp = server.Stamps[i];
                if (!DnsStamp.TryParse(stamp, out _) || stamp.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or ':' or '/'))) throw new InvalidDataException($"{server.Name}: a stamp cannot be written into the configuration.");
                statics.Add((i == 0 ? server.Name : $"{server.Name}+{i + 1}", stamp));
            }
        }
        return statics;
    }

    private void SetState(string next, string? failure)
    {
        lock (gate)
        {
            state = next;
            if (failure is not null) { error = failure; errorAt = DateTimeOffset.UtcNow; }
        }
    }

    /// <summary>What the proxy is doing, with what its log says of its servers and what the lookups it answered took.</summary>
    public DnsStatus Status()
    {
        string current; string? lastError; DateTimeOffset? lastErrorAt;
        lock (gate) { current = state; lastError = error; lastErrorAt = errorAt; }
        var summary = current == "Ready" ? Summary() : null;
        if (summary?.Waiting == true) current = "Waiting";
        if (summary?.Fatal is { } fatal) { lastError = fatal; }
        var took = Volatile.Read(ref latency);
        return new(current, summary?.Fastest, summary?.FastestMs, summary?.Live, Interlocked.Read(ref answered), Interlocked.Read(ref failed), took < 0 ? null : took, lastError, lastErrorAt);
    }

    internal sealed record LogSummary(string? Fastest, int? FastestMs, int? Live, bool Waiting, string? Fatal);

    /// <summary>The log's summary, read again only when the file changed.</summary>
    private LogSummary? Summary()
    {
        try
        {
            var file = new FileInfo(LogPath);
            if (!file.Exists) return null;
            if (log is { } cached && cached.Written == file.LastWriteTimeUtc && cached.Length == file.Length) return cached.Summary;
            if (ReadLogFile() is not { } summary) return null;
            log = (file.LastWriteTimeUtc, file.Length, summary);
            return summary;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>What the log says now; null without one.</summary>
    private static LogSummary? ReadLogFile()
    {
        try
        {
            using var stream = new FileStream(LogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            // The proxy logs from its latest start only; its newest lines are enough.
            if (stream.Length > 64 * 1024) stream.Seek(-64 * 1024, SeekOrigin.End);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return ReadLog(reader.ReadToEnd());
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Whether the proxy's test of its servers has ended: it named the fastest that answered, or it waits for any to.</summary>
    internal static bool TestEnded(LogSummary? summary) => summary is { Fastest: not null } or { Waiting: true };

    [GeneratedRegex(@"Server with the lowest initial latency: (?<name>[a-z0-9._+-]+) \(rtt: (?<rtt>\d+)ms\)(, live servers: (?<live>\d+))?")]
    private static partial Regex FastestLine();

    /// <summary>
    /// What dnscrypt-proxy's log says: the server it found fastest, with its round trip, and how many answer; whether it still
    /// waits for one to answer; and its last fatal error.
    /// </summary>
    internal static LogSummary ReadLog(string text)
    {
        string? fastest = null, fatal = null; int? rtt = null, live = null; var waiting = false;
        foreach (var line in text.Split('\n'))
        {
            if (FastestLine().Match(line) is { Success: true } match)
            {
                // Extra stamps run as name+2 and so on; people know the server by its name.
                fastest = match.Groups["name"].Value.Split('+')[0];
                rtt = int.Parse(match.Groups["rtt"].Value, CultureInfo.InvariantCulture);
                live = match.Groups["live"].Success ? int.Parse(match.Groups["live"].Value, CultureInfo.InvariantCulture) : null;
                waiting = false;
            }
            else if (line.Contains("waiting for at least one server to be reachable", StringComparison.Ordinal)) waiting = true;
            else foreach (var level in new[] { "[FATAL]", "[CRITICAL]" })
                if (line.IndexOf(level, StringComparison.Ordinal) is >= 0 and var at) fatal = line[(at + level.Length)..].Trim();
        }
        return new(fastest, rtt, live, waiting, fatal);
    }

    public void Dispose()
    {
        stop.Cancel();
        try { supervision.Wait(TimeSpan.FromSeconds(10)); } catch (AggregateException) { }
        stop.Dispose();
    }
}
