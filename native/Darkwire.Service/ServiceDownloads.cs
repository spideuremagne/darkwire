using Darkwire.Engine;
using Darkwire.Vpn;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Service;

/// <summary>
/// HTTPS downloads the service makes itself: GeoIP releases, blocklists and the resolver list. They leave along the route
/// set for Darkwire's own connections: the physical network, or a VPN profile's tunnel and nothing else while it is down.
/// Their sockets are pinned to that interface, as the router's relay sockets are, so Darkwire's capture routes never loop the
/// service's own traffic back through the router; the router-mode relay filter permits it.
/// </summary>
internal static class ServiceDownloads
{
    private static readonly HttpClient client = new(new SocketsHttpHandler
    {
        ConnectCallback = ConnectPinnedAsync, ConnectTimeout = TimeSpan.FromSeconds(30), AllowAutoRedirect = true, MaxAutomaticRedirections = 3,
        AutomaticDecompression = DecompressionMethods.None, PooledConnectionLifetime = TimeSpan.FromMinutes(5)
    }) { Timeout = TimeSpan.FromMinutes(10) };

    // The connections open now, idle ones kept for reuse included, by the interface each is pinned to.
    private static readonly ConcurrentDictionary<PinnedStream, ulong> open = new();

    /// <summary>
    /// Where a download to an address leaves: the egress the route for Darkwire's own connections gives it, or null when that
    /// route reaches nowhere now. Unset, downloads leave physically.
    /// </summary>
    public static Func<IPAddress, Egress?>? Route { get; set; }

    /// <summary>
    /// Ends at once the connections pinned to an interface that is going away, so they neither keep it alive nor serve another
    /// download; a download using one fails, to be tried again.
    /// </summary>
    public static void Abandon(ulong luid)
    {
        foreach (var (stream, pinned) in open)
            if (pinned == luid) stream.Abort();
    }

    /// <summary>The egress Windows would choose among the physical interfaces, leaving out Darkwire's adapter and the ones given.</summary>
    public static Egress? Physical(IPAddress destination, Func<ulong, bool>? excluded = null)
    {
        var interfaces = new NetworkEnvironment([ConnectionRouter.AdapterId]).Capture().Interfaces.Select(i => i.Luid).Where(luid => excluded?.Invoke(luid) != true).ToArray();
        return new EgressSelector(() => interfaces).Select(destination);
    }

    /// <summary>Downloads an HTTPS resource into a new file, refusing anything larger than the limit. Redirects must stay on HTTPS.</summary>
    public static async Task DownloadAsync(Uri uri, string destination, long maximumBytes, CancellationToken cancellation)
    {
        if (uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo)) throw new InvalidDataException("Only HTTPS sources without credentials are downloaded.");
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellation).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) throw new InvalidDataException("The source redirected away from HTTPS.");
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > maximumBytes) throw new InvalidDataException("The source is larger than allowed.");
        await using var source = new LimitedStream(await response.Content.ReadAsStreamAsync(cancellation).ConfigureAwait(false), maximumBytes);
        await using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
        await source.CopyToAsync(target, cancellation).ConfigureAwait(false);
    }

    private static async ValueTask<Stream> ConnectPinnedAsync(SocketsHttpConnectionContext context, CancellationToken cancellation)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellation).ConfigureAwait(false);
        var select = Route ?? (address => Physical(address));
        SocketException? failure = null;
        foreach (var address in addresses)
        {
            if (select(address) is not { } route) continue;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                var ipv4 = address.AddressFamily == AddressFamily.InterNetwork;
                // IP_UNICAST_IF: IPv4 takes the interface index in network byte order, IPv6 in host order.
                socket.SetSocketOption(ipv4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, (SocketOptionName)31, ipv4 ? IPAddress.HostToNetworkOrder((int)route.Index) : (int)route.Index);
                socket.Bind(new IPEndPoint(route.Source, 0));
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellation).ConfigureAwait(false);
                var stream = new PinnedStream(socket);
                open[stream] = route.Luid;
                return stream;
            }
            catch (SocketException error) { failure = error; socket.Dispose(); }
            catch { socket.Dispose(); throw; }
        }
        throw new HttpRequestException("The route for Darkwire's own connections does not reach " + context.DnsEndPoint.Host + " now.", failure);
    }

    /// <summary>A download connection, listed as open until it is disposed.</summary>
    private sealed class PinnedStream(Socket socket) : NetworkStream(socket, ownsSocket: true)
    {
        /// <summary>Resets the connection rather than closing it, so nothing of it lingers on the interface.</summary>
        public void Abort()
        {
            try { Socket.LingerState = new(true, 0); } catch (Exception error) when (error is SocketException or ObjectDisposedException) { }
            Dispose();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) open.TryRemove(this, out _);
            base.Dispose(disposing);
        }
    }
}

/// <summary>Stops reading past a size limit, so a download or a small archive cannot grow without bound.</summary>
internal sealed class LimitedStream(Stream inner, long limit) : Stream
{
    private long total;
    public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));
    public override int Read(Span<byte> buffer) => Count(inner.Read(buffer));
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellation = default) => Count(await inner.ReadAsync(buffer, cancellation).ConfigureAwait(false));
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellation) => ReadAsync(buffer.AsMemory(offset, count), cancellation).AsTask();
    private int Count(int read)
    {
        total += read;
        return total > limit ? throw new InvalidDataException("The data is larger than allowed.") : read;
    }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => total; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    public override ValueTask DisposeAsync() { Dispose(true); GC.SuppressFinalize(this); return ValueTask.CompletedTask; }
}
