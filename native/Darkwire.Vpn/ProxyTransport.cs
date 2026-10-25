using System.Buffers;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Darkwire.Vpn.Checks")]
[assembly: InternalsVisibleTo("Darkwire.Service")]

namespace Darkwire.Vpn;

internal static class ProxyTransport
{
    public static async Task RelayTcpAsync(Socket first, Socket second, TimeSpan idleTimeout, CancellationToken cancellation)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        lifetime.CancelAfter(idleTimeout);
        async Task Copy(Socket source, Socket destination)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(32 * 1024);
            try
            {
                while (true)
                {
                    var count = await source.ReceiveAsync(buffer.AsMemory(0, 32 * 1024), SocketFlags.None, lifetime.Token).ConfigureAwait(false);
                    if (count == 0) { destination.Shutdown(SocketShutdown.Send); return; }
                    lifetime.CancelAfter(idleTimeout);
                    for (var sent = 0; sent < count;)
                    {
                        var written = await destination.SendAsync(buffer.AsMemory(sent, count - sent), SocketFlags.None, lifetime.Token).ConfigureAwait(false);
                        if (written <= 0) throw new IOException("The proxy stream closed while sending.");
                        sent += written; lifetime.CancelAfter(idleTimeout);
                    }
                }
            }
            catch { await lifetime.CancelAsync().ConfigureAwait(false); throw; }
            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        }
        await Task.WhenAll(Copy(first, second), Copy(second, first)).ConfigureAwait(false);
    }
}
