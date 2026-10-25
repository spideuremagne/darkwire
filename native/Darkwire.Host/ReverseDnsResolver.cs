using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Darkwire.Host;

/// <summary>Bounded, coalesced PTR lookups for optional display metadata.</summary>
public sealed class ReverseDnsResolver
{
    private sealed record CacheEntry(string? Name, DateTimeOffset Expires);
    private readonly object gate = new();
    private readonly Dictionary<string, CacheEntry> cache = [];
    private readonly Dictionary<string, Task<string?>> pending = [];
    private readonly SemaphoreSlim slots = new(4, 4);
    private readonly Func<IPAddress, CancellationToken, Task<string?>> lookup;
    private readonly Func<DateTimeOffset> now;
    private readonly int capacity;
    private readonly TimeSpan timeout;

    public ReverseDnsResolver(Func<IPAddress, CancellationToken, Task<string?>>? lookup = null,
        Func<DateTimeOffset>? now = null, int capacity = 2048, TimeSpan? timeout = null)
    {
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        this.capacity = capacity;
        this.timeout = timeout ?? TimeSpan.FromSeconds(2);
        if (this.timeout <= TimeSpan.Zero || this.timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(timeout));
        this.now = now ?? (() => DateTimeOffset.UtcNow);
        this.lookup = lookup ?? (async (address, token) => (await Dns.GetHostEntryAsync(address.ToString(), token).ConfigureAwait(false)).HostName);
    }

    public bool TryGet(string address, out string? name)
    {
        name = null;
        if (!IPAddress.TryParse(address, out var ip)) return false;
        lock (gate)
        {
            var key = ip.ToString();
            if (!cache.TryGetValue(key, out var entry)) return false;
            if (entry.Expires <= now()) { cache.Remove(key); return false; }
            name = entry.Name; return true;
        }
    }

    public Task<string?> ResolveAsync(string address, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return Task.FromResult<string?>(null);
        var key = ip.ToString();
        lock (gate)
        {
            if (TryGet(key, out var cached)) return Task.FromResult(cached);
            if (pending.TryGetValue(key, out var task)) return task.WaitAsync(cancellationToken);
            // Bound queued work as well as the completed cache. The UI submits at most 32 addresses per refresh.
            if (pending.Count >= 64) return Task.FromResult<string?>(null);
            var completion = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            pending[key] = completion.Task;
            _ = ResolveCore(ip, key, completion, cancellationToken);
            return completion.Task;
        }
    }

    private async Task ResolveCore(IPAddress address, string key, TaskCompletionSource<string?> completion, CancellationToken cancellationToken)
    {
        string? name = null;
        var entered = false;
        Task<string?>? operation = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await slots.WaitAsync(deadline.Token).ConfigureAwait(false); entered = true;
            operation = lookup(address, deadline.Token);
            var value = await operation.WaitAsync(deadline.Token).ConfigureAwait(false);
            value = value?.TrimEnd('.');
            if (value is { Length: > 0 and <= 253 } && Uri.CheckHostName(value) == UriHostNameType.Dns && !IPAddress.TryParse(value, out _)) name = value;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException) { }
        catch (Exception ex) { completion.TrySetException(ex); }
        finally
        {
            if (entered)
            {
                if (operation is null || operation.IsCompleted) slots.Release();
                else _ = ReleaseWhenCompleted(operation);
            }
            lock (gate)
            {
                pending.Remove(key);
                if (!cancellationToken.IsCancellationRequested)
                {
                    while (cache.Count >= capacity) cache.Remove(cache.MinBy(p => p.Value.Expires).Key);
                    cache[key] = new(name, now().Add(name is null ? TimeSpan.FromMinutes(2) : TimeSpan.FromMinutes(15)));
                }
            }
            completion.TrySetResult(name);
        }
    }
    private async Task ReleaseWhenCompleted(Task<string?> operation)
    {
        // Some DNS providers do not immediately honor cancellation. Keep their slots
        // occupied until they finish, so timeouts cannot create unbounded native work.
        try { await operation.ConfigureAwait(false); }
        catch (Exception) { }
        finally { slots.Release(); }
    }
}
