using Darkwire.Engine;
using System.Collections.Concurrent;

namespace Darkwire.Service;

/// <summary>
/// Counts what blocklists block in the router: lookups it answers itself and flows it refuses, by list. One block several
/// lists name counts once in all and once for each list. The kernel's drops are counted by the filter backend and added to
/// the status.
/// </summary>
internal sealed class BlocklistHitCounter
{
    private readonly ConcurrentDictionary<string, long> byList = new(StringComparer.Ordinal);
    private long total;
    public DateTimeOffset Since { get; } = DateTimeOffset.UtcNow;

    public void Hit(IEnumerable<string> lists)
    {
        var any = false;
        foreach (var key in lists) { byList.AddOrUpdate(key, 1, (_, count) => count + 1); any = true; }
        if (any) Interlocked.Increment(ref total);
    }

    /// <summary>The counts, with the kernel's drops for each list added.</summary>
    public BlocklistHits Snapshot(IEnumerable<(string Key, long Count)> kernel)
    {
        var lists = byList.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        var all = Interlocked.Read(ref total);
        foreach (var (key, count) in kernel) { lists[key] = lists.GetValueOrDefault(key) + count; all += count; }
        return new(all, Since, lists);
    }
}
