using Darkwire.Core;
using Darkwire.Engine;
using System.Text;
using System.Text.Json;

namespace Darkwire.Service;

public interface IBlocklistStore : IBlocklistContents
{
    /// <summary>Changes whenever a stored list does.</summary>
    long Version { get; }
    /// <summary>A downloaded domain list's names, or null while it has not been downloaded.</summary>
    DomainFilter? Names(string catalogId);
    IReadOnlyList<BlocklistStatus> Status();
    /// <summary>Queues a download unless the stored copy is younger than <paramref name="maximumAge"/> or one is already on its way.</summary>
    void Request(string catalogId, TimeSpan maximumAge);
}

/// <summary>
/// Catalog lists the service downloads itself and keeps, normalized, in its protected state folder. Lists the enforced policy
/// enables are refreshed daily; anyone may ask for a catalog list ahead of enabling it, since only catalog URLs are fetched.
/// Downloads run one at a time in the background, and a failed one keeps the previous copy. A list with no copy yet, which
/// blocks nothing until it has one, tries again a minute after failing, then after twice as long each time, up to an hour.
/// </summary>
internal sealed class BlocklistStore : IBlocklistStore
{
    public static readonly TimeSpan Refresh = TimeSpan.FromDays(1), Preload = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(1), RetryPreload = TimeSpan.FromMinutes(1);
    private const long MaximumDownload = 48L * 1024 * 1024;
    private readonly object gate = new();
    private readonly Func<Uri, string, long, CancellationToken, Task> download;
    private readonly string directory;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, Stored> lists = [];
    private readonly Queue<string> queue = new();
    private readonly SemaphoreSlim wake = new(0);
    private long version;

    public BlocklistStore(Func<Uri, string, long, CancellationToken, Task> download, string directory, TimeProvider clock)
    {
        this.download = download; this.directory = directory; this.clock = clock;
        Directory.CreateDirectory(directory);
    }

    public static string DefaultDirectory => Path.Combine(ServiceHost.StateDirectory, "Blocklists");
    /// <summary>Runs after a download changed a list, outside the store's lock; the coordinator applies the change.</summary>
    public Action? Changed { get; set; }
    public long Version => Interlocked.Read(ref version);

    private sealed class Stored
    {
        public DateTimeOffset? UpdatedAt, FailedAt;
        public int Count, Failures;
        public string? Error;
        public bool Queued, Downloading, Loaded;
        public DomainFilter? Names;
        public IReadOnlyList<string>? Networks;
    }
    private sealed record Metadata(DateTimeOffset UpdatedAt, int Count);

    public IReadOnlyList<BlocklistStatus> Status()
    {
        lock (gate)
            return BlocklistCatalog.Entries.Select(e =>
            {
                var list = Entry(e.Id);
                return new BlocklistStatus(e.Id, list.Count, list.UpdatedAt, list.Queued || list.Downloading, list.Error);
            }).ToArray();
    }

    public DomainFilter? Names(string catalogId) { lock (gate) return Load(catalogId).Names; }
    public IReadOnlyList<string>? Networks(string catalogId) { lock (gate) return Load(catalogId).Networks; }

    public void Request(string catalogId, TimeSpan maximumAge)
    {
        if (BlocklistCatalog.Find(catalogId) is null) throw new InvalidDataException("Unknown catalog blocklist.");
        lock (gate)
        {
            var list = Entry(catalogId); var now = clock.GetUtcNow();
            if (list.Queued || list.Downloading || list.UpdatedAt is { } updated && now - updated < maximumAge) return;
            // Refreshes back off after a failure; a preload may try again a minute later.
            if (list.FailedAt is { } failed && now - failed < RetryAfter(list, maximumAge)) return;
            list.Queued = true; queue.Enqueue(catalogId);
        }
        wake.Release();
    }

    /// <summary>
    /// How long a failed list waits before it is fetched again: a minute when someone asks for it; a list with no copy yet a
    /// minute, then twice as long after each failure up to an hour, since it blocks nothing meanwhile; a list with a copy, which
    /// stays in force, an hour.
    /// </summary>
    private static TimeSpan RetryAfter(Stored list, TimeSpan maximumAge) =>
        maximumAge < Refresh ? RetryPreload : list.UpdatedAt is null ? TimeSpan.FromMinutes(Math.Min(60, 1 << Math.Clamp(list.Failures - 1, 0, 6))) : RetryAfterFailure;

    /// <summary>When the daily refresh fetches a list that failed then again: once its wait is over, and once a fresh copy it has goes stale.</summary>
    private static DateTimeOffset RetryAt(Stored list, DateTimeOffset failed)
    {
        var retry = failed + RetryAfter(list, Refresh);
        return list.UpdatedAt is { } updated && updated + Refresh > retry ? updated + Refresh : retry;
    }

    /// <summary>Keeps the enabled lists fresh and serves requests until canceled; checks at least hourly, and when a failed list may try again.</summary>
    public async Task RunAsync(Func<IReadOnlyList<string>> enabled, CancellationToken cancellation)
    {
        // Networking settles after boot before the first download; requests made meanwhile wait in the queue.
        try { await Task.Delay(TimeSpan.FromMinutes(1), cancellation).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }
        while (!cancellation.IsCancellationRequested)
        {
            var lists = enabled();
            try
            {
                foreach (var id in lists) Request(id, Refresh);
                while (Next() is { } id) await FetchAsync(id, cancellation).ConfigureAwait(false);
            }
            catch (Exception error) when (error is not OperationCanceledException and not OutOfMemoryException) { ServiceHost.Log("Blocklist refresh stopped early: " + error.Message); }
            try { await wake.WaitAsync(NextCheck(lists), cancellation).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>How long until an enabled list that failed may be fetched again, at most an hour and at least a second.</summary>
    internal TimeSpan NextCheck(IEnumerable<string> enabled)
    {
        var wait = TimeSpan.FromHours(1); var now = clock.GetUtcNow();
        lock (gate)
            foreach (var id in enabled)
            {
                if (BlocklistCatalog.Find(id) is null || Entry(id) is not { FailedAt: { } failed } list) continue;
                var due = RetryAt(list, failed) - now;
                if (due < wait) wait = due;
            }
        return wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait;
    }

    private string? Next() { lock (gate) return queue.TryDequeue(out var id) ? id : null; }

    internal async Task FetchAsync(string id, CancellationToken cancellation)
    {
        var entry = BlocklistCatalog.Find(id) ?? throw new InvalidDataException("Unknown catalog blocklist.");
        lock (gate) { var list = Entry(id); list.Queued = false; list.Downloading = true; }
        var temporary = Path.Combine(directory, id + "-" + Guid.NewGuid().ToString("N") + ".download");
        var changed = false;
        try
        {
            await download(new Uri(entry.Url), temporary, MaximumDownload, cancellation).ConfigureAwait(false);
            BlocklistContent content;
            using (var reader = new StreamReader(temporary, Encoding.UTF8)) content = BlocklistContent.Parse(reader, entry.Format);
            if (content.Count == 0) throw new InvalidDataException("The download held nothing Darkwire can block; the previous copy stays.");
            // A mirror's error page or a cut-off file must not quietly replace a good copy.
            int previous; lock (gate) previous = Entry(id).Count;
            if (previous >= 1_000 && content.Count < previous / 10) throw new InvalidDataException($"The download holds {content.Count:N0} entries against {previous:N0} before; the previous copy stays.");
            var now = clock.GetUtcNow();
            Save(id, content, now);
            var names = entry.Domains ? DomainFilter.From(content) : null;
            lock (gate)
            {
                var list = Entry(id);
                list.Names = names; list.Networks = entry.Domains ? null : content.Networks; list.Loaded = true;
                list.UpdatedAt = now; list.Count = content.Count; list.FailedAt = null; list.Failures = 0; list.Error = null;
                Interlocked.Increment(ref version);
            }
            changed = true;
        }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException ||
            error is OperationCanceledException && !cancellation.IsCancellationRequested)
        {
            lock (gate)
            {
                var list = Entry(id); var now = clock.GetUtcNow();
                list.FailedAt = now; list.Failures++;
                list.Error = $"Download failed: {error.Message.TrimEnd('.')}. Trying again at {RetryAt(list, now).ToLocalTime():HH:mm}.";
            }
            ServiceHost.Log($"Blocklist {id} was not updated: {error.Message}");
        }
        finally
        {
            lock (gate) Entry(id).Downloading = false;
            try { File.Delete(temporary); } catch (IOException) { }
        }
        if (!changed) return;
        try { Changed?.Invoke(); }
        catch (Exception error) when (error is not OutOfMemoryException) { ServiceHost.Log($"Blocklist {id} was stored but not applied: {error.Message}"); }
    }

    private void Save(string id, BlocklistContent content, DateTimeOffset now)
    {
        var path = Path.Combine(directory, id + ".txt");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            { content.Write(writer); writer.Flush(); stream.Flush(true); }
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        File.WriteAllText(Path.Combine(directory, id + ".json"), JsonSerializer.Serialize(new Metadata(now, content.Count)));
    }

    // Callers hold the gate. Metadata loads on first use; the names or networks only when the coordinator asks for them.
    private Stored Entry(string id)
    {
        if (lists.TryGetValue(id, out var list)) return list;
        lists[id] = list = new();
        try
        {
            var metadata = Path.Combine(directory, id + ".json");
            if (File.Exists(metadata) && File.Exists(Path.Combine(directory, id + ".txt")) && new FileInfo(metadata).Length < 4096 &&
                JsonSerializer.Deserialize<Metadata>(File.ReadAllText(metadata)) is { } read)
            { list.UpdatedAt = read.UpdatedAt; list.Count = read.Count; }
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException) { }
        return list;
    }

    private Stored Load(string id)
    {
        var list = Entry(id);
        if (list.Loaded || list.UpdatedAt is null || BlocklistCatalog.Find(id) is not { } entry) return list;
        list.Loaded = true;
        try
        {
            using var reader = File.OpenText(Path.Combine(directory, id + ".txt"));
            var content = BlocklistContent.Read(reader);
            if (entry.Domains) list.Names = DomainFilter.From(content); else list.Networks = content.Networks;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            list.UpdatedAt = null; list.Count = 0; list.Error = "The stored copy could not be read; it downloads again.";
            ServiceHost.Log($"Blocklist {id} could not be read: {error.Message}");
            if (!list.Queued && !list.Downloading) { list.Queued = true; queue.Enqueue(id); wake.Release(); }
        }
        return list;
    }
}
