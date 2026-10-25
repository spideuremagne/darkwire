using Darkwire.Core;
using Darkwire.Engine;
using System.Text;
using System.Text.Json;

namespace Darkwire.Service;

public interface IResolverCatalog
{
    /// <summary>The servers on the list the service holds; empty before it has one.</summary>
    IReadOnlyList<DnsCatalogEntry> Servers { get; }
    DnsCatalog Catalog();
    /// <summary>Asks for a check of the mirrors soon, unless one runs or the last failed a moment ago.</summary>
    void Request();
}

/// <summary>
/// The DNSCrypt project's public resolver list, which the DNS picker offers: downloaded from the project's mirrors and kept
/// only when its minisign signature verifies with the project's key, names this list, and is no older than the copy held, so
/// no mirror can serve another list or an older one. It is checked weekly, through Darkwire's own route, and never bundled:
/// the policy keeps the stamps of the servers chosen from it for when the service has no copy.
/// </summary>
internal sealed class ResolverListStore : IResolverCatalog
{
    public static readonly TimeSpan Refresh = TimeSpan.FromDays(7);
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(1), RetryRequested = TimeSpan.FromMinutes(1);
    private const long MaximumDownload = 4L * 1024 * 1024;
    private const string SignatureName = ResolverList.FileName + ".minisig", StateName = "checked.json";
    private readonly object gate = new();
    private readonly Func<Uri, string, long, CancellationToken, Task> download;
    private readonly string directory;
    private readonly TimeProvider clock;
    private readonly SemaphoreSlim wake = new(0);
    private readonly string publicKey;
    private IReadOnlyList<DnsCatalogEntry> servers = [];
    private long? signedAt;
    private DateTimeOffset? checkedAt, failedAt;
    private bool checking, requested;
    private string? error;

    /// <param name="publicKey">The minisign key the list must be signed with; the DNSCrypt project's unless a check gives its own.</param>
    public ResolverListStore(Func<Uri, string, long, CancellationToken, Task> download, string directory, TimeProvider clock, string publicKey = ResolverList.PublicKey)
    {
        this.download = download; this.directory = directory; this.clock = clock; this.publicKey = publicKey;
        Directory.CreateDirectory(directory);
        Load();
    }

    public static string DefaultDirectory => Path.Combine(ServiceHost.StateDirectory, "Resolvers");
    /// <summary>Runs after a check changed the list, outside the store's lock; the coordinator applies new stamps.</summary>
    public Action? Changed { get; set; }

    public IReadOnlyList<DnsCatalogEntry> Servers { get { lock (gate) return servers; } }

    public DnsCatalog Catalog()
    {
        lock (gate) return new(servers, signedAt is { } time ? DateTimeOffset.FromUnixTimeSeconds(time) : null, checkedAt, checking || requested, error);
    }

    public void Request()
    {
        lock (gate)
        {
            if (checking || requested || failedAt is { } failed && clock.GetUtcNow() - failed < RetryRequested) return;
            requested = true;
        }
        wake.Release();
    }

    /// <summary>Checks the mirrors when the copy held is a week old, or when asked, until canceled.</summary>
    public async Task RunAsync(CancellationToken cancellation)
    {
        // Networking settles after boot before the first check; a request meanwhile waits.
        try { await wake.WaitAsync(TimeSpan.FromMinutes(1), cancellation).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }
        while (!cancellation.IsCancellationRequested)
        {
            bool due;
            lock (gate)
            {
                var now = clock.GetUtcNow();
                due = requested || (checkedAt is null || now - checkedAt >= Refresh) && (failedAt is null || now - failedAt >= RetryAfterFailure);
            }
            if (due)
            {
                try { await CheckAsync(cancellation).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return; }
            }
            try { await wake.WaitAsync(TimeSpan.FromHours(1), cancellation).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Tries each mirror in turn until one serves a list that verifies; a failed check keeps the copy held.</summary>
    internal async Task CheckAsync(CancellationToken cancellation)
    {
        lock (gate) { checking = true; requested = false; }
        List<string> failures = [];
        var changed = false;
        try
        {
            foreach (var url in ResolverList.Urls)
            {
                var list = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".download");
                var signature = list + ".minisig";
                try
                {
                    await download(new Uri(url), list, MaximumDownload, cancellation).ConfigureAwait(false);
                    await download(new Uri(url + ".minisig"), signature, 4096, cancellation).ConfigureAwait(false);
                    var (entries, signed) = Verify(await File.ReadAllBytesAsync(list, cancellation).ConfigureAwait(false), await File.ReadAllTextAsync(signature, cancellation).ConfigureAwait(false), publicKey);
                    long? held; lock (gate) held = signedAt;
                    if (signed < held) throw new InvalidDataException("The mirror serves a list older than the one held.");
                    var now = clock.GetUtcNow();
                    if (signed != held)
                    {
                        File.Move(list, Path.Combine(directory, ResolverList.FileName), true);
                        File.Move(signature, Path.Combine(directory, SignatureName), true);
                        changed = true;
                    }
                    File.WriteAllText(Path.Combine(directory, StateName), JsonSerializer.Serialize(new Checked(now)));
                    lock (gate) { servers = entries; signedAt = signed; checkedAt = now; failedAt = null; error = null; }
                    return;
                }
                catch (Exception failure) when (failure is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException ||
                    failure is OperationCanceledException && !cancellation.IsCancellationRequested)
                { failures.Add($"{new Uri(url).Host}: {failure.Message}"); }
                finally
                {
                    foreach (var file in new[] { list, signature }) try { File.Delete(file); } catch (IOException) { }
                }
            }
            var message = "The resolver list was not updated: " + string.Join(" ", failures);
            lock (gate) { failedAt = clock.GetUtcNow(); error = message; }
            ServiceHost.Log(message);
        }
        finally
        {
            lock (gate) checking = false;
            if (changed)
            {
                try { Changed?.Invoke(); }
                catch (Exception failure) when (failure is not OutOfMemoryException) { ServiceHost.Log("The resolver list was stored but not applied: " + failure.Message); }
            }
        }
    }

    /// <summary>
    /// The servers on a signed list, and when it was signed: the signature must verify with the project's key and its trusted
    /// comment name this list, and the list must hold servers.
    /// </summary>
    internal static (IReadOnlyList<DnsCatalogEntry> Servers, long SignedAt) Verify(byte[] list, string signature, string publicKey = ResolverList.PublicKey)
    {
        var comment = Minisign.Verify(publicKey, list, signature);
        if (ResolverList.SignedAt(comment) is not { } signed) throw new InvalidDataException("The signature is for another file.");
        var entries = ResolverList.Parse(Encoding.UTF8.GetString(list));
        if (entries.Count < 10) throw new InvalidDataException("The signed list holds almost no servers.");
        return (entries, signed);
    }

    private sealed record Checked(DateTimeOffset At);

    /// <summary>The copy held from before, verified again; one that no longer verifies is left unused and downloads again.</summary>
    private void Load()
    {
        var list = Path.Combine(directory, ResolverList.FileName);
        var signature = Path.Combine(directory, SignatureName);
        if (!File.Exists(list) || !File.Exists(signature)) return;
        try
        {
            if (new FileInfo(list).Length > MaximumDownload) throw new InvalidDataException("The stored list is too large.");
            var (entries, signed) = Verify(File.ReadAllBytes(list), File.ReadAllText(signature), publicKey);
            servers = entries; signedAt = signed;
            var state = Path.Combine(directory, StateName);
            if (File.Exists(state) && new FileInfo(state).Length < 1024 && JsonSerializer.Deserialize<Checked>(File.ReadAllText(state)) is { } read) checkedAt = read.At;
        }
        catch (Exception failure) when (failure is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            servers = []; signedAt = null; checkedAt = null;
            ServiceHost.Log("The stored resolver list was not used: " + failure.Message);
        }
    }
}
