using System.Net;

namespace Darkwire.Service;

/// <summary>
/// Turns for tunnel starts that would take the same address. Windows gives an address to one interface only, so a start has
/// to see where an earlier one put its addresses: each waits until no start in progress claims any of its own.
/// </summary>
internal sealed class AddressClaims
{
    private readonly object gate = new();
    private readonly List<(IPAddress[] Addresses, TaskCompletionSource Done)> held = [];

    /// <summary>Waits for the starts in progress that claim any of the addresses, then claims them until the handle is disposed.</summary>
    public async Task<IDisposable> ClaimAsync(IEnumerable<IPAddress> addresses, CancellationToken cancellation)
    {
        var wanted = addresses.Distinct().ToArray();
        while (true)
        {
            Task busy;
            lock (gate)
            {
                var other = held.Find(claim => claim.Addresses.Intersect(wanted).Any());
                if (other.Done is null)
                {
                    var claim = (wanted, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
                    held.Add(claim);
                    return new Release(this, claim);
                }
                busy = other.Done.Task;
            }
            await busy.WaitAsync(cancellation).ConfigureAwait(false);
        }
    }

    private sealed class Release(AddressClaims owner, (IPAddress[] Addresses, TaskCompletionSource Done) claim) : IDisposable
    {
        private int released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref released, 1) != 0) return;
            lock (owner.gate) owner.held.Remove(claim);
            claim.Done.SetResult();
        }
    }
}
