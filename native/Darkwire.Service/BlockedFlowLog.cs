using Darkwire.Core;
using Darkwire.Engine;

namespace Darkwire.Service;

/// <summary>
/// Connection attempts Darkwire refused lately, from the router's decisions and the kernel's drops: one entry for each
/// program, destination, direction and reason, with when it last happened and how often. The newest are kept.
/// </summary>
internal sealed class BlockedFlowLog
{
    public const int Capacity = 100;
    private readonly object gate = new();
    private readonly Dictionary<(string, string, int, string, TrafficDirection, string), BlockedFlow> flows = [];

    public void Record(BlockedFlow flow)
    {
        lock (gate)
        {
            var key = (flow.Application, flow.RemoteAddress, flow.RemotePort, flow.Protocol, flow.Direction, flow.Reason);
            flows[key] = flows.TryGetValue(key, out var known) ? known with { Time = flow.Time, Count = known.Count + flow.Count } : flow;
            if (flows.Count <= Capacity * 2) return;
            foreach (var old in flows.OrderBy(p => p.Value.Time).Take(flows.Count - Capacity).Select(p => p.Key).ToArray()) flows.Remove(old);
        }
    }

    /// <summary>The newest refusals first.</summary>
    public IReadOnlyList<BlockedFlow> Snapshot()
    {
        lock (gate) return [.. flows.Values.OrderByDescending(f => f.Time).Take(Capacity)];
    }

    public void Clear() { lock (gate) flows.Clear(); }
}
