using Darkwire.Core;

namespace Darkwire.Engine;

/// <param name="Lock">The filter belongs to the startup lock's sublayer rather than the policy's.</param>
public sealed record WfpRegistration(NativeFilter Filter, Guid Layer, uint Flags, bool Lock = false)
{
    public bool BootTime => Flags == 2;
}

/// <summary>
/// Pairs runtime policy with a closed startup policy until BFE loads persistent filters, and with the startup lock that holds
/// from then until the service has restored its state.
/// </summary>
public static class WfpInstallationPlan
{
    public const int StartupGuardCount = 4;

    public static IReadOnlyList<WfpRegistration> Build(FilterPlan plan)
    {
        PersistentFilterSession.ValidatePlan(plan);
        List<WfpRegistration> registrations = [];
        foreach (var filter in plan.Filters)
            registrations.Add(new(filter, AuthorizationLayer(filter.Ipv6, filter.Direction), 1));
        // An empty plan is Open or restoration. It must remove startup guards and the startup lock too.
        if (plan.Filters.Count > 0)
        {
            foreach (var ipv6 in new[] { false, true })
            foreach (var direction in new[] { TrafficDirection.Inbound, TrafficDirection.Outbound })
            {
                var guard = new NativeFilter("Darkwire startup protection", null, ipv6, direction, RuleAction.Deny, ulong.MaxValue);
                registrations.Add(new(guard, PacketLayer(ipv6, direction), 2));
            }
            foreach (var filter in plan.StartupLock)
                registrations.Add(new(filter, AuthorizationLayer(filter.Ipv6, filter.Direction), 1, Lock: true));
        }
        return registrations.AsReadOnly();
    }

    internal static Guid AuthorizationLayer(bool ipv6, TrafficDirection direction) => direction == TrafficDirection.Inbound
        ? ipv6 ? WfpNative.ReceiveV6 : WfpNative.ReceiveV4
        : ipv6 ? WfpNative.ConnectV6 : WfpNative.ConnectV4;
    private static Guid PacketLayer(bool ipv6, TrafficDirection direction) => direction == TrafficDirection.Inbound
        ? ipv6 ? WfpNative.InboundPacketV6 : WfpNative.InboundPacketV4
        : ipv6 ? WfpNative.OutboundPacketV6 : WfpNative.OutboundPacketV4;
}
