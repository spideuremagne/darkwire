using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Core;

/// <summary>
/// A flow owner as WFP's ALE layers see it: application ID, canonical SIDs of the token user and enabled groups, and the
/// AppContainer package SID. Sids is null when the token could not be read; the package then counts as unknown too.
/// </summary>
public sealed record FlowOwner(string ApplicationId, IReadOnlySet<string>? Sids, string? PackageSid);

/// <summary>One connection attempt. ICMP carries its type and code; Owner, InterfaceLuid and ProfileId are null when unknown.</summary>
public sealed record FlowQuery(TrafficDirection Direction, byte Protocol, IPAddress LocalAddress, ushort LocalPort, IPAddress RemoteAddress, ushort RemotePort,
    FlowOwner? Owner, ulong? InterfaceLuid = null, uint? ProfileId = null, byte? IcmpType = null, byte? IcmpCode = null, uint Flags = 0, uint? TunnelType = null);

/// <summary>The filter deciding a flow. An uncertain verdict is a deny reached through conditions the flow could not settle.</summary>
public sealed record PlanVerdict(NativeFilter Filter, bool Certain)
{
    public RuleAction Action => Filter.Action;
    /// <summary>No rule, list or core exception matched: the mode's default applies.</summary>
    public bool IsDefault => Filter.Weight == FilterCompiler.DefaultWeight;
}

/// <summary>
/// Evaluates a compiled plan in user mode the way the Darkwire WFP sublayer arbitrates it: the highest-weight matching
/// filter decides. A condition the flow cannot settle (unknown owner, interface or profile) never lets an allow match
/// and always lets a deny match, so missing facts can only block.
/// </summary>
public sealed class PlanMatcher
{
    private readonly Entry[][] groups;

    /// <param name="applicationId">Maps a filter's application path to the key flow owners carry (WFP application IDs in production).</param>
    /// <param name="accountSid">Resolves a user or group name to its canonical SID string.</param>
    public PlanMatcher(FilterPlan plan, Func<string, string> applicationId, Func<string, string> accountSid)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.CanApply) throw new InvalidOperationException("A plan with errors cannot be evaluated.");
        var applications = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var accounts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lists = new List<Entry>[] { [], [], [], [] };
        foreach (var filter in plan.Filters)
        {
            if (filter.Direction is not (TrafficDirection.Inbound or TrafficDirection.Outbound)) throw new InvalidDataException("A native filter has exactly one direction.");
            string? application = null;
            if (filter.ApplicationPath is { } path && !applications.TryGetValue(path, out application)) applications[path] = application = applicationId(path);
            var users = filter.Users is null ? null : RuleValidator.Tokens(filter.Users).Select(account =>
                accounts.TryGetValue(account, out var sid) ? sid : accounts[account] = accountSid(account)).ToArray();
            var service = filter.Service is null ? null : filter.Service == IdentitySelectors.AllServices ? "S-1-5-6" : IdentitySelectors.ServiceSid(filter.Service);
            lists[Group(filter.Ipv6, filter.Direction)].Add(new(filter, application, Network(filter.RemoteNetwork, filter.Ipv6), Network(filter.LocalNetwork, filter.Ipv6), service, users));
        }
        // OrderByDescending is stable; within one weight every compiled filter carries the same action.
        groups = lists.Select(list => list.OrderByDescending(e => e.Filter.Weight).ToArray()).ToArray();
    }

    /// <summary>The deciding filter, or null when nothing matches (an Open plan has no filters).</summary>
    public PlanVerdict? Match(FlowQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Direction is not (TrafficDirection.Inbound or TrafficDirection.Outbound)) throw new ArgumentException("A flow has exactly one direction.", nameof(query));
        var ipv6 = query.RemoteAddress.AddressFamily == AddressFamily.InterNetworkV6;
        if (query.LocalAddress.AddressFamily != query.RemoteAddress.AddressFamily || query.RemoteAddress.IsIPv4MappedToIPv6 || query.LocalAddress.IsIPv4MappedToIPv6)
            throw new ArgumentException("Local and remote addresses must share one native family.", nameof(query));
        var facts = new Facts(query, Number(query.LocalAddress), Number(query.RemoteAddress));
        foreach (var entry in groups[Group(ipv6, query.Direction)])
        {
            switch (Evaluate(entry, facts))
            {
                case Truth.True: return new(entry.Filter, true);
                case Truth.Unknown when entry.Filter.Action == RuleAction.Deny: return new(entry.Filter, false);
            }
        }
        return null;
    }

    private static Truth Evaluate(Entry entry, in Facts facts)
    {
        var filter = entry.Filter; var query = facts.Query;
        if (filter.Protocol is byte protocol && protocol != query.Protocol) return Truth.False;
        if (filter.LocalPort is { } local && (query.LocalPort < local.Low || query.LocalPort > local.High)) return Truth.False;
        if (filter.RemotePort is { } remote && (query.RemotePort < remote.Low || query.RemotePort > remote.High)) return Truth.False;
        if (filter.IcmpType is byte type && query.IcmpType != type) return Truth.False;
        if (filter.IcmpCode is byte code && query.IcmpCode != code) return Truth.False;
        if (entry.Remote is { } remoteNetwork && !remoteNetwork.Contains(facts.Remote)) return Truth.False;
        if (entry.Local is { } localNetwork && !localNetwork.Contains(facts.Local)) return Truth.False;
        if (filter.RequiredFlags is uint flags && (query.Flags & flags) != flags) return Truth.False;
        if (filter.TunnelType is uint tunnel && query.TunnelType != tunnel) return Truth.False;
        var truth = Truth.True;
        if (filter.LocalInterfaceLuid is ulong luid)
        {
            if (query.InterfaceLuid is null) truth = Truth.Unknown;
            else if (query.InterfaceLuid != luid) return Truth.False;
        }
        if (filter.CurrentProfileId is uint profile)
        {
            if (query.ProfileId is null) truth = Truth.Unknown;
            else if (query.ProfileId != profile) return Truth.False;
        }
        if (entry.Application is null && entry.Service is null && entry.Users is null && filter.Package is null) return truth;
        if (query.Owner is not { } owner) return Truth.Unknown;
        if (entry.Application is not null && !string.Equals(entry.Application, owner.ApplicationId, StringComparison.OrdinalIgnoreCase)) return Truth.False;
        if (entry.Service is null && entry.Users is null && filter.Package is null) return truth;
        if (owner.Sids is not { } sids) return Truth.Unknown;
        // One security descriptor carries service and user scope together, so both must hold.
        if (entry.Service is not null && !sids.Contains(entry.Service)) return Truth.False;
        if (entry.Users is not null && !entry.Users.Any(sids.Contains)) return Truth.False;
        if (filter.Package is { } package && !(package == IdentitySelectors.AllPackages ? owner.PackageSid is not null
            : string.Equals(package, owner.PackageSid, StringComparison.OrdinalIgnoreCase))) return Truth.False;
        return truth;
    }

    private static int Group(bool ipv6, TrafficDirection direction) => (ipv6 ? 2 : 0) + (direction == TrafficDirection.Outbound ? 1 : 0);

    private static Prefix? Network(string? selector, bool ipv6)
    {
        if (selector is null) return null;
        if (!IpNetwork.TryParse(selector, out var network) || (network.Address.AddressFamily == AddressFamily.InterNetworkV6) != ipv6)
            throw new InvalidDataException("Invalid native network " + selector + ".");
        return new(Number(network.Address), network.Prefix, ipv6 ? 128 : 32);
    }

    private static UInt128 Number(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written)) throw new ArgumentException("Unsupported address.", nameof(address));
        return written == 4 ? BinaryPrimitives.ReadUInt32BigEndian(bytes) : BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }

    private enum Truth : byte { False, Unknown, True }
    private readonly record struct Facts(FlowQuery Query, UInt128 Local, UInt128 Remote);
    private readonly record struct Prefix(UInt128 Network, int Length, int Bits)
    {
        public bool Contains(UInt128 address) => Length == 0 || (Network ^ address) >> (Bits - Length) == UInt128.Zero;
    }
    private sealed record Entry(NativeFilter Filter, string? Application, Prefix? Remote, Prefix? Local, string? Service, string[]? Users);
}
