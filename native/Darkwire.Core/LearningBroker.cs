using System.Net;

namespace Darkwire.Core;

public sealed record LearningRequest(Guid Id, Connection Connection, DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt, long PolicyRevision, int Attempts = 1);

/// <summary>
/// How far a learning decision reaches beyond the attempt it answers, always for the same application (and service) and
/// direction: the host and port asked for, over the protocol asked about; any host on that port, over TCP and UDP, since a
/// service on a port often takes both (HTTPS and QUIC, DNS); that host on any port, or any host and port, over every
/// protocol. For an inbound attempt the port is the local one the peer reached; a peer's own port is ephemeral and never kept.
/// </summary>
public enum LearningScope { Exact, AnyHost, AnyPort, AnyHostAndPort }

/// <summary>
/// Service-side queue for denied, unmatched connection attempts. Approval permits retries;
/// this is not a kernel-pended socket. The caller supplies authenticated WFP observations.
/// </summary>
public sealed class LearningBroker
{
    public const int MaximumPending = 256;
    public static readonly TimeSpan PromptLifetime = TimeSpan.FromSeconds(60);
    private readonly object gate = new();
    private readonly TimeProvider clock;
    private readonly PolicyEngine engine = new();
    private readonly Dictionary<Guid, LearningRequest> pending = [];
    private AppState state;
    private long revision = 1;

    public LearningBroker(AppState state, TimeProvider? timeProvider = null)
    { this.state = Snapshot(state); clock = timeProvider ?? TimeProvider.System; }

    public IReadOnlyList<LearningRequest> Pending
    {
        get { lock (gate) { Expire(); return pending.Values.OrderBy(p => p.CreatedAt).ToArray(); } }
    }

    /// <summary>
    /// Takes a new policy. Requests it still leaves unmatched stay, answerable under it, so a change elsewhere in the policy
    /// asks nothing again; those it now decides are withdrawn, such as the other attempts a broader answer covers.
    /// </summary>
    public void UpdatePolicy(AppState policy)
    {
        var copy = Snapshot(policy);
        lock (gate)
        {
            state = copy; revision++;
            foreach (var (id, request) in pending.ToArray())
            {
                if (engine.Evaluate(state, request.Connection).Kind == DecisionKind.Prompt) pending[id] = request with { PolicyRevision = revision };
                else pending.Remove(id);
            }
        }
    }

    public LearningRequest? Observe(Connection connection)
    {
        lock (gate)
        {
            Expire();
            if (state.Mode != FirewallMode.Learning || !TrustedShape(connection) || engine.Evaluate(state, connection).Kind != DecisionKind.Prompt) return null;
            return Add(connection);
        }
    }

    /// <summary>
    /// A connection the tunnel router is holding because the compiled plan matched no rule. The router already decided
    /// it is unmatched, so the preview engine is not consulted again; the shape and mode checks still apply.
    /// </summary>
    public LearningRequest? Ask(Connection connection)
    {
        lock (gate)
        {
            Expire();
            return state.Mode == FirewallMode.Learning && TrustedShape(connection) ? Add(connection) : null;
        }
    }

    // Callers hold the gate.
    private LearningRequest? Add(Connection connection)
    {
        var existing = pending.Values.FirstOrDefault(p => SameScope(p.Connection, connection));
        if (existing is not null)
        {
            var updated = existing with { Attempts = existing.Attempts == int.MaxValue ? int.MaxValue : existing.Attempts + 1 };
            pending[existing.Id] = updated; return updated;
        }
        // Excess attempts stay blocked by the default WFP rule. No eviction can reset a prompt's expiry.
        if (pending.Count >= MaximumPending) return null;
        var now = clock.GetUtcNow(); var request = new LearningRequest(Guid.NewGuid(), connection, now, now + PromptLifetime, revision);
        pending.Add(request.Id, request); return request;
    }

    public IReadOnlyList<FirewallRule> Resolve(Guid id, RuleAction action, LearningScope scope = LearningScope.Exact)
    {
        lock (gate)
        {
            var rules = PrepareResolution(id, action, scope);
            pending.Remove(id);
            return rules;
        }
    }

    // The service commits the resulting rules before UpdatePolicy consumes the request and the others they answer.
    // A failed WFP transaction must leave the original request available for retry.
    /// <summary>The rules a decision installs: one, or for any host on a port one each for TCP and UDP, the protocol asked about first.</summary>
    public IReadOnlyList<FirewallRule> PrepareResolution(Guid id, RuleAction action, LearningScope scope = LearningScope.Exact)
    {
        if (!Enum.IsDefined(action)) throw new ArgumentOutOfRangeException(nameof(action));
        if (!Enum.IsDefined(scope)) throw new ArgumentOutOfRangeException(nameof(scope));
        lock (gate)
        {
            Expire();
            if (!pending.TryGetValue(id, out var request) || request.PolicyRevision != revision || state.Mode != FirewallMode.Learning)
                throw new InvalidOperationException("This connection request has expired or policy has changed.");
            var c = request.Connection; var inbound = c.Direction == TrafficDirection.Inbound;
            var host = scope is LearningScope.Exact or LearningScope.AnyPort;
            var port = scope is LearningScope.Exact or LearningScope.AnyHost
                ? (inbound ? c.LocalPort : c.RemotePort).ToString(System.Globalization.CultureInfo.InvariantCulture) : "*";
            // Ports need TCP or UDP, so a port's answer takes one rule for each; an answer for any port needs no protocol.
            string[] protocols = scope switch { LearningScope.Exact => [c.Protocol], LearningScope.AnyHost => [c.Protocol, c.Protocol == "TCP" ? "UDP" : "TCP"], _ => ["Any"] };
            return [.. protocols.Select(protocol => new FirewallRule
            {
                ApplicationName = c.Application, Path = c.Path, Group = "Learning", Action = action,
                // A service host's rule names the service that asked, never every service svchost.exe runs; WFP still applies it
                // to the whole process, so services sharing that process are covered too.
                Service = string.IsNullOrEmpty(c.Service) ? "*" : c.Service,
                Direction = c.Direction, Protocol = protocol, RemoteAddresses = host ? c.RemoteAddress : "*",
                // An inbound peer's port is ephemeral, so an inbound rule keeps the local port the peer reached instead.
                RemotePorts = inbound ? "*" : port, LocalPorts = inbound ? port : "*",
                Source = "Darkwire learning"
            })];
        }
    }

    private void Expire()
    {
        var now = clock.GetUtcNow();
        foreach (var id in pending.Where(p => p.Value.ExpiresAt <= now).Select(p => p.Key).ToArray()) pending.Remove(id);
    }
    private static bool TrustedShape(Connection c) =>
        !string.IsNullOrWhiteSpace(c.Application) && Path.IsPathFullyQualified(c.Path) &&
        c.Direction is TrafficDirection.Inbound or TrafficDirection.Outbound &&
        c.Protocol is "TCP" or "UDP" && c.RemotePort is > 0 and <= 65535 && c.LocalPort is > 0 and <= 65535 &&
        IPAddress.TryParse(c.RemoteAddress, out var ip) && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any);
    // Attempts an exact decision would answer alike share one prompt: inbound ones by the local port, whatever the peer's.
    private static bool SameScope(Connection a, Connection b) =>
        a.Path.Equals(b.Path, StringComparison.OrdinalIgnoreCase) && a.Service.Equals(b.Service, StringComparison.OrdinalIgnoreCase) && a.Direction == b.Direction && a.Protocol == b.Protocol &&
        a.RemoteAddress == b.RemoteAddress && (a.Direction == TrafficDirection.Inbound ? a.LocalPort == b.LocalPort : a.RemotePort == b.RemotePort);
    private static AppState Snapshot(AppState policy)
    {
        var errors = PolicyValidation.Validate(policy);
        if (errors.Count > 0) throw new InvalidDataException(string.Join(Environment.NewLine, errors));
        return System.Text.Json.JsonSerializer.Deserialize<AppState>(System.Text.Json.JsonSerializer.Serialize(policy, StateStore.JsonOptions), StateStore.JsonOptions)
            ?? throw new InvalidDataException("Empty policy.");
    }
}
