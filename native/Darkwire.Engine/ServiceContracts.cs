using Darkwire.Core;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Darkwire.Engine;

/// <param name="VpnBackends">The VPN kinds whose protected backend the service has; null when it cannot route connections.</param>
/// <param name="Routes">The VPN profiles the enforced policy runs; null when it runs none or Darkwire is not enforcing.</param>
/// <param name="LocalNetworkBypassesVpn">Whether the enforced policy keeps local network traffic off VPN tunnels; null when Darkwire is not enforcing.</param>
/// <param name="ListHits">What blocklists blocked since the service started; null when Darkwire is not enforcing.</param>
/// <param name="OwnTraffic">Where the enforced policy sends Darkwire's own connections; null when Darkwire is not enforcing.</param>
/// <param name="Dns">How Darkwire's DNS proxy answers; null without encrypted DNS servers or a running router.</param>
/// <param name="Blocked">Connections Darkwire refused lately, newest first; null when Darkwire is not enforcing.</param>
/// <param name="Filters">Darkwire's filters in WFP: what the service installed lately and what its last audit found; null before it installed any.</param>
/// <param name="FirewallWarningsHidden">Whether Darkwire hides Windows Security's Firewall and network protection area and its warnings; null when Darkwire is not enforcing.</param>
public sealed record ServiceStatus(bool Installed, bool Active, string Phase, FirewallMode Mode,
    int FilterCount, bool LearningEventsReady, string Message, int PendingCount = 0, long PolicyRevision = 0, int BootFilterCount = 0,
    IReadOnlyList<string>? Alerts = null, IReadOnlyList<TunnelStatus>? Tunnels = null, GeoIpUpdateStatus? GeoIp = null,
    IReadOnlyList<string>? VpnBackends = null, IReadOnlyList<VpnRouteStatus>? Routes = null, bool? LocalNetworkBypassesVpn = null,
    BlocklistHits? ListHits = null, bool StartupLocked = false, OwnRoute? OwnTraffic = null, Guid? OwnTrafficProfileId = null,
    DnsStatus? Dns = null, IReadOnlyList<BlockedFlow>? Blocked = null, FilterState? Filters = null, bool? FirewallWarningsHidden = null);
/// <summary>
/// Darkwire's filters in WFP: the startup lock filters the last install registered, whether this run of the service holds the
/// lock's release, the policy and lock filters its last audit found and when, and the latest installs, newest first.
/// </summary>
public sealed record FilterState(int? LockFilters, bool Released, DateTimeOffset? AuditedAt, int? AuditedFilters, int? AuditedLock, IReadOnlyList<FilterInstall> Installs);
/// <summary>
/// One install of Darkwire's filters: when, what it was for, the policy revision, its policy filters, the startup lock filters
/// its plan held and those WFP registered, and whether the service had restored its state, which releases the lock first.
/// </summary>
/// <param name="Added">The filters the install added, all others staying as they were; null when the backend does not count them.</param>
/// <param name="Milliseconds">How long the install took.</param>
public sealed record FilterInstall(DateTimeOffset Time, string Cause, long Revision, int Filters, int LockPlanned, int? LockRegistered, bool Restored,
    int? Added = null, int? Removed = null, int? Milliseconds = null);
/// <summary>
/// Lookups, connections and packets blocklists blocked since a time: in all, and by list, keyed by catalog ID or, for a
/// custom list, by "custom:" and its name, and the names blocked one by one under <see cref="NamesKey"/>. One block several
/// lists name counts once in all and once for each list.
/// </summary>
public sealed record BlocklistHits(long Total, DateTimeOffset Since, IReadOnlyDictionary<string, long> ByList)
{
    public const string NamesKey = "names";
    public static string CustomKey(string name) => "custom:" + name;
}
/// <summary>
/// Darkwire's DNS proxy: Starting, Ready, Waiting (no server reachable yet) or Failed; the server that answered fastest when
/// it last measured them, its round trip, and how many answer; lookups it answered and failed since the router started, how
/// long the last answer took; and the last failure.
/// </summary>
public sealed record DnsStatus(string State, string? Fastest = null, int? FastestMs = null, int? LiveServers = null, long Answered = 0, long Failed = 0,
    int? LatencyMs = null, string? Error = null, DateTimeOffset? ErrorAt = null);
/// <summary>The public resolver list the service keeps: its servers, when it was signed and last checked, and how the last check ended.</summary>
public sealed record DnsCatalog(IReadOnlyList<DnsCatalogEntry> Servers, DateTimeOffset? SignedAt, DateTimeOffset? CheckedAt, bool Checking, string? Error = null);
/// <summary>A connection attempt Darkwire refused: the last time and how often, by which application, to where, and why.</summary>
public sealed record BlockedFlow(DateTimeOffset Time, string Application, string RemoteAddress, int RemotePort, string Protocol, TrafficDirection Direction, string Reason, int Count = 1);
/// <summary>
/// A TCP connection Darkwire's router carries or holds, by the application's socket on Darkwire's adapter and its
/// destination, with the VPN profile whose tunnel it takes; none for the physical network.
/// </summary>
public sealed record RoutedConnection(string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, Guid? ProfileId = null);
/// <summary>
/// Policy settings the app applies by themselves, each only when given: the blocklists and blocked names, what internal access
/// allows, the geographic restrictions, the startup lock, the DNS over HTTPS servers and whether Windows Security's firewall
/// warnings are shown.
/// </summary>
public sealed record PolicySettings(IReadOnlyList<BlocklistSource>? Blocklists = null, InternalAccess? InternalNetworks = null, GeoSettings? Geography = null, bool? StartupLock = null,
    IReadOnlyList<string>? BlockedNames = null, IReadOnlyList<DnsServer>? DnsServers = null, bool? ShowFirewallWarnings = null);
/// <summary>Countries blocked, or allowed under an allow list, and the autonomous systems blocked.</summary>
public sealed record GeoSettings(IReadOnlyList<string> BlockedCountries, bool CountryAllowList, IReadOnlyList<string> AllowedCountries, IReadOnlyList<uint> BlockedAsns);
/// <summary>
/// A VPN profile the enforced policy runs: the credentials it uses, its applications, whether it carries every other
/// application, whether it is kept connected with or without anything routed through it, and whether it was disconnected,
/// so that it has no tunnel and what it carries is refused.
/// </summary>
public sealed record VpnRouteStatus(Guid ProfileId, string Kind, Guid CredentialsRevision, IReadOnlyList<string> Applications, bool Default, bool Kept = false, bool Disconnected = false);
/// <summary>
/// A check of a running tunnel: whether its own DNS server answered a question sent through it, which server, and in how
/// many milliseconds; no server when the tunnel names none it carries.
/// </summary>
public sealed record VpnCheck(Guid ProfileId, bool Answered, string? Server = null, int? Milliseconds = null);
/// <summary>
/// The VPN part of a policy: the profiles with their applications and whether each is kept connected, the profile that
/// carries every other application, whether local network traffic stays off the tunnels, and where Darkwire's own connections go.
/// </summary>
public sealed record VpnRoutes(IReadOnlyList<VpnProfile> Profiles, Guid? DefaultProfileId, bool BypassLocal = true, OwnRoute OwnTraffic = OwnRoute.Default, Guid? OwnTrafficProfileId = null);
/// <summary>The service's GeoIP updates: the release it last found, when it last checked, whether a check is running, and how the last one ended.</summary>
public sealed record GeoIpUpdateStatus(string? Release, DateTimeOffset? LastCheck, bool Checking, string? Outcome = null, bool Failed = false);
/// <summary>
/// One VPN profile the router runs: Starting, Up or Failed, with its interface index, addresses and the resolvers its tunnel
/// carries once up, the bytes its interface sent and received since, when its server last answered, by bytes received or a
/// handshake WireGuard completed, when the router first
/// sent a flow through it, the addresses it shares with another tunnel that holds them, the bits per second it
/// received and sent between health checks, about two seconds apart, oldest first, over the last five minutes, once
/// its server has answered and then fell silent while it kept sending, when the first send that went unanswered was, and
/// how many times Darkwire has reconnected it since its server last answered, because the server stopped answering. Once
/// up, a tunnel is checked end to end, its DNS server asked through it: when a check last passed, whether one is going on,
/// when the last failed, and how many restarts failed checks have led to since one passed.
/// </summary>
public sealed record TunnelStatus(Guid ProfileId, string Kind, string State, DateTimeOffset Since, uint? Interface = null,
    IReadOnlyList<string>? Addresses = null, string? Error = null, IReadOnlyList<string>? Resolvers = null,
    long SentBytes = 0, long ReceivedBytes = 0, DateTimeOffset? LastReceived = null, DateTimeOffset? Routed = null, IReadOnlyList<string>? Shared = null,
    IReadOnlyList<long>? InRates = null, IReadOnlyList<long>? OutRates = null, DateTimeOffset? Silent = null, int Reconnects = 0,
    DateTimeOffset? Checked = null, bool Checking = false, DateTimeOffset? CheckFailed = null, int CheckRestarts = 0)
{
    /// <summary>
    /// Since when the tunnel has had traffic to carry without anything back from its server: since it first had any, when the
    /// server never answered, or since the server fell silent, as WireGuard's unanswered handshakes can show before any byte
    /// came in; null while it hears back or has had nothing to carry.
    /// </summary>
    [JsonIgnore] public DateTimeOffset? Unanswered => State != "Up" ? null : ReceivedBytes == 0 ? Routed ?? (SentBytes > 0 ? Since : Silent) : Silent;
}
public sealed record VpnConfigurationUpload(Guid Id, string Kind, string Configuration)
{ public override string ToString() => $"VPN configuration upload {Id:N} (redacted)"; }
public sealed record StoredVpnProfile(Guid Id, string Kind, string Endpoint, Guid Revision, DateTimeOffset UpdatedAt);
// A null profile means the user-configured default route, not necessarily a physical adapter.
public sealed record LearningRouteChoice(Guid? VpnProfileId = null);
public sealed record ServiceRequest(string Command, AppState? Policy = null, Guid? RequestId = null, RuleAction? Action = null, string? GeoCsv = null, long? ExpectedRevision = null,
    VpnConfigurationUpload? VpnConfiguration = null, Guid? VpnProfileId = null, LearningRouteChoice? LearningRoute = null, string? BlocklistId = null,
    LearningScope? Scope = null, VpnRoutes? Routes = null, PolicySettings? Settings = null)
{ public override string ToString() => $"Service request {Command}"; }
/// <summary>Windows defaults per profile bit (1 Domain, 2 Private, 4 Public): whether unmatched traffic is allowed today.</summary>
public sealed record WindowsDefaults(Dictionary<int, bool> InboundAllowed, Dictionary<int, bool> OutboundAllowed);
/// <summary>A catalog list in the service's store: what it blocks once downloaded, when it last was, and any download in progress or failed.</summary>
public sealed record BlocklistStatus(string Id, int Count, DateTimeOffset? UpdatedAt, bool Downloading, string? Error = null, bool Enforced = false);
public sealed record ServiceResponse(bool Success, string Message, ServiceStatus? Status = null,
    AppState? Policy = null, IReadOnlyList<LearningRequest>? Pending = null, IReadOnlyList<string>? Errors = null,
    IReadOnlyList<StoredVpnProfile>? VpnProfiles = null, WindowsDefaults? Defaults = null, IReadOnlyList<BlocklistStatus>? Blocklists = null,
    DnsCatalog? DnsCatalog = null, IReadOnlyList<RoutedConnection>? Routed = null, VpnCheck? Check = null);

/// <summary>Local, length-bounded protocol. The service authenticates the Windows client token on every request.</summary>
public static class ServiceProtocol
{
    public const string PipeName = "Darkwire.Control.v1";
    public const string AdministratorPipeName = "Darkwire.Admin.v1";
    public const int MaximumMessageBytes = 8 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new(StateStore.JsonOptions)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 48, AllowDuplicateProperties = false };
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken token, int maximumBytes = MaximumMessageBytes)
    {
        if (maximumBytes is <= 0 or > MaximumMessageBytes) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        var header = new byte[4]; await stream.ReadExactlyAsync(header, token);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maximumBytes) throw new InvalidDataException("Invalid control message length.");
        var data = new byte[length]; await stream.ReadExactlyAsync(data, token);
        try { return JsonSerializer.Deserialize<T>(data, Options) ?? throw new InvalidDataException("Empty control message."); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(data); }
    }
    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken token)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(message, Options);
        try
        {
        if (data.Length > MaximumMessageBytes) throw new InvalidDataException("Control message exceeds the size limit.");
        var header = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(header, data.Length);
        await stream.WriteAsync(header, token); await stream.WriteAsync(data, token); await stream.FlushAsync(token);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(data); }
    }
}

public static class ServiceClient
{
    /// <summary>
    /// Commands any interactive user may send: reads, and asking for a catalog list download or a resolver list check, which
    /// fetch only what the service's own catalog names. Everything else needs an administrator on the administrator pipe.
    /// </summary>
    public static bool IsPublic(string command) => command is "status" or "policy" or "pending" or "vpn-profiles" or "blocklists" or "preload-blocklist" or "refresh-geoip" or "dns-servers"
        or "routed-connections";

    public static async Task<ServiceResponse> SendAsync(ServiceRequest request, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var read = IsPublic(request.Command);
        using var pipe = new NamedPipeClientStream(".", read ? ServiceProtocol.PipeName : ServiceProtocol.AdministratorPipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        // A read gives up soon, what it last read standing meanwhile; an administrator's action waits its turn.
        await pipe.ConnectAsync(read ? 1500 : 15_000, timeout.Token);
        ServicePeerIdentity.ValidateServer(pipe.SafePipeHandle);
        await ServiceProtocol.WriteAsync(pipe, request, timeout.Token);
        return await ServiceProtocol.ReadAsync<ServiceResponse>(pipe, timeout.Token);
    }
}
