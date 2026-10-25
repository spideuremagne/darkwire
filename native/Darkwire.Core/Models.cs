using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace Darkwire.Core;

public enum FirewallMode { Open, Learning, BlockNew, Lockdown }
public enum RuleAction { Allow, Deny }
public enum TrafficDirection { Any, Outbound, Inbound, Unknown }
public enum DecisionKind { Allow, Deny, Prompt }
/// <summary>How an inherited Windows rule is enforced. Darkwire never allows traffic Windows blocks.</summary>
/// <remarks>Narrowed: allow rules lose untranslatable alternatives; block rules drop untranslatable restrictions.
/// Unenforced: an enabled allow rule with no safe subset. Both require consent. Inert: disabled and untranslatable.</remarks>
public enum ImportOutcome { Exact, Narrowed, Unenforced, Inert, Refused }

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string name = "")
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value; PropertyChanged?.Invoke(this, new(name)); return true;
    }
    public void Notify([CallerMemberName] string name = "") => PropertyChanged?.Invoke(this, new(name));
}

public sealed class FirewallRule : Observable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    private string applicationName = "New rule", group = "Custom", path = "*", location = "Any";
    private string localPorts = "*", remoteAddresses = "*", remotePorts = "*", protocol = "Any", service = "*", user = "*";
    private string localAddresses = "*", icmpTypesAndCodes = "*", package = "*";
    private bool enabled = true, edgeTraversal, narrowingAccepted;
    private RuleAction action;
    private TrafficDirection direction = TrafficDirection.Outbound;
    public string ApplicationName { get => applicationName; set => Set(ref applicationName, value); }
    public string Group { get => group; set => Set(ref group, value); }
    public string Path { get => path; set => Set(ref path, value); }
    public string Location { get => location; set => Set(ref location, value); }
    public bool Enabled { get => enabled; set => Set(ref enabled, value); }
    public RuleAction Action { get => action; set => Set(ref action, value); }
    public TrafficDirection Direction { get => direction; set => Set(ref direction, value); }
    public string LocalPorts { get => localPorts; set => Set(ref localPorts, value); }
    public string RemoteAddresses { get => remoteAddresses; set => Set(ref remoteAddresses, value); }
    public string RemotePorts { get => remotePorts; set => Set(ref remotePorts, value); }
    public string Protocol { get => protocol; set => Set(ref protocol, value); }
    public string Service { get => service; set => Set(ref service, value); }
    public string User { get => user; set => Set(ref user, value); }
    public string LocalAddresses { get => localAddresses; set => Set(ref localAddresses, value); }
    public string IcmpTypesAndCodes { get => icmpTypesAndCodes; set => Set(ref icmpTypesAndCodes, value); }
    /// <summary>AppContainer package SID, AllPackages, or *.</summary>
    public string Package { get => package; set => Set(ref package, value); }
    /// <summary>Inbound only: also admit Teredo edge traffic, as Windows edge traversal does.</summary>
    public bool EdgeTraversal { get => edgeTraversal; set => Set(ref edgeTraversal, value); }
    public bool NarrowingAccepted { get => narrowingAccepted; set { if (Set(ref narrowingAccepted, value)) Notify(nameof(ImportStatus)); } }
    public string Source { get; set; } = "Darkwire";
    public string? WindowsRuleId { get; set; }
    public ImportOutcome? Import { get; set; }
    [JsonIgnore] public string ImportStatus => Import switch
    {
        ImportOutcome.Narrowed => Action == RuleAction.Deny ? "Broader block" + (NarrowingAccepted ? " · accepted" : " · review") : "Reduced scope",
        ImportOutcome.Unenforced => "Not enforced · out of scope",
        ImportOutcome.Inert => "Kept disabled",
        ImportOutcome.Refused => "Can't import",
        _ => ""
    };
    public string? ImportWarning { get; set; }
    public string? OriginalDefinition { get; set; }
}

public sealed record Connection(string Application, string Path, int ProcessId, string RemoteAddress,
    int RemotePort, int LocalPort, string Protocol, TrafficDirection Direction,
    string Location = "Unknown", string Service = "", string User = "", string Country = "",
    uint Asn = 0, string Hostname = "", string LocalAddress = "", string State = "Established",
    string ReverseHostname = "", byte? IcmpType = null, byte? IcmpCode = null, string HostedServices = "")
{
    /// <summary>
    /// The process with the service the connection belongs to, as "svchost · Dnscache", or with every service it hosts when
    /// that is unknown. Service is set when the process runs one service, or its socket was tagged with one of several.
    /// </summary>
    public string ProcessDisplay => Service.Length > 0 ? Application + " · " + Service : HostedServices.Length > 0 ? Application + " · " + HostedServices : Application;
    /// <summary>The other services in the connection's process. WFP sees the token they share, not the service, so a rule for its service reaches them too.</summary>
    public string[] SharedServices() => Service.Length == 0 ? [] :
        HostedServices.Split(", ", StringSplitOptions.RemoveEmptyEntries).Where(s => !s.Equals(Service, StringComparison.OrdinalIgnoreCase)).ToArray();
    public string Destination => ConnectionDisplay.Destination(RemoteAddress, Hostname, ReverseHostname);
    public string Endpoint => ConnectionDisplay.Endpoint(RemoteAddress, RemotePort);
    public string CountryDisplay => string.IsNullOrEmpty(Country) ? "Unresolved" : Country;
}
public sealed record PolicyDecision(DecisionKind Kind, string Reason, Guid? RuleId = null);
public sealed record GeoRecord(string Network, string Country, string CountryName, string City,
    double Latitude, double Longitude, uint Asn, string Organization, string Region = "");
public sealed class BlocklistSource
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "Custom list";
    public string Url { get; set; } = "";
    /// <summary>A <see cref="BlocklistCatalog"/> list, which the service downloads and keeps itself; its entries never travel in the policy.</summary>
    public string? CatalogId { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset? UpdatedAt { get; set; }
    public List<string> Entries { get; set; } = [];
    [JsonIgnore] public string CountDisplay => $"{Entries.Count:N0} entries";
    [JsonIgnore] public string UpdatedDisplay => UpdatedAt?.ToLocalTime().ToString("MMM d, HH:mm") ?? "Not downloaded";
}
public sealed class VpnProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "New profile";
    public string Kind { get; set; } = "WireGuard";
    public string Endpoint { get; set; } = "";
    public string EncryptedConfig { get; set; } = "";
    public Guid CredentialsRevision { get; set; }
    public List<string> Applications { get; set; } = [];
    public bool KillSwitch { get; set; } = true;
    /// <summary>Connected from the VPN page: its tunnel runs even while nothing routes through it, ready for routes.</summary>
    public bool KeepConnected { get; set; }
    /// <summary>
    /// Disconnected from the VPN page: its tunnel does not run, though applications, the default route or Darkwire's own
    /// connections use it, and what it carries is refused until it is connected again, never sent another way.
    /// </summary>
    public bool Disconnected { get; set; }
    [JsonIgnore] public string AppCount => Applications.Count == 1 ? "1 application" : $"{Applications.Count} applications";
}
/// <summary>
/// What happens to traffic with internal addresses: allowed out, and in on networks Windows calls private or domain; refused
/// both ways unless a rule allows it; or decided by rules and prompts like any other traffic.
/// </summary>
public enum InternalAccess { Allow, Block, Rules }
/// <summary>
/// Where Darkwire's own connections leave, its downloads and its encrypted DNS: the default route (the default VPN profile's
/// tunnel when there is one), Windows' route, or one VPN profile's tunnel.
/// </summary>
public enum OwnRoute { Default, Windows, Profile }
/// <summary>
/// An encrypted DNS server, DNS over HTTPS or DNSCrypt, that answers the lookups Darkwire's resolver sends to the internet: one
/// from the public resolver list by its name, or one of your own.
/// </summary>
public sealed class DnsServer
{
    public string Name { get; set; } = "";
    /// <summary>Its DNS stamps: for a listed server those the list had when it was chosen, which the service's verified copy of the list overrides.</summary>
    public List<string> Stamps { get; set; } = [];
    /// <summary>On the public resolver list under <see cref="Name"/>, rather than entered by hand.</summary>
    public bool Listed { get; set; }
}
public sealed class ColumnPreference
{
    public string Name { get; set; } = "";
    public int Order { get; set; }
    public bool Visible { get; set; } = true;
    public double Width { get; set; } = 140;
}
public sealed class AppState
{
    public int SchemaVersion { get; set; } = 1;
    public FirewallMode Mode { get; set; } = FirewallMode.Learning;
    public List<FirewallRule> Rules { get; set; } = [];
    public List<BlocklistSource> Blocklists { get; set; } = [];
    public List<VpnProfile> VpnProfiles { get; set; } = [];
    public Guid? DefaultOutboundVpnProfileId { get; set; }
    /// <summary>
    /// Traffic to the physical networks' own subnets and to internal addresses (<see cref="Core.InternalNetworks"/>) stays off VPN
    /// tunnels, unless a tunnel routes that private network itself; <see cref="InternalNetworks"/> and rules still decide it.
    /// </summary>
    public bool LocalNetworkBypassesVpn { get; set; } = true;
    /// <summary>Traffic with internal addresses: allowed unless set otherwise.</summary>
    public InternalAccess InternalNetworks { get; set; } = InternalAccess.Allow;
    /// <summary>Where Darkwire's own downloads and encrypted DNS leave; with <see cref="OwnRoute.Profile"/>, through <see cref="OwnTrafficProfileId"/>.</summary>
    public OwnRoute OwnTraffic { get; set; } = OwnRoute.Default;
    public Guid? OwnTrafficProfileId { get; set; }
    /// <summary>
    /// Encrypted DNS servers for the lookups that leave the local network, the fastest answering; empty leaves them to the
    /// network's own servers, or the default VPN profile's. Local names still go to those.
    /// </summary>
    public List<DnsServer> DnsServers { get; set; } = [];
    /// <summary>Names, with their subdomains, that DNS filtering answers with this PC's own address.</summary>
    public List<string> BlockedNames { get; set; } = [];
    public List<string> BlockedCountries { get; set; } = [];
    /// <summary>While set, apps may reach only the countries in <see cref="AllowedCountries"/>; <see cref="BlockedCountries"/> waits unused.</summary>
    public bool CountryAllowList { get; set; }
    public List<string> AllowedCountries { get; set; } = [];
    public List<uint> BlockedAsns { get; set; } = [];
    /// <summary>Keeps DHCP, IPv6 neighbor discovery and, outside Lockdown, the Windows DNS client working in enforced modes.</summary>
    public bool CoreNetworking { get; set; } = true;
    /// <summary>Routes outbound unicast through Darkwire's tunnel router, which holds new connections until a rule or decision exists.</summary>
    public bool RouteConnections { get; set; } = true;
    /// <summary>
    /// From Windows' start until the service has its policy in force, its router running and its VPN tunnels up or failed,
    /// nothing reaches the network but what that restore needs (<see cref="FilterCompiler.StartupLock"/>); the block returns
    /// whenever the service stops.
    /// </summary>
    public bool StartupLock { get; set; } = true;
    /// <summary>
    /// Windows Security keeps its Firewall and network protection area, which says Windows Firewall is off, while Darkwire
    /// enforces. Otherwise, the default, Darkwire hides that area and its warnings through Windows' own Group Policy value
    /// until Windows Firewall is back in control.
    /// </summary>
    public bool ShowFirewallWarnings { get; set; }
    /// <summary>The desktop app opens in the tray when this user signs in; the service starts with Windows either way.</summary>
    public bool StartAtSignIn { get; set; } = true;
    public List<ColumnPreference> Columns { get; set; } = [];
    /// <summary>Desktop palette: System follows Windows, Dark is Obsidian, Light is Glacier.</summary>
    public string AppAppearance { get; set; } = "System";
    public string NavigationPlacement { get; set; } = "Left";
    public string AtlasPresentation { get; set; } = "Standard";
    public string MapEffectPreset { get; set; } = "Balanced";
    public bool RouteParticles { get; set; } = true;
    public bool EndpointRipples { get; set; } = true;
    public bool PolicyShockwaves { get; set; } = true;
    public bool AmbientParticles { get; set; }
    public bool AtmosphereGlow { get; set; } = true;
    public bool AutoRotateGlobe { get; set; }
    public int EffectIntensity { get; set; } = 45;
    public string Theme { get; set; } = "Amethyst";
    public string MapProjection { get; set; } = "Flat";
    /// <summary>Set once the user picks a map view; until then the map opens flat.</summary>
    public bool MapProjectionChosen { get; set; }
    /// <summary>Where the map draws this PC: a country (alpha-2) or a position set in Settings; when neither, Windows' region setting.</summary>
    public string? MapOriginCountry { get; set; }
    /// <summary>The city picked in Settings, whose position is the one stored, or the one nearest a pin; null for a typed position.</summary>
    public string? MapOriginCity { get; set; }
    public double? MapOriginLatitude { get; set; }
    public double? MapOriginLongitude { get; set; }
    /// <summary>Set once the first run's question of where this PC is has been answered or put off; Settings asks again on request.</summary>
    public bool MapOriginAsked { get; set; }
    public string BackgroundPreset { get; set; } = "Space";
    public bool SpaceSunMoon { get; set; } = true;
    public bool SpaceUfos { get; set; }
    public string CloudDirection { get; set; } = "Left";
    public bool ReducedMotion { get; set; }
    public bool CloseToTray { get; set; } = true;
    public bool ReverseDnsEnabled { get; set; }
    /// <summary>A CSV imported by an earlier version, which replaces the automatic database in the app until removed.</summary>
    public string? GeoDatabasePath { get; set; }
}
