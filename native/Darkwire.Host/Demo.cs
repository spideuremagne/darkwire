namespace Darkwire.Host;

public static class Demo
{
    /// <summary>
    /// The PC a demo shows in place of this one, so its captures carry nothing of the PC they were taken on: a name, and the
    /// Windows region and time zone of the demo's San Francisco anchor.
    /// </summary>
    public const string DeviceName = "DEMO-PC", Region = "US", TimeZone = "Pacific Standard Time";

    public static AppState State() => new()
    {
        Mode = FirewallMode.Learning,
        Rules =
        [
            new() { ApplicationName = "Microsoft Edge", Group = "Browsers", Path = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", RemotePorts = "80,443", Protocol = "TCP" },
            new() { ApplicationName = "Visual Studio", Group = "Development", Path = @"C:\Program Files\Microsoft Visual Studio\devenv.exe", RemotePorts = "443", Protocol = "TCP" },
            new() { ApplicationName = "Spotify", Group = "Media", Path = @"C:\Apps\Spotify.exe", RemotePorts = "443", Protocol = "TCP" },
            new() { ApplicationName = "Discord", Group = "Communication", Path = @"C:\Apps\Discord.exe", RemotePorts = "443,50000-65535", Protocol = "Any" },
            new() { ApplicationName = "Telemetry service", Group = "Privacy", Path = @"C:\Apps\telemetry.exe", Action = RuleAction.Deny },
            new() { ApplicationName = "Windows Update", Group = "System", Path = @"C:\Windows\System32\svchost.exe", Service = "wuauserv", RemotePorts = "80,443", Protocol = "TCP" },
            new() { ApplicationName = "Local DNS", Group = "Network", Protocol = "UDP", RemotePorts = "53", RemoteAddresses = "192.168.0.0/16" },
            new() { ApplicationName = "Steam", Group = "Games", Path = @"C:\Program Files (x86)\Steam\steam.exe", RemotePorts = "443,27015-27050", Protocol = "TCP" },
            new() { ApplicationName = "File sharing", Group = "Local network", Direction = TrafficDirection.Inbound, LocalPorts = "445", RemoteAddresses = "192.168.0.0/16", Protocol = "TCP", Location = "Private", Enabled = false },
            new() { ApplicationName = "Remote desktop", Group = "Remote access", Direction = TrafficDirection.Inbound, LocalPorts = "3389", Protocol = "TCP", Enabled = false }
        ],
        VpnProfiles = [ new() { Name = "Work / Amsterdam", Kind = "WireGuard", Endpoint = "vpn.example.net:51820", CredentialsRevision = Guid.NewGuid(), Applications = [@"C:\Program Files\Microsoft Visual Studio\devenv.exe"] },
            new() { Name = "Private / Stockholm", Kind = "WireGuard", Endpoint = "se.example.net:51820", CredentialsRevision = Guid.NewGuid(), Applications = [@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"] },
            new() { Name = "Travel / Lisbon", Kind = "WireGuard", Endpoint = "pt.example.net:51820", CredentialsRevision = Guid.NewGuid(), KeepConnected = true } ],
        Blocklists = [new() { CatalogId = "hagezi-pro", Name = "HaGeZi Multi Pro" }, new() { CatalogId = "firehol-level1", Name = "FireHOL Level 1" },
            new() { Name = "Tracking & analytics", Url = "https://example.com/trackers.txt", Entries = ["telemetry.example.com", "analytics.example.com"], UpdatedAt = DateTimeOffset.Now.AddHours(-2) }, new() { Name = "Untrusted networks", Url = "https://example.com/networks.txt", Entries = ["203.0.113.0/24", "198.51.100.0/24"], UpdatedAt = DateTimeOffset.Now.AddHours(-5) }],
        BlockedCountries = ["KP"], BlockedAsns = [64496],
        DnsServers = [new() { Name = "quad9-doh-ip4-port443-filter-pri", Stamps = [DnsStamp.FromUrl("https://dns.quad9.net/dns-query", 3)], Listed = true },
            new() { Name = "mullvad-doh", Stamps = [DnsStamp.FromUrl("https://dns.mullvad.net/dns-query", 7)], Listed = true }],
        BlockedNames = ["ads.example.com", "telemetry.example.net"]
    };
    /// <summary>
    /// The service as the demo's VPN page shows it: enforcing the demo's routes, with the first tunnel up and carrying traffic,
    /// the second retrying, and the third up but unanswered.
    /// </summary>
    public static Darkwire.Engine.ServiceStatus Status(AppState state)
    {
        var now = DateTimeOffset.Now; var routes = VpnState.Draft(state);
        var tunnels = state.VpnProfiles.Where(p => routes.Any(r => r.ProfileId == p.Id)).Take(3).Select((p, i) => i switch
        {
            0 => new Darkwire.Engine.TunnelStatus(p.Id, p.Kind, "Up", now.AddMinutes(-42), 23, ["10.64.0.2"], Resolvers: ["10.64.0.1"], SentBytes: 18_400_000, ReceivedBytes: 214_000_000, LastReceived: now,
                InRates: [.. Enumerable.Range(0, 150).Select(s => (long)(30e6 + 18e6 * Math.Sin(s / 9.0) + 6e6 * Math.Sin(s / 2.3)))],
                OutRates: [.. Enumerable.Range(0, 150).Select(s => (long)(2.4e6 + 1.6e6 * Math.Sin(s / 7.0 + 1)))]),
            1 => new Darkwire.Engine.TunnelStatus(p.Id, p.Kind, "Failed", now.AddMinutes(-3), Error: "The handshake never completed."),
            _ => new Darkwire.Engine.TunnelStatus(p.Id, p.Kind, "Up", now.AddMinutes(-1), 31, ["10.66.0.2"], Resolvers: ["10.66.0.1"], SentBytes: 4_820)
        }).ToArray();
        return new(true, true, "Active", state.Mode, 1288, true, "Darkwire is enforcing.", PolicyRevision: 7,
            Tunnels: tunnels, VpnBackends: ["WireGuard"], Routes: routes.Count > 0 ? routes : null, LocalNetworkBypassesVpn: state.LocalNetworkBypassesVpn);
    }
    /// <summary>The service's catalog list status for the demo: two enforced lists, two downloaded, one downloading.</summary>
    public static IReadOnlyList<Darkwire.Engine.BlocklistStatus> ListStatus() => BlocklistCatalog.Entries.Select(e => e.Id switch
    {
        "hagezi-pro" or "firehol-level1" => new Darkwire.Engine.BlocklistStatus(e.Id, e.Estimate, DateTimeOffset.Now.AddHours(-3), false, Enforced: true),
        "oisd-small" or "urlhaus" => new(e.Id, e.Estimate, DateTimeOffset.Now.AddDays(-1), false),
        "1hosts-lite" => new(e.Id, 0, null, true),
        _ => new(e.Id, 0, null, false)
    }).ToArray();
    /// <summary>What the demo's enforced lists blocked since a morning start.</summary>
    public static Darkwire.Engine.BlocklistHits ListHits() =>
        new(1_284, DateTimeOffset.Now.Date.AddHours(8), new Dictionary<string, long> { ["hagezi-pro"] = 1_102, ["firehol-level1"] = 196, [Darkwire.Engine.BlocklistHits.CustomKey("Tracking & analytics")] = 31,
            [Darkwire.Engine.BlocklistHits.NamesKey] = 12 });

    /// <summary>The demo's DNS proxy, answering through the fastest of its servers.</summary>
    public static Darkwire.Engine.DnsStatus DnsStatus() => new("Ready", "quad9-doh-ip4-port443-filter-pri", 14, 3, 4_812, 3, 21);

    /// <summary>
    /// A stand-in for the public resolver list, for demos and captures: servers named as the list names them, with descriptions
    /// and stamps written for the demo. The real list comes from the service, signed by the DNSCrypt project.
    /// </summary>
    public static Darkwire.Engine.DnsCatalog DnsCatalog()
    {
        var servers = new (string Name, string Host, bool Doh, bool Dnssec, bool NoLog, bool NoFilter, string About)[]
        {
            ("adguard-dns-doh", "dns.adguard-dns.com", true, true, true, false, "Blocks ads and trackers."), ("adguard-dns-unfiltered-doh", "unfiltered.adguard-dns.com", true, true, true, true, "Answers everything."),
            ("cira-private", "private.canadianshield.cira.ca", true, true, true, true, "Canadian, answers everything."), ("cira-protected", "protected.canadianshield.cira.ca", true, true, true, false, "Canadian, blocks malware and phishing."),
            ("cisco-doh", "doh.opendns.com", true, false, false, false, "Blocks phishing."), ("cleanbrowsing-security-doh", "doh.cleanbrowsing.org", true, true, true, false, "Blocks malicious domains."),
            ("cloudflare", "cloudflare-dns.com", true, true, true, true, "Answers everything."), ("cloudflare-security", "security.cloudflare-dns.com", true, true, true, false, "Blocks malware."),
            ("comodo-02", "8.20.247.2", false, false, false, false, "Blocks malicious domains."), ("cs-de", "de.cryptostorm.is", false, false, true, true, "Germany, answers everything."),
            ("cs-ch", "ch.cryptostorm.is", false, false, true, true, "Switzerland, answers everything."), ("dnscry.pt-amsterdam-ipv4", "ams.dnscry.pt", true, true, true, true, "Amsterdam, answers everything."),
            ("dnscry.pt-frankfurt-ipv4", "fra.dnscry.pt", true, true, true, true, "Frankfurt, answers everything."), ("libredns", "doh.libredns.gr", true, true, true, true, "Greece, answers everything."),
            ("mullvad-doh", "dns.mullvad.net", true, true, true, true, "Answers everything."), ("mullvad-adblock-doh", "adblock.dns.mullvad.net", true, true, true, false, "Blocks ads and trackers."),
            ("nextdns", "dns.nextdns.io", true, true, false, true, "Answers everything unless set up otherwise."), ("plan9dns-nj", "nj.plan9-dns.com", true, true, true, true, "New Jersey, answers everything."),
            ("quad9-doh-ip4-port443-filter-pri", "dns.quad9.net", true, true, true, false, "Blocks malware."), ("quad9-doh-ip4-port443-nofilter-pri", "dns10.quad9.net", true, true, true, true, "Answers everything."),
            ("quad9-dnscrypt-ip4-filter-pri", "9.9.9.9", false, true, true, false, "Blocks malware."), ("uncensoreddns-ipv4", "anycast.uncensoreddns.org", true, true, true, true, "Answers everything."),
            ("adfilter-adl", "adl.adfilter.net", true, true, true, false, "Adelaide, blocks ads and trackers."), ("a-and-a", "dns.aa.net.uk", true, true, true, true, "Answers everything.")
        };
        return new([.. servers.Select(s => new DnsCatalogEntry(s.Name, DnsProviders.Of(s.Name), "Demo entry. " + s.About, s.Doh ? DnsProtocol.Https : DnsProtocol.DnsCrypt,
            s.Dnssec, s.NoLog, s.NoFilter, false, [DnsStamp.FromUrl("https://" + s.Host + "/dns-query", (s.Dnssec ? 1UL : 0) | (s.NoLog ? 2UL : 0) | (s.NoFilter ? 4UL : 0))]))],
            DateTimeOffset.Now.AddDays(-2), DateTimeOffset.Now.AddHours(-5), false);
    }
    /// <summary>The router's report for the demo's outbound connections: each through its application's profile, or the default one.</summary>
    public static IReadOnlyList<Darkwire.Engine.RoutedConnection> Routed(AppState state) =>
        [.. Connections().Where(c => c.Direction == TrafficDirection.Outbound).Select(c => new Darkwire.Engine.RoutedConnection(c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort,
            state.VpnProfiles.FirstOrDefault(p => p.Applications.Contains(c.Path, StringComparer.OrdinalIgnoreCase))?.Id ?? state.DefaultOutboundVpnProfileId))];
    public static List<Connection> Connections() =>
    [
        new("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 8740, "104.18.32.7", 443, 52341, "TCP", TrafficDirection.Outbound, "Private", Country:"US", Asn:13335, Hostname:"cloudflare.com", LocalAddress:"192.168.1.42"),
        new("Visual Studio", @"C:\Program Files\Microsoft Visual Studio\devenv.exe", 4128, "140.82.112.4", 443, 52348, "TCP", TrafficDirection.Outbound, "Private", Country:"US", Asn:36459, Hostname:"github.com", LocalAddress:"192.168.1.42"),
        new("Spotify", @"C:\Apps\Spotify.exe", 9216, "35.186.224.25", 443, 52362, "TCP", TrafficDirection.Outbound, "Private", Country:"SE", Asn:15169, Hostname:"audio.spotify.com", LocalAddress:"192.168.1.42"),
        new("Telemetry service", @"C:\Apps\telemetry.exe", 11240, "203.0.113.42", 443, 52366, "TCP", TrafficDirection.Outbound, "Private", Country:"DE", Asn:64496, Hostname:"telemetry.example.com", LocalAddress:"192.168.1.42"),
        new("Discord", @"C:\Apps\Discord.exe", 5880, "162.159.135.234", 443, 52370, "TCP", TrafficDirection.Outbound, "Private", Country:"NL", Asn:13335, Hostname:"gateway.discord.gg", LocalAddress:"192.168.1.42"),
        new("Steam", @"C:\Program Files (x86)\Steam\steam.exe", 6572, "23.54.10.8", 443, 52412, "TCP", TrafficDirection.Outbound, "Private", Country:"JP", Asn:20940, Hostname:"cdn.steampowered.com", LocalAddress:"192.168.1.42"),
        new("Windows Update", @"C:\Windows\System32\svchost.exe", 2016, "13.107.4.50", 443, 52414, "TCP", TrafficDirection.Outbound, "Private", "wuauserv", Country:"US", Asn:8075, Hostname:"download.windowsupdate.com", LocalAddress:"192.168.1.42"),
        new("Signal", @"C:\Apps\Signal.exe", 7140, "76.223.92.165", 443, 52500, "TCP", TrafficDirection.Outbound, "Private", Country:"GB", Asn:16509, Hostname:"chat.signal.org", LocalAddress:"192.168.1.42"),
        new("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 8740, "151.101.1.69", 443, 52600, "TCP", TrafficDirection.Outbound, "Private", Country:"SG", Asn:54113, Hostname:"api.example.net", LocalAddress:"192.168.1.42"),
        new("Remote desktop", @"C:\Windows\System32\svchost.exe", 2040, "192.0.2.18", 54212, 3389, "TCP", TrafficDirection.Inbound, "Private", Country:"AU", Asn:64497, LocalAddress:"192.168.1.42"),
        new("File sharing", @"C:\Windows\System32\svchost.exe", 2040, "198.51.100.16", 55120, 445, "TCP", TrafficDirection.Inbound, "Private", Country:"BR", Asn:64498, LocalAddress:"192.168.1.42")
    ];
    private static readonly (string Address, string Country, string Application, int Port, string Protocol, TrafficDirection Direction, string Reason, int Count)[] Refused =
    [
        ("203.0.113.42", "DE", @"C:\Apps\telemetry.exe", 443, "TCP", TrafficDirection.Outbound, "Telemetry service", 14),
        ("198.51.100.23", "BR", "Windows", 3389, "TCP", TrafficDirection.Inbound, "No rule allows it", 37),
        ("192.0.2.144", "AU", "Windows", 22, "TCP", TrafficDirection.Inbound, "FireHOL Level 1", 9),
        ("203.0.113.90", "JP", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 443, "TCP", TrafficDirection.Outbound, "HaGeZi Multi Pro", 5),
        ("198.51.100.200", "SG", @"C:\Apps\updater.exe", 443, "TCP", TrafficDirection.Outbound, "Not allowed yet", 2)
    ];

    /// <summary>What the demo's service refused lately: an application's telemetry, scans from abroad, a listed tracker and one waiting for a decision.</summary>
    public static IReadOnlyList<Darkwire.Engine.BlockedFlow> Blocked() =>
        [.. Refused.Select((r, i) => new Darkwire.Engine.BlockedFlow(DateTimeOffset.Now.AddMinutes(-2 - 7 * i), r.Application, r.Address, r.Port, r.Protocol, r.Direction, r.Reason, r.Count))];

    /// <summary>The country the demo places an address in, for the demo's refusals.</summary>
    public static string CountryOf(string address) => Refused.FirstOrDefault(r => r.Address == address).Country ?? "";

    public static GeoRecord? LocationFor(Connection connection)
    {
        var point = connection.Country switch
        {
            "US" => ("United States", "New York", "New York", 40.71, -74.0),
            "GB" => ("United Kingdom", "London", "England", 51.5, -.12),
            "NL" => ("Netherlands", "Amsterdam", "North Holland", 52.37, 4.89),
            "SE" => ("Sweden", "Stockholm", "Stockholm County", 59.33, 18.06),
            "DE" => ("Germany", "Frankfurt am Main", "Hesse", 50.11, 8.68),
            "JP" => ("Japan", "Tokyo", "Tokyo", 35.68, 139.69),
            "SG" => ("Singapore", "Singapore", "", 1.35, 103.82),
            "AU" => ("Australia", "Sydney", "New South Wales", -33.86, 151.2),
            "BR" => ("Brazil", "São Paulo", "São Paulo", -23.55, -46.63),
            _ => default
        };
        return point.Item1 is null ? null : new(connection.RemoteAddress + "/32", connection.Country, point.Item1, point.Item2, point.Item4, point.Item5, connection.Asn, "Demo location", point.Item3);
    }
    public static readonly MapRoute[] Points = [new(37.77,-122.42,false,TrafficDirection.Outbound),new(40.71,-74.0,false,TrafficDirection.Outbound),new(51.5,-.12,false,TrafficDirection.Outbound),new(52.37,4.89,false,TrafficDirection.Outbound),new(59.33,18.06,false,TrafficDirection.Outbound),new(50.11,8.68,true,TrafficDirection.Outbound),new(35.68,139.69,false,TrafficDirection.Outbound),new(1.35,103.82,false,TrafficDirection.Outbound),new(-33.86,151.2,false,TrafficDirection.Inbound),new(-23.55,-46.63,true,TrafficDirection.Inbound)];
    public static readonly double[] Download = [120000,180000,150000,210000,170000,220000,190000,420000,610000,460000,550000,180000,190000,270000,210000,330000,260000,410000,780000,620000,420000,480000,390000,300000,280000,490000,560000,430000,620000,780000,540000,420000];
    public static readonly double[] Upload = [23000,27000,19000,21000,34000,41000,29000,32000,26000,57000,49000,24000,21000,39000,65000,43000,25000,42000,27000,31000,69000,58000,39000,35000,28000,54000,46000,32000,45000,67000,72000,58000];
}
