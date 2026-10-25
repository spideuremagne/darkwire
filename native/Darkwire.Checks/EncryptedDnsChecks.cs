using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Host;
using System.Buffers.Binary;
using System.Text;

/// <summary>Encrypted DNS: the signatures that vouch for the resolver list, DNS stamps, the list itself, local names, and the policy around them.</summary>
internal static class EncryptedDnsChecks
{
    private static void Expect(bool value, string message = "Encrypted DNS invariant failed.") { if (!value) throw new Exception(message); }
    private static void Throws(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Expected the input to be refused."); }

    private static readonly byte[] Seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), KeyId = [1, 2, 3, 4, 5, 6, 7, 8];

    /// <summary>A stamp from its parts, as sdns:// and URL-safe base64.</summary>
    internal static string Stamp(params byte[][] parts) => DnsStamp.Scheme + Convert.ToBase64String([.. parts.SelectMany(p => p)]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Text(string value) => [(byte)value.Length, .. Encoding.ASCII.GetBytes(value)];
    private static byte[] Claims(ulong properties) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(bytes, properties); return bytes; }
    /// <summary>A DNSCrypt stamp for an address and provider, with a made-up key.</summary>
    internal static string DnsCrypt(string address, string provider, ulong properties = 1) => Stamp([1], Claims(properties), Text(address), [32, .. Enumerable.Range(0, 32).Select(i => (byte)i)], Text(provider));

    public static void Run(Action<string, Action> check)
    {
        check("BLAKE2b-512 matches the RFC 7693 vectors", () =>
        {
            Expect(Convert.ToHexString(Blake2b.Hash512("abc"u8)) == "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923");
            Expect(Convert.ToHexString(Blake2b.Hash512([])) == "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE");
        });
        check("Ed25519 verifies the RFC 8032 vectors and refuses anything changed", () =>
        {
            var key1 = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            var signature1 = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
            var key2 = Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
            var signature2 = Convert.FromHexString("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
            Expect(Ed25519.Verify(key1, [], signature1) && Ed25519.Verify(key2, [0x72], signature2), "A test vector did not verify.");
            Expect(!Ed25519.Verify(key1, [0], signature1) && !Ed25519.Verify(key2, [0x72], signature1) && !Ed25519.Verify(key1, [], [.. signature1[..63], (byte)(signature1[63] ^ 1)]));
            // The checks' own signer reproduces the vectors, so what it signs below is signed as RFC 8032 says.
            Expect(Ed25519.PublicKey(Seed).SequenceEqual(key1) && Ed25519.Sign(Seed, []).SequenceEqual(signature1));
            // S at or above the group order is never accepted.
            var order = Convert.FromHexString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
            Expect(!Ed25519.Verify(key1, [], [.. signature1[..32], .. order]));
        });
        check("Minisign signatures verify over the file and the trusted comment, prehashed or not", () =>
        {
            var key = Minisign.PublicKey(Seed, KeyId);
            var data = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("## server\n\nA line long enough to span several BLAKE2b blocks.\n", 40)));
            foreach (var prehash in new[] { true, false })
                Expect(Minisign.Verify(key, data, Minisign.Sign(Seed, KeyId, data, "timestamp:1700000000\tfile:public-resolvers.md", prehash)) == "timestamp:1700000000\tfile:public-resolvers.md");
            var signature = Minisign.Sign(Seed, KeyId, data, "timestamp:1700000000\tfile:public-resolvers.md\thashed");
            Throws(() => Minisign.Verify(key, [.. data, (byte)'!'], signature));
            Throws(() => Minisign.Verify(key, data, signature.Replace("timestamp:1700000000", "timestamp:1900000000")));
            Throws(() => Minisign.Verify(Minisign.PublicKey(Seed, [8, 7, 6, 5, 4, 3, 2, 1]), data, signature));
            Throws(() => Minisign.Verify(Minisign.PublicKey(new byte[32], KeyId), data, signature));
            Throws(() => Minisign.Verify(key, data, "untrusted comment: x\nnot base64\n"));
            Throws(() => Minisign.Verify("not a key", data, signature));
        });
        check("The resolver list's signature must name the list and when it was signed", () =>
        {
            // minisign separates the fields with tabs.
            Expect(ResolverList.SignedAt("timestamp:1792154145\tfile:public-resolvers.md") == 1792154145 && ResolverList.SignedAt("timestamp:1760000000\tfile:public-resolvers.md\thashed") == 1760000000);
            Expect(ResolverList.SignedAt("timestamp:1760000000\tfile:relays.md\thashed") is null && ResolverList.SignedAt("file:public-resolvers.md") is null);
            Expect(ResolverList.SignedAt("timestamp:-5\tfile:public-resolvers.md") is null && ResolverList.SignedAt("") is null);
        });
        check("DNS stamps read DoH and DNSCrypt servers and what they claim", () =>
        {
            var doh = DnsStamp.Parse(DnsStamp.FromUrl("https://dns.example/dns-query", 7));
            Expect(doh is { Protocol: DnsProtocol.Https, Host: "dns.example", Path: "/dns-query", Address: "", Dnssec: true, NoLog: true, NoFilter: true, Ipv6: false } && doh.Display == "https://dns.example/dns-query");
            Expect(DnsStamp.Parse(DnsStamp.FromUrl("dns.example")) is { Host: "dns.example", Path: "/dns-query", Properties: 0 });
            Expect(DnsStamp.Parse(DnsStamp.FromUrl("https://9.9.9.9:8443/query")) is { Address: "9.9.9.9", Host: "9.9.9.9:8443", Path: "/query" });
            Expect(DnsStamp.Parse(DnsStamp.FromUrl("https://[2620:fe::fe]/dns-query")) is { Ipv6: true, Address: "[2620:fe::fe]" });
            var crypt = DnsStamp.Parse(DnsCrypt("[2620:fe::9]:8443", "2.dnscrypt-cert.example", 3));
            Expect(crypt is { Protocol: DnsProtocol.DnsCrypt, Address: "[2620:fe::9]:8443", Host: "2.dnscrypt-cert.example", Dnssec: true, NoLog: true, NoFilter: false, Ipv6: true });
            // A DoH stamp may pin certificate hashes and name bootstrap addresses.
            var pinned = Stamp([2], Claims(1), Text("1.1.1.1"), [0x80 | 32, .. new byte[32], 32, .. new byte[32]], Text("one.example"), Text("/dns-query"), [7, .. "1.0.0.1"u8]);
            Expect(DnsStamp.Parse(pinned) is { Host: "one.example", Address: "1.1.1.1" });
        });
        check("DNS stamps of other protocols, or malformed, are refused", () =>
        {
            Throws(() => DnsStamp.Parse("https://dns.example"));
            Throws(() => DnsStamp.Parse(Stamp([5], Claims(0), Text("odoh.example"), Text("/dns-query"))));
            Throws(() => DnsStamp.Parse(Stamp([3], Claims(0), Text("9.9.9.9"), [0], Text("dns.example"))));
            Throws(() => DnsStamp.Parse(DnsStamp.FromUrl("https://dns.example/dns-query")[..^4]));
            Throws(() => DnsStamp.Parse(Stamp([2], Claims(0), Text(""), [0], Text("dns.example"), Text("/dns-query"), [0], [9])));
            Throws(() => DnsStamp.Parse(Stamp([2], Claims(0), Text("not-an-address"), [0], Text("dns.example"), Text("/dns-query"))));
            Throws(() => DnsStamp.Parse(Stamp([2], Claims(0), Text(""), [0], Text("bad host"), Text("/dns-query"))));
            Throws(() => DnsStamp.Parse(Stamp([2], Claims(0), Text(""), [0], Text("dns.example"), Text("no-slash"))));
            Throws(() => DnsStamp.Parse(Stamp([1], Claims(0), Text("9.9.9.9"), [4, 1, 2, 3, 4], Text("2.dnscrypt-cert.example"))));
            Throws(() => DnsStamp.Parse("sdns://" + new string('A', DnsStamp.MaximumLength)));
            foreach (var url in new[] { "http://dns.example/dns-query", "https://user@dns.example/dns-query", "https://dns.example/dns-query?x=1", "ftp://dns.example" })
                Throws(() => DnsStamp.FromUrl(url));
        });
        check("The resolver list keeps DoH and DNSCrypt servers with their stamps, once each, grouped by provider", () =>
        {
            var doh = DnsStamp.FromUrl("https://alpha.example/dns-query", 3);
            var crypt1 = DnsCrypt("192.0.2.1:443", "2.dnscrypt-cert.beta.example", 5); var crypt2 = DnsCrypt("192.0.2.2:443", "2.dnscrypt-cert.beta.example", 5);
            var odoh = Stamp([5], Claims(0), Text("odoh.example"), Text("/dns-query"));
            var markdown = $"# public-resolvers\n\nWhat the list is.\n\n## alpha-doh\n\nAlpha answers\nover DoH.\n\n{doh}\n\n## quad9-dnscrypt-ip4-filter-pri\r\n\r\nTwo addresses.\r\n\r\n{crypt1}\r\n{crypt2}\r\n\r\n" +
                $"## gamma-odoh\n\nOblivious only.\n\n{odoh}\n\n## Bad Name\n\nUpper case.\n\n{doh}\n\n## alpha-doh\n\nAgain.\n\n{crypt1}\n";
            var entries = ResolverList.Parse(markdown);
            Expect(entries.Count == 2 && entries[0] is { Name: "alpha-doh", Description: "Alpha answers over DoH.", Protocol: DnsProtocol.Https, Dnssec: true, NoLog: true, NoFilter: false, Provider: DnsProviders.Other } && entries[0].Stamps.SequenceEqual([doh]));
            Expect(entries[1] is { Name: "quad9-dnscrypt-ip4-filter-pri", Protocol: DnsProtocol.DnsCrypt, Provider: "Quad9", Dnssec: true, NoFilter: true } && entries[1].Stamps.SequenceEqual([crypt1, crypt2]));
            Expect(DnsProviders.Of("cs-ch") == "cryptostorm" && DnsProviders.Of("cisco") == "Cisco OpenDNS" && DnsProviders.Of("ciscoish") == DnsProviders.Other && DnsProviders.Of("dnscry.pt-adelaide-ipv4") == "dnscry.pt");
            Expect(DnsProviders.Names.Count == 15 && DnsProviders.Names.Contains("UncensoredDNS") && DnsProviders.Names.Contains("Plan 9 DNS"));
        });
        check("Local names stay with the local network's DNS; names on the internet go to the encrypted servers", () =>
        {
            string[] domains = ["corp.example.com.", "HOME"];
            foreach (var name in new[] { "nas", "printer.lan", "router.home.arpa", "box.local", "1.0.168.192.in-addr.arpa", "4.3.2.10.in-addr.arpa", "9.20.172.in-addr.arpa",
                "1.0.0.127.in-addr.arpa", "8.e.f.ip6.arpa", "b.d.f.ip6.arpa", "ipv4only.arpa", "www.msftconnecttest.com", "dns.msftncsi.com", "intranet.corp.example.com", "corp.example.com", "tv.home", "5.70.100.in-addr.arpa" })
                Expect(LocalNames.Contains(name, domains), name + " should be local.");
            foreach (var name in new[] { "example.com", "lan.example.com", "local.example", "9.32.172.in-addr.arpa", "8.8.8.8.in-addr.arpa", "example.corp.example.org", "msftconnecttest.com.evil.example", "5.128.100.in-addr.arpa", "xlan" + ".example" })
                Expect(!LocalNames.Contains(name, domains), name + " should go to the encrypted servers.");
        });
        check("Policy refuses DNS servers without valid stamps or names, twice-chosen servers, and badly written blocked names", () =>
        {
            var good = new DnsServer { Name = "quad9-doh-ip4-port443-filter-pri", Stamps = [DnsStamp.FromUrl("https://dns.quad9.net/dns-query", 3)], Listed = true };
            Expect(PolicyValidation.Validate(new() { DnsServers = [good], BlockedNames = ["ads.example.com"] }).Count == 0);
            Expect(PolicyValidation.DnsServerError(new() { Name = "Upper", Stamps = good.Stamps }) is not null && PolicyValidation.DnsServerError(new() { Name = "ok", Stamps = [] }) is not null);
            Expect(PolicyValidation.DnsServerError(new() { Name = "ok", Stamps = ["sdns://AA"] }) is not null && PolicyValidation.DnsServerError(new() { Name = "ok", Stamps = [.. Enumerable.Repeat(good.Stamps[0], 9)] }) is not null);
            Expect(PolicyValidation.Validate(new() { DnsServers = [good, good] }).Contains("Each DNS server can be chosen once."));
            Expect(PolicyValidation.Validate(new() { BlockedNames = ["Ads.Example.com"] }).Count == 1 && PolicyValidation.Validate(new() { BlockedNames = ["localhost"] }).Count == 1);
            Expect(PolicyValidation.Validate(new() { DnsServers = [.. Enumerable.Range(0, 65).Select(i => new DnsServer { Name = "s" + i, Stamps = good.Stamps })] }).Count == 1);
            Expect(PolicyValidation.Validate(new() { OwnTraffic = OwnRoute.Profile, OwnTrafficProfileId = Guid.NewGuid() }).Contains("The VPN profile for Darkwire's own connections does not exist."));
            Expect(PolicyValidation.Validate(new() { OwnTraffic = (OwnRoute)9 }).Contains("Unknown route for Darkwire's own connections."));
        });
        check("Encrypted DNS and blocked names need the router; with it, they refuse link-local DNS and route in Open", () =>
        {
            var server = new DnsServer { Name = "alpha", Stamps = [DnsStamp.FromUrl("https://alpha.example/dns-query")] };
            Expect(!FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, DnsServers = [server], RouteConnections = false }).CanApply);
            Expect(!FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, BlockedNames = ["ads.example.com"], RouteConnections = false }).CanApply);
            foreach (var policy in new AppState[] { new() { Mode = FirewallMode.BlockNew, DnsServers = [server] }, new() { Mode = FirewallMode.BlockNew, BlockedNames = ["ads.example.com"] } })
                Expect(FilterCompiler.Compile(policy).Filters.Count(f => f.Name == "DNS filtering: unrouted server") == 4);
            Expect(FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew }).Filters.All(f => f.Name != "DNS filtering: unrouted server"));
            Expect(FilterCompiler.RoutesInOpen(new() { Mode = FirewallMode.Open, DnsServers = [server] }) && !FilterCompiler.RoutesInOpen(new() { Mode = FirewallMode.Open }));
            Expect(FilterCompiler.Compile(new() { Mode = FirewallMode.Open, DnsServers = [server] }).Filters.Count > 0);
        });
        check("Darkwire's own connections follow the default route unless sent another way, and run their profile", () =>
        {
            var work = new VpnProfile { Name = "Work" }; var home = new VpnProfile { Name = "Home" };
            var policy = new AppState { VpnProfiles = [work, home] };
            Expect(VpnAssignments.OwnProfile(policy) is null && !VpnAssignments.Routed(policy) && !VpnAssignments.Running(policy).Any());
            policy.DefaultOutboundVpnProfileId = work.Id;
            Expect(VpnAssignments.OwnProfile(policy) == work.Id);
            policy.OwnTraffic = OwnRoute.Windows;
            Expect(VpnAssignments.OwnProfile(policy) is null);
            policy.OwnTraffic = OwnRoute.Profile; policy.OwnTrafficProfileId = home.Id; policy.DefaultOutboundVpnProfileId = null;
            Expect(VpnAssignments.OwnProfile(policy) == home.Id && VpnAssignments.Routed(policy) && VpnAssignments.Running(policy).Single() == home && VpnAssignments.InUse(policy).Single() == home);
            Expect(!FilterCompiler.Compile(Copy(policy, routing: false)).CanApply && FilterCompiler.Compile(Copy(policy, routing: true)).CanApply, "Own traffic through a profile needs routing.");
        });
        check("The editor's routes count as applied only when Darkwire's own connections go the same way", () =>
        {
            var work = new VpnProfile { Name = "Work", Kind = "WireGuard" };
            var draft = new AppState { VpnProfiles = [work], OwnTraffic = OwnRoute.Windows };
            var status = new ServiceStatus(true, true, "Active", FirewallMode.BlockNew, 1, true, "", OwnTraffic: OwnRoute.Windows);
            Expect(VpnState.Applied(draft, status));
            Expect(!VpnState.Applied(draft, status with { OwnTraffic = OwnRoute.Default }));
            draft.OwnTraffic = OwnRoute.Profile; draft.OwnTrafficProfileId = work.Id;
            var routes = VpnState.Draft(draft);
            Expect(routes.Count == 1 && !VpnState.Applied(draft, status with { OwnTraffic = OwnRoute.Profile, OwnTrafficProfileId = Guid.NewGuid(), Routes = routes }));
            Expect(VpnState.Applied(draft, status with { OwnTraffic = OwnRoute.Profile, OwnTrafficProfileId = work.Id, Routes = routes }));
        });
        check("Servers of your own are named from where they are, unlike any other", () =>
        {
            var stamp = DnsStamp.Parse(DnsStamp.FromUrl("https://DNS.Example:8443/dns-query"));
            Expect(MainWindow.OwnName(stamp, []) == "own-dns.example-8443" && MainWindow.OwnName(stamp, ["own-dns.example-8443", "own-dns.example-8443-2"]) == "own-dns.example-8443-3");
            Expect(ResolverList.ValidName(MainWindow.OwnName(DnsStamp.Parse(DnsStamp.FromUrl("https://[2620:fe::fe]/x")), [])));
            Expect(ResolverList.ValidName(MainWindow.OwnName(DnsStamp.Parse(DnsStamp.FromUrl("https://" + new string('a', 60) + ".example/x")), [])));
        });
    }

    private static AppState Copy(AppState policy, bool routing)
    {
        var copy = new AppState { VpnProfiles = policy.VpnProfiles, OwnTraffic = policy.OwnTraffic, OwnTrafficProfileId = policy.OwnTrafficProfileId, Mode = FirewallMode.BlockNew, RouteConnections = routing };
        return copy;
    }
}
