using Darkwire.Core;
using Darkwire.Engine;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Darkwire.Service;

internal static class ServiceVpnTests
{
    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool condition) { if (!condition) throw new Exception("VPN service invariant failed."); }
        var key = Convert.ToBase64String(Enumerable.Repeat((byte)0x41, 32).ToArray());
        var config = $"[Interface]\nPrivateKey = {key}\nAddress = 10.50.0.2/32\nDNS = 10.50.0.1\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51820\n";
        var root = Path.Combine(Path.GetTempPath(), "Darkwire-vault-check-" + Guid.NewGuid().ToString("N"));
        try
        {
            var verified = 0; var vault = new VpnProfileVault(root, () => verified++); var id = Guid.NewGuid();
            StoredVpnProfile? stored = null;
            check("Service vault encrypts credentials and retains isolated DNS configuration", () =>
            {
                stored = vault.Save(id, "WireGuard", config);
                var disk = File.ReadAllText(Path.Combine(root, "Profiles", id.ToString("N") + ".json"));
                Assert(!disk.Contains(key) && !disk.Contains("PrivateKey"));
                var loaded = vault.Read(id, stored.Revision);
                Assert(loaded.NormalizedConfiguration.Contains(key) && loaded.DnsServers.Single().ToString() == "10.50.0.1" && verified >= 2);
                Assert(vault.List().Single().Id == id);
            });
            check("Invalid replacement cannot overwrite working VPN credentials", () =>
            {
                try { vault.Save(id, "WireGuard", config + "PostUp = run\n"); throw new Exception("Unsafe config accepted"); } catch (InvalidDataException) { }
                Assert(vault.Read(id, stored!.Revision).Endpoint == stored.Endpoint);
            });
            check("The service stores no OpenVPN profile, and lists one an earlier build stored, so it can be deleted, but never reads it", () =>
            {
                const string ovpn = "client\ndev tun\nremote 198.51.100.9 1194\nremote-cert-tls server\n<ca>\nTEST CERTIFICATE DATA\n</ca>\n";
                try { vault.Save(Guid.NewGuid(), "OpenVPN", ovpn); throw new Exception("An OpenVPN profile was stored."); }
                catch (InvalidDataException error) { Assert(error.Message.Contains("WireGuard tunnels only")); }
                // An earlier build's entry, made here by naming OpenVPN in a stored envelope.
                var old = vault.Save(Guid.NewGuid(), "WireGuard", config);
                var file = Path.Combine(root, "Profiles", old.Id.ToString("N") + ".json");
                File.WriteAllText(file, File.ReadAllText(file).Replace("\"WireGuard\"", "\"OpenVPN\""));
                Assert(vault.List().Single(p => p.Id == old.Id).Kind == "OpenVPN");
                try { vault.Read(old.Id, old.Revision); throw new Exception("An OpenVPN profile was read."); }
                catch (Exception error) when (error is InvalidDataException or System.Security.Cryptography.CryptographicException) { }
                vault.Delete(old.Id);
                Assert(vault.List().Single().Id == id);
            });
            check("Credential revision rejects stale readers", () =>
            {
                var replacement = vault.Save(id, "WireGuard", config);
                Assert(replacement.Revision != stored!.Revision);
                try { vault.Read(id, stored.Revision); throw new Exception("Stale revision accepted"); } catch (InvalidDataException) { }
                stored = replacement;
            });
            check("DPAPI context prevents profile credential substitution", () =>
            {
                var bytes = DpapiSecrets.Protect([1, 2, 3], "profile-a", true);
                try { DpapiSecrets.Unprotect(bytes, "profile-b"); throw new Exception("Wrong context accepted"); } catch (CryptographicException) { }
            });
            check("DPAPI remains compatible with desktop imports and WireGuard's no-entropy format", () =>
            {
                byte[] value = [12, 37, 61, 84];
                var legacy = LegacyDpapi(value, protect: true, "legacy import");
                Assert(DpapiSecrets.Unprotect(legacy, "").SequenceEqual(value));
                var encrypted = DpapiSecrets.Protect(value, "", description: "tunnel-name");
                Assert(LegacyDpapi(encrypted, protect: false, "tunnel-name").SequenceEqual(value));
            });
            check("Vault rejects profile ID mismatch and removes only the chosen profile", () =>
            {
                var second = Guid.NewGuid(); vault.Save(second, "WireGuard", config);
                var firstPath = Path.Combine(root, "Profiles", id.ToString("N") + ".json");
                var secondPath = Path.Combine(root, "Profiles", second.ToString("N") + ".json");
                File.Copy(firstPath, secondPath, true);
                try { vault.Read(second, stored!.Revision); throw new Exception("Swapped profile accepted"); } catch (InvalidDataException) { }
                vault.Delete(second); Assert(vault.List().Single().Id == id);
            });
            check("WireGuard runtime uses stable bounded names and validated source addresses", () =>
            {
                // Valid WireGuard tunnel names, the first the profile ID itself and the others never an ID.
                var names = WireGuardBackend.Names(id);
                Assert(names.Count == 3 && names.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 3 && names[0] == id.ToString("N") && names.SequenceEqual(WireGuardBackend.Names(id)));
                Assert(names.All(n => n.Length == 32 && n.All(char.IsAsciiLetterOrDigit)) && names.Skip(1).All(n => !Guid.TryParseExact(n, "N", out _)));
                var parsed = Darkwire.Vpn.VpnConfiguration.Parse("WireGuard", config);
                Assert(WireGuardBackend.InterfaceAddresses(parsed.NormalizedConfiguration).Single().ToString() == "10.50.0.2");
                try { WireGuardBackend.InterfaceAddresses("[Interface]\nAddress = 127.0.0.1/8\n"); throw new Exception("Loopback adapter accepted"); } catch (InvalidDataException) { }
            });
            check("A profile shares an address another tunnel holds, runs WireGuard without it, and is refused one another interface holds", () =>
            {
                static IPAddress Ip(string text) => IPAddress.Parse(text);
                static string[] Lines(string text) => text.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
                // Profiles from one provider often give every device the same address and resolver.
                var normalized = Darkwire.Vpn.VpnConfiguration.Parse("WireGuard", config.Replace("Address = 10.50.0.2/32", "Address = 10.88.0.2/32, 2001:db8:88::2/128")).NormalizedConfiguration;
                Assert(WireGuardBackend.InterfacePrefixes(normalized).SequenceEqual([(Ip("10.88.0.2"), 32), (Ip("2001:db8:88::2"), 128)]));
                Assert(WireGuardBackend.InterfacePrefixes("[Interface]\nAddress = 10.14.0.2/16, 10.14.0.3\n").SequenceEqual([(Ip("10.14.0.2"), 16), (Ip("10.14.0.3"), 32)]));
                var partly = Lines(WireGuardBackend.WithoutAddresses(normalized, new HashSet<IPAddress> { Ip("10.88.0.2") }));
                bool Other(string line) => !line.StartsWith("Address", StringComparison.Ordinal);
                Assert(partly.Contains("Address = 2001:db8:88::2/128") && partly.Where(Other).SequenceEqual(Lines(normalized).Where(Other)));
                var none = Lines(WireGuardBackend.WithoutAddresses(normalized, new HashSet<IPAddress> { Ip("10.88.0.2"), Ip("2001:db8:88::2") }));
                Assert(none.Length == Lines(normalized).Length - 1 && none.SequenceEqual(Lines(normalized).Where(Other)) && none.Contains("Table = off") && none.Contains("AllowedIPs = 0.0.0.0/0"));
                var tunnel = Guid.NewGuid(); var nic = Guid.NewGuid();
                Darkwire.Vpn.AddressHolder? Held(IPAddress address) => address.ToString() switch
                {
                    "10.88.0.2" => new(tunnel, "WireGuard Tunnel", true),
                    "192.168.1.20" => new(nic, "Ethernet", true),
                    "192.168.9.20" => new(nic, "Wi-Fi", false),
                    _ => null
                };
                Assert(TunnelBackends.Shared([Ip("10.88.0.2"), Ip("2001:db8:88::2")], Held, id => id == tunnel).SetEquals([Ip("10.88.0.2")]));
                // WireGuard clears an address from an interface that is down as it starts.
                Assert(TunnelBackends.Shared([Ip("192.168.9.20")], Held, id => id == tunnel).Count == 0);
                try { TunnelBackends.Shared([Ip("192.168.1.20")], Held, id => id == tunnel); throw new Exception("An address another interface holds was taken."); }
                catch (InvalidOperationException error) { Assert(error.Message.Contains("Ethernet") && error.Message.Contains("192.168.1.20")); }
            });
            check("A WireGuard start takes a name its profile's earlier tunnels left free, waits while none is, and says what holds them", () =>
            {
                var names = WireGuardBackend.Names(id);
                string Free(Func<string, string?> holding, Func<string, bool> recorded) =>
                    WireGuardBackend.FreeNameAsync(names, holding, recorded, TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
                Assert(Free(_ => null, _ => false) == names[0]);
                // The previous tunnel's interface still there: the next name.
                Assert(Free(name => name == names[0] ? "WireGuard Tunnel, Down" : null, _ => false) == names[1]);
                // Its records left behind, as after a backend that did not stop cleanly: neither name is free.
                Assert(Free(name => name == names[0] ? "WireGuard Tunnel, Down" : null, name => name == names[1]) == names[2]);
                // All taken: the start goes on once Windows removes one.
                var looks = 0;
                Assert(Free(name => name == names[1] && ++looks > 3 ? null : "WireGuard Tunnel #2, Down", _ => false) == names[1] && looks == 4);
                try { WireGuardBackend.FreeNameAsync(names, _ => "WireGuard Tunnel, Down", _ => false, TimeSpan.FromMilliseconds(300), CancellationToken.None).GetAwaiter().GetResult(); throw new Exception("Names all taken were ignored."); }
                catch (InvalidOperationException error) { if (!error.Message.Contains("WireGuard Tunnel, Down")) throw new Exception(error.Message); }
                // A start given up meanwhile is canceled, not failed for the interfaces.
                using var stop = new CancellationTokenSource(100);
                try { WireGuardBackend.FreeNameAsync(names, _ => "WireGuard Tunnel, Down", _ => false, TimeSpan.FromSeconds(5), stop.Token).GetAwaiter().GetResult(); throw new Exception("A canceled start went on waiting."); }
                catch (OperationCanceledException) { }
            });
            check("WireGuard's driver answer gives each tunnel's bytes to and from its servers and its last handshake, and one in an unknown layout is refused", () =>
            {
                // An interface record, then each peer with its allowed IPs after it, as WG_IOCTL_GET answers.
                static byte[] Answer(params (ulong Sent, ulong Received, DateTime? Handshake, int AllowedIps)[] peers)
                {
                    var answer = new byte[WireGuardPeers.InterfaceSize + peers.Sum(p => WireGuardPeers.PeerSize + p.AllowedIps * WireGuardPeers.AllowedIpSize)];
                    BinaryPrimitives.WriteUInt32LittleEndian(answer.AsSpan(WireGuardPeers.PeersCountAt), (uint)peers.Length);
                    var offset = WireGuardPeers.InterfaceSize;
                    foreach (var (sent, received, handshake, allowed) in peers)
                    {
                        var peer = answer.AsSpan(offset, WireGuardPeers.PeerSize);
                        BinaryPrimitives.WriteUInt64LittleEndian(peer[WireGuardPeers.SentAt..], sent);
                        BinaryPrimitives.WriteUInt64LittleEndian(peer[WireGuardPeers.ReceivedAt..], received);
                        BinaryPrimitives.WriteUInt64LittleEndian(peer[WireGuardPeers.HandshakeAt..], (ulong)(handshake?.ToFileTimeUtc() ?? 0));
                        BinaryPrimitives.WriteUInt32LittleEndian(peer[WireGuardPeers.AllowedIpsAt..], (uint)allowed);
                        offset += WireGuardPeers.PeerSize + allowed * WireGuardPeers.AllowedIpSize;
                    }
                    return answer;
                }
                var shook = new DateTime(2026, 10, 22, 1, 35, 0, DateTimeKind.Utc);
                Assert(WireGuardPeers.Parse(Answer((1_000, 2_000, shook, 2), (10, 0, null, 0))) is { Sent: 1_010, Received: 2_000, LastHandshake: var last } && last == new DateTimeOffset(shook));
                Assert(WireGuardPeers.Parse(Answer((148, 0, null, 1))) is { Sent: 148, LastHandshake: null } && WireGuardPeers.Parse(Answer()) is null);
                // Cut short, longer than its records, a handshake before WireGuard for Windows existed, or no interface record.
                byte[][] unknown = [Answer((1, 1, shook, 2))[..^8], [.. Answer((1, 1, shook, 0)), 0, 0, 0, 0, 0, 0, 0, 0], Answer((1, 1, new DateTime(1999, 1, 1, 0, 0, 0, DateTimeKind.Utc), 0)), new byte[40]];
                foreach (var answer in unknown)
                {
                    try { WireGuardPeers.Parse(answer); throw new Exception("An answer in an unknown layout was read."); }
                    catch (InvalidDataException) { }
                }
            });
            check("Starts that would take a common address take turns, while others start at once", () =>
            {
                static IPAddress Ip(string text) => IPAddress.Parse(text);
                var claims = new AddressClaims();
                var first = claims.ClaimAsync([Ip("10.88.0.2")], CancellationToken.None);
                Assert(first.IsCompletedSuccessfully);
                var second = claims.ClaimAsync([Ip("2001:db8:88::2"), Ip("10.88.0.2")], CancellationToken.None);
                Assert(!second.IsCompleted && claims.ClaimAsync([Ip("10.9.0.2")], CancellationToken.None).IsCompletedSuccessfully && claims.ClaimAsync([], CancellationToken.None).IsCompletedSuccessfully);
                using (var canceled = new CancellationTokenSource())
                {
                    var waiting = claims.ClaimAsync([Ip("10.88.0.2")], canceled.Token);
                    canceled.Cancel();
                    try { waiting.GetAwaiter().GetResult(); throw new Exception("A canceled start kept waiting."); } catch (OperationCanceledException) { }
                }
                first.Result.Dispose(); first.Result.Dispose();
                Assert(second.Wait(TimeSpan.FromSeconds(5)));
                // A start waits for any claim on one of its addresses.
                var third = claims.ClaimAsync([Ip("2001:db8:88::2")], CancellationToken.None);
                Assert(!third.IsCompleted);
                second.Result.Dispose();
                Assert(third.Wait(TimeSpan.FromSeconds(5)));
            });
            check("Backends get the endpoint addresses the service looked up, never the name, while the Windows DNS client is confined", () =>
            {
                var parsed = Darkwire.Vpn.VpnConfiguration.Parse("WireGuard", config);
                List<string> asked = [];
                Task<IReadOnlyList<IPAddress>> Resolve(string host, CancellationToken _)
                { asked.Add(host); return Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("2001:db8::7"), IPAddress.Parse("198.51.100.7")]); }
                var runtime = TunnelBackends.RuntimeConfigurationAsync(parsed, Resolve, CancellationToken.None).GetAwaiter().GetResult();
                Assert(asked.SequenceEqual(["vpn.example.net"]) && runtime.Contains("Endpoint = 198.51.100.7:51820") && !runtime.Contains("vpn.example.net") && runtime.Contains(key));
                // Without a resolver the backend runs the stored configuration and resolves its peer through Windows.
                Assert(TunnelBackends.RuntimeConfigurationAsync(parsed, null, CancellationToken.None).GetAwaiter().GetResult() == parsed.NormalizedConfiguration);
                // A failed lookup fails the start; an address endpoint needs none.
                try
                {
                    TunnelBackends.RuntimeConfigurationAsync(parsed, (_, _) => Task.FromException<IReadOnlyList<IPAddress>>(new IOException("No DNS server answered.")), CancellationToken.None).GetAwaiter().GetResult();
                    throw new Exception("A failed lookup was accepted.");
                }
                catch (IOException) { }
                var literal = Darkwire.Vpn.VpnConfiguration.Parse("WireGuard", config.Replace("vpn.example.net", "198.51.100.7"));
                asked.Clear();
                Assert(TunnelBackends.RuntimeConfigurationAsync(literal, Resolve, CancellationToken.None).GetAwaiter().GetResult() == literal.NormalizedConfiguration && asked.Count == 0);
                // The servers whose routes the service holds: every address looked up for a name, and an address the profile names.
                var (prepared, peers) = TunnelBackends.PrepareAsync(parsed, Resolve, CancellationToken.None).GetAwaiter().GetResult();
                Assert(prepared == runtime && peers.Select(p => p.ToString()).Order().SequenceEqual(["198.51.100.7", "2001:db8::7"]));
                Assert(TunnelBackends.PrepareAsync(literal, Resolve, CancellationToken.None).GetAwaiter().GetResult().Peers.Single().ToString() == "198.51.100.7");
            });
            check("VPN servers are routed over the physical network while any tunnel needs them, and follow network changes", () =>
            {
                static IPAddress Ip(string text) => IPAddress.Parse(text);
                var table = new PeerTable(); var routes = new PeerRoutes(table);
                table.Hops[Ip("198.51.100.7")] = (7, Ip("192.168.1.1"));
                var first = routes.Hold([Ip("198.51.100.7"), Ip("203.0.113.9")]);
                var second = routes.Hold([Ip("198.51.100.7")]);
                // A server no physical route reaches yet gets its route once one does.
                Assert(table.Routes.SetEquals([(7UL, Ip("198.51.100.7"), Ip("192.168.1.1"))]));
                first.Dispose(); first.Dispose();
                // A server another tunnel still needs keeps its route.
                Assert(table.Routes.Count == 1 && routes.Routed().Single().Peer.Equals(Ip("198.51.100.7")));
                var third = routes.Hold([Ip("203.0.113.9")]);
                table.Hops[Ip("198.51.100.7")] = (8, Ip("10.0.0.1")); table.Hops[Ip("203.0.113.9")] = (8, Ip("10.0.0.1"));
                routes.Refresh();
                Assert(table.Routes.SetEquals([(8UL, Ip("198.51.100.7"), Ip("10.0.0.1")), (8UL, Ip("203.0.113.9"), Ip("10.0.0.1"))]));
                second.Dispose(); third.Dispose();
                Assert(table.Routes.Count == 0 && routes.Routed().Count == 0);
                routes.Hold([Ip("198.51.100.7")]); routes.Clear();
                Assert(table.Routes.Count == 0);
            });
            check("Endpoint lookups ask only the physical interfaces' routable DNS servers, never Darkwire's or a tunnel's", () =>
            {
                var network = new NetworkSnapshot([
                    new(7, ["192.168.1.0/24"], ["192.168.1.1/32", "fe80::1/128", "2001:db8::53/128", "192.168.1.1/32"], [], [], []),
                    new(900, ["10.64.0.2/32"], ["10.64.0.1/32"], [], [], []),
                    new(1, ["198.18.0.0/15"], ["198.18.0.2/32"], [], [], []),
                    new(8, ["10.0.0.0/24"], ["9.9.9.9/32", "198.18.0.2/32", "127.0.0.1/32", "224.0.0.1/32", "fd5a:9c33:21e7::2/128"], [], [], [])]);
                var servers = ConnectionRouter.PhysicalDnsServers(network, luid => luid is 900 or 1);
                Assert(servers.Select(s => s.ToString()).SequenceEqual(["192.168.1.1", "2001:db8::53", "9.9.9.9"]));
            });
            check("WireGuard SCM commands quote protected paths without accepting argument injection", () =>
            {
                var command = OwnedTunnelService.Command(@"C:\Program Files\Darkwire\wireguard.exe", @"C:\ProgramData\Darkwire\profile.conf.dpapi");
                Assert(command == "\"C:\\Program Files\\Darkwire\\wireguard.exe\" /tunnelservice \"C:\\ProgramData\\Darkwire\\profile.conf.dpapi\"");
                try { OwnedTunnelService.Command(@"C:\wg.exe", "C:\\bad\" command"); throw new Exception("Command injection accepted"); } catch (InvalidDataException) { }
            });
            check("Installation integrity detects changed and unexpected dependency files", () =>
            {
                var installation = Path.Combine(root, "Install"); Directory.CreateDirectory(installation);
                var file = Path.Combine(installation, "backend.dll"); File.WriteAllText(file, "test binary");
                var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
                var manifest = System.Text.Json.JsonSerializer.Serialize(new { Version = 1, Files = new[] { new { Path = "backend.dll", Sha256 = hash } } });
                File.WriteAllText(Path.Combine(installation, InstallationIntegrity.ManifestName), manifest);
                InstallationIntegrity.Verify(installation);
                File.WriteAllText(file, "changed binary");
                try { InstallationIntegrity.Verify(installation); throw new Exception("Change ignored"); } catch (InvalidDataException) { }
                File.WriteAllText(file, "test binary"); File.WriteAllText(Path.Combine(installation, "unexpected.dll"), "injection");
                try { InstallationIntegrity.Verify(installation); throw new Exception("New DLL ignored"); } catch (InvalidDataException) { }
                foreach (var item in Directory.EnumerateFiles(installation)) File.Delete(item); Directory.Delete(installation);
            });
            check("Service vault accepts 100 profiles and rejects the 101st without eviction", () =>
            {
                for (var i = vault.List().Count; i < 100; i++) vault.Save(Guid.NewGuid(), "WireGuard", config);
                try { vault.Save(Guid.NewGuid(), "WireGuard", config); throw new Exception("Profile cap ignored"); } catch (InvalidDataException) { }
                Assert(vault.List().Count == 100 && vault.Read(id, stored!.Revision).Endpoint == stored.Endpoint);
            });
        }
        finally
        {
            // Delete only the two children created by this test, including on assertion failure.
            foreach (var name in new[] { "Profiles", "Install" })
            {
                var child = Path.Combine(root, name);
                if (Directory.Exists(child))
                { foreach (var file in Directory.EnumerateFiles(child)) File.Delete(file); Directory.Delete(child); }
            }
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }
    // Independent old-format call: optional entropy is a null pointer, not a zero-length blob.
    private static byte[] LegacyDpapi(byte[] value, bool protect, string description)
    {
        var input = new Blob { Length = value.Length, Data = Marshal.AllocHGlobal(value.Length) };
        Blob output = default; IntPtr decodedDescription = IntPtr.Zero;
        try
        {
            Marshal.Copy(value, 0, input.Data, value.Length);
            var ok = protect ? CryptProtectData(ref input, description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, out decodedDescription, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException("Legacy DPAPI interoperability failed.");
            if (!protect && Marshal.PtrToStringUni(decodedDescription) != description) throw new Exception("DPAPI description was not preserved.");
            var bytes = new byte[output.Length]; Marshal.Copy(output.Data, bytes, 0, bytes.Length); return bytes;
        }
        finally
        {
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            if (decodedDescription != IntPtr.Zero) LocalFree(decodedDescription);
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);

    /// <summary>A route table where the physical network reaches the addresses given in Hops.</summary>
    private sealed class PeerTable : IPeerRouteTable
    {
        public readonly Dictionary<IPAddress, (ulong Luid, IPAddress NextHop)> Hops = [];
        public readonly HashSet<(ulong, IPAddress, IPAddress)> Routes = [];
        public (ulong Luid, IPAddress NextHop)? Find(IPAddress peer) => Hops.TryGetValue(peer, out var hop) ? hop : null;
        public void Add(ulong luid, IPAddress peer, IPAddress nextHop) { if (!Routes.Add((luid, peer, nextHop))) throw new Exception("A route was added twice."); }
        public void Delete(ulong luid, IPAddress peer, IPAddress nextHop) { if (!Routes.Remove((luid, peer, nextHop))) throw new Exception("A route that was never added was deleted."); }
    }
}
