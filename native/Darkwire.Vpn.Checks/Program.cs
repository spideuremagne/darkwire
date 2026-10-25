using Darkwire.Vpn;
using System.Net;

if (await ProcessChecks.RunChild(args) is { } childResult) return childResult;

var passed = 0; var failed = 0;
void Check(string name, Action test) { try { test(); Console.WriteLine("PASS " + name); passed++; } catch (Exception ex) { Console.WriteLine("FAIL " + name + ": " + ex.Message); failed++; } }
void Expect(bool value) { if (!value) throw new Exception("Assertion failed."); }
void Reject(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Expected rejection."); }
var key = Convert.ToBase64String(Enumerable.Repeat((byte)0x41, 32).ToArray());
var wg = $"[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 10.0.0.1\n[Peer]\nPublicKey = {key}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";
Check("WireGuard endpoint parsed", () => Expect(VpnConfiguration.Parse("WireGuard", wg).Endpoint == "vpn.example.com:51820"));
Check("WireGuard forces managed routes", () => Expect(VpnConfiguration.Parse("WireGuard", wg).NormalizedConfiguration.Contains("Table = off")));
Check("WireGuard isolates DNS settings", () => { var p = VpnConfiguration.Parse("WireGuard", wg); Expect(p.DnsServers.Single().Equals(IPAddress.Parse("10.0.0.1"))); Expect(!p.NormalizedConfiguration.Contains("DNS =")); });
Check("Profile ToString never contains private key", () => Expect(!VpnConfiguration.Parse("WireGuard", wg).ToString().Contains(key)));
foreach (var hook in new[] { "PostUp", "PreUp", "PostDown", "PreDown", "SaveConfig", "Unknown" })
    Check("WireGuard rejects " + hook, () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("[Peer]", hook + " = command\n[Peer]"))));
Check("WireGuard rejects duplicate secret", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("[Peer]", "PrivateKey = " + key + "\n[Peer]"))));
Check("WireGuard rejects missing private key", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("PrivateKey = " + key + "\n", ""))));
Check("WireGuard rejects zero key", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace(key, Convert.ToBase64String(new byte[32])))));
Check("WireGuard rejects invalid key size", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace(key, "YWJj"))));
Check("WireGuard rejects invalid prefix", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("::/0", "::/129"))));
Check("WireGuard rejects endpoint command syntax", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("vpn.example.com", "vpn.example.com;command"))));
Check("WireGuard rejects endpoint port zero", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace(":51820", ":0"))));
Check("WireGuard accepts bracketed IPv6 endpoint", () => Expect(VpnConfiguration.Parse("WireGuard", wg.Replace("vpn.example.com", "[2001:db8::4]")).Endpoint == "[2001:db8::4]:51820"));
Check("WireGuard rejects ambiguous IPv6 endpoint", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("vpn.example.com", "2001:db8::4"))));
Check("WireGuard rejects loopback endpoint", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("vpn.example.com", "127.0.0.1"))));
Check("WireGuard rejects multicast endpoint", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("vpn.example.com", "224.1.1.1"))));
Check("WireGuard rejects DNS search domains", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg.Replace("DNS = 10.0.0.1", "DNS = internal.example"))));
Check("Invalid profile kind rejected", () => Reject(() => VpnConfiguration.Parse("OTHER", wg)));
Check("Control character rejected", () => Reject(() => VpnConfiguration.Parse("WireGuard", wg + "\0")));
Check("Oversized profile rejected", () => Reject(() => VpnConfiguration.Parse("WireGuard", new string('a', VpnConfiguration.MaximumCharacters + 1))));
Check("OpenVPN profiles are refused, saying Darkwire runs WireGuard only", () =>
{
    var ovpn = "client\ndev tun\nremote vpn.example.com 1194 udp\nremote-cert-tls server\n<ca>\nTEST CERTIFICATE DATA\n</ca>\n";
    try { VpnConfiguration.Parse("OpenVPN", ovpn); throw new Exception("An OpenVPN profile was accepted."); }
    catch (InvalidDataException error) { Expect(error.Message.Contains("WireGuard tunnels only") && error.Message.Contains("OpenVPN is no longer supported")); }
    Reject(() => VpnConfiguration.ResolveEndpoints("OpenVPN", ovpn, _ => [IPAddress.Parse("203.0.113.9")]));
});
ProcessChecks.Run(Check, args.Contains("--native-loopback"));
RouterChecks.Run(Check);
VpnRouteChecks.Run(Check, args.Contains("--native-loopback"));
DnsChecks.Run(Check, args.Contains("--native-loopback"));
DnsLookupChecks.Run(Check, args.Contains("--native-loopback"));

var tunnelProfile = new TunnelProfileAssignment(Guid.NewGuid(), "WireGuard", [@"C:\Apps\Example.exe"]);
Check("Tunnel plan selects one profile for canonical app path", () => Expect(TunnelRoutingPlan.Build([tunnelProfile]).FindApplication(@"c:\Apps\Folder\..\EXAMPLE.exe")?.ProfileId == tunnelProfile.ProfileId));
Check("Tunnel plan has no implicit profile for unassigned app", () => Expect(TunnelRoutingPlan.Build([tunnelProfile]).FindApplication(@"C:\Apps\Other.exe") is null));
Check("Default tunnel is selected only when an app has no override", () =>
{
    var first = Guid.NewGuid(); var second = Guid.NewGuid();
    var plan = TunnelRoutingPlan.Build([new(first, "WireGuard", []), new(second, "WireGuard", [@"C:\Apps\app.exe"])], first);
    Expect(plan.FindApplication(@"C:\Apps\app.exe")?.ProfileId == second);
    Expect(plan.FindApplication(@"C:\Apps\other.exe")?.ProfileId == first);
});
Check("Tunnel plan snapshots mutable assignment lists", () => { var apps = new List<string> { @"C:\Apps\Example.exe" }; var plan = TunnelRoutingPlan.Build([tunnelProfile with { Applications = apps }]); apps.Clear(); Expect(plan.Applications.Count == 1); });
Check("Tunnel plan accepts 100 profiles, OpenVPN ones from earlier builds among them", () => Expect(TunnelRoutingPlan.Build(Enumerable.Range(0, 100).Select(i => new TunnelProfileAssignment(Guid.NewGuid(), i % 2 == 0 ? "WireGuard" : "OpenVPN", []))).ProfileCount == 100));
Check("Tunnel plan rejects 101 profiles", () => Reject(() => TunnelRoutingPlan.Build(Enumerable.Range(0, 101).Select(_ => new TunnelProfileAssignment(Guid.NewGuid(), "WireGuard", [])))));
Check("Tunnel plan rejects duplicate profile ID", () => Reject(() => TunnelRoutingPlan.Build([tunnelProfile, tunnelProfile with { Applications = [] }])));
Check("Tunnel plan rejects app assigned to two profiles", () => Reject(() => TunnelRoutingPlan.Build([tunnelProfile, tunnelProfile with { ProfileId = Guid.NewGuid() }])));
Check("Tunnel plan rejects case-variant duplicate assignment", () => Reject(() => TunnelRoutingPlan.Build([tunnelProfile with { Applications = [@"C:\Apps\Example.exe", @"c:\apps\EXAMPLE.exe"] }])));
Check("Tunnel plan preserves mandatory leak protections", () => { var p = TunnelRoutingPlan.Build([tunnelProfile]); Expect(p.RequiresTunnelOnlyDns && p.RequiresFailClosedOnTunnelLoss && p.RequiresBlockingUnsupportedAddressFamilies && p.RequiresBlockingUnsupportedProtocols); });
foreach (var path in new[] { @"Apps\Example.exe", @"\\server\Example.exe", @"C:\Apps\Example.exe:stream", @"C:\Apps\Example.dll", @"\\?\C:\Apps\Example.exe", @"C:\Apps\*.exe" })
    Check("Tunnel plan rejects unsupported application path " + path, () => Reject(() => TunnelRoutingPlan.Build([tunnelProfile with { Applications = [path] }])));

Console.WriteLine($"\n{passed} passed; {failed} failed. No tunnel or external connection was opened.");
return failed == 0 ? 0 : 1;
