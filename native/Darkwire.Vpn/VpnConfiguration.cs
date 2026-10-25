using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Vpn;

/// <summary>Contains secrets. Do not log, serialize, or display NormalizedConfiguration.</summary>
public sealed class ParsedVpnConfiguration
{
    internal ParsedVpnConfiguration(string kind, string endpoint, string configuration, IReadOnlyList<IPAddress> dnsServers, IReadOnlyList<NetPrefix> networks)
    {
        Kind = kind; Endpoint = endpoint; NormalizedConfiguration = configuration; DnsServers = dnsServers; Networks = networks;
    }
    public string Kind { get; }
    public string Endpoint { get; }
    public string NormalizedConfiguration { get; }
    /// <summary>The profile's own resolvers, its WireGuard DNS. Never applied to Windows.</summary>
    public IReadOnlyList<IPAddress> DnsServers { get; }
    /// <summary>Destinations the tunnel carries: its peers' AllowedIPs.</summary>
    public IReadOnlyList<NetPrefix> Networks { get; }
    public override string ToString() => $"{Kind} profile ({Endpoint})";
}

/// <summary>
/// Parses a deliberately bounded, self-contained WireGuard client configuration. Settings the service decides itself, such as
/// the routing table and Windows DNS, are left out of what the backend runs; unknown ones, script hooks among them, fail closed.
/// Import never invokes scripts, reads referenced files, changes routes, or starts a tunnel.
/// </summary>
public static class VpnConfiguration
{
    public const int MaximumCharacters = 2 * 1024 * 1024;
    public static ParsedVpnConfiguration Parse(string kind, string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length is 0 or > MaximumCharacters || text.Any(c => char.IsControl(c) && c is not '\r' and not '\n' and not '\t'))
            throw new InvalidDataException("The VPN profile is empty, too large, or contains control characters.");
        return kind == "WireGuard" ? WireGuard(text) : throw new InvalidDataException(Unsupported(kind));
    }

    /// <summary>
    /// Why a profile of another kind is neither imported nor run: Darkwire runs WireGuard tunnels only. Earlier builds also ran
    /// OpenVPN, whose profiles a policy may still name.
    /// </summary>
    public static string Unsupported(string kind) => kind == "OpenVPN"
        ? "Darkwire runs WireGuard tunnels only; OpenVPN is no longer supported. Import your provider's WireGuard configuration instead."
        : "Darkwire runs WireGuard tunnels only.";

    private static ParsedVpnConfiguration WireGuard(string text)
    {
        var sections = new List<(string Name, Dictionary<string, string> Values)>();
        Dictionary<string, string>? current = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            if (line is "[Interface]" or "[Peer]")
            {
                if (line == "[Interface]" && sections.Count != 0 || line == "[Peer]" && sections.Count == 0)
                    throw new InvalidDataException("WireGuard requires one Interface section followed by Peer sections.");
                if (sections.Count > 32) throw new InvalidDataException("A profile supports at most 32 WireGuard peers.");
                current = new(StringComparer.OrdinalIgnoreCase); sections.Add((line, current)); continue;
            }
            var separator = line.IndexOf('=');
            if (current is null || separator <= 0 || separator == line.Length - 1)
                throw new InvalidDataException("Invalid WireGuard section or setting.");
            var key = line[..separator].Trim(); var value = line[(separator + 1)..].Trim();
            if (!current.TryAdd(key, value)) throw new InvalidDataException($"Duplicate WireGuard setting: {SafeName(key)}.");
        }
        if (sections.Count < 2) throw new InvalidDataException("WireGuard requires an Interface and at least one Peer.");
        var dns = new List<IPAddress>(); var endpoints = new List<string>(); var networks = new List<NetPrefix>(); var result = new StringBuilder();
        foreach (var (name, values) in sections)
        {
            var isInterface = name == "[Interface]";
            Require(values, isInterface ? ["PrivateKey", "Address"] : ["PublicKey", "AllowedIPs", "Endpoint"]);
            result.AppendLine(name);
            foreach (var (key, value) in values)
            {
                switch (key.ToLowerInvariant())
                {
                    case "privatekey" when isInterface:
                    case "publickey" when !isInterface:
                    case "presharedkey" when !isInterface:
                        ValidateKey(value); break;
                    case "address" when isInterface:
                        foreach (var prefix in SplitList(value)) ValidatePrefix(prefix); break;
                    case "allowedips" when !isInterface:
                        foreach (var prefix in SplitList(value)) { ValidatePrefix(prefix); networks.Add(NetPrefix.Parse(prefix)); }
                        break;
                    case "dns" when isInterface:
                        foreach (var address in SplitList(value))
                        {
                            if (!IPAddress.TryParse(address, out var ip) || !IsUnicast(ip))
                                throw new InvalidDataException("WireGuard DNS must contain unicast IP addresses; DNS search domains are not supported.");
                            dns.Add(ip);
                        }
                        // The service must resolve DNS through the selected tunnel. Never change system DNS on import.
                        continue;
                    case "endpoint" when !isInterface:
                        endpoints.Add(ParseEndpoint(value)); break;
                    case "listenport" when isInterface:
                    case "persistentkeepalive" when !isInterface:
                        ValidateInteger(value, 0, 65535); break;
                    case "mtu" when isInterface:
                        ValidateInteger(value, 576, 65535); break;
                    case "table" when isInterface:
                        if (value is not "off" and not "auto" and not "main") throw new InvalidDataException("Unsupported WireGuard routing table.");
                        continue;
                    default: throw new InvalidDataException($"Unsupported WireGuard setting: {SafeName(key)}. Script hooks are not permitted.");
                }
                result.Append(key).Append(" = ").AppendLine(value);
            }
            if (isInterface) result.AppendLine("Table = off");
            result.AppendLine();
        }
        return new("WireGuard", string.Join(", ", endpoints.Distinct()), result.ToString(), dns.AsReadOnly(), networks.Distinct().ToArray());
    }

    /// <summary>The host and port of each endpoint in a profile's endpoint summary, such as "vpn.example.net:51820, [2001:db8::4]:51820".</summary>
    public static IReadOnlyList<(string Host, ushort Port)> Endpoints(string summary)
    {
        ArgumentNullException.ThrowIfNull(summary);
        List<(string, ushort)> result = [];
        foreach (var entry in summary.Split(", "))
        {
            var separator = entry.LastIndexOf(':');
            if (separator <= 0) throw new InvalidDataException("Invalid VPN endpoint summary.");
            var host = entry[..separator];
            if (host.Contains(':') && (!host.StartsWith('[') || !host.EndsWith(']'))) throw new InvalidDataException("Invalid VPN endpoint summary.");
            result.Add((ValidateHost(host.Trim('[', ']')), checked((ushort)ParsePort(entry[(separator + 1)..]))));
        }
        return result;
    }

    /// <summary>
    /// A normalized configuration with each peer's endpoint host name replaced by an address looked up for it, the name's
    /// first IPv4 address or else its first IPv6 one, so the backend never resolves a name itself. Address endpoints and
    /// every other line stay as they are. A name without a usable address is refused.
    /// </summary>
    public static string ResolveEndpoints(string kind, string normalized, Func<string, IReadOnlyList<IPAddress>> addresses)
    {
        ArgumentNullException.ThrowIfNull(normalized);
        if (kind != "WireGuard") throw new InvalidDataException(Unsupported(kind));
        IPAddress Usable(string host) =>
            addresses(host).Where(a => IsUnicast(a) && !a.IsIPv6LinkLocal).OrderBy(a => a.AddressFamily == AddressFamily.InterNetworkV6).FirstOrDefault()
            ?? throw new InvalidDataException($"The VPN endpoint {host} has no address to connect to.");
        var lines = normalized.Split('\n');
        var output = new List<string>(lines.Length);
        var peer = false;
        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (line is "[Interface]" or "[Peer]") peer = line == "[Peer]";
            var separator = line.IndexOf('=');
            if (peer && separator > 0 && line[..separator].Trim().Equals("Endpoint", StringComparison.OrdinalIgnoreCase))
            {
                var endpoint = ParseEndpoint(line[(separator + 1)..].Trim());
                var colon = endpoint.LastIndexOf(':');
                var host = endpoint[..colon].Trim('[', ']');
                if (!IPAddress.TryParse(host, out _))
                {
                    var address = Usable(host);
                    var target = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
                    output.Add($"{line[..separator].TrimEnd()} = {target}{endpoint[colon..]}{raw[line.Length..]}");
                    continue;
                }
            }
            output.Add(raw);
        }
        return string.Join('\n', output);
    }

    private static string SafeName(string value) => value.Length <= 40 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ? value : "unknown";
    private static void Require(Dictionary<string, string> values, string[] keys)
    { foreach (var key in keys) if (!values.ContainsKey(key)) throw new InvalidDataException($"WireGuard requires {key}."); }
    private static IEnumerable<string> SplitList(string value)
    { var entries = value.Split(',').Select(x => x.Trim()).ToArray(); if (entries.Any(string.IsNullOrEmpty)) throw new InvalidDataException("Empty WireGuard list item."); return entries; }
    private static void ValidateKey(string value)
    {
        byte[]? bytes = null;
        try { bytes = Convert.FromBase64String(value); if (bytes.Length != 32 || bytes.All(x => x == 0)) throw new FormatException(); }
        catch (FormatException) { throw new InvalidDataException("WireGuard keys must encode a nonzero 32-byte value."); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void ValidatePrefix(string value)
    {
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address) || address.IsIPv4MappedToIPv6 || address.ScopeIdOrZero() != 0)
            throw new InvalidDataException("Invalid WireGuard IP prefix.");
        if (parts.Length == 2) ValidateInteger(parts[1], 0, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
    }
    private static string ParseEndpoint(string value)
    {
        var separator = value.LastIndexOf(':');
        if (separator <= 0) throw new InvalidDataException("WireGuard endpoint requires host and port.");
        var inputHost = value[..separator];
        if (inputHost.Contains(':') && (!inputHost.StartsWith('[') || !inputHost.EndsWith(']')))
            throw new InvalidDataException("Enclose an IPv6 WireGuard endpoint in brackets.");
        var host = ValidateHost(inputHost.Trim('[', ']')); var port = ParsePort(value[(separator + 1)..]);
        return host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";
    }
    private static string ValidateHost(string value)
    {
        if (IPAddress.TryParse(value, out var address))
        {
            if (!IsUnicast(address)) throw new InvalidDataException("VPN endpoint must be a unicast address.");
            return address.ToString();
        }
        string ascii;
        try { ascii = new IdnMapping().GetAscii(value); } catch (ArgumentException) { throw new InvalidDataException("Invalid VPN endpoint hostname."); }
        if (ascii.Length is < 1 or > 253 || ascii.Split('.').Any(p => p.Length is < 1 or > 63 || p[0] == '-' || p[^1] == '-' || p.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new InvalidDataException("Invalid VPN endpoint hostname.");
        return ascii.ToLowerInvariant();
    }
    public static bool IsUnicast(IPAddress address) => !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any) &&
        !address.Equals(IPAddress.Broadcast) && !address.IsIPv6Multicast && !address.IsIPv4MappedToIPv6 && address.ScopeIdOrZero() == 0 &&
        (address.AddressFamily != AddressFamily.InterNetwork || address.GetAddressBytes()[0] < 224);
    private static int ParsePort(string value) { ValidateInteger(value, 1, 65535); return int.Parse(value, CultureInfo.InvariantCulture); }
    private static void ValidateInteger(string value, int min, int max)
    { if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < min || parsed > max) throw new InvalidDataException("VPN numeric setting is outside its supported range."); }
    private static long ScopeIdOrZero(this IPAddress address) => address.AddressFamily == AddressFamily.InterNetworkV6 ? address.ScopeId : 0;
}
