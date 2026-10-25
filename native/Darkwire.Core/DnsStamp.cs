using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Darkwire.Core;

public enum DnsProtocol { DnsCrypt = 1, Https = 2 }

/// <summary>
/// A DNS stamp (sdns://, https://dnscrypt.info/stamps-specifications): how to reach an encrypted DNS server and what it
/// claims of itself. Darkwire takes DNSCrypt and DNS over HTTPS stamps, the protocols dnscrypt-proxy answers through for it.
/// </summary>
/// <param name="Address">The server's IP address, with a port when not the protocol's default; empty for a DoH server found by its host name.</param>
/// <param name="Host">The DoH server's host name, with a port when not 443; for DNSCrypt, the provider name.</param>
/// <param name="Path">The DoH query path; empty for DNSCrypt.</param>
public sealed record DnsStamp(DnsProtocol Protocol, ulong Properties, string Address, string Host, string Path)
{
    public const string Scheme = "sdns://";
    public const int MaximumLength = 2048;
    /// <summary>The server says it validates DNSSEC, keeps no logs, and blocks nothing of its own.</summary>
    public bool Dnssec => (Properties & 1) != 0;
    public bool NoLog => (Properties & 2) != 0;
    public bool NoFilter => (Properties & 4) != 0;
    /// <summary>The server is reached over IPv6.</summary>
    public bool Ipv6 => Address.StartsWith('[');
    public string ProtocolName => Protocol == DnsProtocol.Https ? "DNS over HTTPS" : "DNSCrypt";
    /// <summary>Where the server is, for people: a DoH server's URL, a DNSCrypt server's address.</summary>
    public string Display => Protocol == DnsProtocol.Https ? "https://" + Host + Path : Address;

    public static bool TryParse(string? text, out DnsStamp stamp)
    {
        try { stamp = Parse(text); return true; }
        catch (InvalidDataException) { stamp = null!; return false; }
    }

    /// <summary>A DNSCrypt or DoH stamp; throws <see cref="InvalidDataException"/> for anything else.</summary>
    public static DnsStamp Parse(string? text)
    {
        if (text is null || text.Length > MaximumLength || !text.StartsWith(Scheme, StringComparison.Ordinal)) throw new InvalidDataException("A DNS stamp starts with sdns://.");
        byte[] data;
        try
        {
            var body = text[Scheme.Length..].Replace('-', '+').Replace('_', '/');
            data = Convert.FromBase64String(body.PadRight(body.Length + (4 - body.Length % 4) % 4, '='));
        }
        catch (FormatException) { throw new InvalidDataException("The DNS stamp is not URL-safe base64."); }
        var reader = new Reader(data);
        var protocol = reader.Byte();
        if (protocol is not (1 or 2)) throw new InvalidDataException("Only DNSCrypt and DNS over HTTPS stamps are supported.");
        var properties = reader.UInt64();
        var address = reader.Text();
        if (address.Length > 0 && !ValidAddress(address)) throw new InvalidDataException("The DNS stamp's server address is invalid.");
        if (protocol == 1)
        {
            if (address.Length == 0 || address.StartsWith(':') || reader.Bytes().Length != 32) throw new InvalidDataException("A DNSCrypt stamp needs the server's address and public key.");
            var provider = reader.Text();
            if (provider.Length is 0 or > 253 || provider.Any(c => c is <= ' ' or > '~')) throw new InvalidDataException("The DNSCrypt provider name is invalid.");
            reader.End();
            return new(DnsProtocol.DnsCrypt, properties, address, provider, "");
        }
        // DoH: certificate hashes the server must chain to, its host name and the query path, then optional bootstrap addresses.
        foreach (var hash in reader.Set()) if (hash.Length is not (0 or 32)) throw new InvalidDataException("A DoH stamp's certificate hash is invalid.");
        var host = reader.Text(); var path = reader.Text();
        if (!ValidHost(host)) throw new InvalidDataException("The DoH stamp's host name is invalid.");
        if (!path.StartsWith('/') || path.Length > 512 || path.Any(c => c is <= ' ' or > '~' or '#' or '?')) throw new InvalidDataException("The DoH stamp's path is invalid.");
        if (!reader.AtEnd) foreach (var bootstrap in reader.Set()) if (!IPAddress.TryParse(Encoding.ASCII.GetString(bootstrap), out _)) throw new InvalidDataException("The DoH stamp's bootstrap address is invalid.");
        reader.End();
        return new(DnsProtocol.Https, properties, address, host, path);
    }

    /// <summary>
    /// A DoH stamp for a server given as a URL, or as a host name for its /dns-query path: found by its host name unless the
    /// URL's host is an address, and claiming nothing unless told what to claim.
    /// </summary>
    /// <param name="properties">What the stamp claims: 1 DNSSEC, 2 no logs, 4 no filtering.</param>
    public static string FromUrl(string text, ulong properties = 0)
    {
        text = text.Trim();
        if (!text.Contains("://", StringComparison.Ordinal)) text = "https://" + text;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps || url.UserInfo.Length > 0 || url.Query.Length > 0 || url.Fragment.Length > 0)
            throw new InvalidDataException("Enter a DNS over HTTPS URL such as https://dns.example/dns-query, or a DNS stamp.");
        var host = url.HostNameType == UriHostNameType.IPv6 ? url.Host : url.IdnHost;
        var authority = url.IsDefaultPort ? host : host + ":" + url.Port;
        var path = url.AbsolutePath is "" or "/" ? "/dns-query" : url.AbsolutePath;
        var address = url.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6 ? host : "";
        var stamp = new List<byte> { 2 };
        var claims = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(claims, properties); stamp.AddRange(claims);
        void Text(string value)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            if (bytes.Length > 255) throw new InvalidDataException("The DNS over HTTPS URL is too long.");
            stamp.Add((byte)bytes.Length); stamp.AddRange(bytes);
        }
        Text(address); stamp.Add(0); Text(authority); Text(path);
        var encoded = Scheme + Convert.ToBase64String([.. stamp]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Parse(encoded);
        return encoded;
    }

    private static bool ValidAddress(string address)
    {
        // A port alone keeps the server's address to its host name.
        if (address.StartsWith(':')) return ushort.TryParse(address[1..], out var only) && only > 0;
        if (address.StartsWith('['))
        {
            var close = address.IndexOf(']');
            return close > 1 && IPAddress.TryParse(address[1..close], out var six) && six.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                (close == address.Length - 1 || address[close + 1] == ':' && ushort.TryParse(address[(close + 2)..], out var port) && port > 0);
        }
        var colon = address.IndexOf(':');
        var host = colon < 0 ? address : address[..colon];
        return IPAddress.TryParse(host, out var four) && four.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && host.Count(c => c == '.') == 3 &&
            (colon < 0 || ushort.TryParse(address[(colon + 1)..], out var p) && p > 0);
    }

    private static bool ValidHost(string host)
    {
        if (host.Length is 0 or > 260) return false;
        if (host.StartsWith('[')) return ValidAddress(host);
        var colon = host.IndexOf(':');
        var name = colon < 0 ? host : host[..colon];
        if (colon >= 0 && (!ushort.TryParse(host[(colon + 1)..], out var port) || port == 0)) return false;
        return Uri.CheckHostName(name) is UriHostNameType.Dns or UriHostNameType.IPv4;
    }

    private ref struct Reader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> data = data;
        private int position;
        public readonly bool AtEnd => position == data.Length;
        public byte Byte() => position < data.Length ? data[position++] : throw Truncated();
        public ulong UInt64()
        {
            if (data.Length - position < 8) throw Truncated();
            var value = BinaryPrimitives.ReadUInt64LittleEndian(data[position..]); position += 8; return value;
        }
        public ReadOnlySpan<byte> Bytes()
        {
            var length = Byte();
            if (data.Length - position < length) throw Truncated();
            var value = data.Slice(position, length); position += length; return value;
        }
        public string Text()
        {
            var bytes = Bytes();
            foreach (var b in bytes) if (b is < 0x20 or > 0x7E) throw new InvalidDataException("A DNS stamp field holds characters other than printable ASCII.");
            return Encoding.ASCII.GetString(bytes);
        }
        /// <summary>A variable-length set: each length but the last has its top bit set.</summary>
        public List<byte[]> Set()
        {
            List<byte[]> items = [];
            while (true)
            {
                var length = Byte();
                var size = length & 0x7F;
                if (data.Length - position < size) throw Truncated();
                items.Add(data.Slice(position, size).ToArray()); position += size;
                if ((length & 0x80) == 0) return items;
                if (items.Count > 16) throw new InvalidDataException("A DNS stamp set is too long.");
            }
        }
        public readonly void End() { if (!AtEnd) throw new InvalidDataException("The DNS stamp has data past its end."); }
        private static InvalidDataException Truncated() => new("The DNS stamp is cut short.");
    }
}
