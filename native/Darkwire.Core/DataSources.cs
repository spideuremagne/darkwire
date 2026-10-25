using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Darkwire.Core;

public static class BlocklistParser
{
    public static List<string> Parse(string text)
    {
        HashSet<string> entries = new(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Split('#')[0].Trim();
            if (line.Length == 0 || line.StartsWith('!') || line.StartsWith('[')) continue;
            if (IpNetwork.TryParse(line, out _)) { entries.Add(line); continue; }
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var candidates = parts.Length > 1 && IPAddress.TryParse(parts[0], out _) ? parts.Skip(1) : parts.Take(1);
            foreach (var value in candidates)
            {
                var domain = value.TrimEnd('.').ToLowerInvariant();
                if (domain.StartsWith("||") && domain.EndsWith('^')) domain = domain[2..^1];
                if (domain == "localhost" || !domain.Contains('.') || Uri.CheckHostName(domain) != UriHostNameType.Dns) continue;
                entries.Add(domain);
            }
        }
        return entries.Order(StringComparer.Ordinal).ToList();
    }
    public static bool Matches(string entry, Connection c)
    {
        if (IpNetwork.TryParse(entry, out var net)) return IPAddress.TryParse(c.RemoteAddress, out var ip) && net.Contains(ip);
        return !string.IsNullOrEmpty(c.Hostname) && (c.Hostname.Equals(entry, StringComparison.OrdinalIgnoreCase) || c.Hostname.EndsWith('.' + entry, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class GeoDatabase : IGeoLookup
{
    private sealed class Node { public Node? Zero, One; public GeoRecord? Record; }
    private readonly Node v4 = new(), v6 = new();
    public int Count { get; private set; }
    /// <summary>Expands the effective longest-prefix policy, excluding more-specific exceptions.</summary>
    public IReadOnlyList<string> RestrictedNetworks(IEnumerable<string> countries, IEnumerable<uint> autonomousSystems, int maximumNetworks = 10_000)
    {
        if (maximumNetworks < 1) throw new ArgumentOutOfRangeException(nameof(maximumNetworks));
        var countrySet = countries.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var asnSet = autonomousSystems.Where(a => a != 0).ToHashSet();
        List<string> networks = [];
        bool Restricted(GeoRecord? record) => record is not null && (countrySet.Contains(record.Country) || asnSet.Contains(record.Asn));
        void Walk(Node? node, GeoRecord? inherited, byte[] address, int prefix)
        {
            var effective = node?.Record ?? inherited;
            if (node is null || node.Zero is null && node.One is null)
            {
                if (Restricted(effective))
                {
                    networks.Add(new IPAddress(address) + "/" + prefix);
                    if (networks.Count > maximumNetworks) throw new InvalidDataException("Geographic policy exceeds the native filter limit.");
                }
                return;
            }
            Walk(node.Zero, effective, address, prefix + 1);
            var one = (byte[])address.Clone(); one[prefix / 8] |= (byte)(1 << (7 - prefix % 8));
            Walk(node.One, effective, one, prefix + 1);
        }
        Walk(v4, null, new byte[4], 0); Walk(v6, null, new byte[16], 0);
        return networks;
    }
    public GeoRecord? Lookup(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return null;
        var bytes = ip.GetAddressBytes(); Node? node = bytes.Length == 4 ? v4 : v6;
        GeoRecord? found = node.Record;
        for (var i = 0; i < bytes.Length * 8 && node is not null; i++)
        {
            node = (bytes[i / 8] & (1 << (7 - i % 8))) == 0 ? node.Zero : node.One;
            if (node?.Record is not null) found = node.Record;
        }
        return found;
    }
    public static GeoDatabase Load(TextReader reader)
    {
        var db = new GeoDatabase();
        var header = CsvLine(reader.ReadLine() ?? "").Select(s => s.Trim().TrimStart('\uFEFF').ToLowerInvariant()).ToArray();
        var required = new[] { "network", "country", "country_name", "city", "latitude", "longitude", "asn", "organization" };
        var indices = required.Select(k => Array.IndexOf(header, k)).ToArray();
        if (indices.Any(i => i < 0)) throw new InvalidDataException("CSV columns: network,country,country_name,city,latitude,longitude,asn,organization");
        string? line; var lineNumber = 1;
        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = CsvLine(line);
            if (fields.Count <= indices.Max()) throw new InvalidDataException($"Missing fields on line {lineNumber}.");
            string Field(int i) => fields[indices[i]];
            if (!IpNetwork.TryParse(Field(0), out var net) || !double.TryParse(Field(4), CultureInfo.InvariantCulture, out var lat) ||
                !double.TryParse(Field(5), CultureInfo.InvariantCulture, out var lon) || !double.IsFinite(lat) || !double.IsFinite(lon) || lat is < -90 or > 90 || lon is < -180 or > 180 ||
                !uint.TryParse(Field(6).Replace("AS", "", StringComparison.OrdinalIgnoreCase), out var asn))
                throw new InvalidDataException($"Invalid network or location on line {lineNumber}.");
            var country = Field(1).ToUpperInvariant();
            if (country.Length != 2 || country.Any(c => c is < 'A' or > 'Z')) throw new InvalidDataException($"Invalid country on line {lineNumber}.");
            var record = new GeoRecord(Field(0), country, Field(2), Field(3), lat, lon, asn, Field(7));
            var bytes = net.Address.GetAddressBytes(); var node = bytes.Length == 4 ? db.v4 : db.v6;
            for (var i = 0; i < net.Prefix; i++)
            {
                if ((bytes[i / 8] & (1 << (7 - i % 8))) == 0) node = node.Zero ??= new();
                else node = node.One ??= new();
            }
            node.Record = record; db.Count++;
            if (db.Count > 2_000_000) throw new InvalidDataException("Database exceeds two million networks.");
        }
        if (db.Count == 0) throw new InvalidDataException("The database contains no networks.");
        return db;
    }
    public static List<string> CsvLine(string line)
    {
        List<string> values = []; var field = new StringBuilder(); var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"') { if (quoted && i + 1 < line.Length && line[i + 1] == '"') { field.Append('"'); i++; } else quoted = !quoted; }
            else if (c == ',' && !quoted) { values.Add(field.ToString()); field.Clear(); }
            else field.Append(c);
        }
        if (quoted) throw new InvalidDataException("Unclosed CSV quote.");
        values.Add(field.ToString()); return values;
    }
}

public static class StateStore
{
    public static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    public static AppState Read(string path)
    {
        if (!File.Exists(path)) return new();
        var state = JsonSerializer.Deserialize<AppState>(File.ReadAllText(path), JsonOptions) ?? throw new InvalidDataException("Empty settings.");
        if (state.SchemaVersion != 1) throw new InvalidDataException("Unsupported settings version.");
        if (state.Rules is null || state.Blocklists is null || state.VpnProfiles is null || state.Columns is null || state.BlockedAsns is null || state.BlockedCountries is null || state.AllowedCountries is null ||
            state.DnsServers is null || state.BlockedNames is null || state.DnsServers.Any(s => s?.Stamps is null)) throw new InvalidDataException("Invalid settings structure.");
        if (!Enum.IsDefined(state.Mode) || state.Rules.Any(r => r is null) || state.Blocklists.Any(b => b is null || b.Entries is null || b.Entries.Any(e => e is null)) || state.VpnProfiles.Any(p => p is null || p.Applications is null) || state.Columns.Any(c => c is null || !double.IsFinite(c.Width))) throw new InvalidDataException("Invalid settings values.");
        return Upgrade(state);
    }

    /// <summary>The map opens flat until the user picks a view.</summary>
    public static AppState Upgrade(AppState state)
    {
        if (!state.MapProjectionChosen) state.MapProjection = "Flat";
        return state;
    }
    public static void Write(string path, AppState state)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions)); File.Move(temp, path, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
