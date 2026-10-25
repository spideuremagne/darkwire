using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Darkwire.Core;

/// <summary>Country and ASN lookups shared by the desktop and the service, whichever format the data came in.</summary>
public interface IGeoLookup
{
    int Count { get; }
    GeoRecord? Lookup(string address);
    /// <summary>The networks a country or ASN restriction blocks, as CIDRs, within the native filter budget.</summary>
    IReadOnlyList<string> RestrictedNetworks(IEnumerable<string> countries, IEnumerable<uint> autonomousSystems, int maximumNetworks = 10_000);
}

/// <summary>
/// DB-IP Lite country and ASN ranges as sorted arrays: one binary search per lookup and about 20 MB for the whole IPv4 and
/// IPv6 address space. Built from DB-IP's CSV releases at build time, and by the service's weekly update.
/// </summary>
public sealed class GeoIpDatabase : IGeoLookup
{
    private const uint Magic = 0x4F454744; // "DGEO"
    private const int FormatVersion = 1, MaximumRanges = 4_000_000, MaximumAsns = 1_000_000, MaximumText = 512;
    private readonly string[] countries;
    private readonly uint[] countryV4; private readonly byte[] countryV4Code;
    private readonly UInt128[] countryV6; private readonly byte[] countryV6Code;
    private readonly uint[] asnV4Start, asnV4End; private readonly int[] asnV4Index;
    private readonly UInt128[] asnV6Start, asnV6End; private readonly int[] asnV6Index;
    private readonly uint[] asnNumbers; private readonly string[] organizations;
    private readonly string[] countryNames;

    /// <summary>The DB-IP release, as year and month ("2026-10").</summary>
    public string Release { get; }
    public int Count => countryV4.Length + countryV6.Length + asnV4Start.Length + asnV6Start.Length;
    /// <summary>Map position for a country code; records have no coordinates without it, since the country data has none.</summary>
    public Func<string, (double Latitude, double Longitude)?>? Locate { get; set; }
    /// <summary>City data for the app's lookups. A record takes its city and position only where both name the same country.</summary>
    public GeoIpCities? Cities { get; set; }

    private GeoIpDatabase(string release, string[] countries, uint[] countryV4, byte[] countryV4Code, UInt128[] countryV6, byte[] countryV6Code,
        uint[] asnV4Start, uint[] asnV4End, int[] asnV4Index, UInt128[] asnV6Start, UInt128[] asnV6End, int[] asnV6Index, uint[] asnNumbers, string[] organizations)
    {
        Release = release; this.countries = countries;
        this.countryV4 = countryV4; this.countryV4Code = countryV4Code; this.countryV6 = countryV6; this.countryV6Code = countryV6Code;
        this.asnV4Start = asnV4Start; this.asnV4End = asnV4End; this.asnV4Index = asnV4Index;
        this.asnV6Start = asnV6Start; this.asnV6End = asnV6End; this.asnV6Index = asnV6Index;
        this.asnNumbers = asnNumbers; this.organizations = organizations;
        countryNames = countries.Select(CountryName).ToArray();
    }

    public GeoRecord? Lookup(string address) => IPAddress.TryParse(address, out var ip) ? Lookup(ip) : null;
    public GeoRecord? Lookup(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        int code, asn;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var key = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
            code = Floor(countryV4, key) is var c and >= 0 ? countryV4Code[c] : 0;
            asn = Floor(asnV4Start, key) is var a and >= 0 && key <= asnV4End[a] ? asnV4Index[a] : -1;
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var key = BinaryPrimitives.ReadUInt128BigEndian(address.GetAddressBytes());
            code = Floor(countryV6, key) is var c and >= 0 ? countryV6Code[c] : 0;
            asn = Floor(asnV6Start, key) is var a and >= 0 && key <= asnV6End[a] ? asnV6Index[a] : -1;
        }
        else return null;
        if (code == 0 && asn < 0) return null;
        var country = countries[code];
        var place = code == 0 ? null : Cities?.Lookup(address) is { } found && found.Country == country ? found : null;
        var position = place is not null ? (place.Latitude, place.Longitude) : code == 0 ? null : Locate?.Invoke(country);
        return new GeoRecord("", country, countryNames[code], place?.City ?? "", position?.Latitude ?? double.NaN, position?.Longitude ?? double.NaN,
            asn < 0 ? 0 : asnNumbers[asn], asn < 0 ? "" : organizations[asn], place?.Region ?? "");
    }

    public IReadOnlyList<string> RestrictedNetworks(IEnumerable<string> countrySet, IEnumerable<uint> autonomousSystems, int maximumNetworks = 10_000)
    {
        if (maximumNetworks < 1) throw new ArgumentOutOfRangeException(nameof(maximumNetworks));
        var blockedCountries = countrySet.Select(c => c.ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
        var blockedAsns = autonomousSystems.Where(a => a != 0).ToHashSet();
        var codes = Enumerable.Range(0, countries.Length).Where(i => i > 0 && blockedCountries.Contains(countries[i])).Select(i => (byte)i).ToHashSet();
        var asns = Enumerable.Range(0, asnNumbers.Length).Where(i => blockedAsns.Contains(asnNumbers[i])).ToHashSet();
        List<string> networks = [];
        void Emit(IEnumerable<(UInt128 First, UInt128 Last)> ranges, int bits)
        {
            foreach (var (first, last) in AddressRanges.Merge(ranges))
            foreach (var network in AddressRanges.Cidrs(first, last, bits))
            {
                networks.Add(network);
                if (networks.Count > maximumNetworks) throw new InvalidDataException("Geographic policy exceeds the native filter limit.");
            }
        }
        Emit(Ranges(countryV4.Select(v => (UInt128)v).ToArray(), countryV4Code, codes, uint.MaxValue)
            .Concat(Enumerable.Range(0, asnV4Start.Length).Where(i => asns.Contains(asnV4Index[i])).Select(i => ((UInt128)asnV4Start[i], (UInt128)asnV4End[i]))), 32);
        Emit(Ranges(countryV6, countryV6Code, codes, UInt128.MaxValue)
            .Concat(Enumerable.Range(0, asnV6Start.Length).Where(i => asns.Contains(asnV6Index[i])).Select(i => (asnV6Start[i], asnV6End[i]))), 128);
        return networks;
    }

    /// <summary>Country ranges are contiguous, so each one ends where the next begins.</summary>
    private static IEnumerable<(UInt128 First, UInt128 Last)> Ranges(UInt128[] starts, byte[] codes, HashSet<byte> wanted, UInt128 familyEnd)
    {
        for (var i = 0; i < starts.Length; i++)
            if (wanted.Contains(codes[i])) yield return (starts[i], i + 1 < starts.Length ? starts[i + 1] - 1 : familyEnd);
    }

    private static int Floor<T>(T[] starts, T key) where T : IComparable<T>
    {
        var index = Array.BinarySearch(starts, key);
        return index >= 0 ? index : ~index - 1;
    }

    private static string CountryName(string code)
    {
        if (code.Length == 0) return "Unknown";
        try { return new RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return code; }
    }

    /// <summary>
    /// Builds the database from DB-IP's Lite CSVs: "first,last,country" and "first,last,asn,organization", each family sorted
    /// and without overlaps. Gaps in country coverage become unknown, and ZZ (reserved space) is unknown as well.
    /// </summary>
    public static GeoIpDatabase Build(TextReader countryCsv, TextReader asnCsv, string release)
    {
        if (!IsRelease(release)) throw new InvalidDataException("The release must be year and month, such as 2026-10.");
        var countryIndex = new Dictionary<string, byte>(StringComparer.Ordinal) { [""] = 0 };
        List<string> countryList = [""];
        var v4 = new List<(UInt128 First, UInt128 Last, int Value)>(); var v6 = new List<(UInt128 First, UInt128 Last, int Value)>();
        var line = 0;
        foreach (var fields in Rows(countryCsv, 3))
        {
            line++;
            var code = fields[2].Trim().ToUpperInvariant();
            if (code.Length != 2 || code.Any(c => c is < 'A' or > 'Z')) throw new InvalidDataException($"Invalid country on country line {line}.");
            if (code == "ZZ") code = "";
            if (!countryIndex.TryGetValue(code, out var index))
            {
                if (countryList.Count > byte.MaxValue) throw new InvalidDataException("Too many country codes.");
                countryIndex[code] = index = (byte)countryList.Count; countryList.Add(code);
            }
            Add(fields, index, v4, v6, line, "country");
        }
        var asnIndex = new Dictionary<uint, int>(); List<uint> numbers = []; List<string> names = [];
        var a4 = new List<(UInt128 First, UInt128 Last, int Value)>(); var a6 = new List<(UInt128 First, UInt128 Last, int Value)>();
        line = 0;
        foreach (var fields in Rows(asnCsv, 4))
        {
            line++;
            if (!uint.TryParse(fields[2].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number == 0)
                throw new InvalidDataException($"Invalid AS number on ASN line {line}.");
            if (!asnIndex.TryGetValue(number, out var index))
            {
                if (numbers.Count >= MaximumAsns) throw new InvalidDataException("Too many autonomous systems.");
                asnIndex[number] = index = numbers.Count; numbers.Add(number); names.Add(Text(fields[3]));
            }
            Add(fields, index, a4, a6, line, "ASN");
        }
        var countries = countryList.ToArray();
        var (c4, c4Code) = Contiguous(v4, uint.MaxValue); var (c6, c6Code) = Contiguous(v6, UInt128.MaxValue);
        return new(release, countries, c4.Select(v => (uint)v).ToArray(), c4Code, c6, c6Code,
            a4.Select(r => (uint)r.First).ToArray(), a4.Select(r => (uint)r.Last).ToArray(), a4.Select(r => r.Value).ToArray(),
            a6.Select(r => r.First).ToArray(), a6.Select(r => r.Last).ToArray(), a6.Select(r => r.Value).ToArray(), numbers.ToArray(), names.ToArray());
    }

    internal static IEnumerable<List<string>> Rows(TextReader reader, int columns, int maximum = MaximumRanges)
    {
        string? text; var count = 0;
        while ((text = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(text)) continue;
            if (++count > maximum) throw new InvalidDataException("The GeoIP source has too many ranges.");
            var fields = GeoDatabase.CsvLine(text);
            if (fields.Count != columns) throw new InvalidDataException($"Expected {columns} fields on line {count}.");
            yield return fields;
        }
        if (count == 0) throw new InvalidDataException("The GeoIP source is empty.");
    }

    private static void Add(List<string> fields, int value, List<(UInt128, UInt128, int)> v4, List<(UInt128, UInt128, int)> v6, int line, string kind)
    {
        var (ipv4, start, end) = Range(fields, line, kind);
        var list = ipv4 ? v4 : v6;
        if (list.Count > 0 && start <= list[^1].Item2) throw new InvalidDataException($"Unsorted or overlapping range on {kind} line {line}.");
        list.Add((start, end, value));
    }

    /// <summary>A row's first and last address, which must be one family, unscoped, and in order.</summary>
    internal static (bool IPv4, UInt128 First, UInt128 Last) Range(List<string> fields, int line, string kind)
    {
        if (!IPAddress.TryParse(fields[0].Trim(), out var first) || !IPAddress.TryParse(fields[1].Trim(), out var last) || first.AddressFamily != last.AddressFamily ||
            first.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new InvalidDataException($"Invalid range on {kind} line {line}.");
        var ipv4 = first.AddressFamily == AddressFamily.InterNetwork;
        if (!ipv4 && (first.ScopeId != 0 || last.ScopeId != 0)) throw new InvalidDataException($"Scoped address on {kind} line {line}.");
        var start = ipv4 ? BinaryPrimitives.ReadUInt32BigEndian(first.GetAddressBytes()) : BinaryPrimitives.ReadUInt128BigEndian(first.GetAddressBytes());
        var end = ipv4 ? BinaryPrimitives.ReadUInt32BigEndian(last.GetAddressBytes()) : BinaryPrimitives.ReadUInt128BigEndian(last.GetAddressBytes());
        if (end < start) throw new InvalidDataException($"Unsorted or overlapping range on {kind} line {line}.");
        return (ipv4, start, end);
    }

    /// <summary>Starts of a gap-free cover of the family, with unknown filling the gaps; adjacent equal values merge.</summary>
    private static (UInt128[] Starts, byte[] Codes) Contiguous(List<(UInt128 First, UInt128 Last, int Value)> ranges, UInt128 familyEnd)
    {
        List<UInt128> starts = []; List<byte> codes = [];
        void Push(UInt128 start, byte code) { if (codes.Count > 0 && codes[^1] == code) return; starts.Add(start); codes.Add(code); }
        UInt128 next = 0; var complete = false;
        foreach (var (first, last, value) in ranges)
        {
            if (first > next) Push(next, 0);
            Push(first, (byte)value);
            if (last == familyEnd) { complete = true; break; }
            next = last + 1;
        }
        if (!complete) Push(next, 0);
        return (starts.ToArray(), codes.ToArray());
    }

    internal static string Text(string value, string kind = "organization")
    {
        var trimmed = value.Trim();
        if (trimmed.Length > MaximumText || trimmed.Any(char.IsControl)) throw new InvalidDataException($"Invalid {kind} name.");
        return trimmed;
    }

    internal static bool IsRelease(string value) =>
        value.Length == 7 && value[4] == '-' && int.TryParse(value.AsSpan(0, 4), NumberStyles.None, CultureInfo.InvariantCulture, out var year) &&
        int.TryParse(value.AsSpan(5, 2), NumberStyles.None, CultureInfo.InvariantCulture, out var month) && year is >= 2020 and <= 2200 && month is >= 1 and <= 12;

    public void Write(Stream stream)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(Magic); writer.Write(FormatVersion); writer.Write(Release);
        writer.Write(countries.Length); foreach (var country in countries) writer.Write(country);
        WriteArray(writer, countryV4); WriteArray(writer, countryV4Code); WriteArray(writer, countryV6); WriteArray(writer, countryV6Code);
        WriteArray(writer, asnV4Start); WriteArray(writer, asnV4End); WriteArray(writer, asnV4Index);
        WriteArray(writer, asnV6Start); WriteArray(writer, asnV6End); WriteArray(writer, asnV6Index);
        WriteArray(writer, asnNumbers); writer.Write(organizations.Length); foreach (var name in organizations) writer.Write(name);
    }

    internal static void WriteArray<T>(BinaryWriter writer, T[] values) where T : unmanaged
    { writer.Write(values.Length); writer.Write(MemoryMarshal.AsBytes(values.AsSpan())); }

    /// <summary>The release in a database file's header, without reading the rest.</summary>
    public static string ReadRelease(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        if (reader.ReadUInt32() != Magic || reader.ReadInt32() != FormatVersion) throw new InvalidDataException("Not a Darkwire GeoIP database.");
        var release = reader.ReadString();
        return IsRelease(release) ? release : throw new InvalidDataException("Invalid GeoIP release.");
    }

    /// <summary>The newest readable database among the files, by release; a missing or damaged file is skipped.</summary>
    public static GeoIpDatabase? Newest(IEnumerable<string> paths) => Newest(paths, ReadRelease, Read);

    internal static T? Newest<T>(IEnumerable<string> paths, Func<Stream, string> readRelease, Func<Stream, T> read) where T : class
    {
        var candidates = new List<(string Release, string Path)>();
        foreach (var path in paths.Where(File.Exists))
        {
            try { using var stream = File.OpenRead(path); candidates.Add((readRelease(stream), path)); }
            catch (Exception error) when (error is InvalidDataException or IOException) { }
        }
        foreach (var (_, path) in candidates.OrderByDescending(c => c.Release, StringComparer.Ordinal))
        {
            try { using var stream = File.OpenRead(path); return read(stream); }
            catch (Exception error) when (error is InvalidDataException or IOException) { }
        }
        return null;
    }

    /// <summary>Reads and fully validates a database: sorted, non-overlapping ranges and every index in bounds.</summary>
    public static GeoIpDatabase Read(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        if (reader.ReadUInt32() != Magic || reader.ReadInt32() != FormatVersion) throw new InvalidDataException("Not a Darkwire GeoIP database.");
        var release = reader.ReadString();
        if (!IsRelease(release)) throw new InvalidDataException("Invalid GeoIP release.");
        var countries = new string[Length(reader, byte.MaxValue + 1)];
        for (var i = 0; i < countries.Length; i++)
        {
            countries[i] = reader.ReadString();
            if (i == 0 ? countries[i].Length != 0 : countries[i].Length != 2 || countries[i].Any(c => c is < 'A' or > 'Z')) throw new InvalidDataException("Invalid country table.");
        }
        var c4 = ReadArray<uint>(reader, MaximumRanges); var c4Code = ReadArray<byte>(reader, MaximumRanges);
        var c6 = ReadArray<UInt128>(reader, MaximumRanges); var c6Code = ReadArray<byte>(reader, MaximumRanges);
        var a4Start = ReadArray<uint>(reader, MaximumRanges); var a4End = ReadArray<uint>(reader, MaximumRanges); var a4Index = ReadArray<int>(reader, MaximumRanges);
        var a6Start = ReadArray<UInt128>(reader, MaximumRanges); var a6End = ReadArray<UInt128>(reader, MaximumRanges); var a6Index = ReadArray<int>(reader, MaximumRanges);
        var numbers = ReadArray<uint>(reader, MaximumAsns);
        var names = new string[Length(reader, MaximumAsns)];
        for (var i = 0; i < names.Length; i++) names[i] = Text(reader.ReadString());
        if (stream.CanSeek && stream.Position != stream.Length) throw new InvalidDataException("Trailing GeoIP data.");
        if (c4.Length != c4Code.Length || c6.Length != c6Code.Length || a4Start.Length != a4End.Length || a4Start.Length != a4Index.Length ||
            a6Start.Length != a6End.Length || a6Start.Length != a6Index.Length || numbers.Length != names.Length ||
            c4.Length == 0 || c4[0] != 0 || c6.Length == 0 || c6[0] != 0 ||
            !Ascending(c4) || !Ascending(c6) || c4Code.Concat(c6Code).Any(c => c >= countries.Length) ||
            !Disjoint(a4Start, a4End) || !Disjoint(a6Start, a6End) || a4Index.Concat(a6Index).Any(i => i < 0 || i >= numbers.Length) || numbers.Any(n => n == 0))
            throw new InvalidDataException("Inconsistent GeoIP database.");
        return new(release, countries, c4, c4Code, c6, c6Code, a4Start, a4End, a4Index, a6Start, a6End, a6Index, numbers, names);
    }

    internal static int Length(BinaryReader reader, int maximum)
    {
        var length = reader.ReadInt32();
        return length is >= 0 && length <= maximum ? length : throw new InvalidDataException("Invalid GeoIP table length.");
    }

    internal static T[] ReadArray<T>(BinaryReader reader, int maximum) where T : unmanaged
    {
        var values = new T[Length(reader, maximum)];
        reader.BaseStream.ReadExactly(MemoryMarshal.AsBytes(values.AsSpan()));
        return values;
    }

    private static bool Ascending<T>(T[] values) where T : IComparable<T>
    {
        for (var i = 1; i < values.Length; i++) if (values[i - 1].CompareTo(values[i]) >= 0) return false;
        return true;
    }

    private static bool Disjoint<T>(T[] starts, T[] ends) where T : IComparable<T>
    {
        for (var i = 0; i < starts.Length; i++)
            if (starts[i].CompareTo(ends[i]) > 0 || i > 0 && ends[i - 1].CompareTo(starts[i]) >= 0) return false;
        return true;
    }
}
