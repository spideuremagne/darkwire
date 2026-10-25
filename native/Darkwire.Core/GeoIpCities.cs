using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Darkwire.Core;

/// <summary>Where DB-IP's city data places an address: the city, its state or province, and a map position for that city.</summary>
public sealed record GeoPlace(string Country, string Region, string City, double Latitude, double Longitude);

/// <summary>
/// DB-IP Lite city ranges, for the app's map and connection list; the service enforces with the country data alone. A
/// release's 7.8 million ranges take about 40 MB: neighbouring ranges in one place merge, IPv6 is kept per /64 network, each
/// place keeps the position most of its ranges give, and range starts are varint deltas in blocks of 64, found with one binary
/// search over the blocks' first starts and a short scan. Built from DB-IP's CSV releases at build time and by the service.
/// </summary>
public sealed class GeoIpCities
{
    private const uint Magic = 0x59544344; // "DCTY"
    private const int FormatVersion = 1, Block = 64, MaximumRows = 16_000_000, MaximumPlaces = 2_000_000, MaximumBytes = 512 * 1024 * 1024;
    /// <summary>One family's ranges: the first start of each block, where each block's entries begin, and the entries.</summary>
    private sealed record Ranges(int Count, ulong[] Keys, int[] Offsets, byte[] Data);
    private readonly string[] regionCountries, regionNames;
    private readonly ushort[] placeRegions; private readonly float[] latitudes, longitudes;
    private readonly int[] nameStarts; private readonly byte[] names;
    private readonly Ranges v4, v6;

    /// <summary>The DB-IP release, as year and month ("2026-10").</summary>
    public string Release { get; }
    public int Count => v4.Count + v6.Count;
    public int Places => placeRegions.Length;

    private GeoIpCities(string release, string[] regionCountries, string[] regionNames, ushort[] placeRegions, float[] latitudes, float[] longitudes,
        int[] nameStarts, byte[] names, Ranges v4, Ranges v6)
    {
        Release = release; this.regionCountries = regionCountries; this.regionNames = regionNames; this.placeRegions = placeRegions;
        this.latitudes = latitudes; this.longitudes = longitudes; this.nameStarts = nameStarts; this.names = names; this.v4 = v4; this.v6 = v6;
    }

    public GeoPlace? Lookup(string address) => IPAddress.TryParse(address, out var ip) ? Lookup(ip) : null;
    public GeoPlace? Lookup(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var place = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => Find(v4, BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes())),
            // Kept per /64: an address takes the place of its network's first address.
            AddressFamily.InterNetworkV6 => Find(v6, BinaryPrimitives.ReadUInt64BigEndian(address.GetAddressBytes())),
            _ => 0
        };
        if (place-- == 0) return null;
        var region = placeRegions[place];
        return new(regionCountries[region], regionNames[region], Encoding.UTF8.GetString(names, nameStarts[place], nameStarts[place + 1] - nameStarts[place]),
            latitudes[place], longitudes[place]);
    }

    /// <summary>The place number of the last range starting at or before the key, where 0 means none.</summary>
    private static int Find(Ranges ranges, ulong key)
    {
        var block = Array.BinarySearch(ranges.Keys, key);
        if (block < 0 && (block = ~block - 1) < 0) return 0;
        var position = ranges.Offsets[block];
        var end = block + 1 < ranges.Offsets.Length ? ranges.Offsets[block + 1] : ranges.Data.Length;
        var start = ranges.Keys[block]; var place = Varint(ranges.Data, ref position);
        while (position < end)
        {
            var next = start + Varint(ranges.Data, ref position);
            if (next > key) break;
            start = next; place = Varint(ranges.Data, ref position);
        }
        return (int)place;
    }

    /// <summary>
    /// Builds the city data from DB-IP's City Lite CSV: "first,last,continent,country,region,city,latitude,longitude", each
    /// family sorted and without overlaps. Reserved space (ZZ) and ranges naming neither a region nor a city have no place.
    /// </summary>
    public static GeoIpCities Build(TextReader cityCsv, string release)
    {
        if (!GeoIpDatabase.IsRelease(release)) throw new InvalidDataException("The release must be year and month, such as 2026-10.");
        var placeIndex = new Dictionary<(string Country, string Region, string City), int>();
        List<(string Country, string Region, string City)> placeList = [];
        // Ranges per position of each place, and the line where the position first appeared, which settles ties.
        var positions = new Dictionary<(int Place, float Latitude, float Longitude), (int Ranges, int First)>();
        List<ulong> starts4 = [], starts6 = []; List<int> places4 = [], places6 = [];
        void Add(bool ipv4, UInt128 start, int place)
        {
            if (ipv4) { Append(starts4, places4, (ulong)start, place); return; }
            // Kept per /64: a network takes the place of the range holding its first address, so a range starting inside a
            // /64 begins at the next one, and one starting inside the last /64 holds no network's first address.
            var network = (ulong)(start >> 64); var inside = (ulong)start != 0;
            if (!inside || network != ulong.MaxValue) Append(starts6, places6, inside ? network + 1 : network, place);
        }
        UInt128? last4 = null, last6 = null; var line = 0;
        foreach (var fields in GeoIpDatabase.Rows(cityCsv, 8, MaximumRows))
        {
            line++;
            var (ipv4, first, last) = GeoIpDatabase.Range(fields, line, "city");
            var previous = ipv4 ? last4 : last6;
            if (first <= previous) throw new InvalidDataException($"Unsorted or overlapping range on city line {line}.");
            // Gaps in coverage have no place.
            if (previous is { } end && first > end + 1) Add(ipv4, end + 1, 0);
            if (ipv4) last4 = last; else last6 = last;
            var country = fields[3].Trim().ToUpperInvariant();
            if (country.Length != 2 || country.Any(c => c is < 'A' or > 'Z')) throw new InvalidDataException($"Invalid country on city line {line}.");
            var region = GeoIpDatabase.Text(fields[4], "region"); var city = GeoIpDatabase.Text(fields[5], "city");
            if (!double.TryParse(fields[6].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var latitude) ||
                !double.TryParse(fields[7].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var longitude) ||
                !double.IsFinite(latitude) || !double.IsFinite(longitude) || latitude is < -90 or > 90 || longitude is < -180 or > 180)
                throw new InvalidDataException($"Invalid position on city line {line}.");
            var place = 0;
            if (country != "ZZ" && (region.Length > 0 || city.Length > 0))
            {
                if (!placeIndex.TryGetValue((country, region, city), out place))
                {
                    if (placeList.Count == MaximumPlaces) throw new InvalidDataException("The city source names too many places.");
                    placeIndex[(country, region, city)] = place = placeList.Count + 1; placeList.Add((country, region, city));
                }
                var position = (place, (float)latitude, (float)longitude);
                positions[position] = positions.TryGetValue(position, out var seen) ? (seen.Ranges + 1, seen.First) : (1, line);
            }
            Add(ipv4, first, place);
        }
        if (last4 < uint.MaxValue) Add(true, last4.Value + 1, 0);
        if (last6 < UInt128.MaxValue) Add(false, last6.Value + 1, 0);

        // The places ranges use, numbered by use so the common ones encode in one or two bytes; 0 stays "no place".
        var uses = new int[placeList.Count + 1];
        foreach (var place in places4) uses[place]++;
        foreach (var place in places6) uses[place]++;
        var order = Enumerable.Range(1, placeList.Count).Where(p => uses[p] > 0).OrderByDescending(p => uses[p]).ThenBy(p => p).ToArray();
        var number = new int[placeList.Count + 1];
        for (var i = 0; i < order.Length; i++) number[order[i]] = i + 1;
        var best = new (float Latitude, float Longitude, int Ranges, int First)[placeList.Count + 1];
        foreach (var ((place, latitude, longitude), (ranges, firstLine)) in positions)
            if (ranges > best[place].Ranges || ranges == best[place].Ranges && firstLine < best[place].First) best[place] = (latitude, longitude, ranges, firstLine);

        var regionIndex = new Dictionary<(string Country, string Region), ushort>(); List<string> regionCountries = [], regionNames = [];
        var placeRegions = new ushort[order.Length]; var latitudes = new float[order.Length]; var longitudes = new float[order.Length];
        var nameStarts = new int[order.Length + 1]; var names = new MemoryStream();
        for (var i = 0; i < order.Length; i++)
        {
            var (country, region, city) = placeList[order[i] - 1];
            if (!regionIndex.TryGetValue((country, region), out var index))
            {
                if (regionCountries.Count > ushort.MaxValue) throw new InvalidDataException("The city source names too many regions.");
                regionIndex[(country, region)] = index = (ushort)regionCountries.Count; regionCountries.Add(country); regionNames.Add(region);
            }
            placeRegions[i] = index; (latitudes[i], longitudes[i]) = (best[order[i]].Latitude, best[order[i]].Longitude);
            names.Write(Encoding.UTF8.GetBytes(city)); nameStarts[i + 1] = (int)names.Length;
        }
        return new(release, [.. regionCountries], [.. regionNames], placeRegions, latitudes, longitudes, nameStarts, names.ToArray(),
            Encode(starts4, places4, number), Encode(starts6, places6, number));
    }

    /// <summary>Adds a range start, merging it into the range before when both have the same place.</summary>
    private static void Append(List<ulong> starts, List<int> places, ulong start, int place)
    {
        // Only IPv6 kept per /64 repeats a start: the later range holds the network's first address.
        if (starts.Count > 0 && starts[^1] == start) { starts.RemoveAt(starts.Count - 1); places.RemoveAt(places.Count - 1); }
        if (places.Count > 0 && places[^1] == place) return;
        starts.Add(start); places.Add(place);
    }

    private static Ranges Encode(List<ulong> starts, List<int> places, int[] number)
    {
        var keys = new ulong[(starts.Count + Block - 1) / Block]; var offsets = new int[keys.Length];
        var data = new List<byte>(starts.Count * 4);
        for (var i = 0; i < starts.Count; i++)
        {
            if (i % Block == 0) { keys[i / Block] = starts[i]; offsets[i / Block] = data.Count; }
            else WriteVarint(data, starts[i] - starts[i - 1]);
            WriteVarint(data, (ulong)number[places[i]]);
        }
        return new(starts.Count, keys, offsets, [.. data]);
    }

    private static void WriteVarint(List<byte> data, ulong value)
    {
        for (; value >= 0x80; value >>= 7) data.Add((byte)(value | 0x80));
        data.Add((byte)value);
    }

    private static ulong Varint(byte[] data, ref int position)
    {
        ulong value = 0;
        for (var shift = 0; ; shift += 7)
        {
            var next = data[position++];
            value |= (ulong)(next & 0x7F) << shift;
            if (next < 0x80) return value;
        }
    }

    public void Write(Stream stream)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(Magic); writer.Write(FormatVersion); writer.Write(Release);
        writer.Write(regionCountries.Length);
        for (var i = 0; i < regionCountries.Length; i++) { writer.Write(regionCountries[i]); writer.Write(regionNames[i]); }
        GeoIpDatabase.WriteArray(writer, placeRegions); GeoIpDatabase.WriteArray(writer, latitudes); GeoIpDatabase.WriteArray(writer, longitudes);
        GeoIpDatabase.WriteArray(writer, nameStarts); GeoIpDatabase.WriteArray(writer, names);
        foreach (var ranges in new[] { v4, v6 })
        {
            writer.Write(ranges.Count);
            GeoIpDatabase.WriteArray(writer, ranges.Keys); GeoIpDatabase.WriteArray(writer, ranges.Offsets); GeoIpDatabase.WriteArray(writer, ranges.Data);
        }
    }

    /// <summary>The release in a city data file's header, without reading the rest.</summary>
    public static string ReadRelease(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        return Header(reader);
    }

    /// <summary>The newest readable city data among the files, by release; a missing or damaged file is skipped.</summary>
    public static GeoIpCities? Newest(IEnumerable<string> paths) => GeoIpDatabase.Newest(paths, ReadRelease, Read);

    private static string Header(BinaryReader reader)
    {
        if (reader.ReadUInt32() != Magic || reader.ReadInt32() != FormatVersion) throw new InvalidDataException("Not a Darkwire city database.");
        var release = reader.ReadString();
        return GeoIpDatabase.IsRelease(release) ? release : throw new InvalidDataException("Invalid city data release.");
    }

    /// <summary>Reads and fully validates city data: every name, position and block decoded once, every index in bounds.</summary>
    public static GeoIpCities Read(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var release = Header(reader);
        var regionCountries = new string[GeoIpDatabase.Length(reader, ushort.MaxValue + 1)]; var regionNames = new string[regionCountries.Length];
        for (var i = 0; i < regionCountries.Length; i++)
        {
            regionCountries[i] = reader.ReadString(); regionNames[i] = GeoIpDatabase.Text(reader.ReadString(), "region");
            if (regionCountries[i].Length != 2 || regionCountries[i].Any(c => c is < 'A' or > 'Z')) throw new InvalidDataException("Invalid city region table.");
        }
        var placeRegions = GeoIpDatabase.ReadArray<ushort>(reader, MaximumPlaces);
        var latitudes = GeoIpDatabase.ReadArray<float>(reader, MaximumPlaces); var longitudes = GeoIpDatabase.ReadArray<float>(reader, MaximumPlaces);
        var nameStarts = GeoIpDatabase.ReadArray<int>(reader, MaximumPlaces + 1); var names = GeoIpDatabase.ReadArray<byte>(reader, MaximumBytes);
        var v4 = ReadRanges(reader); var v6 = ReadRanges(reader);
        if (stream.CanSeek && stream.Position != stream.Length) throw new InvalidDataException("Trailing city data.");
        var places = placeRegions.Length;
        if (latitudes.Length != places || longitudes.Length != places || nameStarts.Length != places + 1 || nameStarts[0] != 0 || nameStarts[^1] != names.Length ||
            placeRegions.Any(r => r >= regionCountries.Length) || latitudes.Any(l => !float.IsFinite(l) || l is < -90 or > 90) ||
            longitudes.Any(l => !float.IsFinite(l) || l is < -180 or > 180))
            throw new InvalidDataException("Inconsistent city data.");
        for (var i = 0; i < places; i++)
        {
            if (nameStarts[i + 1] < nameStarts[i]) throw new InvalidDataException("Inconsistent city data.");
            GeoIpDatabase.Text(Encoding.UTF8.GetString(names, nameStarts[i], nameStarts[i + 1] - nameStarts[i]), "city");
        }
        Validate(v4, uint.MaxValue, places); Validate(v6, ulong.MaxValue, places);
        return new(release, regionCountries, regionNames, placeRegions, latitudes, longitudes, nameStarts, names, v4, v6);
    }

    private static Ranges ReadRanges(BinaryReader reader) => new(GeoIpDatabase.Length(reader, MaximumRows),
        GeoIpDatabase.ReadArray<ulong>(reader, MaximumRows), GeoIpDatabase.ReadArray<int>(reader, MaximumRows), GeoIpDatabase.ReadArray<byte>(reader, MaximumBytes));

    /// <summary>Whole blocks but the last, each ending where the next begins; starts ascending within the family; places in range.</summary>
    private static void Validate(Ranges ranges, ulong familyEnd, int places)
    {
        var blocks = (ranges.Count + Block - 1) / Block;
        if (ranges.Keys.Length != blocks || ranges.Offsets.Length != blocks || blocks == 0 && ranges.Data.Length != 0) throw new InvalidDataException("Inconsistent city data.");
        ulong? previous = null;
        for (var block = 0; block < blocks; block++)
        {
            var position = ranges.Offsets[block]; var end = block + 1 < blocks ? ranges.Offsets[block + 1] : ranges.Data.Length;
            var start = ranges.Keys[block];
            if (position < 0 || position >= end || end > ranges.Data.Length || start > familyEnd || previous >= start) throw new InvalidDataException("Inconsistent city data.");
            for (var entry = 0; entry < Math.Min(Block, ranges.Count - block * Block); entry++)
            {
                if (entry > 0)
                {
                    var delta = CheckedVarint(ranges.Data, ref position, end);
                    if (delta == 0 || delta > familyEnd - start) throw new InvalidDataException("Inconsistent city data.");
                    start += delta;
                }
                if (CheckedVarint(ranges.Data, ref position, end) > (ulong)places) throw new InvalidDataException("Inconsistent city data.");
            }
            if (position != end) throw new InvalidDataException("Inconsistent city data.");
            previous = start;
        }
    }

    private static ulong CheckedVarint(byte[] data, ref int position, int end)
    {
        ulong value = 0;
        for (var shift = 0; shift < 64; shift += 7)
        {
            if (position >= end) break;
            var next = data[position++];
            if (shift == 63 && next > 1) break;
            value |= (ulong)(next & 0x7F) << shift;
            if (next < 0x80) return value;
        }
        throw new InvalidDataException("Inconsistent city data.");
    }
}
