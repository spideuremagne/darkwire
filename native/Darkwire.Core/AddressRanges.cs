using System.Buffers.Binary;
using System.Net;

namespace Darkwire.Core;

/// <summary>Inclusive address ranges as numbers: merging, exact CIDR covers, and the space blocklists never cover.</summary>
public static class AddressRanges
{
    /// <summary>
    /// Loopback, private, shared, link-local, multicast, broadcast and other special-purpose space (RFC 6890), and Darkwire's
    /// own tunnel network. Publishers' bogon sets include the local network a PC needs, so lists never block this space; rules still can.
    /// </summary>
    public static IReadOnlyList<string> Protected { get; } =
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "224.0.0.0/3", "::/127", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"
    ];
    private static readonly (UInt128 First, UInt128 Last)[] protected4 = Excluded(false), protected6 = Excluded(true);

    /// <summary>The fewest exact CIDRs covering the networks, without protected space; IPv4 first.</summary>
    public static IReadOnlyList<string> Normalize(IEnumerable<IpNetwork> networks)
    {
        List<(UInt128 First, UInt128 Last)> v4 = [], v6 = [];
        foreach (var network in networks)
        {
            var (first, last, bits) = Range(network);
            (bits == 32 ? v4 : v6).Add((first, last));
        }
        return Cover(v4, 32, protected4).Concat(Cover(v6, 128, protected6)).ToArray();
    }

    private static IEnumerable<string> Cover(List<(UInt128 First, UInt128 Last)> ranges, int bits, (UInt128 First, UInt128 Last)[] excluded)
    {
        foreach (var (first, last) in Subtract(Merge(ranges), excluded))
        foreach (var network in Cidrs(first, last, bits))
            yield return network;
    }

    private static (UInt128 First, UInt128 Last)[] Excluded(bool ipv6) => Merge(Protected
        .Select(text => { IpNetwork.TryParse(text, out var network); return network; })
        .Select(Range).Where(r => r.Bits == (ipv6 ? 128 : 32)).Select(r => (r.First, r.Last))).ToArray();

    /// <summary>The range a network covers, whatever host bits its address carries.</summary>
    public static (UInt128 First, UInt128 Last, int Bits) Range(IpNetwork network)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (!network.Address.TryWriteBytes(bytes, out var written) || written is not (4 or 16)) throw new ArgumentException("Unsupported address.", nameof(network));
        var bits = written * 8;
        var value = written == 4 ? BinaryPrimitives.ReadUInt32BigEndian(bytes) : BinaryPrimitives.ReadUInt128BigEndian(bytes);
        var host = bits - network.Prefix;
        var span = host == 0 ? UInt128.Zero : host == 128 ? UInt128.MaxValue : ((UInt128)1 << host) - 1;
        var first = value & ~span;
        return (first, first | span, bits);
    }

    /// <summary>Sorted, disjoint ranges with adjacent and overlapping ones joined.</summary>
    public static IEnumerable<(UInt128 First, UInt128 Last)> Merge(IEnumerable<(UInt128 First, UInt128 Last)> ranges)
    {
        (UInt128 First, UInt128 Last)? open = null;
        foreach (var range in ranges.OrderBy(r => r.First))
        {
            if (open is { } current && (range.First <= current.Last || current.Last != UInt128.MaxValue && range.First == current.Last + 1))
            { open = (current.First, UInt128.Max(current.Last, range.Last)); continue; }
            if (open is { } done) yield return done;
            open = range;
        }
        if (open is { } last) yield return last;
    }

    /// <summary>Whether a network lies wholly inside any of the containers, of either family.</summary>
    public static bool Within(IpNetwork network, IEnumerable<string> containers)
    {
        var (first, last, bits) = Range(network);
        foreach (var text in containers)
        {
            if (!IpNetwork.TryParse(text, out var container)) continue;
            var (from, to, size) = Range(container);
            if (size == bits && from <= first && last <= to) return true;
        }
        return false;
    }

    /// <summary>The exact CIDRs covering the networks without the excluded ones, IPv4 first.</summary>
    public static IReadOnlyList<string> Without(IEnumerable<string> networks, IEnumerable<string> excluded)
    {
        static List<(UInt128 First, UInt128 Last)>[] Split(IEnumerable<string> texts)
        {
            List<(UInt128 First, UInt128 Last)> v4 = [], v6 = [];
            foreach (var text in texts)
            {
                if (!IpNetwork.TryParse(text, out var network)) throw new ArgumentException("Invalid network " + text + ".", nameof(networks));
                var (first, last, bits) = Range(network);
                (bits == 32 ? v4 : v6).Add((first, last));
            }
            return [v4, v6];
        }
        var covered = Split(networks); var removed = Split(excluded);
        return [.. Enumerable.Range(0, 2).SelectMany(family => Subtract(Merge(covered[family]), [.. Merge(removed[family])])
            .SelectMany(r => Cidrs(r.First, r.Last, family == 0 ? 32 : 128)))];
    }

    /// <summary>What remains of sorted, disjoint ranges after removing sorted, disjoint exclusions.</summary>
    private static IEnumerable<(UInt128 First, UInt128 Last)> Subtract(IEnumerable<(UInt128 First, UInt128 Last)> ranges, (UInt128 First, UInt128 Last)[] excluded)
    {
        foreach (var range in ranges)
        {
            var first = range.First; var covered = false;
            foreach (var (from, to) in excluded)
            {
                if (to < first) continue;
                if (from > range.Last) break;
                if (from > first) yield return (first, from - 1);
                if (to >= range.Last) { covered = true; break; }
                first = to + 1;
            }
            if (!covered) yield return (first, range.Last);
        }
    }

    /// <summary>The exact CIDR cover of an inclusive range: largest aligned blocks first, never wider than the range.</summary>
    public static IEnumerable<string> Cidrs(UInt128 first, UInt128 last, int bits)
    {
        while (true)
        {
            var aligned = first == 0 ? bits : Math.Min(bits, (int)UInt128.TrailingZeroCount(first));
            var span = last - first;
            // The largest block that still fits: floor(log2(span + 1)), where span + 1 = 2^128 for the whole IPv6 space.
            var fits = span == UInt128.MaxValue ? 128 : 127 - (int)UInt128.LeadingZeroCount(span + 1);
            var host = Math.Min(aligned, Math.Min(fits, bits));
            yield return Format(first, bits) + "/" + (bits - host);
            if (host == bits) yield break;
            var size = (UInt128)1 << host;
            if (span < size) yield break;
            first += size;
        }
    }

    private static string Format(UInt128 value, int bits)
    {
        if (bits == 32) return new IPAddress(BinaryPrimitives.ReverseEndianness((uint)value)).ToString();
        var bytes = new byte[16]; BinaryPrimitives.WriteUInt128BigEndian(bytes, value); return new IPAddress(bytes).ToString();
    }
}
