using System.Buffers.Binary;

namespace Darkwire.Vpn;

/// <summary>
/// Bounded IPv4/IPv6 reassembly. Any overlap other than an exact duplicate discards the whole datagram
/// (RFC 5722), so overlapping fragments can never rewrite headers policy already inspected. IPv6 headers
/// before the fragment header are dropped; the reassembled packet only feeds this router's parser.
/// </summary>
public sealed class FragmentReassembler
{
    public const int MaximumDatagrams = 64, MaximumFragments = 128, MaximumBufferedBytes = 4 * 1024 * 1024;
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);
    private readonly Dictionary<Key, Datagram> datagrams = [];
    private int buffered;

    public int Pending => datagrams.Count;

    /// <summary>Stores one fragment; returns the whole packet once every byte has arrived.</summary>
    public byte[]? Add(ReadOnlySpan<byte> packet, in IpPacket header, DateTimeOffset now)
    {
        if (!header.IsFragment) throw new ArgumentException("The packet is not a fragment.", nameof(header));
        var key = new Key(header.Source, header.Destination, header.V6 ? (byte)0 : header.Protocol, header.FragmentId);
        var data = packet[header.TransportOffset..header.Length];
        var start = header.FragmentOffset; var end = start + data.Length;
        if (data.IsEmpty || end > (header.V6 ? 0xFFFF : 0xFFFF - 20) || (header.MoreFragments && data.Length % 8 != 0)) { Discard(key); return null; }
        if (!datagrams.TryGetValue(key, out var datagram))
        {
            Expire(now);
            if (datagrams.Count >= MaximumDatagrams) return null;
            datagram = new(now + Lifetime);
            datagrams.Add(key, datagram);
        }
        if (buffered + data.Length > MaximumBufferedBytes || datagram.Parts.Count >= MaximumFragments) { Discard(key); return null; }
        var index = 0;
        for (; index < datagram.Parts.Count && datagram.Parts[index].Offset < start; index++) { }
        foreach (var part in datagram.Parts)
        {
            if (part.Offset >= end || start >= part.Offset + part.Data.Length) continue;
            if (part.Offset == start && part.Data.Length == data.Length) return null;
            Discard(key); return null;
        }
        if (!header.MoreFragments)
        {
            if (datagram.Total >= 0 && datagram.Total != end) { Discard(key); return null; }
            datagram.Total = end;
        }
        if (datagram.Total >= 0 && (header.MoreFragments ? end >= datagram.Total : end > datagram.Total)) { Discard(key); return null; }
        if (datagram.Total >= 0 && datagram.Parts.Count > 0 && datagram.Parts[^1].Offset + datagram.Parts[^1].Data.Length > datagram.Total) { Discard(key); return null; }
        datagram.Parts.Insert(index, new(start, data.ToArray()));
        datagram.Bytes += data.Length; buffered += data.Length;
        if (start == 0)
        {
            datagram.Header = packet[..(header.V6 ? 40 : header.TransportOffset)].ToArray();
            datagram.Protocol = header.Protocol;
        }
        if (datagram.Header is null || datagram.Total < 0) return null;
        var covered = 0;
        foreach (var part in datagram.Parts)
        {
            if (part.Offset != covered) return null;
            covered += part.Data.Length;
        }
        if (covered != datagram.Total) return null;
        Discard(key);
        if (datagram.Header.Length + datagram.Total > (header.V6 ? 40 + 0xFFFF : 0xFFFF)) return null;
        var whole = new byte[datagram.Header.Length + datagram.Total];
        datagram.Header.CopyTo(whole, 0);
        foreach (var part in datagram.Parts) part.Data.CopyTo(whole, datagram.Header.Length + part.Offset);
        if (header.V6)
        {
            BinaryPrimitives.WriteUInt16BigEndian(whole.AsSpan(4), (ushort)datagram.Total);
            whole[6] = datagram.Protocol;
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(whole.AsSpan(2), (ushort)whole.Length);
            BinaryPrimitives.WriteUInt16BigEndian(whole.AsSpan(6), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(whole.AsSpan(6)) & 0x4000));
            Checksum.RefreshIPv4Header(whole);
        }
        return whole;
    }

    public void Expire(DateTimeOffset now)
    {
        foreach (var pair in datagrams.Where(p => p.Value.Expires <= now).ToArray()) Discard(pair.Key);
    }

    private void Discard(Key key)
    {
        if (datagrams.Remove(key, out var datagram)) buffered -= datagram.Bytes;
    }

    private readonly record struct Key(NetAddress Source, NetAddress Destination, byte Protocol, uint Id);
    private readonly record struct Part(int Offset, byte[] Data);
    private sealed class Datagram(DateTimeOffset expires)
    {
        public DateTimeOffset Expires { get; } = expires;
        public List<Part> Parts { get; } = [];
        public byte[]? Header { get; set; }
        public byte Protocol { get; set; }
        public int Total { get; set; } = -1;
        public int Bytes { get; set; }
    }
}
