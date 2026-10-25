using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Darkwire.Vpn;

/// <summary>An IPv4 or IPv6 address held by value; IPv4 occupies the low 32 bits.</summary>
public readonly record struct NetAddress(UInt128 Value, bool V6)
{
    public int Length => V6 ? 16 : 4;

    public static NetAddress Read(ReadOnlySpan<byte> bytes) => bytes.Length switch
    {
        4 => new(BinaryPrimitives.ReadUInt32BigEndian(bytes), false),
        16 => new(BinaryPrimitives.ReadUInt128BigEndian(bytes), true),
        _ => throw new ArgumentException("An IP address is 4 or 16 bytes.", nameof(bytes))
    };

    public static NetAddress Parse(string text) => From(IPAddress.Parse(text));

    public static NetAddress From(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0) throw new ArgumentException("A scoped IPv6 address cannot be routed.", nameof(address));
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written)) throw new ArgumentException("Unsupported address family.", nameof(address));
        return Read(bytes[..written]);
    }

    public void Write(Span<byte> destination)
    {
        if (V6) BinaryPrimitives.WriteUInt128BigEndian(destination, Value);
        else BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)Value);
    }

    public IPAddress ToIPAddress()
    {
        Span<byte> bytes = stackalloc byte[16];
        Write(bytes);
        return new IPAddress(bytes[..Length]);
    }

    public bool Within(NetAddress network, int prefix)
    {
        var bits = V6 ? 128 : 32;
        if (V6 != network.V6) return false;
        if (prefix <= 0) return true;
        return prefix >= bits ? Value == network.Value : (Value ^ network.Value) >> (bits - prefix) == UInt128.Zero;
    }

    /// <summary>Unicast outside loopback, multicast, broadcast, unspecified, IPv6 link-local and IPv4-compatible or mapped space.</summary>
    public bool IsRoutableUnicast
    {
        get
        {
            if (!V6) { var first = (uint)Value >> 24; return first is not (0 or 127) && first < 224; }
            var high = (ulong)(Value >> 64); var low = (ulong)Value;
            if (high == 0 && (low >> 32 == 0 || low >> 32 == 0xFFFF)) return false;
            return high >> 56 != 0xFF && high >> 54 != 0x3FA;
        }
    }

    public override string ToString() => ToIPAddress().ToString();
}

public readonly record struct NetEndpoint(NetAddress Address, ushort Port)
{
    public static NetEndpoint From(IPEndPoint endpoint) => new(NetAddress.From(endpoint.Address), checked((ushort)endpoint.Port));
    public IPEndPoint ToIPEndPoint() => new(Address.ToIPAddress(), Port);
    public override string ToString() => Address.V6 ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

/// <summary>An IP network: an address and a prefix length of its family. Host bits are ignored.</summary>
public readonly record struct NetPrefix(NetAddress Network, int Length)
{
    public bool Contains(NetAddress address) => address.Within(Network, Length);

    public static NetPrefix Parse(string text)
    {
        var parts = text.Split('/');
        var address = NetAddress.Parse(parts[0]);
        var bits = address.V6 ? 128 : 32;
        if (parts.Length > 2 || !int.TryParse(parts.Length == 2 ? parts[1] : bits.ToString(System.Globalization.CultureInfo.InvariantCulture),
            System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var length) || length > bits)
            throw new FormatException("Invalid network prefix.");
        return new(address, length);
    }

    public override string ToString() => Network + "/" + Length;
}

/// <summary>
/// Header fields of one IP packet. Parsing follows only validated lengths and rejects source routes, jumbograms,
/// misplaced Hop-by-Hop options and long extension chains. A fragment stops at its fragment header: the upper
/// layer is parsed after reassembly. ICMP fields use the first 8 bytes; echo identifiers ride in IcmpIdentifier.
/// </summary>
public readonly struct IpPacket
{
    public const byte Fin = 0x01, Syn = 0x02, Rst = 0x04, Psh = 0x08, Ack = 0x10;
    public int Length { get; init; }
    public int TransportOffset { get; init; }
    public byte Protocol { get; init; }
    public NetAddress Source { get; init; }
    public NetAddress Destination { get; init; }
    public bool IsFragment { get; init; }
    public int FragmentOffset { get; init; }
    public bool MoreFragments { get; init; }
    public uint FragmentId { get; init; }
    public ushort SourcePort { get; init; }
    public ushort DestinationPort { get; init; }
    public byte TcpFlags { get; init; }
    public uint Sequence { get; init; }
    public uint Acknowledgment { get; init; }
    public byte IcmpType { get; init; }
    public byte IcmpCode { get; init; }
    public ushort IcmpIdentifier { get; init; }
    public ushort IcmpSequence { get; init; }
    public int PayloadOffset { get; init; }
    public int PayloadLength { get; init; }
    public bool V6 => Source.V6;

    public static bool TryParse(ReadOnlySpan<byte> packet, out IpPacket result)
    {
        result = default;
        if (packet.IsEmpty) return false;
        var v6 = packet[0] >> 4 == 6;
        int length, offset, fragmentOffset = 0;
        bool more = false, fragment = false;
        uint id = 0;
        byte protocol;
        NetAddress source, destination;
        if (packet[0] >> 4 == 4)
        {
            if (packet.Length < 20) return false;
            offset = (packet[0] & 0x0F) * 4;
            length = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            if (offset < 20 || length < offset || length > packet.Length) return false;
            var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
            if ((flags & 0x8000) != 0) return false;
            more = (flags & 0x2000) != 0; fragmentOffset = (flags & 0x1FFF) * 8; fragment = more || fragmentOffset != 0;
            id = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            protocol = packet[9];
            source = NetAddress.Read(packet.Slice(12, 4)); destination = NetAddress.Read(packet.Slice(16, 4));
        }
        else if (v6)
        {
            if (packet.Length < 40) return false;
            length = 40 + BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            // A zero payload length announces a jumbogram; nothing this router forwards is one.
            if (length == 40 || length > packet.Length) return false;
            protocol = packet[6]; offset = 40;
            source = NetAddress.Read(packet.Slice(8, 16)); destination = NetAddress.Read(packet.Slice(24, 16));
            var fragmentHeader = false;
            for (var headers = 0; !fragment && protocol is 0 or 43 or 44 or 60 or 135 or 139 or 140; headers++)
            {
                if (headers == 8 || offset + 8 > length) return false;
                var next = packet[offset];
                switch (protocol)
                {
                    case 0 when offset != 40: return false;
                    // Segments left: the real destination sits in the routing header, not the address policy sees.
                    case 43 when packet[offset + 3] != 0: return false;
                    case 44:
                        if (fragmentHeader) return false;
                        fragmentHeader = true;
                        var field = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]);
                        fragmentOffset = field & 0xFFF8; more = (field & 1) != 0; fragment = more || fragmentOffset != 0;
                        id = BinaryPrimitives.ReadUInt32BigEndian(packet[(offset + 4)..]);
                        protocol = next; offset += 8;
                        continue;
                }
                protocol = next; offset += (packet[offset + 1] + 1) * 8;
                if (offset > length) return false;
            }
        }
        else return false;

        int payloadOffset = offset, payloadLength = length - offset;
        ushort sourcePort = 0, destinationPort = 0, identifier = 0, sequenceNumber = 0;
        byte tcpFlags = 0, icmpType = 0, icmpCode = 0;
        uint sequence = 0, acknowledgment = 0;
        if (!fragment)
        {
            var transport = packet[offset..length];
            switch (protocol)
            {
                case 6:
                    if (transport.Length < 20) return false;
                    var header = (transport[12] >> 4) * 4;
                    if (header < 20 || header > transport.Length) return false;
                    sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport[2..]);
                    sequence = BinaryPrimitives.ReadUInt32BigEndian(transport[4..]); acknowledgment = BinaryPrimitives.ReadUInt32BigEndian(transport[8..]);
                    tcpFlags = transport[13]; payloadOffset = offset + header; payloadLength = transport.Length - header;
                    break;
                case 17:
                    if (transport.Length < 8) return false;
                    var datagram = BinaryPrimitives.ReadUInt16BigEndian(transport[4..]);
                    if (datagram < 8 || datagram > transport.Length) return false;
                    sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport[2..]);
                    payloadOffset = offset + 8; payloadLength = datagram - 8;
                    break;
                case 1 when !v6:
                case 58 when v6:
                    if (transport.Length < 8) return false;
                    icmpType = transport[0]; icmpCode = transport[1];
                    identifier = BinaryPrimitives.ReadUInt16BigEndian(transport[4..]); sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(transport[6..]);
                    payloadOffset = offset + 8; payloadLength = transport.Length - 8;
                    break;
            }
        }
        result = new IpPacket
        {
            Length = length, TransportOffset = offset, Protocol = protocol, Source = source, Destination = destination,
            IsFragment = fragment, FragmentOffset = fragmentOffset, MoreFragments = more, FragmentId = id,
            SourcePort = sourcePort, DestinationPort = destinationPort, TcpFlags = tcpFlags, Sequence = sequence, Acknowledgment = acknowledgment,
            IcmpType = icmpType, IcmpCode = icmpCode, IcmpIdentifier = identifier, IcmpSequence = sequenceNumber,
            PayloadOffset = payloadOffset, PayloadLength = payloadLength
        };
        return true;
    }
}

/// <summary>RFC 1071 Internet checksum, with RFC 1624 incremental updates for address and port rewrites.</summary>
public static class Checksum
{
    /// <summary>Adds big-endian 16-bit words to a running sum. Only the last chunk of a message may have odd length.</summary>
    public static ulong Add(ulong sum, ReadOnlySpan<byte> data)
    {
        var i = 0;
        // A 32-bit word w = hi * 2^16 + lo is congruent to hi + lo modulo 2^16 - 1, so folding yields the 16-bit sum.
        for (; i + 4 <= data.Length; i += 4) sum += BinaryPrimitives.ReadUInt32BigEndian(data[i..]);
        if (i + 2 <= data.Length) { sum += BinaryPrimitives.ReadUInt16BigEndian(data[i..]); i += 2; }
        if (i < data.Length) sum += (ulong)data[i] << 8;
        return sum;
    }

    /// <summary>Folds carries and complements; a message summed with its own checksum folds to zero.</summary>
    public static ushort Fold(ulong sum)
    {
        while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static ulong Sum(NetAddress address)
    {
        if (!address.V6) { var value = (uint)address.Value; return (value >> 16) + (value & 0xFFFF); }
        return Words((ulong)(address.Value >> 64)) + Words((ulong)address.Value);
        static ulong Words(ulong value) => (value >> 48) + ((value >> 32) & 0xFFFF) + ((value >> 16) & 0xFFFF) + (value & 0xFFFF);
    }

    /// <summary>TCP, UDP and ICMPv6 pseudo-header. A 32-bit IPv6 length folds the same way as its two words.</summary>
    public static ulong Pseudo(NetAddress source, NetAddress destination, byte protocol, int length) =>
        Sum(source) + Sum(destination) + protocol + (ulong)length;

    public static ushort Transport(NetAddress source, NetAddress destination, byte protocol, ReadOnlySpan<byte> segment) =>
        Fold(Add(Pseudo(source, destination, protocol, segment.Length), segment));

    /// <summary>RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'), for any number of replaced words.</summary>
    public static ushort Adjust(ushort checksum, ulong removed, int removedWords, ulong added) =>
        Fold((ushort)~checksum + (ulong)removedWords * 0xFFFF - removed + added);

    public static void RefreshIPv4Header(Span<byte> packet)
    {
        var header = packet[..((packet[0] & 0x0F) * 4)];
        header[10] = 0; header[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], Fold(Add(0, header)));
    }
}

public enum UnreachableCode : byte { Host, Port, Prohibited }

/// <summary>Builds and rewrites packets the router writes back to the host stack.</summary>
public static class PacketBuilder
{
    public const byte HopLimit = 64;

    /// <summary>Rewrites both endpoints of an unfragmented TCP or UDP packet in place, keeping every checksum valid.</summary>
    public static void Rewrite(Span<byte> packet, in IpPacket header, NetEndpoint source, NetEndpoint destination)
    {
        if (header.IsFragment || header.Protocol is not (6 or 17) || source.Address.V6 != header.V6 || destination.Address.V6 != header.V6)
            throw new InvalidOperationException("Only unfragmented TCP and UDP packets keep their family through translation.");
        var transport = packet[header.TransportOffset..];
        var at = header.Protocol == 6 ? 16 : 6;
        var checksum = BinaryPrimitives.ReadUInt16BigEndian(transport[at..]);
        // IPv4 UDP may omit its checksum; IPv6 never may.
        if (header.Protocol == 6 || header.V6 || checksum != 0)
        {
            var removed = Checksum.Sum(header.Source) + Checksum.Sum(header.Destination) + header.SourcePort + header.DestinationPort;
            var added = Checksum.Sum(source.Address) + Checksum.Sum(destination.Address) + source.Port + destination.Port;
            checksum = Checksum.Adjust(checksum, removed, header.V6 ? 18 : 6, added);
            if (header.Protocol == 17 && checksum == 0) checksum = 0xFFFF;
            BinaryPrimitives.WriteUInt16BigEndian(transport[at..], checksum);
        }
        BinaryPrimitives.WriteUInt16BigEndian(transport, source.Port);
        BinaryPrimitives.WriteUInt16BigEndian(transport[2..], destination.Port);
        if (header.V6) { source.Address.Write(packet[8..]); destination.Address.Write(packet[24..]); return; }
        source.Address.Write(packet[12..]); destination.Address.Write(packet[16..]);
        Checksum.RefreshIPv4Header(packet);
    }

    public static byte[] Tcp(NetEndpoint source, NetEndpoint destination, uint sequence, uint acknowledgment, byte flags, ushort window,
        ReadOnlySpan<byte> options, ReadOnlySpan<byte> payload, ushort identification = 0)
    {
        if (options.Length % 4 != 0 || options.Length > 40) throw new ArgumentException("TCP options occupy whole words, at most 40 bytes.", nameof(options));
        var header = 20 + options.Length;
        var packet = Allocate(source.Address, destination.Address, 6, header + payload.Length, identification, out var at);
        var tcp = packet.AsSpan(at);
        BinaryPrimitives.WriteUInt16BigEndian(tcp, source.Port); BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], destination.Port);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], sequence); BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], acknowledgment);
        tcp[12] = (byte)(header / 4 << 4); tcp[13] = flags; BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], window);
        options.CopyTo(tcp[20..]); payload.CopyTo(tcp[header..]);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[16..], Checksum.Transport(source.Address, destination.Address, 6, tcp));
        return packet;
    }

    public static byte[] Udp(NetEndpoint source, NetEndpoint destination, ReadOnlySpan<byte> payload, ushort identification = 0)
    {
        var packet = Allocate(source.Address, destination.Address, 17, 8 + payload.Length, identification, out var at);
        var udp = packet.AsSpan(at);
        BinaryPrimitives.WriteUInt16BigEndian(udp, source.Port); BinaryPrimitives.WriteUInt16BigEndian(udp[2..], destination.Port);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], (ushort)(8 + payload.Length));
        payload.CopyTo(udp[8..]);
        var checksum = Checksum.Transport(source.Address, destination.Address, 17, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp[6..], checksum == 0 ? (ushort)0xFFFF : checksum);
        return packet;
    }

    public static byte[] Echo(NetAddress source, NetAddress destination, bool reply, ushort identifier, ushort sequence, ReadOnlySpan<byte> data, ushort identification = 0)
    {
        var v6 = source.V6;
        var packet = Allocate(source, destination, (byte)(v6 ? 58 : 1), 8 + data.Length, identification, out var at);
        var icmp = packet.AsSpan(at);
        icmp[0] = (byte)(v6 ? (reply ? 129 : 128) : (reply ? 0 : 8));
        BinaryPrimitives.WriteUInt16BigEndian(icmp[4..], identifier); BinaryPrimitives.WriteUInt16BigEndian(icmp[6..], sequence);
        data.CopyTo(icmp[8..]);
        BinaryPrimitives.WriteUInt16BigEndian(icmp[2..], v6 ? Checksum.Transport(source, destination, 58, icmp) : Checksum.Fold(Checksum.Add(0, icmp)));
        return packet;
    }

    /// <summary>RFC 9293 3.10.7.1 reset for a segment that reached no connection; null for a reset, which is never answered.</summary>
    public static byte[]? Reset(in IpPacket segment)
    {
        if (segment.Protocol != 6 || segment.IsFragment || (segment.TcpFlags & IpPacket.Rst) != 0) return null;
        var source = new NetEndpoint(segment.Destination, segment.DestinationPort);
        var destination = new NetEndpoint(segment.Source, segment.SourcePort);
        if ((segment.TcpFlags & IpPacket.Ack) != 0) return Tcp(source, destination, segment.Acknowledgment, 0, IpPacket.Rst, 0, [], []);
        var length = (uint)segment.PayloadLength + ((segment.TcpFlags & IpPacket.Syn) != 0 ? 1u : 0) + ((segment.TcpFlags & IpPacket.Fin) != 0 ? 1u : 0);
        return Tcp(source, destination, 0, unchecked(segment.Sequence + length), IpPacket.Rst | IpPacket.Ack, 0, [], []);
    }

    /// <summary>ICMP destination unreachable quoting as much of the original as RFC 1812 (576) or RFC 4443 (1280) allow.</summary>
    public static byte[] Unreachable(NetAddress source, ReadOnlySpan<byte> original, in IpPacket header, UnreachableCode code)
    {
        var v6 = header.V6;
        if (source.V6 != v6) throw new ArgumentException("ICMP errors keep the family of the packet they quote.", nameof(source));
        var quoted = original[..Math.Min(header.Length, v6 ? 1232 : 548)];
        var packet = Allocate(source, header.Source, (byte)(v6 ? 58 : 1), 8 + quoted.Length, 0, out var at);
        var icmp = packet.AsSpan(at);
        icmp[0] = (byte)(v6 ? 1 : 3);
        icmp[1] = (byte)(code switch { UnreachableCode.Host => v6 ? 3 : 1, UnreachableCode.Port => v6 ? 4 : 3, _ => v6 ? 1 : 13 });
        quoted.CopyTo(icmp[8..]);
        BinaryPrimitives.WriteUInt16BigEndian(icmp[2..], v6 ? Checksum.Transport(source, header.Source, 58, icmp) : Checksum.Fold(Checksum.Add(0, icmp)));
        return packet;
    }

    /// <summary>Splits a packet this class built (no IPv6 extension headers) into fragments that fit the MTU.</summary>
    public static List<byte[]> Fragment(ReadOnlySpan<byte> packet, int mtu, uint identification)
    {
        if (!IpPacket.TryParse(packet, out var header) || header.IsFragment || (header.V6 && header.TransportOffset != 40))
            throw new ArgumentException("Only whole packets without extension headers can be fragmented.", nameof(packet));
        var unfragmentable = header.V6 ? 48 : header.TransportOffset;
        var chunk = (mtu - unfragmentable) & ~7;
        if (chunk < 8) throw new ArgumentOutOfRangeException(nameof(mtu));
        var payload = packet[header.TransportOffset..header.Length];
        List<byte[]> fragments = [];
        for (var offset = 0; offset < payload.Length; offset += chunk)
        {
            var size = Math.Min(chunk, payload.Length - offset);
            var more = offset + size < payload.Length;
            var fragment = new byte[unfragmentable + size];
            payload.Slice(offset, size).CopyTo(fragment.AsSpan(unfragmentable));
            if (header.V6)
            {
                packet[..40].CopyTo(fragment);
                fragment[6] = 44;
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(4), (ushort)(8 + size));
                fragment[40] = header.Protocol;
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(42), (ushort)(offset | (more ? 1 : 0)));
                BinaryPrimitives.WriteUInt32BigEndian(fragment.AsSpan(44), identification);
            }
            else
            {
                packet[..unfragmentable].CopyTo(fragment);
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(2), (ushort)fragment.Length);
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(6), (ushort)((more ? 0x2000 : 0) | offset / 8));
                Checksum.RefreshIPv4Header(fragment);
            }
            fragments.Add(fragment);
        }
        return fragments;
    }

    private static byte[] Allocate(NetAddress source, NetAddress destination, byte protocol, int length, ushort identification, out int ip)
    {
        if (source.V6 != destination.V6) throw new ArgumentException("Both endpoints must share an address family.");
        ip = source.V6 ? 40 : 20;
        if (length > 0xFFFF - (source.V6 ? 0 : ip)) throw new ArgumentOutOfRangeException(nameof(length), "The packet exceeds the IP length field.");
        var packet = new byte[ip + length];
        if (source.V6)
        {
            packet[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)length);
            packet[6] = protocol; packet[7] = HopLimit;
            source.Write(packet.AsSpan(8)); destination.Write(packet.AsSpan(24));
        }
        else
        {
            packet[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), identification);
            packet[8] = HopLimit; packet[9] = protocol;
            source.Write(packet.AsSpan(12)); destination.Write(packet.AsSpan(16));
            Checksum.RefreshIPv4Header(packet);
        }
        return packet;
    }
}
