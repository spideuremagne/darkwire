using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Vpn;

/// <summary>What a DNS message says about one question: not a response to it, a server that could not answer, or an answer.</summary>
public enum DnsReply : byte { Unrelated, Failed, Answered }

/// <summary>
/// Address lookups the service makes itself, for VPN endpoint host names. While a default VPN profile confines the Windows
/// DNS client to that profile's tunnel, a backend resolving its peer through Windows would wait for the very tunnel it is
/// starting. The service asks the physical network's DNS servers instead, over UDP from sockets connected to each server and
/// pinned to its interface as relay sockets are. Only the asked server's answer to the asked question counts, and only
/// addresses of the asked name or of the aliases it leads to.
/// </summary>
public static class DnsLookup
{
    public const ushort A = 1, Aaaa = 28;
    private const ushort Cname = 5, Internet = 1;
    private const int Header = 12, MaximumAliases = 8, MaximumPointers = 16;

    /// <summary>A recursive query for one name and type; the name is a host name of ASCII labels.</summary>
    public static byte[] Query(ushort id, string name, ushort type)
    {
        var labels = name.Split('.');
        if (name.Length is 0 or > 253 || labels.Any(l => l.Length is 0 or > 63 || l.Any(c => c is <= ' ' or > '~')))
            throw new ArgumentException("Not a DNS host name.", nameof(name));
        var query = new byte[Header + name.Length + 2 + 4];
        BinaryPrimitives.WriteUInt16BigEndian(query, id);
        query[2] = 0x01; query[5] = 1;
        var at = Header;
        foreach (var label in labels)
        {
            query[at++] = (byte)label.Length;
            at += Encoding.ASCII.GetBytes(label, query.AsSpan(at));
        }
        query[at++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(at), type);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(at + 2), Internet);
        return query;
    }

    /// <summary>
    /// Reads a message as the answer to query <paramref name="id"/> for <paramref name="name"/>. Answered adds the name's
    /// addresses of the type, none when it has none or does not exist; Failed means the server could not answer (an error,
    /// a truncated or unreadable response); Unrelated means the message answers something else.
    /// </summary>
    public static DnsReply Read(ReadOnlySpan<byte> message, ushort id, string name, ushort type, List<IPAddress> addresses)
    {
        if (message.Length < Header || BinaryPrimitives.ReadUInt16BigEndian(message) != id) return DnsReply.Unrelated;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        if ((flags & 0x8000) == 0 || (flags >> 11 & 0xF) != 0) return DnsReply.Unrelated;
        var at = Header;
        if (BinaryPrimitives.ReadUInt16BigEndian(message[4..]) != 1 || Name(message, ref at) is not { } asked || at + 4 > message.Length) return DnsReply.Failed;
        if (!asked.Equals(name, StringComparison.OrdinalIgnoreCase) || BinaryPrimitives.ReadUInt16BigEndian(message[at..]) != type ||
            BinaryPrimitives.ReadUInt16BigEndian(message[(at + 2)..]) != Internet) return DnsReply.Unrelated;
        at += 4;
        // Truncation, and any error but a name that does not exist, leave the question to another server.
        var code = flags & 0xF;
        if ((flags & 0x0200) != 0 || code is not (0 or 3)) return DnsReply.Failed;
        if (code == 3) return DnsReply.Answered;
        List<(string Owner, ushort Type, int Data, int Length)> records = [];
        for (var count = BinaryPrimitives.ReadUInt16BigEndian(message[6..]); count > 0; count--)
        {
            if (Name(message, ref at) is not { } owner || at + 10 > message.Length) return DnsReply.Failed;
            var recordType = BinaryPrimitives.ReadUInt16BigEndian(message[at..]);
            var recordClass = BinaryPrimitives.ReadUInt16BigEndian(message[(at + 2)..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(message[(at + 8)..]);
            at += 10;
            if (at + length > message.Length) return DnsReply.Failed;
            if (recordClass == Internet) records.Add((owner, recordType, at, length));
            at += length;
        }
        // Aliases lead from the asked name; records about other names are not part of the answer.
        List<string> chain = [name.ToLowerInvariant()];
        while (records.FindIndex(r => r.Type == Cname && r.Owner == chain[^1]) is var alias and >= 0)
        {
            var target = records[alias].Data;
            if (Name(message, ref target) is not { } next || target > records[alias].Data + records[alias].Length || chain.Contains(next) || chain.Count > MaximumAliases)
                return DnsReply.Failed;
            chain.Add(next);
        }
        List<IPAddress> answer = [];
        foreach (var record in records)
        {
            if (record.Type != type || !chain.Contains(record.Owner)) continue;
            if (record.Length != (type == Aaaa ? 16 : 4)) return DnsReply.Failed;
            answer.Add(new IPAddress(message.Slice(record.Data, record.Length)));
        }
        addresses.AddRange(answer);
        return DnsReply.Answered;
    }

    /// <summary>
    /// The host's addresses, IPv4 first, from the first server that gives any. Each server is asked from a socket pinned to
    /// the egress <paramref name="egress"/> chooses for it and connected to it, and waited for at most <paramref name="timeout"/>.
    /// </summary>
    public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, IReadOnlyList<IPEndPoint> servers, Func<IPAddress, Egress?> egress, TimeSpan timeout,
        CancellationToken cancellation)
    {
        foreach (var server in servers)
            if (egress(server.Address) is { } route && await AskAsync(host, server, route, timeout, cancellation).ConfigureAwait(false) is { Count: > 0 } found)
                return found;
        throw new IOException(servers.Count == 0 ? $"No DNS server on the physical network can look up {host}." : $"No DNS server on the physical network gave an address for {host}.");
    }

    /// <summary>The addresses one server gives for the host, IPv4 first; a type it fails or does not answer in time adds none.</summary>
    private static async Task<List<IPAddress>> AskAsync(string host, IPEndPoint server, Egress route, TimeSpan timeout, CancellationToken cancellation)
    {
        var first = (ushort)RandomNumberGenerator.GetInt32(0x10000);
        ushort[] ids = [first, (ushort)(first ^ (1 + RandomNumberGenerator.GetInt32(0xFFFF)))], types = [A, Aaaa];
        List<IPAddress>[] found = [[], []];
        var pending = new[] { true, true };
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        limit.CancelAfter(timeout);
        try
        {
            using var socket = RouterRelay.Pinned(route, SocketType.Dgram, ProtocolType.Udp);
            await socket.ConnectAsync(server, limit.Token).ConfigureAwait(false);
            for (var i = 0; i < 2; i++) await socket.SendAsync(Query(ids[i], host, types[i]), SocketFlags.None, limit.Token).ConfigureAwait(false);
            var buffer = new byte[4096];
            while (pending[0] || pending[1])
            {
                var count = await socket.ReceiveAsync(buffer, SocketFlags.None, limit.Token).ConfigureAwait(false);
                for (var i = 0; i < 2; i++)
                    if (pending[i] && Read(buffer.AsSpan(0, count), ids[i], host, types[i], found[i]) != DnsReply.Unrelated) pending[i] = false;
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { }
        // A refused or unreachable server, or a datagram too large to be a plain answer.
        catch (SocketException) { }
        return [.. found[0].Concat(found[1]).Distinct()];
    }

    /// <summary>
    /// A name at <paramref name="at"/>, lowercased and without its root label, advancing past it; compression pointers are
    /// followed a bounded number of times. Null for a name that runs out of the message or uses extended label types.
    /// </summary>
    private static string? Name(ReadOnlySpan<byte> message, ref int at)
    {
        var name = new StringBuilder(64);
        int position = at, pointers = 0;
        while (true)
        {
            if (position >= message.Length) return null;
            var length = message[position];
            if ((length & 0xC0) == 0xC0)
            {
                if (position + 1 >= message.Length || ++pointers > MaximumPointers) return null;
                if (pointers == 1) at = position + 2;
                position = (length & 0x3F) << 8 | message[position + 1];
                continue;
            }
            if ((length & 0xC0) != 0) return null;
            position++;
            if (length == 0)
            {
                if (pointers == 0) at = position;
                return name.ToString();
            }
            if (position + length > message.Length) return null;
            if (name.Length > 0) name.Append('.');
            foreach (var octet in message.Slice(position, length)) name.Append(octet is >= (byte)'A' and <= (byte)'Z' ? (char)(octet + 32) : (char)octet);
            if (name.Length > 253) return null;
            position += length;
        }
    }
}
