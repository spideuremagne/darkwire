using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Darkwire.Vpn;

/// <summary>
/// Plain DNS the router answers itself. A standard query for a blocked name gets a nonexistent-domain answer and never
/// leaves, and one for a name answered locally gets this PC's own loopback address; one the filter cannot read is refused
/// rather than relayed, so no encoding it misreads reaches a resolver. Other messages, such as dynamic updates, go through
/// unchanged.
/// </summary>
public static class DnsAnswers
{
    public const ushort Port = 53;
    /// <summary>How long applications may keep a name answered with the loopback address.</summary>
    public const uint LoopbackTtl = 300;
    private const int Header = 12;
    private const ushort Response = 0x8000, RecursionDesired = 0x0100, RecursionAvailable = 0x0080, CheckingDisabled = 0x0010;
    private const ushort FormatError = 1, ServerFailure = 2, NameError = 3;
    private const ushort TypeA = 1, TypeAaaa = 28, TypeAny = 255, ClassIn = 1, ClassAny = 255;

    /// <summary>
    /// The answer to a DNS message an application sent, or null to relay it unchanged. An empty answer drops a message too
    /// short to be DNS. A name both lists name is answered with the loopback address.
    /// </summary>
    /// <param name="blocks">Names answered as nonexistent; null for none.</param>
    /// <param name="loopback">Names answered with the loopback address; null for none.</param>
    public static byte[]? Filter(ReadOnlySpan<byte> message, Func<string, bool>? blocks, Func<string, bool>? loopback = null)
    {
        if (message.Length < Header) return [];
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        // Responses, and opcodes other than QUERY (NOTIFY, UPDATE), carry no lookup.
        if ((flags & Response) != 0 || (flags >> 11 & 0xF) != 0) return null;
        if (Question(message) is not ({ } name, var end)) return Answer(message, flags, Header, FormatError);
        if (loopback?.Invoke(name) == true) return Loopback(message, flags, end);
        return blocks?.Invoke(name) == true ? Answer(message, flags, end, NameError) : null;
    }

    /// <summary>The name a standard query asks about, lowercased without its root label; null for anything else.</summary>
    public static string? QuestionName(ReadOnlySpan<byte> message)
    {
        if (message.Length < Header) return null;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        return (flags & Response) != 0 || (flags >> 11 & 0xF) != 0 ? null : Question(message).Name;
    }

    /// <summary>A server failure in answer to a query, for one nothing could answer; null for a message too short to answer.</summary>
    public static byte[]? Failure(ReadOnlySpan<byte> query)
    {
        if (query.Length < Header) return null;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(query[2..]);
        var end = Question(query) is ({ }, var found) ? found : Header;
        return Answer(query, flags, end, ServerFailure);
    }

    /// <summary>
    /// A copy of a query asking the resolver to validate DNSSEC itself: the checking-disabled bit cleared, so a validating
    /// server never hands back data that failed validation.
    /// </summary>
    public static byte[] Validating(ReadOnlySpan<byte> query)
    {
        var copy = query.ToArray();
        if (copy.Length >= Header) BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(2), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(copy.AsSpan(2)) & ~CheckingDisabled));
        return copy;
    }

    /// <summary>Whether a response answers a query: its identifier, the response bit, and the same question.</summary>
    public static bool Answers(ReadOnlySpan<byte> query, ReadOnlySpan<byte> response)
    {
        if (query.Length < Header || response.Length < Header || !response[..2].SequenceEqual(query[..2]) || (BinaryPrimitives.ReadUInt16BigEndian(response[2..]) & Response) == 0) return false;
        if (Question(query) is not ({ }, var end)) return true;
        // A server answering a question echoes it; the name may differ in case only, its type and class not at all.
        if (response.Length < end || BinaryPrimitives.ReadUInt16BigEndian(response[4..]) != 1 || !response[(end - 4)..end].SequenceEqual(query[(end - 4)..end])) return false;
        for (var i = Header; i < end - 4; i++)
        {
            if (response[i] == query[i]) continue;
            // Label lengths and other octets match exactly; only letters may differ, in case.
            var folded = query[i] | 0x20;
            if (folded is < 'a' or > 'z' || (response[i] | 0x20) != folded) return false;
        }
        return true;
    }

    /// <summary>The single question's name, lowercased without its root label, and where the question ends; null when the query is not one plain question.</summary>
    internal static (string? Name, int End) Question(ReadOnlySpan<byte> message)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(message[4..]) != 1 || BinaryPrimitives.ReadUInt16BigEndian(message[6..]) != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(message[8..]) != 0) return (null, 0);
        var name = new StringBuilder(64);
        var position = Header;
        while (true)
        {
            if (position >= message.Length) return (null, 0);
            var length = message[position++];
            if (length == 0) break;
            // A query has no earlier name to point at; compression and extended label types are not plain questions.
            if (length > 63 || position + length > message.Length) return (null, 0);
            if (name.Length > 0) name.Append('.');
            foreach (var octet in message.Slice(position, length)) name.Append(octet is >= (byte)'A' and <= (byte)'Z' ? (char)(octet + 32) : (char)octet);
            if (name.Length > 253) return (null, 0);
            position += length;
        }
        // QTYPE and QCLASS follow the name.
        return position + 4 <= message.Length ? (name.ToString(), position + 4) : (null, 0);
    }

    /// <summary>The header and question echoed back as a response with the given code and no records.</summary>
    private static byte[] Answer(ReadOnlySpan<byte> query, ushort flags, int end, ushort code)
    {
        var answer = query[..end].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(2), (ushort)(Response | flags & (RecursionDesired | CheckingDisabled) | RecursionAvailable | code));
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(4), (ushort)(end > Header ? 1 : 0));
        answer.AsSpan(6, 6).Clear();
        return answer;
    }

    /// <summary>
    /// The loopback address for an address question: 127.0.0.1 for A, ::1 for AAAA, both for ANY. The name exists without
    /// records of any other type, so other questions get an empty answer rather than a nonexistent name.
    /// </summary>
    private static byte[] Loopback(ReadOnlySpan<byte> query, ushort flags, int end)
    {
        var type = BinaryPrimitives.ReadUInt16BigEndian(query[(end - 4)..]); var @class = BinaryPrimitives.ReadUInt16BigEndian(query[(end - 2)..]);
        List<byte[]> addresses = [];
        if (@class is ClassIn or ClassAny)
        {
            if (type is TypeA or TypeAny) addresses.Add(IPAddress.Loopback.GetAddressBytes());
            if (type is TypeAaaa or TypeAny) addresses.Add(IPAddress.IPv6Loopback.GetAddressBytes());
        }
        var header = Answer(query, flags, end, 0);
        var answer = new byte[header.Length + addresses.Sum(a => 12 + a.Length)];
        header.CopyTo(answer, 0);
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(6), (ushort)addresses.Count);
        var position = header.Length;
        foreach (var address in addresses)
        {
            // The owner is the question's name, by a pointer to it right after the header.
            var record = answer.AsSpan(position);
            BinaryPrimitives.WriteUInt16BigEndian(record, 0xC000 | Header);
            BinaryPrimitives.WriteUInt16BigEndian(record[2..], address.Length == 4 ? TypeA : TypeAaaa);
            BinaryPrimitives.WriteUInt16BigEndian(record[4..], ClassIn);
            BinaryPrimitives.WriteUInt32BigEndian(record[6..], LoopbackTtl);
            BinaryPrimitives.WriteUInt16BigEndian(record[10..], (ushort)address.Length);
            address.CopyTo(record[12..]);
            position += 12 + address.Length;
        }
        return answer;
    }

    /// <summary>The local answer a filter gives a query over TCP, or null to send it on.</summary>
    public static Func<byte[], ValueTask<byte[]?>> Filtering(Func<string, bool>? blocks, Func<string, bool>? loopback) =>
        query => ValueTask.FromResult(Filter(query, blocks, loopback));

    /// <summary>
    /// Relays DNS over TCP message by message: each query from the application gets the answer <paramref name="answer"/> gives
    /// it, or goes to the server when that is null, its answer written back between the server's whole responses; an empty
    /// answer drops it. Without a server, a query nothing answers gets a server failure. Either side may close; the idle
    /// timeout ends a quiet connection.
    /// </summary>
    public static async Task RelayTcpAsync(Socket application, Socket? server, Func<byte[], ValueTask<byte[]?>> answer, TimeSpan idleTimeout, CancellationToken cancellation)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        lifetime.CancelAfter(idleTimeout);
        using var writing = new SemaphoreSlim(1, 1);
        async Task<byte[]?> ReadAsync(Socket source)
        {
            var prefix = new byte[2];
            if (!await FillAsync(source, prefix, lifetime.Token, end: true).ConfigureAwait(false)) return null;
            var message = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
            if (message.Length == 0 || !await FillAsync(source, message, lifetime.Token, end: false).ConfigureAwait(false)) throw new IOException("A DNS message was cut short.");
            lifetime.CancelAfter(idleTimeout);
            return message;
        }
        async Task SendAsync(Socket destination, byte[] message)
        {
            var framed = new byte[message.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length); message.CopyTo(framed, 2);
            for (var sent = 0; sent < framed.Length;)
            {
                var written = await destination.SendAsync(framed.AsMemory(sent), SocketFlags.None, lifetime.Token).ConfigureAwait(false);
                if (written <= 0) throw new IOException("The DNS stream closed while sending.");
                sent += written;
            }
            lifetime.CancelAfter(idleTimeout);
        }
        // Local answers and the server's responses share the application's stream; each goes out whole.
        async Task ReplyAsync(byte[] message)
        {
            await writing.WaitAsync(lifetime.Token).ConfigureAwait(false);
            try { await SendAsync(application, message).ConfigureAwait(false); }
            finally { writing.Release(); }
        }
        async Task Queries()
        {
            try
            {
                while (await ReadAsync(application).ConfigureAwait(false) is { } query)
                {
                    var local = await answer(query).ConfigureAwait(false);
                    if (local is null && server is not null) await SendAsync(server, query).ConfigureAwait(false);
                    else if ((local ?? Failure(query)) is { Length: > 0 } reply) await ReplyAsync(reply).ConfigureAwait(false);
                }
                if (server is not null) server.Shutdown(SocketShutdown.Send);
                else application.Shutdown(SocketShutdown.Send);
            }
            catch { await lifetime.CancelAsync().ConfigureAwait(false); throw; }
        }
        async Task Responses()
        {
            if (server is null) return;
            try
            {
                while (await ReadAsync(server).ConfigureAwait(false) is { } response) await ReplyAsync(response).ConfigureAwait(false);
                application.Shutdown(SocketShutdown.Send);
            }
            catch { await lifetime.CancelAsync().ConfigureAwait(false); throw; }
        }
        await Task.WhenAll(Queries(), Responses()).ConfigureAwait(false);
    }

    /// <summary>Reads exactly the buffer; false when the stream ended cleanly before its first byte and <paramref name="end"/> allows that.</summary>
    private static async Task<bool> FillAsync(Socket source, byte[] buffer, CancellationToken cancellation, bool end)
    {
        for (var read = 0; read < buffer.Length;)
        {
            var count = await source.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, cancellation).ConfigureAwait(false);
            if (count == 0) return end && read == 0 ? false : throw new IOException("A DNS message was cut short.");
            read += count;
        }
        return true;
    }
}

/// <summary>
/// Answers lookups bound for the internet through an encrypted DNS server: those sent to Darkwire's resolver, and plain DNS
/// on the physical network to any server. Names a local network answers stay with the server the flow already reaches.
/// </summary>
public interface IDnsForwarder
{
    /// <summary>Whether the forwarder answers the name; false for one a local network answers. Called while the router lock may be held.</summary>
    bool Answers(string name);
    /// <summary>The answer to a query, a server failure when none came in time; never throws for a failed lookup.</summary>
    /// <param name="stream">The query came over TCP, so its answer may be as large as DNS allows.</param>
    Task<byte[]> AskAsync(byte[] query, bool stream, CancellationToken cancellation);
}
