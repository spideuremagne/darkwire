using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("Darkwire.Checks")]
[assembly: InternalsVisibleTo("Darkwire.Service")]

namespace Darkwire.Core;

/// <summary>
/// Verifies minisign signatures, as the DNSCrypt project signs its resolver lists and releases: Ed25519 (RFC 8032) over the
/// file, or over its BLAKE2b-512 hash for a prehashed ("ED") signature, and over the signature with its trusted comment.
/// Verification handles only public data, so the reference arithmetic needs no constant-time care.
/// </summary>
public static class Minisign
{
    /// <summary>
    /// The trusted comment of a signature the key made over the data; throws <see cref="InvalidDataException"/> when the key or
    /// the signature file is malformed, names another key, or does not verify.
    /// </summary>
    public static string Verify(string publicKey, ReadOnlySpan<byte> data, string signatureFile)
    {
        byte[] key;
        try { key = Convert.FromBase64String(publicKey.Trim()); }
        catch (FormatException) { throw new InvalidDataException("The minisign public key is not base64."); }
        if (key.Length != 42 || key[0] != 'E' || key[1] != 'd') throw new InvalidDataException("The minisign public key is malformed.");
        var lines = signatureFile.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToArray();
        const string Trusted = "trusted comment: ";
        if (lines.Length < 4 || !lines[0].StartsWith("untrusted comment: ", StringComparison.Ordinal) || !lines[2].StartsWith(Trusted, StringComparison.Ordinal))
            throw new InvalidDataException("The minisign signature is malformed.");
        byte[] signature, global;
        try { signature = Convert.FromBase64String(lines[1]); global = Convert.FromBase64String(lines[3]); }
        catch (FormatException) { throw new InvalidDataException("The minisign signature is not base64."); }
        if (signature.Length != 74 || global.Length != 64 || signature[0] != 'E' || signature[1] is not ((byte)'d' or (byte)'D'))
            throw new InvalidDataException("The minisign signature is malformed.");
        if (!signature.AsSpan(2, 8).SequenceEqual(key.AsSpan(2, 8))) throw new InvalidDataException("The file was signed with another key.");
        var point = key[10..];
        var message = signature[1] == 'D' ? Blake2b.Hash512(data) : data.ToArray();
        if (!Ed25519.Verify(point, message, signature[10..])) throw new InvalidDataException("The minisign signature does not match the file.");
        var comment = lines[2][Trusted.Length..];
        if (!Ed25519.Verify(point, [.. signature[10..], .. Encoding.UTF8.GetBytes(comment)], global)) throw new InvalidDataException("The minisign trusted comment does not verify.");
        return comment;
    }

    /// <summary>A minisign public key for a seed and key ID. Darkwire only verifies; its checks sign their own test data.</summary>
    internal static string PublicKey(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyId) => Convert.ToBase64String([(byte)'E', (byte)'d', .. keyId, .. Ed25519.PublicKey(seed)]);

    /// <summary>A minisign signature file over the data, prehashed ("ED") or not ("Ed"), for checks.</summary>
    internal static string Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> data, string trustedComment, bool prehash = true)
    {
        byte[] signature = [(byte)'E', prehash ? (byte)'D' : (byte)'d', .. keyId, .. Ed25519.Sign(seed, prehash ? Blake2b.Hash512(data) : data)];
        var global = Ed25519.Sign(seed, [.. signature[10..], .. Encoding.UTF8.GetBytes(trustedComment)]);
        return $"untrusted comment: signature from a Darkwire check\n{Convert.ToBase64String(signature)}\ntrusted comment: {trustedComment}\n{Convert.ToBase64String(global)}\n";
    }
}

/// <summary>BLAKE2b with a 64-byte digest and no key (RFC 7693).</summary>
public static class Blake2b
{
    private static readonly ulong[] IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
    private static readonly byte[][] Sigma =
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    ];

    public static byte[] Hash512(ReadOnlySpan<byte> data)
    {
        var h = (ulong[])IV.Clone(); h[0] ^= 0x01010000UL ^ 64;
        var m = new ulong[16]; var v = new ulong[16];
        ulong counter = 0; var offset = 0;
        // The last block, full or not, is compressed with the final flag; an empty input is one empty last block.
        while (data.Length - offset > 128) { counter += 128; Compress(h, data.Slice(offset, 128), counter, false, m, v); offset += 128; }
        Span<byte> last = stackalloc byte[128]; last.Clear(); data[offset..].CopyTo(last); counter += (ulong)(data.Length - offset);
        Compress(h, last, counter, true, m, v);
        var output = new byte[64];
        for (var i = 0; i < 8; i++) BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), h[i]);
        return output;
    }

    private static void Compress(ulong[] h, ReadOnlySpan<byte> block, ulong counter, bool last, ulong[] m, ulong[] v)
    {
        for (var i = 0; i < 16; i++) m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block[(i * 8)..]);
        h.CopyTo(v, 0); IV.CopyTo(v, 8); v[12] ^= counter; if (last) v[14] = ~v[14];
        for (var round = 0; round < 12; round++)
        {
            var s = Sigma[round % 10];
            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]); G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]); G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]); G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]); G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]); G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]); G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (var i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] += v[b] + x; v[d] = ulong.RotateRight(v[d] ^ v[a], 32); v[c] += v[d]; v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
        v[a] += v[b] + y; v[d] = ulong.RotateRight(v[d] ^ v[a], 16); v[c] += v[d]; v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
    }
}

/// <summary>Ed25519 signature verification (RFC 8032, section 5.1.7), in extended coordinates over arbitrary-precision integers.</summary>
public static class Ed25519
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D = Mod(-121665 * Inverse(121666));
    private static readonly BigInteger D2 = Mod(2 * D);
    private static readonly BigInteger SquareRootOfMinusOne = BigInteger.ModPow(2, (P - 1) / 4, P);
    private static readonly Point Base = Decode(Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666"))!.Value;

    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);
    private static readonly Point Identity = new(0, 1, 1, 0);

    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        if (Decode(publicKey) is not { } a || Decode(signature[..32]) is not { } r) return false;
        var s = Integer(signature[32..]);
        if (s >= L) return false;
        var h = Integer(SHA512.HashData([.. signature[..32], .. publicKey, .. message])) % L;
        return Equal(Multiply(Base, s), Add(r, Multiply(a, h)));
    }

    /// <summary>The public key for a 32-byte seed (RFC 8032, section 5.1.5), for checks.</summary>
    internal static byte[] PublicKey(ReadOnlySpan<byte> seed) => Encode(Multiply(Base, Scalar(SHA512.HashData(seed))));

    /// <summary>A signature by a 32-byte seed (RFC 8032, section 5.1.6), for checks; Darkwire itself only verifies.</summary>
    internal static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        var hash = SHA512.HashData(seed);
        var a = Scalar(hash); var prefix = hash[32..];
        var publicKey = Encode(Multiply(Base, a));
        var r = Integer(SHA512.HashData([.. prefix, .. message])) % L;
        var encodedR = Encode(Multiply(Base, r));
        var k = Integer(SHA512.HashData([.. encodedR, .. publicKey, .. message])) % L;
        return [.. encodedR, .. Bytes((r + k * a) % L)];
    }

    private static BigInteger Scalar(byte[] hash)
    {
        var clamped = hash[..32]; clamped[0] &= 248; clamped[31] &= 127; clamped[31] |= 64;
        return Integer(clamped);
    }

    private static byte[] Encode(Point point)
    {
        var inverse = Inverse(point.Z);
        var x = Mod(point.X * inverse); var y = Bytes(Mod(point.Y * inverse));
        if (!x.IsEven) y[31] |= 0x80;
        return y;
    }

    private static byte[] Bytes(BigInteger value)
    {
        var bytes = new byte[32];
        value.ToByteArray(isUnsigned: true, isBigEndian: false).CopyTo(bytes, 0);
        return bytes;
    }

    private static BigInteger Mod(BigInteger value) { var r = value % P; return r.Sign < 0 ? r + P : r; }
    private static BigInteger Inverse(BigInteger value) => BigInteger.ModPow(Mod(value), P - 2, P);
    private static BigInteger Integer(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: false);

    private static Point Add(Point p, Point q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X)); var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(p.T * D2 * q.T); var d = Mod(p.Z * 2 * q.Z);
        var e = b - a; var f = d - c; var g = d + c; var h = b + a;
        return new(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Multiply(Point point, BigInteger scalar)
    {
        var result = Identity;
        for (var bit = (int)scalar.GetBitLength() - 1; bit >= 0; bit--)
        {
            result = Add(result, result);
            if (!(scalar >> bit).IsEven) result = Add(result, point);
        }
        return result;
    }

    private static bool Equal(Point p, Point q) => Mod(p.X * q.Z - q.X * p.Z) == 0 && Mod(p.Y * q.Z - q.Y * p.Z) == 0;

    /// <summary>A point from its 32-byte encoding, or null for one that is not canonical or not on the curve.</summary>
    private static Point? Decode(ReadOnlySpan<byte> bytes)
    {
        var copy = bytes.ToArray(); var odd = (copy[31] & 0x80) != 0; copy[31] &= 0x7F;
        var y = Integer(copy);
        if (y >= P) return null;
        var u = Mod(y * y - 1); var v = Mod(D * y * y + 1);
        var xx = Mod(u * Inverse(v));
        var x = BigInteger.ModPow(xx, (P + 3) / 8, P);
        if (Mod(x * x - xx) != 0) x = Mod(x * SquareRootOfMinusOne);
        if (Mod(x * x - xx) != 0) return null;
        if (x.IsZero && odd) return null;
        if (!x.IsEven != odd) x = P - x;
        return new(x, y, 1, Mod(x * y));
    }
}
