using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Darkwire.Core;

/// <summary>An inclusive same-family range. Decomposition covers exactly its endpoints and never widens them.</summary>
public readonly record struct IpAddressRange
{
    private readonly BigInteger first, last;
    private readonly int bits;
    public const int MaximumNetworks = 256;
    private IpAddressRange(BigInteger first, BigInteger last, int bits) { this.first = first; this.last = last; this.bits = bits; }

    public static bool TryParse(string? value, out IpAddressRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(value) || value.Contains('%') || value.Contains('/') || value.Contains('[') || value.Contains(']')) return false;
        var parts = value.Split('-', StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var start) || !IPAddress.TryParse(parts[1], out var end) || start.AddressFamily != end.AddressFamily) return false;
        if (start.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) return false;
        var first = Number(start); var last = Number(end);
        if (first > last) return false;
        range = new(first, last, start.AddressFamily == AddressFamily.InterNetwork ? 32 : 128); return true;
    }

    public bool Contains(IPAddress address)
    {
        if (bits == 0 || address.GetAddressBytes().Length * 8 != bits) return false;
        var number = Number(address); return number >= first && number <= last;
    }

    public IReadOnlyList<IpNetwork> ToNetworks(int maximumNetworks = MaximumNetworks)
    {
        if (bits is not (32 or 128)) throw new InvalidOperationException("The address range is uninitialized.");
        if (maximumNetworks < 1) throw new ArgumentOutOfRangeException(nameof(maximumNetworks));
        List<IpNetwork> result = [];
        var current = first;
        while (current <= last)
        {
            var alignedBits = 0;
            while (alignedBits < bits && ((current >> alignedBits) & BigInteger.One).IsZero) alignedBits++;
            // GetBitLength is exact for the 2^128 full-family range as well as singleton endpoints.
            var remainingBits = checked((int)(last - current + BigInteger.One).GetBitLength() - 1);
            var hostBits = Math.Min(alignedBits, remainingBits);
            if (result.Count >= Math.Min(maximumNetworks, MaximumNetworks)) throw new InvalidDataException("Address range exceeds the CIDR expansion limit.");
            result.Add(new(Address(current, bits / 8), bits - hostBits));
            current += BigInteger.One << hostBits;
        }
        return result;
    }

    private static BigInteger Number(IPAddress address) => new(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
    private static IPAddress Address(BigInteger number, int bytes)
    {
        var compact = number.ToByteArray(isUnsigned: true, isBigEndian: true);
        var result = new byte[bytes]; compact.CopyTo(result, bytes - compact.Length); return new(result);
    }
}
