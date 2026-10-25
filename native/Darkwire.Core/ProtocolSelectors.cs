using System.Globalization;

namespace Darkwire.Core;

public static class IpProtocol
{
    public static bool TryParse(string? text, out byte? value)
    {
        value = text switch { "TCP" => 6, "UDP" => 17, "ICMPv4" => 1, "ICMPv6" => 58, _ => null };
        if (value.HasValue || RuleValidator.IsAny(text)) return true;
        if (text is not null && text.StartsWith("IP ", StringComparison.Ordinal) &&
            byte.TryParse(text.AsSpan(3), NumberStyles.None, CultureInfo.InvariantCulture, out var number))
        { value = number; return true; }
        return false;
    }
    public static string Name(int protocol) => protocol switch
    { 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", 256 => "Any", _ => "IP " + protocol.ToString(CultureInfo.InvariantCulture) };
}

public sealed record IcmpSelector(byte Type, byte? Code);
public static class IcmpSelectors
{
    public static bool TryParse(string? text, out IReadOnlyList<IcmpSelector?> selectors)
    {
        selectors = [];
        if (RuleValidator.IsAny(text)) { selectors = new IcmpSelector?[] { null }; return true; }
        if (string.IsNullOrWhiteSpace(text)) return false;
        var tokens = text.Split(',', StringSplitOptions.TrimEntries);
        if (tokens.Length > 256) return false;
        List<IcmpSelector?> parsed = [];
        foreach (var token in tokens)
        {
            var pair = token.Split(':');
            if (pair.Length != 2 || !byte.TryParse(pair[0], NumberStyles.None, CultureInfo.InvariantCulture, out var type)) return false;
            byte? code = null;
            if (pair[1] != "*")
            {
                if (!byte.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value)) return false;
                code = value;
            }
            parsed.Add(new(type, code));
        }
        selectors = parsed.Distinct().ToArray(); return true;
    }
    public static bool Matches(string text, byte? type, byte? code) => TryParse(text, out var selectors) &&
        selectors.Any(s => s is null || type == s.Type && (s.Code is null || code == s.Code));
}
