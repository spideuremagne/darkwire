using System.Text.RegularExpressions;

namespace Darkwire.Engine;

/// <summary>One value from the Windows Firewall rule store. The registry value name is the stable rule ID.</summary>
public sealed record WindowsRuleRecord(string Id, string Raw, string Version, IReadOnlyList<KeyValuePair<string, string>> Fields)
{
    public IEnumerable<string> All(string key) => Fields.Where(f => f.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Select(f => f.Value);
}

/// <summary>Splits rule strings per [MS-GPFAS] "Firewall Rule and the Firewall Rule Grammar Rule": v{major}.{minor}|Key=Value|...|</summary>
public static partial class WindowsRuleGrammar
{
    public const int MaximumLength = 65_536;
    [GeneratedRegex(@"^\d{1,3}\.\d{1,3}$", RegexOptions.CultureInvariant)] private static partial Regex VersionPattern();

    public static WindowsRuleRecord Parse(string id, string raw)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 1024 || id.Contains('\0')) throw new InvalidDataException("Invalid Windows rule ID.");
        if (string.IsNullOrEmpty(raw) || raw.Length > MaximumLength || raw.Contains('\0')) throw new InvalidDataException("Invalid Windows rule data.");
        var parts = raw.Split('|');
        var head = parts[0];
        if (head.Length < 2 || head[0] is not ('v' or 'V') || !VersionPattern().IsMatch(head[1..])) throw new InvalidDataException("Missing Windows rule version.");
        List<KeyValuePair<string, string>> fields = [];
        for (var i = 1; i < parts.Length; i++)
        {
            var part = parts[i];
            if (part.Length == 0)
            {
                if (i == parts.Length - 1) break;
                throw new InvalidDataException("Empty Windows rule field.");
            }
            var separator = part.IndexOf('=');
            if (separator <= 0) throw new InvalidDataException("Malformed Windows rule field.");
            fields.Add(new(part[..separator], part[(separator + 1)..]));
        }
        return new(id, raw, head[1..], fields);
    }
}
