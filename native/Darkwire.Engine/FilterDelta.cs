using Darkwire.Core;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Engine;

/// <summary>
/// Installs only what changes between policies. Each Darkwire filter's key is derived from everything WFP holds of it and from
/// a secret the service draws each time it starts, so the filters already installed as a new plan wants them stay, and only
/// the others are deleted and added. Replacing every filter at each change took about 20 seconds with a large blocklist
/// installed, while connecting a VPN profile changes a handful.
/// </summary>
internal static class FilterDelta
{
    /// <summary>
    /// The key of each registration, with its conditions as WFP will hold them: the same content gets the same key for the
    /// same secret, and registrations alike in everything are told apart by their order. A new secret gives every filter a new
    /// key, so the first install after the service starts never deletes and adds one key in the same transaction, and no one
    /// else can predict a key.
    /// </summary>
    public static Guid[] Keys(IReadOnlyList<(WfpRegistration Registration, IReadOnlyList<ConditionSpec> Conditions)> filters, byte[] secret)
    {
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        var keys = new Guid[filters.Count];
        for (var i = 0; i < filters.Count; i++)
        {
            var content = Content(filters[i].Registration, filters[i].Conditions);
            var occurrence = seen[content] = seen.TryGetValue(content, out var earlier) ? earlier + 1 : 0;
            var hash = SHA256.HashData([.. secret, .. Encoding.UTF8.GetBytes(content + "#" + occurrence.ToString(CultureInfo.InvariantCulture))]);
            // A version 8 GUID (RFC 9562): derived, not random.
            hash[7] = (byte)(hash[7] & 0x0F | 0x80); hash[8] = (byte)(hash[8] & 0x3F | 0x80);
            keys[i] = new Guid(hash.AsSpan(0, 16));
        }
        return keys;
    }

    /// <summary>Everything WFP holds of a filter, and the rule it comes from, each part unambiguously delimited.</summary>
    private static string Content(WfpRegistration registration, IReadOnlyList<ConditionSpec> conditions)
    {
        var filter = registration.Filter;
        var text = new StringBuilder("darkwire filter 1\n");
        text.Append(CultureInfo.InvariantCulture, $"{filter.Name.Length}:{filter.Name}\n{filter.RuleId?.ToString("N") ?? "-"}\n");
        text.Append(CultureInfo.InvariantCulture, $"{registration.Layer:N} {registration.Flags} {(registration.Lock ? "lock" : "policy")} {filter.Weight} {filter.Action}\n");
        foreach (var condition in conditions)
            text.Append(CultureInfo.InvariantCulture, $"{condition.Field:N} {condition.Match} {condition.Type} {condition.Number} {(condition.Data is { } data ? Convert.ToHexString(data) : "-")} {(condition.Range is { } range ? $"{range.Low}-{range.High}" : "-")}\n");
        return text.ToString();
    }

    /// <summary>
    /// What an apply changes. An installed filter stays when a wanted one has its key, it is enabled and of the same kind,
    /// boot-time or startup lock, and it is one this service installed itself, so a filter put back under a key by someone
    /// else is replaced. Every other installed filter goes, those of an earlier start or version too. Wanted filters not kept
    /// are added.
    /// </summary>
    /// <param name="trusted">Whether a filter ID is one this service installed or kept since it opened WFP.</param>
    /// <returns>The IDs to delete, the indexes of the wanted filters to add, and the ID of each wanted filter kept, by index.</returns>
    public static (IReadOnlyList<ulong> Delete, IReadOnlyList<int> Add, IReadOnlyDictionary<int, ulong> Kept) Between(
        IEnumerable<(ulong Id, Guid Key, bool BootTime, bool Disabled, bool Lock)> installed, IReadOnlyList<(Guid Key, bool BootTime, bool Lock)> wanted, Func<ulong, bool> trusted)
    {
        var index = new Dictionary<Guid, int>(wanted.Count);
        for (var i = 0; i < wanted.Count; i++) index[wanted[i].Key] = i;
        List<ulong> delete = []; Dictionary<int, ulong> kept = [];
        foreach (var filter in installed)
        {
            if (index.TryGetValue(filter.Key, out var i) && trusted(filter.Id) && !filter.Disabled && filter.BootTime == wanted[i].BootTime && filter.Lock == wanted[i].Lock &&
                kept.TryAdd(i, filter.Id)) continue;
            delete.Add(filter.Id);
        }
        return (delete, [.. Enumerable.Range(0, wanted.Count).Where(i => !kept.ContainsKey(i))], kept);
    }
}
