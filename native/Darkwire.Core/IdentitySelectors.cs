using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Darkwire.Core;

/// <summary>Application, service, user and package selectors. The engine converts them to native SIDs and security descriptors.</summary>
public static partial class IdentitySelectors
{
    public const string SystemApplication = "System", AllServices = "AllServices", AllPackages = "AllPackages";
    [GeneratedRegex(@"^S-1-\d{1,13}(-\d{1,10}){1,15}$", RegexOptions.CultureInvariant)] private static partial Regex SidPattern();
    public static bool IsSid(string value) => SidPattern().IsMatch(value);
    /// <summary>Windows uses the literal app ID "System" for traffic owned by the kernel process.</summary>
    public static bool IsSystemApplication(string path) => path.Equals(SystemApplication, StringComparison.OrdinalIgnoreCase);
    public static bool ValidService(string value) => RuleValidator.IsAny(value) || value == AllServices ||
        value.Length is > 0 and <= 256 && !value.Any(c => char.IsControl(c) || c is '/' or '\\' or ',' or '*');
    public static bool ValidUsers(string value) => RuleValidator.IsAny(value) ||
        RuleValidator.Tokens(value) is { Length: > 0 and <= 64 } tokens && tokens.All(t => IsSid(t) || ValidAccount(t));
    public static bool ValidPackage(string value) => RuleValidator.IsAny(value) || value == AllPackages ||
        IsSid(value) && value.StartsWith("S-1-15-2-", StringComparison.Ordinal);
    // Names are resolved to SIDs before any security descriptor is built; SDDL syntax characters never reach it.
    private static bool ValidAccount(string value) => value.Length is > 0 and <= 512 && value.Count(c => c == '\\') <= 1 &&
        !value.Any(c => char.IsControl(c) || c is ',' or '*' or '"' or '/' or ':' or '(' or ')' or ';' or '{' or '}' or '[' or ']');

    /// <summary>NT SERVICE\name SID: SHA-1 of the upper-case UTF-16 name as five little-endian subauthorities.</summary>
    public static string ServiceSid(string serviceName)
    {
        var hash = SHA1.HashData(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
        return "S-1-5-80-" + string.Join('-', Enumerable.Range(0, 5).Select(i => BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(i * 4))));
    }
}
