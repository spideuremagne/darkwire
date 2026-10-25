using System.Collections.ObjectModel;

namespace Darkwire.Vpn;

/// <summary>Non-secret profile metadata used to prepare an immutable application routing plan.</summary>
public sealed record TunnelProfileAssignment(Guid ProfileId, string Kind, IReadOnlyList<string> Applications);
public sealed record PlannedApplicationTunnel(string ApplicationPath, Guid ProfileId, string Kind);

/// <summary>
/// Desired routing only. This type has no active state and never starts a tunnel or approves
/// a connection. A service must independently validate process identity and enforce every
/// requirement below before it can forward an application's traffic.
/// </summary>
public sealed class TunnelRoutingPlan
{
    public const int MaximumProfiles = 100;
    public const int MaximumApplicationAssignments = 20_000;
    private readonly IReadOnlyDictionary<string, PlannedApplicationTunnel> applications;

    private TunnelRoutingPlan(int profileCount, Dictionary<string, PlannedApplicationTunnel> applications, TunnelProfileAssignment? defaultProfile)
    {
        ProfileCount = profileCount;
        this.applications = new ReadOnlyDictionary<string, PlannedApplicationTunnel>(applications);
        DefaultProfileId = defaultProfile?.ProfileId; DefaultProfileKind = defaultProfile?.Kind;
        Applications = Array.AsReadOnly(applications.Values.OrderBy(a => a.ApplicationPath, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public int ProfileCount { get; }
    public Guid? DefaultProfileId { get; }
    public string? DefaultProfileKind { get; }
    public IReadOnlyList<PlannedApplicationTunnel> Applications { get; }

    // These are invariants, not claims about the current runtime's capabilities.
    public bool RequiresTunnelOnlyDns => true;
    public bool RequiresFailClosedOnTunnelLoss => true;
    public bool RequiresBlockingUnsupportedAddressFamilies => true;
    public bool RequiresBlockingUnsupportedProtocols => true;

    public static TunnelRoutingPlan Build(IEnumerable<TunnelProfileAssignment> profiles, Guid? defaultProfileId = null)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        var ids = new HashSet<Guid>();
        var applications = new Dictionary<string, PlannedApplicationTunnel>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        TunnelProfileAssignment? defaultProfile = null;
        foreach (var profile in profiles)
        {
            if (++count > MaximumProfiles) throw new InvalidDataException("Save at most 100 VPN profiles.");
            // An OpenVPN profile from an earlier build still plans, so what it carries is held and refused; it never connects.
            if (profile is null || profile.ProfileId == Guid.Empty || !ids.Add(profile.ProfileId) ||
                profile.Kind is not ("WireGuard" or "OpenVPN") || profile.Applications is null)
                throw new InvalidDataException("Invalid or duplicate tunnel profile.");
            if (profile.ProfileId == defaultProfileId) defaultProfile = profile;
            foreach (var inputPath in profile.Applications)
            {
                if (applications.Count >= MaximumApplicationAssignments) throw new InvalidDataException("Too many application tunnel assignments.");
                var path = NormalizeApplicationPath(inputPath);
                if (!applications.TryAdd(path, new(path, profile.ProfileId, profile.Kind)))
                    throw new InvalidDataException("Each application must have exactly one selected tunnel profile.");
            }
        }
        if (defaultProfileId is not null && defaultProfile is null) throw new InvalidDataException("The default tunnel profile is unavailable.");
        return new(count, applications, defaultProfile);
    }

    /// <summary>
    /// Looks up an already authenticated executable path. A matching path is planning metadata,
    /// not proof of process ownership or permission to bypass the firewall policy.
    /// </summary>
    public PlannedApplicationTunnel? FindApplication(string applicationPath)
    {
        var path = NormalizeApplicationPath(applicationPath);
        return applications.GetValueOrDefault(path) ?? (DefaultProfileId is { } id ? new(path, id, DefaultProfileKind!) : null);
    }

    private static string NormalizeApplicationPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32_000 || path.Any(char.IsControl) ||
            path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] is not ('\\' or '/') ||
            path.AsSpan(2).Contains(':') || path.IndexOfAny(['*', '?', '"', '<', '>', '|']) >= 0)
            throw new InvalidDataException("Select an absolute local executable path for tunnel routing.");
        try
        {
            var canonical = Path.GetFullPath(path);
            if (!Path.IsPathFullyQualified(canonical) || !Path.GetExtension(canonical).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Select an executable file for tunnel routing.");
            return canonical;
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        { throw new InvalidDataException("Invalid application path for tunnel routing."); }
    }
}
