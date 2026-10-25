namespace Darkwire.Core;

public static class VpnAssignments
{
    public const int MaximumProfiles = 100;

    /// <summary>
    /// The policy sends traffic through a VPN profile: an application assignment, a default outbound profile, or Darkwire's own
    /// connections.
    /// </summary>
    public static bool Routed(AppState state) => state.DefaultOutboundVpnProfileId is not null || state.VpnProfiles.Any(p => p.Applications.Count > 0) ||
        state.OwnTraffic == OwnRoute.Profile;

    /// <summary>The profile Darkwire's own connections go through: the default route's unless set otherwise; null for Windows' route.</summary>
    public static Guid? OwnProfile(AppState state) => state.OwnTraffic switch
    {
        OwnRoute.Windows => null,
        OwnRoute.Profile => state.OwnTrafficProfileId,
        _ => state.DefaultOutboundVpnProfileId
    };

    /// <summary>Profiles the policy routes through: every profile with an assigned application, the default one, and Darkwire's own.</summary>
    public static IEnumerable<VpnProfile> InUse(AppState state) =>
        state.VpnProfiles.Where(p => p.Applications.Count > 0 || p.Id == state.DefaultOutboundVpnProfileId || OwnsTraffic(state, p));

    /// <summary>Profiles connected from the VPN page, whose tunnels run whether or not anything routes through them.</summary>
    public static IEnumerable<VpnProfile> Connected(AppState state) => state.VpnProfiles.Where(p => p.KeepConnected);

    /// <summary>
    /// Profiles the service runs: those the policy routes through, and those kept connected. A disconnected one among them
    /// has no tunnel (<see cref="Tunneled"/>), yet still holds what it carries.
    /// </summary>
    public static IEnumerable<VpnProfile> Running(AppState state) =>
        state.VpnProfiles.Where(p => p.KeepConnected || p.Applications.Count > 0 || p.Id == state.DefaultOutboundVpnProfileId || OwnsTraffic(state, p));

    /// <summary>Profiles whose tunnels the service starts: those it runs, but for the disconnected.</summary>
    public static IEnumerable<VpnProfile> Tunneled(AppState state) => Running(state).Where(p => !p.Disconnected);

    private static bool OwnsTraffic(AppState state, VpnProfile profile) => state.OwnTraffic == OwnRoute.Profile && profile.Id == state.OwnTrafficProfileId;

    /// <summary>Why no profile can carry svchost.exe: Windows services share it, so every one of them would go with it.</summary>
    public const string ServiceHostRefusal = "Windows services share svchost.exe and a VPN profile carries a whole program, so no profile can carry one of them: their traffic follows the default route.";

    /// <summary>Whether a VPN profile can carry the program: anything but svchost.exe, environment variables expanded.</summary>
    public static bool Carriable(string applicationPath) =>
        !Path.GetFileName(Environment.ExpandEnvironmentVariables(applicationPath.Trim())).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>Why no profile can carry a service that is part of Windows, or one sharing its process with others.</summary>
    public const string WindowsServiceRefusal = "This service is part of Windows, or shares its process with other services, so it follows the default route: a VPN profile carries a whole program.";

    /// <summary>
    /// Whether a VPN profile can carry a service's program: one running in a process of its own, so the profile carries that
    /// service and nothing else, and not part of Windows, whose own services keep the default route.
    /// </summary>
    /// <param name="hostedServices">The services the process runs, comma separated.</param>
    public static bool CarriableService(string applicationPath, string hostedServices) =>
        Carriable(applicationPath) && !PartOfWindows(applicationPath) &&
        hostedServices.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Length <= 1;

    /// <summary>A program Windows installs: under the Windows folder, or Microsoft Defender's.</summary>
    public static bool PartOfWindows(string applicationPath)
    {
        var path = Environment.ExpandEnvironmentVariables(applicationPath.Trim());
        string[] windows = [Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender")];
        return windows.Any(folder => folder.Length > 0 && path.StartsWith(Path.TrimEndingDirectorySeparator(folder) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    public static void UseDefault(AppState state, string applicationPath)
    {
        if (!Path.IsPathFullyQualified(applicationPath)) throw new ArgumentException("Select an absolute application path.", nameof(applicationPath));
        var path = Path.GetFullPath(applicationPath);
        foreach (var profile in state.VpnProfiles)
            profile.Applications.RemoveAll(app => Path.GetFullPath(app).Equals(path, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Each executable has one selected tunnel configuration; a configuration can serve many apps.</summary>
    public static void Assign(AppState state, Guid profileId, string applicationPath)
    {
        if (!Carriable(applicationPath)) throw new InvalidOperationException(ServiceHostRefusal);
        if (!Path.IsPathFullyQualified(applicationPath)) throw new ArgumentException("Select an absolute application path.", nameof(applicationPath));
        var profile = state.VpnProfiles.SingleOrDefault(p => p.Id == profileId) ?? throw new InvalidOperationException("VPN profile no longer exists.");
        var path = Path.GetFullPath(applicationPath);
        UseDefault(state, path);
        profile.Applications.Add(path);
    }
}
