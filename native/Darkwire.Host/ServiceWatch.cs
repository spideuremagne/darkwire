using Darkwire.Engine;

namespace Darkwire.Host;

/// <summary>
/// The service status the app shows. The service answers its control pipe one request at a time, so a read can time out
/// while it is busy with another; the last answer stands until several reads in a row miss.
/// </summary>
public sealed class ServiceWatch
{
    public const int MissesBeforeOffline = 3;
    private int misses;

    /// <summary>The last answer; null before the first one, and once enough reads in a row have missed.</summary>
    public ServiceStatus? Status { get; private set; }
    /// <summary>Whether any read has finished, answered or not.</summary>
    public bool Read { get; private set; }
    /// <summary>Why the last read missed; null after an answer.</summary>
    public string? Error { get; private set; }
    public bool Offline => Read && Status is null;

    public void Answered(ServiceStatus status) { Status = status; Error = null; misses = 0; Read = true; }

    public void Missed(string error)
    {
        Read = true; Error = error;
        if (++misses >= MissesBeforeOffline) Status = null;
    }
}

public enum SetupAction { SetUp, RestartElevated, CheckAgain }

/// <summary>The Overview's alert while Darkwire does not enforce, or cannot tell whether it does, and what its button does.</summary>
public sealed record SetupAlert(string Title, string Detail, SetupAction Action)
{
    /// <summary>
    /// Null while Darkwire enforces, and before the service was first read. A service that doesn't answer may well be enforcing,
    /// so it is never reported as not enforcing. Demo sessions show what a newly installed PC would, where Darkwire always runs
    /// as administrator, whatever the session itself runs as.
    /// </summary>
    public static SetupAlert? For(ServiceWatch watch, bool elevated, bool demo = false)
    {
        SetupAlert NotEnforcing() => new("Darkwire isn't enforcing yet", "Windows Firewall is still in control, and Darkwire is only watching." +
            (elevated ? "" : " Darkwire is running without administrator rights, which setup needs."), elevated ? SetupAction.SetUp : SetupAction.RestartElevated);
        if (demo) { elevated = true; return NotEnforcing(); }
        return watch.Status switch
        {
            { Active: true } => null,
            { Phase: "Inactive" } => NotEnforcing(),
            { } recovering => new("Darkwire needs recovery", recovering.Message, SetupAction.CheckAgain),
            null when watch.Offline => new("The Darkwire service isn't answering",
                "Darkwire can't tell whether it is enforcing until its service answers." + (watch.Error is { } error ? " " + error : ""), SetupAction.CheckAgain),
            null => null
        };
    }
}
