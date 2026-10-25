using System.Diagnostics;
using System.Threading;

namespace Darkwire.Host;

/// <summary>
/// Whether an upgrade replaced Darkwire's programs while this copy ran. Windows Installer cannot close the running app: it
/// moves the files the app holds open aside, to be deleted at the next restart, and installs the new build in their place,
/// so the app keeps running the build it started with until it starts again.
/// </summary>
public sealed class InstalledBuild
{
    /// <summary>How long a new build's programs stay unchanged before it counts as installed.</summary>
    public static readonly TimeSpan SettleFor = TimeSpan.FromSeconds(5);
    private readonly string folder;
    private readonly Func<bool> installing;
    private readonly Func<DateTime> clock;
    private readonly string started;
    private (string Stamp, DateTime Since)? settling;

    /// <param name="folder">The app's folder, whose programs are read now as the build this copy runs.</param>
    /// <param name="installing">Whether an installation is under way; Windows Installer's by default.</param>
    public InstalledBuild(string folder, Func<bool>? installing = null, Func<DateTime>? clock = null)
    {
        this.folder = folder; this.installing = installing ?? WindowsInstallerBusy; this.clock = clock ?? (() => DateTime.UtcNow);
        started = Stamp(folder);
    }

    /// <summary>Whether a check found a new build in place.</summary>
    public bool Replaced { get; private set; }

    /// <summary>
    /// Looks for a new build: programs other than those this copy started with, Darkwire.exe among them, unchanged for
    /// <see cref="SettleFor"/> while no installation runs. An upgrade writes them over several seconds, and half of one never starts.
    /// </summary>
    public bool Check()
    {
        if (Replaced) return true;
        var now = Stamp(folder);
        if (started.Length == 0 || now.Length == 0 || now == started || !File.Exists(Path.Combine(folder, "Darkwire.exe")) || installing()) { settling = null; return false; }
        if (settling?.Stamp != now) { settling = (now, clock()); return false; }
        return Replaced = clock() - settling.Value.Since >= SettleFor;
    }

    /// <summary>Darkwire's programs in the folder, each by name, size and when it was written; empty when they cannot be read.</summary>
    public static string Stamp(string folder)
    {
        try
        {
            return string.Join("|", new DirectoryInfo(folder).EnumerateFiles("Darkwire*")
                .Where(file => file.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || file.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                .OrderBy(file => file.Name, StringComparer.OrdinalIgnoreCase).Select(file => $"{file.Name} {file.Length} {file.LastWriteTimeUtc.Ticks}"));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { return ""; }
    }

    /// <summary>
    /// Whether Windows Installer is installing something: it holds this mutex meanwhile, and a process that may not open it
    /// still learns that it exists.
    /// </summary>
    public static bool WindowsInstallerBusy()
    {
        try
        {
            if (!Mutex.TryOpenExisting(@"Global\_MSIExecute", out var running)) return false;
            running.Dispose(); return true;
        }
        catch (UnauthorizedAccessException) { return true; }
    }
}

public partial class MainWindow
{
    // Null in demos and captures, which never restart.
    private InstalledBuild? installedBuild;
    private bool restartAsked, quietRestartTried;

    /// <summary>
    /// After an upgrade replaced Darkwire's programs: in the tray Darkwire restarts into the new build by itself; with its
    /// window open a banner says so, and its button restarts it. Neither cuts short a change being applied, a dialog or a
    /// question waiting for an answer.
    /// </summary>
    private void CheckForUpdate()
    {
        if (quitting || installedBuild?.Check() != true) return;
        UpdateBanner.Visibility = Visibility.Visible;
        if (RestartWouldInterrupt) return;
        if (restartAsked) { restartAsked = false; RestartIntoUpdate(); }
        // Once: a copy that cannot start leaves the banner, for the user to try again.
        else if (!IsVisible && !quietRestartTried) { quietRestartTried = true; RestartIntoUpdate(); }
    }

    private bool RestartWouldInterrupt => VpnApplyPending || settingsApplying || settingsTimer?.IsEnabled == true || learningPrompt is not null || OwnedWindows.Count > 0;

    private void RestartForUpdateClick(object sender, RoutedEventArgs e)
    {
        restartAsked = true;
        if (RestartWouldInterrupt) ShowToast("Darkwire restarts once the change being applied is done and its dialogs are closed.");
        CheckForUpdate();
    }

    /// <summary>Starts the new build, which waits for this copy to exit and takes its place: in the tray when this one was there, otherwise on the page shown.</summary>
    private void RestartIntoUpdate()
    {
        var arguments = (IsVisible ? "--page " + currentPage : "--hidden") + " --replace " + Environment.ProcessId;
        try
        {
            using var next = Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Darkwire.exe"), arguments) { UseShellExecute = false, WorkingDirectory = AppContext.BaseDirectory });
            if (next is null) return;
            AppPaths.Log($"Restarting into its update: process {next.Id} started with {arguments}.");
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or IOException)
        {
            AppPaths.Log("Darkwire did not restart into its update: " + error);
            ShowToast("Darkwire could not restart into its update: " + error.Message);
            return;
        }
        quitting = true; Close();
    }
}
