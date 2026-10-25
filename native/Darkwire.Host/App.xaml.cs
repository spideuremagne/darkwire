using System.Diagnostics;
using System.Threading;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class App : Application
{
    private const string InstanceName = "Local\\Darkwire.Desktop";
    private Mutex? singleInstance;
    private EventWaitHandle? showRequests;
    public static string[] Arguments { get; private set; } = [];
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e); Arguments = e.Args;
        if (e.Args.FirstOrDefault() == "--learning-decision")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = ResolveLearningDecision(e.Args); return;
        }
        // Windows starts every user's copy at sign-in (--tray): one who turned that off sees nothing, and it never opens a window.
        var signIn = e.Args.Contains("--tray");
        if (signIn && !StartsAtSignIn()) { Shutdown(); return; }
        if (!e.Args.Contains("--capture") && !AcquireInstance(e.Args)) { Shutdown(); return; }
        DispatcherUnhandledException += (_, args) =>
        {
            AppPaths.Log(args.Exception.ToString());
            MessageBox.Show(args.Exception.Message, "Darkwire could not complete this action"); args.Handled = true;
        };
        var window = new MainWindow(); MainWindow = window;
        // A copy restarted from the tray into an update goes back there (--hidden).
        if (signIn || e.Args.Contains("--hidden")) window.StartInTray(); else window.Show();
    }

    /// <summary>This user's preference; unreadable settings start the app, as the default does.</summary>
    private static bool StartsAtSignIn()
    {
        try { return StateStore.Read(AppPaths.State).StartAtSignIn; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException) { return true; }
    }
    protected override void OnExit(ExitEventArgs e) { showRequests?.Dispose(); singleInstance?.Dispose(); base.OnExit(e); }

    /// <summary>
    /// One desktop instance per session, elevated or not. Administrator controls hand over to an elevated instance, which
    /// waits here for the one it replaces to exit; any other second launch brings the running window forward and exits.
    /// </summary>
    private bool AcquireInstance(string[] args)
    {
        var wait = TimeSpan.Zero;
        var replace = Array.IndexOf(args, "--replace");
        var replacing = replace >= 0 && replace + 1 < args.Length && int.TryParse(args[replace + 1], out var previousId) ? previousId : (int?)null;
        if (replacing is { } id)
        {
            try { using var previous = Process.GetProcessById(id); if (!previous.WaitForExit(15000)) AppPaths.Log($"The copy this one replaces, process {id}, was still running after 15 seconds."); }
            catch (ArgumentException) { }
            wait = TimeSpan.FromSeconds(5);
        }
        try
        {
            singleInstance = new Mutex(false, InstanceName);
            bool owned;
            try { owned = singleInstance.WaitOne(wait); }
            catch (AbandonedMutexException) { owned = true; }
            if (owned)
            {
                showRequests = new EventWaitHandle(false, EventResetMode.AutoReset, InstanceName + ".Show");
                ThreadPool.RegisterWaitForSingleObject(showRequests, (_, _) => Dispatcher.InvokeAsync(() => (MainWindow as MainWindow)?.BringToFront()), null, Timeout.Infinite, false);
                if (replacing is { } replaced) AppPaths.Log($"Started in place of process {replaced}.");
                return true;
            }
        }
        // An elevated instance owns the name, and integrity levels keep this process from opening its objects.
        catch (UnauthorizedAccessException) { }
        if (replacing is { } kept) AppPaths.Log($"Did not start in place of process {kept}: another copy still runs.");
        try { using var running = EventWaitHandle.OpenExisting(InstanceName + ".Show"); running.Set(); return false; }
        catch (Exception error) when (error is WaitHandleCannotBeOpenedException or UnauthorizedAccessException) { }
        MessageBox.Show("Darkwire is already running with administrator rights. Open it from the system tray.", "Darkwire");
        return false;
    }
    private async Task ResolveLearningDecision(string[] args)
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var administrator = new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            if (!administrator || args.Length != 5 || !Guid.TryParseExact(args[1], "N", out var id) || id == Guid.Empty ||
                args[2] is not ("Allow" or "Deny") || !Enum.TryParse<LearningScope>(args[4], ignoreCase: false, out var scope) ||
                !Enum.IsDefined(scope) || args[4] != scope.ToString()) { Shutdown(2); return; }
            var action = args[2] == "Allow" ? RuleAction.Allow : RuleAction.Deny;
            Darkwire.Engine.LearningRouteChoice? route = args[3] switch
            {
                "unchanged" => null,
                "default" => new(),
                _ when Guid.TryParseExact(args[3], "N", out var profile) && profile != Guid.Empty => new(profile),
                _ => throw new InvalidDataException("Invalid learning route.")
            };
            var response = await Darkwire.Engine.ServiceClient.SendAsync(new("resolve", RequestId: id, Action: action, LearningRoute: route, Scope: scope));
            Shutdown(response.Success ? 0 : 1);
        }
        catch { Shutdown(1); }
    }
}
public static class AppPaths
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Darkwire");
    public static string State => Path.Combine(Root, "settings.json");
    /// <summary>Appends to error.log beside the settings; logging never fails the caller.</summary>
    public static void Log(string text)
    {
        try { Directory.CreateDirectory(Root); File.AppendAllText(Path.Combine(Root, "error.log"), DateTimeOffset.Now + " " + text + Environment.NewLine); } catch { }
    }
}
