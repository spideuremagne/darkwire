using Darkwire.Engine;
using Darkwire.Vpn;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Darkwire.Service;

/// <summary>
/// The steps the MSI runs as SYSTEM custom actions: after copying files, before removing them, and on rollback. The service
/// verifies the same ownership, ACLs and file set at every start, so setup reuses its checks rather than restating them.
/// </summary>
internal static class ServiceSetup
{
    // Program tree: SYSTEM and Administrators full control, Users read and execute. State: SYSTEM and Administrators only.
    internal const string ProgramDirectorySddl = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    internal const string ProgramFileSddl = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
    internal const string StateSddl = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private static string ProgramRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire");
    private static string StateRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Darkwire");
    // Unlike a temporary directory, Program Files is writable only by SYSTEM and administrators.
    private static string LogPath => Path.Combine(ProgramRoot, "setup.log");

    /// <summary>Windows Installer formats "--uninstall [UPGRADINGPRODUCTCODE]"; the code is empty unless an upgrade is removing this version.</summary>
    internal static (string Action, bool Upgrading)? Parse(string[] args) => args switch
    {
        ["--install"] => ("install", false),
        ["--rollback"] => ("rollback", false),
        ["--uninstall"] => ("uninstall", false),
        ["--uninstall", var code] when Guid.TryParse(code, out _) => ("uninstall", true),
        _ => null
    };

    public static int Run(string[] args)
    {
        var parsed = Parse(args);
        if (parsed is null) { Console.Error.WriteLine("Darkwire.Service --install | --uninstall [upgrading product code] | --rollback"); return 2; }
        var (action, upgrading) = parsed.Value;
        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
                if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("Setup actions require SYSTEM or an elevated administrator.");
            if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(Path.Combine(ProgramRoot, "Service"), StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Setup actions run only from the installed service directory.");
            Log(action + (upgrading ? " for an upgrade" : "") + ": started");
            if (action == "install") Install();
            else if (action == "rollback") Rollback();
            else Uninstall(upgrading);
            Log(action + ": completed");
            // A completed removal leaves nothing behind; an upgrade keeps the log for the version replacing this one.
            if (action == "uninstall" && !upgrading) File.Delete(LogPath);
            return 0;
        }
        catch (Exception error)
        {
            Log(action + ": failed: " + error);
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static void Install()
    {
        ProtectedStorage.CheckParents(ProgramRoot);
        Protect(new DirectoryInfo(ProgramRoot));
        PrepareState(StateRoot);
        PrepareState(ServiceHost.StateDirectory);
        // The service runs the same checks at every start; failing here rolls the installation back with the reason logged.
        ProtectedStorage.Verify();
        ServiceRegistration.Install();
        ServiceRegistration.Start();
        // Opening the app at sign-in is a convenience: Darkwire installs and protects without it.
        try { SignInTask.Register(Path.Combine(ProgramRoot, "Darkwire.exe")); Log("sign-in task registered"); }
        catch (Exception error) { Log("sign-in task not registered: " + error.Message); }
    }

    /// <summary>
    /// Removal restores Windows Firewall before anything is deleted. An upgrade keeps state, persistent filters and an active
    /// takeover: the next version's service recovers them, and the kernel plan keeps blocking while no service runs.
    /// </summary>
    private static void Uninstall(bool upgrading)
    {
        ServiceRegistration.Stop();
        if (!upgrading)
        {
            try { Restore(); }
            catch
            {
                // Persistent filters are never left without the service that owns them.
                try { ServiceRegistration.Start(); } catch (Exception error) { Log("service restart after failed restoration: " + error.Message); }
                throw;
            }
        }
        RecoverTunnels();
        if (!ServiceRegistration.Delete()) Log("service removal completes when other handles to it close");
        if (upgrading) return;
        RemoveSignInTask();
        RemoveWintunDriver();
        RemoveState();
    }

    private static void RemoveSignInTask()
    {
        try { SignInTask.Remove(); Log("sign-in task removed"); }
        catch (Exception error) { Log("sign-in task removal skipped: " + error.Message); }
    }

    /// <summary>A failed or canceled installation leaves no service and Windows Firewall in control, even when an upgrade kept a takeover.</summary>
    private static void Rollback()
    {
        ServiceRegistration.Stop();
        try { Restore(); } catch (Exception error) { Log("rollback restoration failed: " + error.Message); }
        RecoverTunnels();
        ServiceRegistration.Delete();
        RemoveSignInTask();
    }

    /// <summary>Replaces inherited Program Files ACLs, which grant TrustedInstaller and package SIDs, refusing reparse points before descending.</summary>
    private static void Protect(DirectoryInfo directory)
    {
        RequireNoReparsePoint(directory);
        directory.SetAccessControl(Security<DirectorySecurity>(ProgramDirectorySddl));
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            RequireNoReparsePoint(entry);
            if (entry is DirectoryInfo child) Protect(child);
            else ((FileInfo)entry).SetAccessControl(Security<FileSecurity>(ProgramFileSddl));
        }
    }

    /// <summary>
    /// ProgramData is writable by every user, so an existing state directory is adopted only if it already passes the service's
    /// ownership, ACL and reparse-point checks. Otherwise it may hold planted state, and setup stops.
    /// </summary>
    private static void PrepareState(string path)
    {
        var directory = new DirectoryInfo(path);
        ProtectedStorage.CheckParents(directory.Parent!.FullName);
        if (directory.Exists)
        {
            RequireNoReparsePoint(directory);
            try { ProtectedStorage.VerifyAcl(directory.GetAccessControl()); ProtectedStorage.VerifyTree(path); }
            catch (UnauthorizedAccessException error)
            { throw new UnauthorizedAccessException($"{path} already exists and is not protected: {error.Message} Review and remove it, then run setup again.", error); }
        }
        else directory.Create(Security<DirectorySecurity>(StateSddl));
        directory.SetAccessControl(Security<DirectorySecurity>(StateSddl));
    }

    /// <summary>Runs the coordinator's own restoration with the service stopped, so nothing races it.</summary>
    private static void Restore()
    {
        var state = ServiceHost.StateDirectory;
        if (!Directory.Exists(state)) return;
        // The journal decides which profile states come back, so it must still be protected state.
        ProtectedStorage.CheckParents(state);
        ProtectedStorage.VerifyAcl(new DirectoryInfo(state).GetAccessControl());
        ProtectedStorage.VerifyTree(state);
        using var coordinator = new TakeoverCoordinator(new WindowsFirewallControl(), new PolicyJournal(state), () => new WfpBackend());
        var response = coordinator.Handle(new("restore"));
        if (!response.Success) throw new InvalidOperationException("Windows Firewall restoration failed: " + response.Message);
        Log(response.Message);
    }

    private static void RecoverTunnels()
    {
        try { WireGuardBackend.RecoverOrphansAsync(CancellationToken.None).GetAwaiter().GetResult(); }
        catch (Exception error) { Log("tunnel recovery skipped: " + error.Message); }
    }

    private static void RemoveWintunDriver()
    {
        if (!File.Exists(ConnectionRouter.LibraryPath)) return;
        try { Log(WintunTunnel.DeleteDriver(ConnectionRouter.LibraryPath) ? "Wintun driver removed" : "Wintun driver kept: another adapter still uses it"); }
        catch (Exception error) { Log("Wintun driver removal skipped: " + error.Message); }
    }

    /// <summary>Deletes the journal, firewall backup, VPN vault and logs after restoration, and only while they are still protected.</summary>
    private static void RemoveState()
    {
        var root = new DirectoryInfo(StateRoot);
        if (!root.Exists) return;
        try
        {
            ProtectedStorage.CheckParents(root.FullName);
            ProtectedStorage.VerifyAcl(root.GetAccessControl());
            ProtectedStorage.VerifyTree(root.FullName);
            root.Delete(recursive: true);
            Log("service state removed");
        }
        catch (Exception error) { Log("service state kept at " + root.FullName + ": " + error.Message); }
    }

    private static void RequireNoReparsePoint(FileSystemInfo entry)
    { if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Setup refuses the reparse point at " + entry.FullName + "."); }

    private static T Security<T>(string sddl) where T : FileSystemSecurity, new()
    { var security = new T(); security.SetSecurityDescriptorSddlForm(sddl); return security; }

    private static void Log(string message)
    {
        try { if (Directory.Exists(ProgramRoot)) File.AppendAllText(LogPath, DateTimeOffset.Now.ToString("O") + " " + message + Environment.NewLine); }
        catch { }
    }
}
