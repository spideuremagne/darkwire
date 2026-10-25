using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Darkwire.Service;

/// <summary>SCM registration of the Darkwire service itself. Every operation is limited to the service at the installed path.</summary>
internal static class ServiceRegistration
{
    public const string Name = "Darkwire";
    private const string DisplayName = "Darkwire Filtering Service";
    private const string Description = "Owns persistent firewall policy and authenticated learning decisions.";
    /// <summary>Only SYSTEM and elevated administrators can stop, reconfigure, or delete the service; interactive users can query it.</summary>
    internal const string Sddl = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)";
    /// <summary>Disables managed diagnostic attachment and inherited startup hooks in the privileged process.</summary>
    internal static readonly string[] ProcessEnvironment = ["DOTNET_EnableDiagnostics=0", "COMPlus_EnableDiagnostics=0", "DOTNET_STARTUP_HOOKS=", "CORECLR_ENABLE_PROFILING=0", "COR_ENABLE_PROFILING=0"];
    /// <summary>Restarts after 5, 15 and 30 seconds; the count resets after a day, and failures without a crash count too.</summary>
    private static readonly uint[] RestartDelays = [5000, 15000, 30000];
    private const string Dependencies = "BFE\0MpsSvc\0\0";

    /// <summary>The exact command line clients compare before trusting the control pipe.</summary>
    public static string BinaryPath => $"\"{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire", "Service", "Darkwire.Service.exe")}\" --service";

    /// <summary>Creates the service, or returns an existing registration of this installation to the expected configuration.</summary>
    public static void Install()
    {
        using var manager = OpenManager(ManagerConnect | ManagerCreate);
        using var service = Open(manager, AllAccess) ?? Create(manager);
        RequireOwned(service);
        Check(ChangeServiceConfig(service, OwnProcess, AutoStart, ErrorNormal, BinaryPath, null, IntPtr.Zero, Dependencies, null, null, DisplayName));
        var description = new DescriptionInfo { Text = Description };
        Check(ChangeServiceConfig2(service, 1, ref description));
        uint unrestrictedSid = 1; Check(ChangeServiceConfig2(service, 5, ref unrestrictedSid));
        SetFailureActions(service);
        uint nonCrashFailures = 1; Check(ChangeServiceConfig2(service, 4, ref nonCrashFailures));
        using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + Name, true) ?? throw new InvalidOperationException("The service registry key is missing."))
            key.SetValue("Environment", ProcessEnvironment, RegistryValueKind.MultiString);
        // Last, because it narrows who may reconfigure the service.
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(Sddl, 1, out var security, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { Check(SetServiceObjectSecurity(service, 4, security)); }
        finally { LocalFree(security); }
    }

    /// <summary>Starts the service and waits until it runs; a service that stops during startup fails setup.</summary>
    public static void Start()
    {
        using var manager = OpenManager(ManagerConnect);
        using var service = Open(manager, QueryConfig | QueryStatus | StartAccess) ?? throw new InvalidOperationException("The Darkwire service is not installed.");
        RequireOwned(service);
        if (!StartService(service, 0, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != AlreadyRunning) throw new Win32Exception(error);
        }
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (true)
        {
            var status = Status(service);
            if (status.State == Running) return;
            if (status.State == Stopped)
                throw new InvalidOperationException($"The Darkwire service stopped during startup (exit {status.Win32Exit}, service code {status.SpecificExit}). " +
                    $"Its log is {Path.Combine(ServiceHost.StateDirectory, "service-error.log")}.");
            if (DateTime.UtcNow > deadline) throw new TimeoutException("The Darkwire service did not finish starting.");
            Thread.Sleep(250);
        }
    }

    /// <summary>Stops the service and waits; false when it is not installed.</summary>
    public static bool Stop()
    {
        using var manager = OpenManager(ManagerConnect);
        using var service = Open(manager, QueryConfig | QueryStatus | StopAccess);
        if (service is null) return false;
        RequireOwned(service);
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (true)
        {
            var status = Status(service);
            if (status.State == Stopped) return true;
            if (DateTime.UtcNow > deadline) throw new TimeoutException("The Darkwire service did not stop.");
            // A pending service accepts the stop once it settles.
            if (status.State == Running && !ControlService(service, 1, out _))
            {
                var error = Marshal.GetLastWin32Error();
                if (error is not (NotActive or CannotAcceptControl)) throw new Win32Exception(error);
            }
            Thread.Sleep(250);
        }
    }

    /// <summary>Deletes the registration; false while another open handle (a Services console) delays the SCM's removal.</summary>
    public static bool Delete()
    {
        using var manager = OpenManager(ManagerConnect);
        using (var service = Open(manager, QueryConfig | DeleteAccess))
        {
            if (service is null) return true;
            RequireOwned(service);
            if (!DeleteService(service))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != MarkedForDelete) throw new Win32Exception(error);
            }
        }
        for (var attempt = 0; attempt < 40; attempt++)
        {
            using var remaining = Open(manager, QueryStatus);
            if (remaining is null) return true;
            Thread.Sleep(250);
        }
        return false;
    }

    private static ServiceHandle Create(ServiceHandle manager)
    {
        // The registration an upgrade just deleted stays marked for deletion until every handle to it closes.
        for (var attempt = 0; ; attempt++)
        {
            var handle = CreateService(manager, Name, DisplayName, AllAccess, OwnProcess, AutoStart, ErrorNormal, BinaryPath, null, IntPtr.Zero, Dependencies, null, null);
            if (!handle.IsInvalid) return handle;
            var error = Marshal.GetLastWin32Error(); handle.Dispose();
            if (error != MarkedForDelete) throw new Win32Exception(error);
            if (attempt >= 60) throw new Win32Exception(error, "The previous Darkwire service is still marked for deletion. Close the Services console and run setup again.");
            Thread.Sleep(500);
        }
    }

    private static void RequireOwned(ServiceHandle service)
    {
        QueryServiceConfig(service, IntPtr.Zero, 0, out var bytes);
        if (bytes is 0 or > 65536) throw new InvalidDataException("Invalid service configuration size.");
        var memory = Marshal.AllocHGlobal(checked((int)bytes));
        try
        {
            Check(QueryServiceConfig(service, memory, bytes, out _));
            var config = Marshal.PtrToStructure<Config>(memory);
            if (!string.Equals(Marshal.PtrToStringUni(config.Binary), BinaryPath, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Marshal.PtrToStringUni(config.Account), "LocalSystem", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("A service named Darkwire exists but does not belong to this installation.");
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static void SetFailureActions(ServiceHandle service)
    {
        var size = Marshal.SizeOf<RecoveryAction>();
        var actions = Marshal.AllocHGlobal(size * RestartDelays.Length);
        try
        {
            for (var i = 0; i < RestartDelays.Length; i++) Marshal.StructureToPtr(new RecoveryAction { Type = 1, Delay = RestartDelays[i] }, actions + i * size, false);
            var info = new FailureActionsInfo { ResetPeriod = 86400, Count = (uint)RestartDelays.Length, Actions = actions };
            Check(ChangeServiceConfig2(service, 2, ref info));
        }
        finally { Marshal.FreeHGlobal(actions); }
    }

    private static ServiceHandle OpenManager(uint access)
    {
        var manager = OpenSCManager(null, null, access);
        if (manager.IsInvalid) { var error = Marshal.GetLastWin32Error(); manager.Dispose(); throw new Win32Exception(error); }
        return manager;
    }

    private static ServiceHandle? Open(ServiceHandle manager, uint access)
    {
        var handle = OpenService(manager, Name, access);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastWin32Error(); handle.Dispose();
        return error == DoesNotExist ? null : throw new Win32Exception(error);
    }

    private static ServiceStatus Status(ServiceHandle service)
    {
        Check(QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _));
        return status;
    }

    private static void Check(bool succeeded) { if (!succeeded) throw new Win32Exception(Marshal.GetLastWin32Error()); }

    private const uint ManagerConnect = 0x1, ManagerCreate = 0x2;
    private const uint QueryConfig = 0x1, QueryStatus = 0x4, StartAccess = 0x10, StopAccess = 0x20, DeleteAccess = 0x10000, AllAccess = 0xF01FF;
    private const uint OwnProcess = 0x10, AutoStart = 2, ErrorNormal = 1;
    private const uint Stopped = 1, Running = 4;
    private const int AlreadyRunning = 1056, DoesNotExist = 1060, CannotAcceptControl = 1061, NotActive = 1062, MarkedForDelete = 1072;

    [StructLayout(LayoutKind.Sequential)] private struct Config { public uint Type, Start, Error; public IntPtr Binary, Group; public uint Tag; public IntPtr Dependencies, Account, Display; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint, ProcessId, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicStatus { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct DescriptionInfo { public string Text; }
    [StructLayout(LayoutKind.Sequential)] private struct FailureActionsInfo { public uint ResetPeriod; public IntPtr RebootMessage, Command; public uint Count; public IntPtr Actions; }
    [StructLayout(LayoutKind.Sequential)] private struct RecoveryAction { public uint Type, Delay; }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    { public ServiceHandle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle CreateService(ServiceHandle manager, string name, string display, uint access, uint type, uint start, uint error, string binary, string? group, IntPtr tag, string dependencies, string? account, string? password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig(ServiceHandle service, uint type, uint start, uint error, string? binary, string? group, IntPtr tag, string? dependencies, string? account, string? password, string? display);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref uint value);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref DescriptionInfo value);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref FailureActionsInfo value);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(ServiceHandle service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatus status, int bytes, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartService(ServiceHandle service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ControlService(ServiceHandle service, uint control, out BasicStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceObjectSecurity(ServiceHandle service, uint kind, IntPtr descriptor);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint bytes);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr data);
}
