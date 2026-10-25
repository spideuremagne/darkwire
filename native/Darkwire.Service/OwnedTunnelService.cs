using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Darkwire.Service;

/// <summary>SCM operations limited to an exact Darkwire-owned WireGuard service command.</summary>
internal sealed class OwnedTunnelService : IDisposable
{
    private readonly ServiceHandle service;
    private readonly string expectedCommand;
    private OwnedTunnelService(ServiceHandle service, string expectedCommand) { this.service = service; this.expectedCommand = expectedCommand; }
    public static string Command(string executable, string configuration)
    {
        if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(configuration) || executable.Contains('"') || configuration.Contains('"') ||
            executable.Any(char.IsControl) || configuration.Any(char.IsControl)) throw new InvalidDataException("Invalid tunnel service path.");
        return $"\"{executable}\" /tunnelservice \"{configuration}\"";
    }
    public static OwnedTunnelService Create(string name, string executable, string configuration)
    {
        using var manager = OpenSCManager(null, null, 3);
        CheckHandle(manager);
        var command = Command(executable, configuration);
        // Demand-start prevents an orphan backend from starting before Darkwire's recovery work.
        var handle = CreateService(manager, name, "Darkwire WireGuard tunnel", 0xF01FF, 0x10, 3, 1, command, null, IntPtr.Zero, "Nsi\0TcpIp\0\0", null, null);
        CheckHandle(handle); var result = new OwnedTunnelService(handle, command);
        try
        {
            uint sidType = 1;
            if (!ChangeServiceConfig2(handle, 5, ref sidType)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GR;;;BA)", 1, out var security, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { if (!SetServiceObjectSecurity(handle, 4, security)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
            finally { LocalFree(security); }
            result.Verify(); return result;
        }
        catch { DeleteService(handle); result.Dispose(); throw; }
    }
    public static OwnedTunnelService? OpenExisting(string name, string executable, string configuration)
    {
        using var manager = OpenSCManager(null, null, 1); CheckHandle(manager);
        var handle = OpenService(manager, name, 0x10000 | 1 | 4 | 0x20);
        if (handle.IsInvalid && Marshal.GetLastWin32Error() == 1060) { handle.Dispose(); return null; }
        CheckHandle(handle); var result = new OwnedTunnelService(handle, Command(executable, configuration));
        try { result.Verify(); return result; } catch { result.Dispose(); throw; }
    }
    public async Task<int> StartAsync(CancellationToken cancellation)
    {
        Verify(); if (!StartService(service, 0, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        while (true)
        {
            var status = Status();
            if (status.State == 4 && status.ProcessId != 0) return checked((int)status.ProcessId);
            if (status.State == 1) throw new IOException($"WireGuard service exited during startup (0x{status.Win32Exit:X8}).");
            await Task.Delay(150, timeout.Token).ConfigureAwait(false);
        }
    }
    public bool IsRunning(int processId) { Verify(); var status = Status(); return status.State == 4 && status.ProcessId == processId; }
    public async Task StopAndDeleteAsync(CancellationToken cancellation)
    {
        Verify(); var status = Status();
        if (status.State != 1 && !ControlService(service, 1, out _) && Marshal.GetLastWin32Error() != 1062)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(20));
        while (Status().State != 1) await Task.Delay(150, timeout.Token).ConfigureAwait(false);
        if (!DeleteService(service) && Marshal.GetLastWin32Error() != 1072) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    private ServiceStatus Status()
    {
        if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return status;
    }
    private void Verify()
    {
        // The first call fails asking for the space it needs; any other failure, such as Windows shutting down, is the reason to give.
        if (!QueryServiceConfig(service, IntPtr.Zero, 0, out var bytes) && Marshal.GetLastWin32Error() is var error and not 122) throw new Win32Exception(error);
        if (bytes is 0 or > 65536) throw new InvalidDataException("Invalid tunnel service configuration size.");
        var memory = Marshal.AllocHGlobal(checked((int)bytes));
        try
        {
            if (!QueryServiceConfig(service, memory, bytes, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var config = Marshal.PtrToStructure<Config>(memory);
            if (config.Type != 0x10 || config.Start != 3 || Marshal.PtrToStringUni(config.Account) != "LocalSystem" ||
                !string.Equals(Marshal.PtrToStringUni(config.Binary), expectedCommand, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("The tunnel service is not owned by this Darkwire installation.");
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    private static void CheckHandle(ServiceHandle handle)
    { if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); } }
    public void Dispose() => service.Dispose();
    [StructLayout(LayoutKind.Sequential)] private struct Config { public uint Type, Start, Error; public IntPtr Binary, Group; public uint Tag; public IntPtr Dependencies, Account, Display; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint, ProcessId, Flags; }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    { public ServiceHandle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle CreateService(ServiceHandle manager, string name, string display, uint access, uint type, uint start, uint error, string binary, string? group, IntPtr tag, string dependencies, string? account, string? password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(ServiceHandle service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref uint value);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartService(ServiceHandle service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatus status, int bytes, out uint needed);
    [StructLayout(LayoutKind.Sequential)] private struct BasicStatus { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint; }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ControlService(ServiceHandle service, uint control, out BasicStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceObjectSecurity(ServiceHandle service, uint kind, IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint bytes);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr data);
}
