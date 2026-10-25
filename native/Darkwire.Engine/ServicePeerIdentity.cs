using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Darkwire.Engine;

/// <summary>Rejects a squatted pipe by comparing its owner PID to the SCM-owned LocalSystem service.</summary>
internal static class ServicePeerIdentity
{
    public static void ValidateServer(SafePipeHandle pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe, out var pipePid)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = OpenService(manager, "Darkwire", 5); // QUERY_CONFIG | QUERY_STATUS
            if (service == IntPtr.Zero) throw new UnauthorizedAccessException("The Darkwire service is not installed.");
            try
            {
                if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceProcessStatus>(), out _) || status.ProcessId != pipePid || status.State != 4)
                    throw new UnauthorizedAccessException("The control pipe does not belong to the running Darkwire service.");
                QueryServiceConfig(service, IntPtr.Zero, 0, out var size);
                if (size is 0 or > 65536) throw new UnauthorizedAccessException("The service identity could not be verified.");
                var config = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (!QueryServiceConfig(service, config, size, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    var data = Marshal.PtrToStructure<ServiceConfiguration>(config);
                    var account = Marshal.PtrToStringUni(data.StartName);
                    var binary = Marshal.PtrToStringUni(data.BinaryPath) ?? "";
                    var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire", "Service", "Darkwire.Service.exe");
                    if (!string.Equals(account, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
                        !binary.Equals($"\"{expected}\" --service", StringComparison.OrdinalIgnoreCase))
                        throw new UnauthorizedAccessException("The control pipe service identity does not match the installed product.");
                }
                finally { Marshal.FreeHGlobal(config); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceProcessStatus { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint, ProcessId, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfiguration { public uint Type, StartType, Error; public IntPtr BinaryPath, Group; public uint Tag; public IntPtr Dependencies, StartName, Display; }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceProcessStatus status, int size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
}
