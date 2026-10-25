using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Darkwire.Engine;

/// <summary>
/// Which running services each process hosts, as the service control manager reports them to any user. A service host
/// running one service is named exactly; one running several cannot say which of them owns a given socket.
/// </summary>
public static class ServiceProcesses
{
    private const uint EnumerateService = 0x0004, ProcessInfo = 0, Win32Services = 0x30, Active = 1, MoreData = 234;

    public static IReadOnlyDictionary<int, IReadOnlyList<string>> Read()
    {
        using var manager = OpenSCManager(null, null, EnumerateService);
        if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        Dictionary<int, List<string>> hosted = [];
        uint resume = 0;
        while (true)
        {
            EnumServicesStatusEx(manager, ProcessInfo, Win32Services, Active, IntPtr.Zero, 0, out var needed, out _, ref resume, null);
            if (needed == 0) break;
            var buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                var more = !EnumServicesStatusEx(manager, ProcessInfo, Win32Services, Active, buffer, needed, out _, out var returned, ref resume, null);
                if (more && Marshal.GetLastWin32Error() != MoreData) throw new Win32Exception(Marshal.GetLastWin32Error());
                // ENUM_SERVICE_STATUS_PROCESSW on x64: two string pointers, then SERVICE_STATUS_PROCESS (nine DWORDs, the eighth the process ID), padded to 56 bytes.
                for (var i = 0; i < returned; i++)
                {
                    var entry = buffer + i * 56;
                    var processId = Marshal.ReadInt32(entry, 16 + 7 * 4);
                    if (processId <= 0 || Marshal.PtrToStringUni(Marshal.ReadIntPtr(entry)) is not { Length: > 0 } name) continue;
                    if (!hosted.TryGetValue(processId, out var names)) hosted[processId] = names = [];
                    names.Add(name);
                }
                if (!more) break;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return hosted.ToDictionary(p => p.Key, p => (IReadOnlyList<string>)p.Value.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private sealed class ServiceManager() : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceManager OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "EnumServicesStatusExW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(ServiceManager manager, uint infoLevel, uint serviceType, uint serviceState, IntPtr services, uint size,
        out uint needed, out uint returned, ref uint resume, string? group);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
