using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Darkwire.Service;

/// <summary>System audit settings per subcategory, as POLICY_AUDIT_EVENT_* flags (1 success, 2 failure).</summary>
public interface IAuditPolicy
{
    IReadOnlyDictionary<Guid, uint> Query(IReadOnlyList<Guid> subcategories);
    void Set(IReadOnlyDictionary<Guid, uint> settings);
}

/// <summary>Advanced audit policy through AuditQuerySystemPolicy/AuditSetSystemPolicy. Requires SeSecurityPrivilege.</summary>
internal sealed class WindowsAuditPolicy : IAuditPolicy
{
    // Filtering Platform Connection (5157 blocked connections) and Packet Drop (5152) under Object Access.
    public static readonly Guid FilteringConnection = new("0CCE9226-69AE-11D9-BED3-505054503030"), FilteringPacketDrop = new("0CCE9225-69AE-11D9-BED3-505054503030");
    private static readonly Guid ObjectAccess = new("6997984A-797A-11D9-BED3-505054503030");
    private const uint None = 0x4;

    public IReadOnlyDictionary<Guid, uint> Query(IReadOnlyList<Guid> subcategories)
    {
        EnableSecurityPrivilege();
        if (!AuditQuerySystemPolicy(subcategories.ToArray(), (uint)subcategories.Count, out var buffer)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var size = Marshal.SizeOf<Information>();
            return Enumerable.Range(0, subcategories.Count).Select(i => Marshal.PtrToStructure<Information>(buffer + i * size))
                .ToDictionary(p => p.Subcategory, p => p.Auditing & 0x3);
        }
        finally { AuditFree(buffer); }
    }

    public void Set(IReadOnlyDictionary<Guid, uint> settings)
    {
        EnableSecurityPrivilege();
        // POLICY_AUDIT_EVENT_NONE clears both bits; zero would leave the current value unchanged.
        var entries = settings.Select(p => new Information { Subcategory = p.Key, Auditing = (p.Value & 0x3) == 0 ? None : p.Value & 0x3, Category = ObjectAccess }).ToArray();
        if (!AuditSetSystemPolicy(entries, (uint)entries.Length)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static void EnableSecurityPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out var token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 0x2 };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                throw new UnauthorizedAccessException("SeSecurityPrivilege is unavailable to the service.");
        }
        finally { CloseHandle(token); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct Information { public Guid Subcategory; public uint Auditing; public Guid Category; }
    // TOKEN_PRIVILEGES with one LUID_AND_ATTRIBUTES; LUID is two 32-bit fields, so it is 4-byte aligned.
    [StructLayout(LayoutKind.Sequential, Pack = 4)] private struct TokenPrivileges { public uint Count; public long Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditQuerySystemPolicy(Guid[] subcategories, uint count, out IntPtr policy);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditSetSystemPolicy(Information[] policy, uint count);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, uint length, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
