using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Darkwire.Vpn;

/// <summary>Pins a process object, reads its executable from the kernel, and rejects PID-only reuse.</summary>
public sealed class WindowsFlowProcess : IDisposable
{
    private readonly SafeProcessHandle process;
    private bool disposed;
    public int Id { get; }
    public long StartedAt { get; }
    public string ApplicationPath { get; }
    public bool IsAlive => !disposed && WaitForSingleObject(process, 0) == 258;
    private WindowsFlowProcess(SafeProcessHandle process, int id, long start, string path)
    { this.process = process; Id = id; StartedAt = start; ApplicationPath = path; }
    public static WindowsFlowProcess Open(ulong id)
    {
        if (id is 0 or > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(id));
        var handle = OpenProcess(0x1000 | 0x00100000, false, (uint)id);
        try
        {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var path = new StringBuilder(32768); uint count = (uint)path.Capacity;
            if (!QueryFullProcessImageName(handle, 0, path, ref count) || !GetProcessTimes(handle, out var start, out _, out _, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var canonical = Path.GetFullPath(path.ToString());
            if (canonical.Length < 4 || canonical[1] != ':' || !Path.IsPathFullyQualified(canonical) || canonical.AsSpan(2).Contains(':'))
                throw new InvalidDataException("The process executable is not a local file.");
            var result = new WindowsFlowProcess(handle, (int)id, start, canonical);
            if (!result.IsAlive) throw new IOException("The process has exited.");
            return result;
        }
        catch { handle.Dispose(); throw; }
    }
    public void Dispose() { disposed = true; process.Dispose(); }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint id);
    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
}
