using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Darkwire.Vpn;

/// <summary>A private, non-inherited job owns the worker from the instant it is created.</summary>
internal sealed class ContainedProcess : IDisposable
{
    private readonly SafeJobHandle job;
    private readonly Process process;
    private int stopped;
    public int Id { get; }
    public bool HasExited => process.HasExited;
    public int ExitCode => process.ExitCode;
    public Task WaitForExitAsync(CancellationToken cancellation) => process.WaitForExitAsync(cancellation);
    private ContainedProcess(SafeJobHandle job, Process process) { this.job = job; this.process = process; Id = process.Id; }

    public static ContainedProcess Start(string executable, string arguments, int maximumProcesses = 1)
    {
        executable = Path.GetFullPath(executable);
        if (maximumProcesses is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(maximumProcesses));
        if (!File.Exists(executable) || executable.Contains('"') || arguments.IndexOfAny(['\0', '\r', '\n']) >= 0)
            throw new ArgumentException("Invalid worker executable or arguments.");
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) { job.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        var attributes = IntPtr.Zero; var jobs = IntPtr.Zero; var environment = IntPtr.Zero;
        SafeProcessHandle? nativeProcess = null; IntPtr thread = IntPtr.Zero; Process? managedProcess = null;
        var attributeInitialized = false;
        try
        {
            var limits = new ExtendedLimits { Basic = new() { LimitFlags = 0x2000 | 0x8, ActiveProcessLimit = (uint)maximumProcesses } };
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>())) throw new Win32Exception(Marshal.GetLastWin32Error());
            nuint size = 0;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            attributes = Marshal.AllocHGlobal(checked((int)size));
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            attributeInitialized = true;
            jobs = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, (nuint)0x2000d, jobs, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            environment = Marshal.StringToHGlobalUni(BuildEnvironment());
            var startup = new StartupInfoEx { Startup = new() { Size = Marshal.SizeOf<StartupInfoEx>() }, Attributes = attributes };
            // The job list makes creation atomic: even a parent crash before ResumeThread cannot
            // strand a suspended child. No handle is inherited, the job handle included.
            if (!CreateProcess(executable, new StringBuilder('"' + executable + "\" " + arguments), IntPtr.Zero, IntPtr.Zero, false,
                0x00080000 | 0x00000004 | 0x08000000 | 0x00000400, environment, Path.GetDirectoryName(executable)!, ref startup, out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            nativeProcess = new(info.Process, true); thread = info.Thread;
            managedProcess = Process.GetProcessById(info.ProcessId);
            _ = managedProcess.SafeHandle; // Pin this exact process while it is still suspended.
            if (ResumeThread(thread) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new ContainedProcess(job, managedProcess); managedProcess = null; return result;
        }
        catch { job.Dispose(); managedProcess?.Dispose(); throw; }
        finally
        {
            nativeProcess?.Dispose(); if (thread != IntPtr.Zero) CloseHandle(thread);
            if (attributeInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (jobs != IntPtr.Zero) Marshal.FreeHGlobal(jobs);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }

    internal static string BuildEnvironment()
    {
        // Never inherit DOTNET_STARTUP_HOOKS, profiling variables, search-path additions, or
        // user-selected runtimes into the privileged child.
        var system = Environment.SystemDirectory;
        var windows = Directory.GetParent(system)!.FullName;
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windows, ["WINDIR"] = windows, ["PATH"] = system + ";" + windows,
            ["ProgramFiles"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ["ProgramFiles(x86)"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            ["ProgramW6432"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ["TEMP"] = Path.GetTempPath(), ["TMP"] = Path.GetTempPath(),
            ["DOTNET_EnableDiagnostics"] = "0", ["DOTNET_MULTILEVEL_LOOKUP"] = "0"
        };
        return string.Join('\0', values.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
    }

    public void Stop() { if (Interlocked.Exchange(ref stopped, 1) == 0) job.Dispose(); }
    public void Dispose() { Stop(); process.Dispose(); }

    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long PerProcessTime, PerJobTime; public uint LimitFlags; public nuint MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit; public nuint Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits Basic; public IoCounters Io; public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfo
    { public int Size; public IntPtr Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XCount, YCount, FillAttribute, Flags; public ushort ShowWindow, ReservedSize; public IntPtr ReservedData, StandardInput, StandardOutput, StandardError; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Startup; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public IntPtr Process, Thread; public int ProcessId, ThreadId; }
    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    { public SafeJobHandle() : base(true) { } protected override bool ReleaseHandle() => CloseHandle(handle); }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeJobHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeJobHandle job, int kind, ref ExtendedLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation info);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
