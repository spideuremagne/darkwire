using Darkwire.Vpn;
using System.Diagnostics;
using System.Globalization;

/// <summary>The contained child processes the service starts, and the process identity it pins for a tunnel backend.</summary>
internal static class ProcessChecks
{
    private static void Assert(bool value, string message = "Process invariant failed.") { if (!value) throw new Exception(message); }
    private static string Executable => Path.Combine(AppContext.BaseDirectory, "Darkwire.Vpn.Checks.exe");

    // The checks executable stands in for both the parent that starts a contained child and that child.
    public static async Task<int?> RunChild(string[] args)
    {
        if (args.SequenceEqual(new[] { "--test-contained-parent" }))
        {
            using var child = ContainedProcess.Start(Executable, "--test-contained-child");
            Console.WriteLine(child.Id.ToString(CultureInfo.InvariantCulture)); await Console.Out.FlushAsync();
            await Task.Delay(Timeout.Infinite); return 0;
        }
        if (args.SequenceEqual(new[] { "--test-contained-child" })) { await Task.Delay(Timeout.Infinite); return 0; }
        return null;
    }

    public static void Run(Action<string, Action> check, bool native)
    {
        check("Contained process environment excludes inherited startup hooks and profiling", () =>
        {
            var old = Environment.GetEnvironmentVariable("DOTNET_STARTUP_HOOKS");
            try
            {
                Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", @"C:\Untrusted\hook.dll");
                var block = ContainedProcess.BuildEnvironment();
                Assert(!block.Contains("STARTUP_HOOKS") && !block.Contains("COR_PROFILER") && block.Contains("DOTNET_EnableDiagnostics=0\0") && block.EndsWith("\0\0"));
            }
            finally { Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", old); }
        });
        if (!native) return;
        check("Contained child is killed when its parent process dies abruptly", () => ParentCrash().GetAwaiter().GetResult());
        check("Pinned process identity matches the current executable and cannot outlive disposal", () =>
        {
            using var identity = WindowsFlowProcess.Open((ulong)Environment.ProcessId);
            Assert(identity.Id == Environment.ProcessId && identity.StartedAt > 0 && identity.IsAlive);
            Assert(identity.ApplicationPath.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase));
            identity.Dispose(); Assert(!identity.IsAlive);
        });
    }

    private static async Task ParentCrash()
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var info = new ProcessStartInfo(Executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("--test-contained-parent");
        using var parent = Process.Start(info) ?? throw new Exception("Could not start test parent."); Process? child = null;
        try
        {
            var line = await parent.StandardOutput.ReadLineAsync(limit.Token);
            if (!int.TryParse(line, out var id)) throw new Exception("Test parent failed: " + await parent.StandardError.ReadToEndAsync(limit.Token));
            child = Process.GetProcessById(id); _ = child.SafeHandle;
            parent.Kill(); await parent.WaitForExitAsync(limit.Token);
            await child.WaitForExitAsync(limit.Token); Assert(child.HasExited, "Job handle survived its parent.");
        }
        finally
        {
            if (!parent.HasExited) parent.Kill();
            if (child is not null) { if (!child.HasExited) child.Kill(); child.Dispose(); }
        }
    }
}
