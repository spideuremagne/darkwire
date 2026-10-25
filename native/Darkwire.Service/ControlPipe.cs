using Darkwire.Engine;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Darkwire.Service;

internal static class ControlPipe
{
    /// <summary>Clients the public read lane serves at once, so one waiting on a slow request never times out the next.</summary>
    internal const int PublicInstances = 4;
    /// <summary>
    /// Administrators' requests served at once: a tunnel check never waits for the coordinator, and neither waits behind a
    /// change that does.
    /// </summary>
    internal const int AdministratorInstances = 4;

    public static async Task RunAsync(TakeoverCoordinator coordinator, CancellationToken cancellation)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var read = RunPipeAsync(coordinator, ServiceProtocol.PipeName, PublicInstances, false, lifetime.Token);
        var admin = RunPipeAsync(coordinator, ServiceProtocol.AdministratorPipeName, AdministratorInstances, true, lifetime.Token);
        await Task.WhenAny(read, admin); lifetime.Cancel();
        await Task.WhenAll(read, admin);
    }

    /// <summary>
    /// Serves one pipe with a fixed number of instances, all created before any serves. First-instance detection on the first
    /// prevents silently sharing a name with a pre-existing attacker-controlled pipe, and filling the instance limit leaves no
    /// room to add one later; clients also check that the server is the Darkwire service.
    /// </summary>
    internal static async Task RunPipeAsync(TakeoverCoordinator coordinator, string name, int instances, bool administratorPipe, CancellationToken cancellation)
    {
        var descriptor = IntPtr.Zero;
        List<NamedPipeServerStream> pipes = [];
        // The administrator check runs while impersonating the client at identification level, which cannot open assembly
        // files, so everything it calls is loaded here first.
        using (var self = WindowsIdentity.GetCurrent()) _ = new WindowsPrincipal(self).IsInRole(WindowsBuiltInRole.Administrator);
        try
        {
            var sddl = administratorPipe ? "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)" : "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            for (var i = 0; i < instances; i++)
            {
                var handle = CreateNamedPipe(@"\\.\pipe\" + name, 3u | 0x40000000u | (i == 0 ? 0x00080000u : 0u), 0x8, (uint)instances, 65536, 65536, 0, ref attributes);
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                pipes.Add(new NamedPipeServerStream(PipeDirection.InOut, true, false, handle));
            }
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            var serving = pipes.Select(pipe => ServeAsync(coordinator, pipe, administratorPipe, stop.Token)).ToArray();
            await Task.WhenAny(serving); stop.Cancel();
            await Task.WhenAll(serving);
        }
        finally
        {
            foreach (var pipe in pipes) pipe.Dispose();
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }

    private static async Task ServeAsync(TakeoverCoordinator coordinator, NamedPipeServerStream pipe, bool administratorPipe, CancellationToken cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(cancellation);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(30));
                var answered = await HandleConnectionAsync(coordinator, pipe, administratorPipe, () =>
                {
                    var administrator = false;
                    pipe.RunAsClient(() =>
                    {
                        using var identity = WindowsIdentity.GetCurrent(true) ?? throw new UnauthorizedAccessException("No client identity.");
                        administrator = identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                    });
                    return administrator;
                }, timeout.Token);
                // Disconnecting discards what the client has not read yet, so the reply waits for the client to hang up first.
                if (answered) await AwaitHangUpAsync(pipe, cancellation);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { break; }
            catch (Exception error) when (ClientError(error))
            { ServiceHost.Log("Control request rejected: " + error.Message); }
            finally
            {
                // A client that hung up early leaves the pipe broken rather than connected; only a disconnect makes it serve again.
                try { pipe.Disconnect(); }
                catch (Exception error) when (error is InvalidOperationException or IOException) { }
            }
        }
    }

    /// <summary>Waits briefly for the client to close its end, reading and dropping anything else it sends meanwhile.</summary>
    private static async Task AwaitHangUpAsync(PipeStream pipe, CancellationToken cancellation)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellation); wait.CancelAfter(TimeSpan.FromSeconds(5));
        var buffer = new byte[256];
        try { while (await pipe.ReadAsync(buffer, wait.Token) > 0) { } }
        catch (Exception error) when (error is OperationCanceledException or IOException) { }
    }
    internal static async Task<bool> HandleConnectionAsync(TakeoverCoordinator coordinator, Stream pipe, bool administratorPipe,
        Func<bool> isAdministrator, CancellationToken cancellation)
    {
        try
        {
            // The public read lane accepts only small requests; the admin lane carries policy uploads.
            var request = await ServiceProtocol.ReadAsync<ServiceRequest>(pipe, cancellation, administratorPipe ? ServiceProtocol.MaximumMessageBytes : 1024);
            var administrator = isAdministrator();
            var response = !ServiceClient.IsPublic(request.Command) && (!administrator || !administratorPipe)
                ? new ServiceResponse(false, "Open Darkwire as administrator to change enforced policy.")
                : coordinator.Handle(request);
            await ServiceProtocol.WriteAsync(pipe, response, cancellation); return true;
        }
        catch (Exception error) when (ClientError(error))
        { ServiceHost.Log("Control request rejected: " + error.GetType().Name); return false; }
    }
    private static bool ClientError(Exception error) => error is IOException or InvalidDataException or UnauthorizedAccessException or OperationCanceledException or System.Text.Json.JsonException;
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maximum, uint outputSize, uint inputSize, uint timeout, ref SecurityAttributes attributes);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
