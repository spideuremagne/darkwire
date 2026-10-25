using Darkwire.Engine;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Darkwire.Service;

internal static class ServiceHost
{
    public static string StateDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Darkwire", "Service");
    private static readonly ServiceMain main = RunService;
    private static readonly Handler handler = Control;
    private static readonly CancellationTokenSource stop = new();
    private static IntPtr statusHandle;
    private static uint checkpoint;
    private static bool protectedStorageVerified;
    public static void Run()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem) throw new UnauthorizedAccessException("The Windows service must run as LocalSystem.");
        var table = new[] { new ServiceEntry { Name = "Darkwire", Main = main }, new ServiceEntry() };
        if (!StartServiceCtrlDispatcher(table)) throw new Win32Exception(Marshal.GetLastWin32Error());
        GC.KeepAlive(main); GC.KeepAlive(handler);
    }
    private static void RunService(uint count, IntPtr arguments)
    {
        statusHandle = RegisterServiceCtrlHandlerEx("Darkwire", handler, IntPtr.Zero);
        if (statusHandle == IntPtr.Zero) return;
        SetState(2, 0, 30000);
        try
        {
            ProtectedStorage.Verify();
            Volatile.Write(ref protectedStorageVerified, true);
            Directory.CreateDirectory(StateDirectory);
            WireGuardBackend.RecoverOrphansAsync(stop.Token).GetAwaiter().GetResult();
            RemoveOpenVpnLeftovers();
            // Darkwire's own tunnel is neither a keyword source nor an egress for relayed traffic.
            var vault = new VpnProfileVault(StateDirectory, ProtectedStorage.Verify);
            var lists = new BlocklistStore(ServiceDownloads.DownloadAsync, BlocklistStore.DefaultDirectory, TimeProvider.System);
            var geoUpdates = new GeoIpUpdater(ServiceDownloads.DownloadAsync, GeoIpUpdater.SharedDirectory, StateDirectory, TimeProvider.System);
            var resolvers = new ResolverListStore(ServiceDownloads.DownloadAsync, ResolverListStore.DefaultDirectory, TimeProvider.System);
            using var coordinator = new TakeoverCoordinator(new WindowsFirewallControl(), new PolicyJournal(StateDirectory), () => new WfpBackend(),
                new GeoStore(StateDirectory, GeoIpUpdater.SharedPath, GeoIpUpdater.BundledPath),
                vault, new NetworkEnvironment([ConnectionRouter.AdapterId]),
                createRouter: (learning, verifyFilters) => new ConnectionRouter(connection => learning.Ask(connection) is not null, vault, verifyFilters), blocklists: lists,
                geoUpdates: geoUpdates, connected: new FlowAttribution().Connected, resolvers: resolvers);
            lists.Changed = coordinator.UpdateBlocklists;
            resolvers.Changed = coordinator.UpdateResolvers;
            // Darkwire's own downloads follow the route the enforced policy sets for its own connections.
            ServiceDownloads.Route = coordinator.OwnEgress;
            coordinator.Recover();
            SetState(4, 1 | 4, 0);
            RunControlAsync(coordinator, lists, geoUpdates, resolvers, stop.Token).GetAwaiter().GetResult();
            SetState(1, 0, 0);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { SetState(1, 0, 0); }
        catch (Exception error) { Log(error.ToString()); SetState(1, 0, 0, 1066); }
    }
    private static async Task RunControlAsync(TakeoverCoordinator coordinator, BlocklistStore lists, GeoIpUpdater geoUpdates, ResolverListStore resolvers, CancellationToken cancellation)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var pipe = ControlPipe.RunAsync(coordinator, lifetime.Token);
        var monitor = MonitorAsync(coordinator, lifetime.Token);
        var geo = UpdateGeoAsync(coordinator, geoUpdates, lifetime.Token);
        var blocklists = lists.RunAsync(coordinator.EnabledBlocklists, lifetime.Token);
        var resolverList = resolvers.RunAsync(lifetime.Token);
        var completed = await Task.WhenAny(pipe, monitor);
        lifetime.Cancel();
        try { await completed; }
        finally
        {
            try { await Task.WhenAll(pipe, monitor, geo, blocklists, resolverList); }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        }
    }
    /// <summary>
    /// Hourly, asks the updater whether the weekly GeoIP check is due, and checks at once when the desktop app asks; a failed
    /// check never stops the service.
    /// </summary>
    private static async Task UpdateGeoAsync(TakeoverCoordinator coordinator, GeoIpUpdater updater, CancellationToken cancellation)
    {
        // Networking settles after boot before the first scheduled check.
        var requested = await updater.WaitAsync(TimeSpan.FromMinutes(2), cancellation);
        while (true)
        {
            try
            {
                if (await updater.CheckAsync(GeoIpUpdater.InstalledRelease(GeoIpUpdater.SharedPath, GeoIpUpdater.BundledPath),
                    GeoIpUpdater.InstalledCities(GeoIpUpdater.SharedCitiesPath, GeoIpUpdater.BundledCitiesPath), cancellation, requested) is { } next)
                    coordinator.UpdateGeo(next, next.Release);
            }
            catch (Exception error) when (error is not OperationCanceledException) { Log("GeoIP update check failed: " + error.Message); }
            requested = await updater.WaitAsync(TimeSpan.FromHours(1), cancellation);
        }
    }
    private static async Task MonitorAsync(TakeoverCoordinator coordinator, CancellationToken cancellation)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var ticks = 0;
        while (await timer.WaitForNextTickAsync(cancellation))
        {
            var audit = ++ticks % 30 == 0;
            if (audit)
            {
                // Do not write logs into a path whose protection has become uncertain.
                Volatile.Write(ref protectedStorageVerified, false);
                ProtectedStorage.Verify();
                Volatile.Write(ref protectedStorageVerified, true);
            }
            coordinator.Tick(audit);
        }
    }
    /// <summary>
    /// Deletes the configurations and passwords an earlier build's OpenVPN tunnel left in its runtime folder when its service
    /// stopped abruptly. Darkwire runs WireGuard only now; anything else found there stops the service, as it always did.
    /// </summary>
    private static void RemoveOpenVpnLeftovers()
    {
        var runtime = Path.Combine(StateDirectory, "OpenVpnRuntime");
        if (!Directory.Exists(runtime)) return;
        foreach (var file in Directory.EnumerateFiles(runtime))
        {
            if (Path.GetExtension(file) is not (".ovpn" or ".password") || !Guid.TryParseExact(Path.GetFileNameWithoutExtension(file), "N", out var id) || id == Guid.Empty)
                throw new InvalidDataException("Unexpected OpenVPN runtime storage entry.");
            File.Delete(file);
        }
        if (!Directory.EnumerateFileSystemEntries(runtime).Any()) Directory.Delete(runtime);
    }
    private static uint Control(uint control, uint eventType, IntPtr data, IntPtr context)
    {
        if (control is 1 or 5) { SetState(3, 0, 15000); stop.Cancel(); }
        return 0;
    }
    private static void SetState(uint state, uint accepted, uint wait, uint error = 0)
    {
        var status = new Status { Type = 0x10, State = state, Accepted = accepted, Win32Exit = error, SpecificExit = error == 1066 ? 1u : 0u, Checkpoint = state is 2 or 3 ? ++checkpoint : 0, WaitHint = wait };
        SetServiceStatus(statusHandle, ref status);
    }
    internal static void Log(string message)
    {
        // Startup failure can mean this path is attacker-controlled. Never write into it
        // until ownership, ACLs and every ancestor have passed the storage checks.
        if (!Volatile.Read(ref protectedStorageVerified)) return;
        try
        {
            var path = Path.Combine(StateDirectory, "service-error.log");
            if (File.Exists(path) && new FileInfo(path).Length > 1024 * 1024) File.Move(path, path + ".previous", true);
            File.AppendAllText(path, DateTimeOffset.UtcNow.ToString("O") + " " + message + Environment.NewLine);
        }
        catch { }
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMain(uint count, IntPtr arguments);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Handler(uint control, uint eventType, IntPtr data, IntPtr context);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct ServiceEntry { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; public ServiceMain? Main; }
    [StructLayout(LayoutKind.Sequential)] private struct Status { public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartServiceCtrlDispatcher([In] ServiceEntry[] table);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr RegisterServiceCtrlHandlerEx(string name, Handler handler, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceStatus(IntPtr handle, ref Status status);
}
