using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Darkwire.Vpn;

/// <summary>
/// One Wintun adapter and session from a protected wintun.dll, loaded by full path with a search limited to its own
/// directory and System32. Closing the adapter removes it together with its addresses and routes, so traffic routed
/// to it can never fall back to another interface while Darkwire's leak guard is installed.
/// </summary>
public sealed class WintunTunnel : IDisposable
{
    public const int RingCapacity = 0x800000, MaximumPacket = 0xFFFF;
    private const int NoMoreItems = 259, HandleEof = 38;
    private readonly object sendGate = new();
    private readonly Functions native;
    private IntPtr library, adapter, session;
    private readonly WaitHandle readable;

    public ulong Luid { get; }

    private WintunTunnel(IntPtr library, Functions native, IntPtr adapter, IntPtr session, ulong luid, IntPtr readEvent)
    {
        this.library = library; this.native = native; this.adapter = adapter; this.session = session; Luid = luid;
        readable = new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(readEvent, false) };
    }

    /// <summary>
    /// Creates the adapter and starts its session. Wintun adapters are software devices that vanish with the handle of the
    /// process that created them, so an existing adapter of this name belongs to a live process and is never borrowed.
    /// </summary>
    public static WintunTunnel Create(string libraryPath, string name, Guid id)
    {
        if (!Path.IsPathFullyQualified(libraryPath) || !File.Exists(libraryPath)) throw new FileNotFoundException("The protected Wintun runtime is missing.", libraryPath);
        // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32: dependencies never come from PATH or the working directory.
        var library = LoadLibraryEx(libraryPath, IntPtr.Zero, 0x100 | 0x800);
        if (library == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr adapter = IntPtr.Zero, session = IntPtr.Zero; Functions? native = null;
        try
        {
            native = new Functions(library);
            var existing = native.Open(name);
            if (existing != IntPtr.Zero) { native.Close(existing); throw new InvalidOperationException("Another process owns the " + name + " tunnel adapter."); }
            adapter = native.Create(name, "Darkwire", ref id);
            if (adapter == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError(), "The tunnel adapter could not be created.");
            native.GetLuid(adapter, out var luid);
            session = native.Start(adapter, RingCapacity);
            if (session == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError(), "The tunnel session could not start.");
            var readEvent = native.ReadEvent(session);
            return new(library, native, adapter, session, luid, readEvent);
        }
        catch
        {
            if (session != IntPtr.Zero) native!.End(session);
            if (adapter != IntPtr.Zero) native!.Close(adapter);
            FreeLibrary(library);
            throw;
        }
    }

    /// <summary>Removes the Wintun driver package once no adapter uses it; false while another adapter still does.</summary>
    public static bool DeleteDriver(string libraryPath)
    {
        if (!Path.IsPathFullyQualified(libraryPath) || !File.Exists(libraryPath)) throw new FileNotFoundException("The protected Wintun runtime is missing.", libraryPath);
        var library = LoadLibraryEx(libraryPath, IntPtr.Zero, 0x100 | 0x800);
        if (library == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.GetDelegateForFunctionPointer<DeleteDriverFunction>(NativeLibrary.GetExport(library, "WintunDeleteDriver"))(); }
        finally { FreeLibrary(library); }
    }

    public delegate void PacketHandler(Span<byte> packet);

    /// <summary>
    /// Hands each received packet to the handler, which may rewrite it in place but must not keep the span. Returns when
    /// canceled; throws when the adapter goes away or its ring is corrupt.
    /// </summary>
    public unsafe void Run(PacketHandler handler, CancellationToken cancellation)
    {
        var waits = new[] { readable, cancellation.WaitHandle };
        while (!cancellation.IsCancellationRequested)
        {
            var packet = native.Receive(session, out var size);
            if (packet == IntPtr.Zero)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == NoMoreItems) { WaitHandle.WaitAny(waits); continue; }
                if (error == HandleEof) throw new IOException("The tunnel adapter was removed.");
                throw new Win32Exception(error, "The tunnel ring failed.");
            }
            try { handler(new Span<byte>((void*)packet, checked((int)size))); }
            finally { native.Release(session, packet); }
        }
    }

    /// <summary>Queues a packet toward the host stack; false when the ring is full or the adapter is gone (the packet is dropped).</summary>
    public unsafe bool Send(ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty || packet.Length > MaximumPacket) return false;
        lock (sendGate)
        {
            if (session == IntPtr.Zero) return false;
            var buffer = native.Allocate(session, (uint)packet.Length);
            if (buffer == IntPtr.Zero) return false;
            packet.CopyTo(new Span<byte>((void*)buffer, packet.Length));
            native.Send(session, buffer);
            return true;
        }
    }

    public void Dispose()
    {
        lock (sendGate)
        {
            if (session != IntPtr.Zero) { native.End(session); session = IntPtr.Zero; }
            if (adapter != IntPtr.Zero) { native.Close(adapter); adapter = IntPtr.Zero; }
            if (library != IntPtr.Zero) { FreeLibrary(library); library = IntPtr.Zero; }
        }
        readable.Dispose();
    }

    private sealed class Functions(IntPtr library)
    {
        public readonly CreateAdapter Create = Export<CreateAdapter>(library, "WintunCreateAdapter");
        public readonly OpenAdapter Open = Export<OpenAdapter>(library, "WintunOpenAdapter");
        public readonly CloseAdapter Close = Export<CloseAdapter>(library, "WintunCloseAdapter");
        public readonly GetAdapterLuid GetLuid = Export<GetAdapterLuid>(library, "WintunGetAdapterLUID");
        public readonly StartSession Start = Export<StartSession>(library, "WintunStartSession");
        public readonly EndSession End = Export<EndSession>(library, "WintunEndSession");
        public readonly GetReadWaitEvent ReadEvent = Export<GetReadWaitEvent>(library, "WintunGetReadWaitEvent");
        public readonly ReceivePacket Receive = Export<ReceivePacket>(library, "WintunReceivePacket");
        public readonly ReleaseReceivePacket Release = Export<ReleaseReceivePacket>(library, "WintunReleaseReceivePacket");
        public readonly AllocateSendPacket Allocate = Export<AllocateSendPacket>(library, "WintunAllocateSendPacket");
        public readonly SendPacket Send = Export<SendPacket>(library, "WintunSendPacket");
        private static T Export<T>(IntPtr library, string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)] private delegate IntPtr CreateAdapter(string name, string type, ref Guid requested);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)] private delegate IntPtr OpenAdapter(string name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void CloseAdapter(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void GetAdapterLuid(IntPtr adapter, out ulong luid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] private delegate IntPtr StartSession(IntPtr adapter, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void EndSession(IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate IntPtr GetReadWaitEvent(IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] private delegate IntPtr ReceivePacket(IntPtr session, out uint size);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ReleaseReceivePacket(IntPtr session, IntPtr packet);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] private delegate IntPtr AllocateSendPacket(IntPtr session, uint size);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void SendPacket(IntPtr session, IntPtr packet);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private delegate bool DeleteDriverFunction();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FreeLibrary(IntPtr module);
}
