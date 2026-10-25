using System.Runtime.InteropServices;

namespace Darkwire.Engine;

internal static partial class WfpNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct Provider
    { public Guid Key; public Display Display; public uint Flags; public Blob Data; [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName; }
    [StructLayout(LayoutKind.Sequential)] internal struct EventSubscription { public IntPtr Template; public uint Flags; public Guid SessionKey; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void NetEventCallback(IntPtr context, IntPtr netEvent);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderAdd0(IntPtr engine, ref Provider provider, IntPtr descriptor);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint count, out IntPtr filters, out uint returned);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineSetOption0(IntPtr engine, uint option, ref Value value);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmNetEventSubscribe1(IntPtr engine, ref EventSubscription subscription, NetEventCallback callback, IntPtr context, out IntPtr events);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmNetEventUnsubscribe0(IntPtr engine, IntPtr events);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern uint QueryDosDevice(string device, System.Text.StringBuilder target, int maximum);
}
