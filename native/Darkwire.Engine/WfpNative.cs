using System.Runtime.InteropServices;

namespace Darkwire.Engine;

internal static partial class WfpNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; [MarshalAs(UnmanagedType.LPWStr)] public string? Description; }
    [StructLayout(LayoutKind.Sequential)] internal struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] internal struct Value { [FieldOffset(0)] public uint Type; [FieldOffset(8)] public byte Byte; [FieldOffset(8)] public ushort UShort; [FieldOffset(8)] public uint UInt; [FieldOffset(8)] public IntPtr Pointer; }
    [StructLayout(LayoutKind.Sequential)] internal struct Session { public Guid Key; public Display Display; public uint Flags, Timeout, ProcessId; public IntPtr Sid, Username; public int KernelMode; }
    [StructLayout(LayoutKind.Sequential)] internal struct Sublayer { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public ushort Weight; }
    [StructLayout(LayoutKind.Sequential)] internal struct Condition { public Guid Field; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] internal struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Sequential)] internal struct Filter
    {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data;
        public Guid Layer, Sublayer; public Value Weight; public uint ConditionCount; public IntPtr Conditions;
        public Action Action; public ulong ContextLow, ContextHigh; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Range { public Value Low, High; }
    [StructLayout(LayoutKind.Sequential)] internal struct V4Mask { public uint Address, Mask; }
    [StructLayout(LayoutKind.Sequential)] internal struct V6Mask { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Address; public byte Prefix; }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmEngineOpen0(string? server, uint auth, IntPtr identity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr securityDescriptor);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr securityDescriptor, out ulong id);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string name, out IntPtr appId);
    [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);

    internal static readonly Guid ConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82"), ConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), ReceiveV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), ReceiveV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    internal static readonly Guid AppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971"), Protocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), LocalPort = new("0c1ba1af-5765-453f-af22-a8f791ac775b"), RemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b"), RemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    internal static readonly Guid LocalAddress = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    internal static readonly Guid InboundPacketV4 = new("c86fd1bf-21cd-497e-a0bb-17425c885c58"), InboundPacketV6 = new("f52032cb-991c-46e7-971d-2601459a91ca"), OutboundPacketV4 = new("1e5c9fae-8a84-4135-a331-950b54229ecd"), OutboundPacketV6 = new("a3b3ab6b-3564-488c-9117-f34e82142763");
}
