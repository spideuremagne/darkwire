using System.Runtime.InteropServices;

namespace Darkwire.Engine;

/// <summary>
/// Network category per interface LUID from the Network List Manager, as WFP profile IDs (Public 1, Private 2, Domain 3).
/// An adapter attached to several networks takes the most public one, so a profile-scoped allow never widens.
/// </summary>
public static class NetworkProfiles
{
    public static IReadOnlyDictionary<ulong, uint> Read()
    {
        var result = new Dictionary<ulong, uint>();
        var type = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"));
        if (type is null) return result;
        object? instance = null;
        try
        {
            instance = Activator.CreateInstance(type);
            var connections = ((INetworkListManager)instance!).GetNetworkConnections();
            try
            {
                while (connections.Next(1, out var connection, out var fetched) == 0 && fetched == 1)
                {
                    try
                    {
                        var adapter = connection.GetAdapterId();
                        var network = connection.GetNetwork();
                        int category;
                        try { category = network.GetCategory(); }
                        finally { Marshal.ReleaseComObject(network); }
                        // NLM_NETWORK_CATEGORY: Public 0, Private 1, DomainAuthenticated 2.
                        if (category is < 0 or > 2 || ConvertInterfaceGuidToLuid(ref adapter, out var luid) != 0) continue;
                        var profile = (uint)category + 1;
                        result[luid] = result.TryGetValue(luid, out var known) ? Math.Min(known, profile) : profile;
                    }
                    finally { Marshal.ReleaseComObject(connection); }
                }
            }
            finally { Marshal.ReleaseComObject(connections); }
        }
        catch (COMException) { }
        finally { if (instance is not null) Marshal.FinalReleaseComObject(instance); }
        return result;
    }

    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceGuidToLuid(ref Guid id, out ulong luid);

    // Vtable order from netlistmgr.idl; only the slots used here and those before them are declared.
    [ComImport, Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkListManager
    {
        [return: MarshalAs(UnmanagedType.IUnknown)] object GetNetworks(int flags);
        [return: MarshalAs(UnmanagedType.IUnknown)] object GetNetwork(Guid id);
        IEnumNetworkConnections GetNetworkConnections();
    }

    [ComImport, Guid("DCB00006-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IEnumNetworkConnections
    {
        [return: MarshalAs(UnmanagedType.IUnknown)] object NewEnum();
        [PreserveSig] int Next(uint count, out INetworkConnection connection, out uint fetched);
    }

    [ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkConnection
    {
        INetwork GetNetwork();
        [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnectedToInternet();
        [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnected();
        int GetConnectivity();
        Guid GetConnectionId();
        Guid GetAdapterId();
    }

    [ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetwork
    {
        [return: MarshalAs(UnmanagedType.BStr)] string GetName();
        void SetName([MarshalAs(UnmanagedType.BStr)] string name);
        [return: MarshalAs(UnmanagedType.BStr)] string GetDescription();
        void SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
        Guid GetNetworkId();
        int GetDomainType();
        [return: MarshalAs(UnmanagedType.IUnknown)] object GetNetworkConnections();
        void GetTimeCreatedAndConnected(out uint createdLow, out uint createdHigh, out uint connectedLow, out uint connectedHigh);
        [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnectedToInternet();
        [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnected();
        int GetConnectivity();
        int GetCategory();
    }
}
