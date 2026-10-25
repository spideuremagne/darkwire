using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Darkwire.Engine;

public sealed record ConditionRecord(string Field, string Match, string Value);
public sealed record FilterRecord(ulong Id, string Name, string Provider, string Sublayer, string Layer, string Action, ulong Weight, uint Flags,
    IReadOnlyList<ConditionRecord> Conditions, string? ProviderData);

/// <summary>Read-only decoding of installed WFP filters. Enumeration requires an administrator or SYSTEM.</summary>
public static class WfpInventory
{
    public static readonly Guid MpssvcFirewallProvider = new("decc16ca-3f33-4346-be1e-8fb4ae0f3d62"), MpssvcHardeningProvider = new("4b153735-1049-4480-aab4-d1b9bdc03710"),
        MpssvcAppIsolationProvider = new("3cc2631f-2d5d-43a0-b174-614837d863a1");
    // Names from Windows SDK 10.0.26100.0 fwpmu.h. Unknown GUIDs are reported verbatim.
    private static readonly Dictionary<Guid, string> Names = new Dictionary<string, string>
    {
        ["c86fd1bf-21cd-497e-a0bb-17425c885c58"] = "INBOUND_IPPACKET_V4", ["f52032cb-991c-46e7-971d-2601459a91ca"] = "INBOUND_IPPACKET_V6",
        ["1e5c9fae-8a84-4135-a331-950b54229ecd"] = "OUTBOUND_IPPACKET_V4", ["a3b3ab6b-3564-488c-9117-f34e82142763"] = "OUTBOUND_IPPACKET_V6",
        ["5926dfc8-e3cf-4426-a283-dc393f5d0f9d"] = "INBOUND_TRANSPORT_V4", ["634a869f-fc23-4b90-b0c1-bf620a36ae6f"] = "INBOUND_TRANSPORT_V6",
        ["09e61aea-d214-46e2-9b21-b26b0b2f28c8"] = "OUTBOUND_TRANSPORT_V4", ["e1735bde-013f-4655-b351-a49e15762df0"] = "OUTBOUND_TRANSPORT_V6",
        ["1247d66d-0b60-4a15-8d44-7155d0f53a0c"] = "ALE_RESOURCE_ASSIGNMENT_V4", ["55a650e1-5f0a-4eca-a653-88f53b26aa8c"] = "ALE_RESOURCE_ASSIGNMENT_V6",
        ["88bb5dad-76d7-4227-9c71-df0a3ed7be7e"] = "ALE_AUTH_LISTEN_V4", ["7ac9de24-17dd-4814-b4bd-a9fbc95a321b"] = "ALE_AUTH_LISTEN_V6",
        ["e1cd9fe7-f4b5-4273-96c0-592e487b8650"] = "ALE_AUTH_RECV_ACCEPT_V4", ["a3b42c97-9f04-4672-b87e-cee9c483257f"] = "ALE_AUTH_RECV_ACCEPT_V6",
        ["c38d57d1-05a7-4c33-904f-7fbceee60e82"] = "ALE_AUTH_CONNECT_V4", ["4a72393b-319f-44bc-84c3-ba54dcb3b6b4"] = "ALE_AUTH_CONNECT_V6",
        ["af80470a-5596-4c13-9992-539e6fe57967"] = "ALE_FLOW_ESTABLISHED_V4", ["7021d2b3-dfa4-406e-afeb-6afaf7e70efd"] = "ALE_FLOW_ESTABLISHED_V6",
        ["c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3"] = "ALE_CONNECT_REDIRECT_V4", ["587e54a7-8046-42ba-a0aa-b716250fc7fd"] = "ALE_CONNECT_REDIRECT_V6",
        ["66978cad-c704-42ac-86ac-7c1a231bd253"] = "ALE_BIND_REDIRECT_V4", ["bef02c9c-606b-4536-8c26-1c2fc7b631d4"] = "ALE_BIND_REDIRECT_V6",
        ["eebecc03-ced4-4380-819a-2734397b2b74"] = "SUBLAYER_UNIVERSAL", ["ba69dc66-5176-4979-9c89-26a7b46a8327"] = "SUBLAYER_TEREDO",
        ["b3cdd441-af90-41ba-a745-7c6008ff2300"] = "SUBLAYER_MPSSVC_WSH", ["b3cdd441-af90-41ba-a745-7c6008ff2301"] = "SUBLAYER_MPSSVC_WF",
        ["b3cdd441-af90-41ba-a745-7c6008ff2302"] = "SUBLAYER_MPSSVC_QUARANTINE", ["09a47e38-fa97-471b-b123-18bcd7e65071"] = "SUBLAYER_MPSSVC_EDP",
        ["1ec6c7e1-fdd9-478a-b55f-ff8ba1d2c17d"] = "SUBLAYER_MPSSVC_TENANT_RESTRICTIONS", ["ffe221c3-92a8-4564-a59f-dafb70756020"] = "SUBLAYER_MPSSVC_APP_ISOLATION",
        ["4b153735-1049-4480-aab4-d1b9bdc03710"] = "PROVIDER_MPSSVC_WSH", ["decc16ca-3f33-4346-be1e-8fb4ae0f3d62"] = "PROVIDER_MPSSVC_WF",
        ["a90296f7-46b8-4457-8f84-b05e05d3c622"] = "PROVIDER_MPSSVC_EDP", ["d0718ff9-44da-4f50-9dc2-c963a4247613"] = "PROVIDER_MPSSVC_TENANT_RESTRICTIONS",
        ["3cc2631f-2d5d-43a0-b174-614837d863a1"] = "PROVIDER_MPSSVC_APP_ISOLATION",
        ["81bc78fb-f28d-4886-a604-6acc261f261b"] = "ALE_PACKAGE_FAMILY_NAME", ["71bc78fa-f17c-4997-a602-6abb261f351c"] = "ALE_PACKAGE_ID",
        ["37a57699-5883-4963-92b8-3e704688b0ad"] = "ALE_SECURITY_ATTRIBUTE_FQBN_VALUE", ["37a57700-5884-4964-92b8-3e704688b0ad"] = "IPSEC_SECURITY_REALM_ID",
        ["b1277b9a-b781-40fc-9671-e5f1b989f34e"] = "ALE_EFFECTIVE_NAME", ["d9ee00de-c1ef-4617-bfe3-ffd8f5a08957"] = "IP_LOCAL_ADDRESS",
        ["b235ae9a-1d64-49b8-a44c-5ff3d9095045"] = "IP_REMOTE_ADDRESS", ["6ec7f6c4-376b-45d7-9e9c-d337cedcd237"] = "IP_LOCAL_ADDRESS_TYPE",
        ["1ec1b7c9-4eea-4f5e-b9ef-76beaaaf17ee"] = "IP_DESTINATION_ADDRESS_TYPE", ["4cd62a49-59c3-4969-b7f3-bda5d32890a4"] = "IP_LOCAL_INTERFACE",
        ["618a9b6d-386b-4136-ad6e-b51587cfb1cd"] = "IP_ARRIVAL_INTERFACE", ["89f990de-e798-4e6d-ab76-7c9558292e6f"] = "ARRIVAL_INTERFACE_TYPE",
        ["511166dc-7a8c-4aa7-b533-95ab59fb0340"] = "ARRIVAL_TUNNEL_TYPE", ["cc088db3-1792-4a71-b0f9-037d21cd828b"] = "ARRIVAL_INTERFACE_INDEX",
        ["93ae8f5b-7f6f-4719-98c8-14e97429ef04"] = "IP_NEXTHOP_INTERFACE", ["97537c6c-d9a3-4767-a381-e942675cd920"] = "NEXTHOP_INTERFACE_TYPE",
        ["72b1a111-987b-4720-99dd-c7c576fa2d4c"] = "NEXTHOP_TUNNEL_TYPE", ["46ea1551-2255-492b-8019-aabeee349f40"] = "ORIGINAL_PROFILE_ID",
        ["ab3033c9-c0e3-4759-937d-5758c65d4ae3"] = "CURRENT_PROFILE_ID", ["4ebf7562-9f18-4d06-9941-a7a625744d71"] = "LOCAL_INTERFACE_PROFILE_ID",
        ["cdfe6aab-c083-4142-8679-c08f95329c61"] = "ARRIVAL_INTERFACE_PROFILE_ID", ["d7ff9a56-cdaa-472b-84db-d23963c1d1bf"] = "NEXTHOP_INTERFACE_PROFILE_ID",
        ["11205e8c-11ae-457a-8a44-477026dd764a"] = "REAUTHORIZE_REASON", ["076dfdbe-c56c-4f72-ae8a-2cfe7e5c8286"] = "ORIGINAL_ICMP_TYPE",
        ["daf8cd14-e09e-4c93-a5ae-c5c13b73ffca"] = "INTERFACE_TYPE", ["77a40437-8779-4868-a261-f5a902f1c0cd"] = "TUNNEL_TYPE",
        ["3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"] = "IP_PROTOCOL", ["0c1ba1af-5765-453f-af22-a8f791ac775b"] = "IP_LOCAL_PORT",
        ["c35a604d-d22b-4e1a-91b4-68f674ee674b"] = "IP_REMOTE_PORT", ["632ce23b-5167-435c-86d7-e903684aa80c"] = "FLAGS",
        ["8784c146-ca97-44d6-9fd1-19fb1840cbf7"] = "DIRECTION", ["667fd755-d695-434a-8af5-d3835a1259bc"] = "INTERFACE_INDEX",
        ["0cd42473-d621-4be3-ae8c-72a348d283e1"] = "SUB_INTERFACE_INDEX", ["d78e1e87-8644-4ea5-9437-d809ecefc971"] = "ALE_APP_ID",
        ["0e6cd086-e1fb-4212-842f-8a9f993fb3f6"] = "ALE_ORIGINAL_APP_ID", ["af043a0a-b34d-4f86-979c-c90371af6e66"] = "ALE_USER_ID",
        ["f63073b7-0189-4ab0-95a4-6123cbfab862"] = "ALE_REMOTE_USER_ID", ["1aa47f51-7f93-4508-a271-81abb00c9cab"] = "ALE_REMOTE_MACHINE_ID",
        ["b9f4e088-cb98-4efb-a2c7-ad07332643db"] = "ALE_SIO_FIREWALL_SYSTEM_PORT", ["b482d227-1979-4a98-8044-18bbe6237542"] = "ALE_REAUTH_REASON",
        ["9b539082-eb90-4186-a6cc-de5b63235016"] = "PEER_NAME", ["35a791ab-04ac-4ff2-a6bb-da6cfac71806"] = "COMPARTMENT_ID"
    }.ToDictionary(p => new Guid(p.Key), p => p.Value);
    private static readonly string[] MatchNames = ["EQUAL", "GREATER", "LESS", "GREATER_OR_EQUAL", "LESS_OR_EQUAL", "RANGE", "FLAGS_ALL_SET", "FLAGS_ANY_SET", "FLAGS_NONE_SET", "EQUAL_CASE_INSENSITIVE", "NOT_EQUAL", "PREFIX", "NOT_PREFIX"];

    public static string Name(Guid key) => Names.TryGetValue(key, out var name) ? name : key.ToString();
    public static string Match(uint match) => match < MatchNames.Length ? MatchNames[match] : "MATCH_" + match;

    /// <summary>Reads every installed filter that satisfies <paramref name="include"/> (by provider key).</summary>
    public static IReadOnlyList<FilterRecord> Read(Func<Guid?, bool>? include = null)
    {
        var session = new WfpNative.Session { Key = Guid.NewGuid(), Timeout = 5000, Display = new() { Name = "Darkwire inventory" } };
        Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out var engine));
        try
        {
            List<FilterRecord> result = [];
            Check(WfpNative.FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out var enumeration));
            try
            {
                while (true)
                {
                    Check(WfpNative.FwpmFilterEnum0(engine, enumeration, 512, out var entries, out var count));
                    try
                    {
                        for (var i = 0; i < count; i++)
                        {
                            var filter = Marshal.PtrToStructure<WfpNative.Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                            Guid? provider = filter.Provider == IntPtr.Zero ? null : Marshal.PtrToStructure<Guid>(filter.Provider);
                            if (include is not null && !include(provider)) continue;
                            result.Add(Decode(filter, provider));
                        }
                    }
                    finally { WfpNative.FwpmFreeMemory0(ref entries); }
                    if (count < 512) break;
                }
            }
            finally { WfpNative.FwpmFilterDestroyEnumHandle0(engine, enumeration); }
            return result;
        }
        finally { WfpNative.FwpmEngineClose0(engine); }
    }

    /// <summary>Block filters per Windows Service Hardening and AppContainer isolation provider. Disabling profiles must not reduce them.</summary>
    public static IReadOnlyDictionary<string, int> ProtectionBlocks() =>
        Read(p => p == MpssvcHardeningProvider || p == MpssvcAppIsolationProvider).Where(f => f.Action == "BLOCK")
            .GroupBy(f => f.Provider).ToDictionary(g => g.Key, g => g.Count());

    private static FilterRecord Decode(WfpNative.Filter filter, Guid? provider)
    {
        List<ConditionRecord> conditions = [];
        var size = Marshal.SizeOf<WfpNative.Condition>();
        for (var i = 0; i < filter.ConditionCount; i++)
        {
            var condition = Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions + i * size);
            conditions.Add(new(Name(condition.Field), Match(condition.Match), Value(condition.Value)));
        }
        var weight = filter.EffectiveWeight.Type == 4 && filter.EffectiveWeight.Pointer != IntPtr.Zero ? (ulong)Marshal.ReadInt64(filter.EffectiveWeight.Pointer) : 0;
        var action = filter.Action.Type switch { 0x1001 => "BLOCK", 0x1002 => "PERMIT", 0x5003 => "CALLOUT_TERMINATING", 0x6004 => "CALLOUT_INSPECTION", 0x4005 => "CALLOUT_UNKNOWN", var other => "ACTION_0x" + other.ToString("X") };
        return new(filter.Id, filter.Display.Name ?? "", provider is { } key ? Name(key) : "", Name(filter.Sublayer), Name(filter.Layer), action, weight, filter.Flags,
            conditions, filter.Data.Size is > 0 and <= 4096 ? BlobText(filter.Data) : null);
    }

    private static string Value(WfpNative.Value value)
    {
        if (value.Type is not (0 or 1 or 2 or 3) && value.Pointer == IntPtr.Zero) return "null";
        return value.Type switch
        {
            0 => "EMPTY",
            1 => value.Byte.ToString(),
            2 => value.UShort.ToString(),
            3 => Render(3, value.UInt, null),
            4 => ((ulong)Marshal.ReadInt64(value.Pointer)).ToString(),
            11 => new IPAddress(Bytes(value.Pointer, 16)).ToString(),
            12 or 14 => Render(value.Type, 0, BlobBytes(Marshal.PtrToStructure<WfpNative.Blob>(value.Pointer))),
            13 => new SecurityIdentifier(value.Pointer).Value,
            17 => Marshal.PtrToStringUni(value.Pointer) ?? "null",
            256 => Render(256, 0, Bytes(value.Pointer, 8)),
            257 => Render(257, 0, Bytes(value.Pointer, 17)),
            258 => Value(Marshal.PtrToStructure<WfpNative.Range>(value.Pointer).Low) + "-" + Value(Marshal.PtrToStructure<WfpNative.Range>(value.Pointer).High),
            _ => "type " + value.Type
        };
    }

    /// <summary>Renders a condition the way <see cref="Read"/> does, so installed and compiled filters compare as text.</summary>
    public static ConditionRecord Render(ConditionSpec condition) => new(Name(condition.Field), Match(condition.Match),
        condition.Type == WfpConditions.RangeType && condition.Range is { } range ? range.Low + "-" + range.High : Render(condition.Type, condition.Number, condition.Data));
    /// <summary>An application's ID as <see cref="Read"/> renders the value of an ALE_APP_ID condition naming it.</summary>
    public static string ApplicationIdText(string path) => BlobText(WfpConditions.ApplicationId(path));

    private static string Render(uint type, ulong number, byte[]? data) => type switch
    {
        3 => "0x" + ((uint)number).ToString("X8") + " (" + number + ")",
        12 => BlobText(data ?? []),
        13 => new SecurityIdentifier(data ?? [], 0).Value,
        14 => Sddl(data ?? []),
        256 when data is { Length: 8 } => new IPAddress([data[3], data[2], data[1], data[0]]) + "/" + System.Numerics.BitOperations.PopCount(BitConverter.ToUInt32(data, 4)),
        257 when data is { Length: 17 } => new IPAddress(data[..16]) + "/" + data[16],
        _ => number.ToString()
    };
    private static byte[] Bytes(IntPtr pointer, int count) { var bytes = new byte[count]; Marshal.Copy(pointer, bytes, 0, count); return bytes; }
    private static byte[] BlobBytes(WfpNative.Blob blob) => blob.Data == IntPtr.Zero || blob.Size is 0 or > 65_536 ? [] : Bytes(blob.Data, (int)blob.Size);
    // Application IDs and provider data are NUL-terminated UTF-16; anything else is shown as hex.
    private static string BlobText(WfpNative.Blob blob) => BlobText(BlobBytes(blob));
    private static string BlobText(byte[] bytes)
    {
        if (bytes.Length % 2 == 0 && bytes.Length >= 4 && bytes[^1] == 0 && bytes[^2] == 0)
        {
            var text = Encoding.Unicode.GetString(bytes, 0, bytes.Length - 2);
            if (text.All(c => !char.IsControl(c))) return text;
        }
        return Convert.ToHexString(bytes);
    }
    private static string Sddl(byte[] descriptor)
    {
        if (descriptor.Length == 0) return "";
        var native = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, native, descriptor.Length);
            // OWNER, GROUP, DACL and SACL sections.
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(native, 1, 0xF, out var text, out _)) return "unreadable descriptor";
            try { return Marshal.PtrToStringUni(text) ?? ""; }
            finally { WfpNative.LocalFree(text); }
        }
        finally { Marshal.FreeHGlobal(native); }
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor, uint revision, uint information, out IntPtr text, out uint length);
    private static void Check(uint error) { if (error != 0) throw new Win32Exception(unchecked((int)error), $"WFP error 0x{error:X8}"); }
}
