using Darkwire.Core;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Darkwire.Engine;

/// <summary>A WFP filter condition with a managed payload.</summary>
public sealed record ConditionSpec(Guid Field, uint Match, uint Type, ulong Number = 0, byte[]? Data = null, PortRange? Range = null);

/// <summary>
/// Converts native filters to WFP conditions. Resolving identities needs Windows account and file APIs but no WFP
/// session, so preflight resolves every filter exactly as installation will.
/// </summary>
public static class WfpConditions
{
    public static readonly Guid UserId = new("af043a0a-b34d-4f86-979c-c90371af6e66"), PackageId = new("71bc78fa-f17c-4997-a602-6abb261f351c"),
        Flags = new("632ce23b-5167-435c-86d7-e903684aa80c"), TunnelType = new("77a40437-8779-4868-a261-f5a902f1c0cd"),
        LocalInterface = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4"), CurrentProfile = new("ab3033c9-c0e3-4759-937d-5758c65d4ae3");
    // fwptypes.h FWP_MATCH_TYPE and FWP_DATA_TYPE values.
    public const uint MatchEqual = 0, MatchRange = 5, MatchFlagsAllSet = 6, MatchNotEqual = 10;
    public const uint UInt8 = 1, UInt16 = 2, UInt32 = 3, UInt64 = 4, ByteBlob = 12, Sid = 13, SecurityDescriptor = 14, V4AddressMask = 256, V6AddressMask = 257, RangeType = 258;

    public static IReadOnlyList<ConditionSpec> Resolve(NativeFilter spec, Dictionary<string, byte[]>? cache = null)
    {
        List<ConditionSpec> conditions = [];
        byte[] Cached(string key, Func<byte[]> create) => cache is null ? create() : cache.TryGetValue(key, out var value) ? value : (cache[key] = create());
        if (spec.ApplicationPath is { } path) conditions.Add(new(WfpNative.AppId, MatchEqual, ByteBlob, Data: Cached("app:" + path, () => ApplicationId(path))));
        if (spec.Service is not null || spec.Users is not null)
            conditions.Add(new(UserId, MatchEqual, SecurityDescriptor, Data: Cached($"user:{spec.Service}|{spec.Users}", () => UserDescriptor(spec.Service, spec.Users))));
        // Every AppContainer has a package SID; ordinary processes report the NULL SID.
        if (spec.Package is { } package)
            conditions.Add(package == IdentitySelectors.AllPackages ? new(PackageId, MatchNotEqual, Sid, Data: SidBytes("S-1-0-0")) : new(PackageId, MatchEqual, Sid, Data: SidBytes(package)));
        if (spec.Protocol is byte protocol) conditions.Add(new(WfpNative.Protocol, MatchEqual, UInt8, protocol));
        if (spec.LocalInterfaceLuid is { } luid) conditions.Add(new(LocalInterface, MatchEqual, UInt64, luid));
        if (spec.CurrentProfileId is { } profile) conditions.Add(new(CurrentProfile, MatchEqual, UInt32, profile));
        Port(WfpNative.LocalPort, spec.LocalPort); Port(WfpNative.RemotePort, spec.RemotePort);
        // fwpmu.h defines FWPM_CONDITION_ICMP_TYPE and _CODE as the local and remote port fields.
        if (spec.IcmpType is byte icmpType) conditions.Add(new(WfpNative.LocalPort, MatchEqual, UInt16, icmpType));
        if (spec.IcmpCode is byte icmpCode) conditions.Add(new(WfpNative.RemotePort, MatchEqual, UInt16, icmpCode));
        Address(WfpNative.RemoteAddress, spec.RemoteNetwork); Address(WfpNative.LocalAddress, spec.LocalNetwork);
        if (spec.RequiredFlags is { } flags) conditions.Add(new(Flags, MatchFlagsAllSet, UInt32, flags));
        if (spec.TunnelType is { } tunnel) conditions.Add(new(TunnelType, MatchEqual, UInt32, tunnel));
        return conditions;

        void Port(Guid field, PortRange? port)
        {
            if (port is null) return;
            conditions.Add(port.Low == port.High ? new(field, MatchEqual, UInt16, port.Low) : new(field, MatchRange, RangeType, Range: port));
        }
        void Address(Guid field, string? selector)
        {
            if (selector is null) return;
            if (!IpNetwork.TryParse(selector, out var network)) throw new InvalidDataException("Invalid native network " + selector + ".");
            IpNetwork.TryParse(AddressKeywords.Canonical(network), out var masked);
            var bytes = masked.Address.GetAddressBytes();
            if (bytes.Length == 16) { conditions.Add(new(field, MatchEqual, V6AddressMask, Data: [.. bytes, (byte)network.Prefix])); return; }
            // FWP_V4_ADDR_AND_MASK holds the address and mask in host byte order.
            var data = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(data, BinaryPrimitives.ReadUInt32BigEndian(bytes));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), network.Prefix == 0 ? 0u : uint.MaxValue << (32 - network.Prefix));
            conditions.Add(new(field, MatchEqual, V4AddressMask, Data: data));
        }
    }

    /// <summary>Resolves every registration as installation would, without opening WFP.</summary>
    public static IReadOnlyList<string> Preflight(FilterPlan plan)
    {
        IReadOnlyList<WfpRegistration> registrations;
        try { registrations = WfpInstallationPlan.Build(plan); }
        catch (Exception error) when (error is InvalidDataException or InvalidOperationException) { return [error.Message]; }
        List<string> errors = []; Dictionary<string, byte[]> cache = [];
        foreach (var registration in registrations)
        {
            try { Resolve(registration.Filter, cache); }
            catch (Exception error) when (error is InvalidDataException or Win32Exception or IOException or UnauthorizedAccessException)
            { errors.Add(registration.Filter.Name + ": " + error.Message); }
        }
        return errors.Distinct().Take(100).ToArray();
    }

    /// <summary>FwpmGetAppIdFromFileName0 output: "System" for the kernel, otherwise the lower-case NT device path, NUL-terminated UTF-16.</summary>
    public static byte[] ApplicationId(string path)
    {
        if (IdentitySelectors.IsSystemApplication(path)) return Encoding.Unicode.GetBytes("System\0");
        var expanded = Environment.ExpandEnvironmentVariables(path);
        if (expanded.Contains('%') || !Path.IsPathFullyQualified(expanded)) throw new InvalidDataException("Application path must be absolute: " + path);
        var full = Path.GetFullPath(expanded);
        if (File.Exists(full))
        {
            var error = WfpNative.FwpmGetAppIdFromFileName0(full, out var blob);
            if (error != 0) throw new Win32Exception(unchecked((int)error), "WFP could not identify " + full);
            try
            {
                var value = Marshal.PtrToStructure<WfpNative.Blob>(blob);
                if (value.Size is 0 or > 65_536) throw new InvalidDataException("Invalid WFP application ID.");
                var bytes = new byte[value.Size]; Marshal.Copy(value.Data, bytes, 0, bytes.Length); return bytes;
            }
            finally { WfpNative.FwpmFreeMemory0(ref blob); }
        }
        // Windows keeps rules for executables that are absent or not installed yet; they must still match exactly.
        return Encoding.Unicode.GetBytes(DevicePath(full).ToLowerInvariant() + "\0");
    }

    public static string DevicePath(string fullPath)
    {
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal)) throw new InvalidDataException("Device paths are not supported: " + fullPath);
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal)) return @"\device\mup" + fullPath[1..];
        if (fullPath.Length < 3 || fullPath[1] != ':' || !char.IsAsciiLetter(fullPath[0])) throw new InvalidDataException("Unsupported application path: " + fullPath);
        var drive = fullPath[..2]; var target = new StringBuilder(1024);
        if (WfpNative.QueryDosDevice(drive, target, target.Capacity) == 0) throw new InvalidDataException($"Volume {drive} is unavailable for {fullPath}.");
        var device = target.ToString();
        if (!device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) || device.Contains(';')) throw new InvalidDataException($"Drive {drive} is a substituted or network mapping.");
        return device + fullPath[2..];
    }

    /// <summary>Same shape MPSSVC stores for local user authorization: CC (FWP_ACTRL_MATCH_FILTER) for each permitted SID.</summary>
    public static byte[] UserDescriptor(string? service, string? users)
    {
        var serviceSid = service is null ? null : service == IdentitySelectors.AllServices ? "S-1-5-6" : IdentitySelectors.ServiceSid(service);
        var userSids = users is null ? [] : RuleValidator.Tokens(users).Select(ResolveAccount).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (serviceSid is null && userSids.Length == 0) throw new InvalidDataException("An identity scope requires a service or user.");
        // Service and user restrictions must both hold; separate ALE_USER_ID conditions would be OR'ed by WFP.
        var sddl = userSids.Length == 0 ? $"O:LSD:(A;;CC;;;{serviceSid})"
            : serviceSid is null ? "O:LSD:" + string.Concat(userSids.Select(s => $"(A;;CC;;;{s})"))
            : "O:LSD:" + string.Concat(userSids.Select(s => $"(XA;;CC;;;{s};(Member_of {{SID({serviceSid})}}))"));
        if (!WfpNative.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out var size))
            throw new InvalidDataException("Invalid identity scope: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
        try { var bytes = new byte[size]; Marshal.Copy(descriptor, bytes, 0, (int)size); return bytes; }
        finally { WfpNative.LocalFree(descriptor); }
    }

    public static string ResolveAccount(string account)
    {
        try { return IdentitySelectors.IsSid(account) ? new SecurityIdentifier(account).Value : ((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value; }
        catch (Exception error) when (error is IdentityNotMappedException or ArgumentException or Win32Exception) { throw new InvalidDataException("Unknown account " + account + "."); }
    }

    private static byte[] SidBytes(string sid)
    {
        var value = new SecurityIdentifier(sid); var bytes = new byte[value.BinaryLength];
        value.GetBinaryForm(bytes, 0); return bytes;
    }

    internal static (IntPtr Conditions, uint Count) ToNative(IReadOnlyList<ConditionSpec> conditions, WfpArena arena)
    {
        List<WfpNative.Condition> native = [];
        foreach (var condition in conditions)
        {
            var value = new WfpNative.Value { Type = condition.Type };
            switch (condition.Type)
            {
                case UInt8: value.Byte = checked((byte)condition.Number); break;
                case UInt16: value.UShort = checked((ushort)condition.Number); break;
                case UInt32: value.UInt = checked((uint)condition.Number); break;
                case UInt64: value.Pointer = arena.Allocate(condition.Number); break;
                case ByteBlob or SecurityDescriptor: value.Pointer = arena.Blob(condition.Data ?? throw new InvalidDataException("Missing condition data.")); break;
                case Sid or V4AddressMask or V6AddressMask: value.Pointer = arena.Bytes(condition.Data ?? throw new InvalidDataException("Missing condition data.")); break;
                case RangeType:
                    var range = condition.Range ?? throw new InvalidDataException("Missing condition range.");
                    value.Pointer = arena.Allocate(new WfpNative.Range { Low = new() { Type = UInt16, UShort = range.Low }, High = new() { Type = UInt16, UShort = range.High } });
                    break;
                default: throw new InvalidDataException("Unsupported WFP condition type.");
            }
            native.Add(new() { Field = condition.Field, Match = condition.Match, Value = value });
        }
        return (arena.Array(native), (uint)native.Count);
    }
}

/// <summary>Unmanaged memory for one WFP call.</summary>
internal sealed class WfpArena : IDisposable
{
    private readonly List<IntPtr> pointers = [];
    public IntPtr Allocate<T>(T value) where T : struct
    { var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>()); pointers.Add(pointer); Marshal.StructureToPtr(value, pointer, false); return pointer; }
    public IntPtr Bytes(byte[] data)
    { var pointer = Marshal.AllocHGlobal(Math.Max(1, data.Length)); pointers.Add(pointer); Marshal.Copy(data, 0, pointer, data.Length); return pointer; }
    public IntPtr Blob(byte[] data) => Allocate(new WfpNative.Blob { Size = (uint)data.Length, Data = Bytes(data) });
    public IntPtr Array<T>(List<T> values) where T : struct
    {
        if (values.Count == 0) return IntPtr.Zero;
        var size = Marshal.SizeOf<T>(); var pointer = Marshal.AllocHGlobal(size * values.Count); pointers.Add(pointer);
        for (var i = 0; i < values.Count; i++) Marshal.StructureToPtr(values[i], pointer + i * size, false);
        return pointer;
    }
    public void Dispose() { foreach (var pointer in pointers) Marshal.FreeHGlobal(pointer); }
}
