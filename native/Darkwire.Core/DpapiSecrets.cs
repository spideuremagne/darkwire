using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Darkwire.Core;

/// <summary>DPAPI encryption with bounded inputs and cleared temporary byte buffers.</summary>
public static class DpapiSecrets
{
    public static byte[] Protect(ReadOnlySpan<byte> plaintext, string context, bool machine = false, string description = "Darkwire") => Transform(plaintext, context, true, machine, description);
    public static byte[] Unprotect(ReadOnlySpan<byte> ciphertext, string context) => Transform(ciphertext, context, false, false, "");

    private static byte[] Transform(ReadOnlySpan<byte> bytes, string context, bool protect, bool machine, string description)
    {
        if (bytes.Length is 0 or > 8 * 1024 * 1024) throw new InvalidDataException("Invalid secret size.");
        var input = Allocate(bytes);
        var entropyBytes = Encoding.UTF8.GetBytes(context);
        var entropy = Allocate(entropyBytes);
        Blob output = default;
        try
        {
            var ok = protect
                ? CryptProtectData(ref input, description, ref entropy, IntPtr.Zero, IntPtr.Zero, machine ? 5u : 1u, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException("Windows could not protect or unlock the configuration.", new Win32Exception(Marshal.GetLastWin32Error()));
            if (output.Length is <= 0 or > 8 * 1024 * 1024) throw new CryptographicException("Invalid protected configuration size.");
            var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally
        {
            Clear(input); Marshal.FreeHGlobal(input.Data);
            Clear(entropy); Marshal.FreeHGlobal(entropy.Data); CryptographicOperations.ZeroMemory(entropyBytes);
            Clear(output); if (output.Data != IntPtr.Zero) LocalFree(output.Data);
        }
    }
    private static Blob Allocate(ReadOnlySpan<byte> bytes)
    {
        var result = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(Math.Max(bytes.Length, 1)) };
        var copy = bytes.ToArray();
        try { Marshal.Copy(copy, 0, result.Data, copy.Length); }
        finally { CryptographicOperations.ZeroMemory(copy); }
        return result;
    }
    private static void Clear(Blob blob)
    {
        if (blob.Data == IntPtr.Zero || blob.Length <= 0) return;
        var zeros = new byte[Math.Min(blob.Length, 4096)];
        for (var offset = 0; offset < blob.Length; offset += zeros.Length)
            Marshal.Copy(zeros, 0, blob.Data + offset, Math.Min(zeros.Length, blob.Length - offset));
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description, ref Blob entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, ref Blob entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr data);
}
