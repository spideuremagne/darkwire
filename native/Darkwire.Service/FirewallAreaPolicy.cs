using Microsoft.Win32;

namespace Darkwire.Service;

/// <summary>
/// Windows Security's Group Policy value for its Firewall and network protection area ("Hide the Firewall and network
/// protection area", the DisableNetworkUI CSP): 1 hides the area and suppresses its notifications, among them the warning
/// that the firewall is off; Defender's other areas and notifications stay as they are.
/// </summary>
public interface IFirewallAreaPolicy
{
    /// <summary>The value as a DWORD; null when it is not set, or set to anything else.</summary>
    int? Read();
    /// <summary>Sets the value, or deletes it for null.</summary>
    void Write(int? value);
}

internal sealed class WindowsFirewallAreaPolicy : IFirewallAreaPolicy
{
    private const string Key = @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection", Value = "UILockdown";

    public int? Read()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Key);
        return key?.GetValue(Value) is int value ? value : null;
    }

    public void Write(int? value)
    {
        if (value is { } set)
        {
            using var key = Registry.LocalMachine.CreateSubKey(Key, true);
            key.SetValue(Value, set, RegistryValueKind.DWord);
        }
        else
        {
            using var key = Registry.LocalMachine.OpenSubKey(Key, true);
            key?.DeleteValue(Value, false);
        }
    }
}
