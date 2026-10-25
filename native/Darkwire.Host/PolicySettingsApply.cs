using Darkwire.Engine;
using System.Windows.Threading;

namespace Darkwire.Host;

public partial class MainWindow
{
    /// <summary>Parts of the policy that apply by themselves when edited, as VPN routes do.</summary>
    [Flags] private enum PolicyPart { None = 0, Blocklists = 1, Internal = 2, Geography = 4, Startup = 8, BlockedNames = 16, Dns = 32, WindowsSecurity = 64 }
    private PolicyPart pendingParts;
    private bool settingsApplying;
    private DispatcherTimer? settingsTimer;

    /// <summary>
    /// A setting changed in the editor. While Darkwire enforces policy it applies a moment later, alone, once a burst of edits
    /// settles, keeping the rest of the draft a draft; otherwise it waits in the draft for setup.
    /// </summary>
    private void PolicyChanged(PolicyPart part, string change)
    {
        Save();
        if (!CanApplyNow)
        {
            ShowToast(demo ? change : change + (!Elevated ? " Restart Darkwire as administrator to apply it." : " It applies when Darkwire takes over; set it up from the Overview."));
            return;
        }
        pendingParts |= part;
        if (settingsTimer is null)
        {
            settingsTimer = new() { Interval = TimeSpan.FromMilliseconds(600) };
            settingsTimer.Tick += async (_, _) => { settingsTimer.Stop(); await ApplySettings(); };
        }
        settingsTimer.Stop(); settingsTimer.Start();
        ShowToast(change + " Applying…");
    }

    /// <summary>Sends the changed settings alone; one that fails stays in the draft, and the service keeps what it enforced.</summary>
    private async Task ApplySettings()
    {
        // Settings changed while an apply runs go in the next one.
        if (settingsApplying) { settingsTimer?.Start(); return; }
        var parts = pendingParts; pendingParts = PolicyPart.None;
        if (parts == PolicyPart.None || demo) return;
        settingsApplying = true;
        try
        {
            var settings = new PolicySettings(parts.HasFlag(PolicyPart.Blocklists) ? state.Blocklists : null, parts.HasFlag(PolicyPart.Internal) ? state.InternalNetworks : null,
                parts.HasFlag(PolicyPart.Geography) ? new GeoSettings(state.BlockedCountries, state.CountryAllowList, state.AllowedCountries, state.BlockedAsns) : null,
                parts.HasFlag(PolicyPart.Startup) ? state.StartupLock : null, parts.HasFlag(PolicyPart.BlockedNames) ? state.BlockedNames : null,
                parts.HasFlag(PolicyPart.Dns) ? state.DnsServers : null, parts.HasFlag(PolicyPart.WindowsSecurity) ? state.ShowFirewallWarnings : null);
            var response = await ServiceClient.SendAsync(new("apply-settings", Settings: settings));
            if (!response.Success) throw new InvalidOperationException(response.Message + ErrorList(response));
            // The draft based on the revision just before this change differed from the service only in its own edits, so it still does.
            if (response.Status?.PolicyRevision is { } now && draftPolicyRevision == now - 1) draftPolicyRevision = now;
            ShowToast(response.Message);
        }
        catch (Exception error) when (error is not OutOfMemoryException) { ShowToast("Not applied: " + error.Message); }
        finally { settingsApplying = false; }
        await RefreshService(true);
        if (currentPage == "Blocklists") _ = RefreshBlocklists();
    }
}
