using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Interop;

namespace Darkwire.Host;

public partial class MainWindow
{
    private const int DropFiles = 0x0233, CopyData = 0x004A, CopyGlobalData = 0x0049;

    /// <summary>
    /// Takes files dropped from Explorer: VPN configurations import as profiles. Darkwire runs as administrator, where Windows
    /// refuses OLE drag and drop from Explorer's lower integrity, so the window takes the shell's plain file drop instead and
    /// lets that message, and the two it needs, through.
    /// </summary>
    private void AcceptFileDrops()
    {
        var handle = new WindowInteropHelper(this).Handle;
        // With an OLE drop target, Explorer would offer the drop Windows then refuses; without one it sends WM_DROPFILES.
        _ = RevokeDragDrop(handle);
        DragAcceptFiles(handle, true);
        foreach (var message in new[] { DropFiles, CopyData, CopyGlobalData }) ChangeWindowMessageFilterEx(handle, (uint)message, 1, IntPtr.Zero);
        HwndSource.FromHwnd(handle)?.AddHook(DropHook);
    }

    private IntPtr DropHook(IntPtr window, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message != DropFiles) return IntPtr.Zero;
        handled = true;
        List<string> files = [];
        try
        {
            var count = DragQueryFile(wParam, uint.MaxValue, null, 0);
            for (uint i = 0; i < count && i < 256; i++)
            {
                var length = DragQueryFile(wParam, i, null, 0);
                if (length is 0 or > 32_767) continue;
                var name = new StringBuilder((int)length + 1);
                if (DragQueryFile(wParam, i, name, length + 1) > 0) files.Add(name.ToString());
            }
        }
        finally { DragFinish(wParam); }
        Dispatcher.BeginInvoke(() => DroppedFiles(files));
        return IntPtr.Zero;
    }

    /// <summary>VPN configurations dropped anywhere import on the VPN page; other files are counted and left alone.</summary>
    private void DroppedFiles(IReadOnlyList<string> files)
    {
        var configurations = files.Where(f => VpnConfigurationFile(f) && File.Exists(f)).ToList();
        if (configurations.Count == 0)
        {
            var openVpn = files.Any(f => Path.GetExtension(f).Equals(".ovpn", StringComparison.OrdinalIgnoreCase));
            ShowToast(openVpn ? Darkwire.Vpn.VpnConfiguration.Unsupported("OpenVPN") : "Drop WireGuard .conf files to import them.");
            return;
        }
        if (currentPage != "VPN") Navigate("VPN");
        ImportVpnFiles(configurations, files.Count - configurations.Count);
    }

    [DllImport("ole32.dll")] private static extern int RevokeDragDrop(IntPtr window);
    [DllImport("shell32.dll")] private static extern void DragAcceptFiles(IntPtr window, [MarshalAs(UnmanagedType.Bool)] bool accept);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint DragQueryFile(IntPtr drop, uint index, StringBuilder? file, uint size);
    [DllImport("shell32.dll")] private static extern void DragFinish(IntPtr drop);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeWindowMessageFilterEx(IntPtr window, uint message, uint action, IntPtr status);
}
