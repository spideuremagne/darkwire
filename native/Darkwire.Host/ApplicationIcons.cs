using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media.Imaging;

namespace Darkwire.Host;

/// <summary>Windows executable icons, loaded away from the dispatcher and shared by virtualized rows.</summary>
public static class ApplicationIcons
{
    private static readonly Lazy<Task<BitmapSource>> fallback = new(() => Task.Run(DefaultIcon));
    private static readonly ApplicationIconCache<BitmapSource> cache = new(256, 2,
        path => Task.Run(() => ReadIcon(path)), () => fallback.Value);

    internal static Task<BitmapSource> DefaultAsync => fallback.Value;
    internal static BitmapSource? DefaultIfReady => fallback.IsValueCreated && fallback.Value.IsCompletedSuccessfully ? fallback.Value.Result : null;

    public static Task<BitmapSource> GetAsync(string? executable) => NormalizePath(executable) is { } path ? cache.GetAsync(path) : fallback.Value;

    /// <summary>Only ordinary, absolute DOS executable paths can reach the native resource reader.</summary>
    public static string? NormalizePath(string? executable)
    {
        if (string.IsNullOrWhiteSpace(executable)) return null;
        var path = Environment.ExpandEnvironmentVariables(executable.Trim());
        if (path.Length >= 2 && path[0] == '"' && path[^1] == '"') path = path[1..^1];
        path = path.Replace('/', '\\');
        if (path.Length is < 4 or > 32767 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\'
            || path.AsSpan(2).IndexOfAny(':', '*', '?') >= 0 || path.Any(c => c < 32 || "<>|\"".Contains(c))
            || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        // Win32 ignores these suffixes in path components. Refuse their ambiguous spelling.
        if (path[3..].Split('\\').Any(part => part.Length == 0 || part.EndsWith(' ') || part.EndsWith('.') && part is not ("." or ".."))) return null;
        try { return Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    /// <summary>A local fixed drive and no reparse points: UNC, mapped drives and junctions cannot trigger network I/O.</summary>
    private static bool LocalFile(string path)
    {
        if (GetDriveType(path[..3]) != 3) return false; // DRIVE_FIXED; reject removable/offline and remote volumes too.
        try
        {
            var current = path[..3];
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
            var parts = path[3..].Split('\\');
            for (var i = 0; i < parts.Length; i++)
            {
                current = Path.Combine(current, parts[i]);
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0) return false;
                if (i == parts.Length - 1 && (attributes & FileAttributes.Directory) != 0) return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return false; }
    }

    private static BitmapSource ReadIcon(string path)
    {
        if (!LocalFile(path)) return fallback.Value.GetAwaiter().GetResult();
        nint large = 0, small = 0;
        try
        {
            // Read PE icon resources directly through the Windows shell. SHGetFileInfo's registered icon handlers
            // are deliberately not used: a rule path is data, never a request to instantiate a shell extension.
            if (ExtractIconEx(path, 0, out large, out small, 1) > 0 && (large != 0 || small != 0))
                return Bitmap(large != 0 ? large : small);
        }
        finally
        {
            if (large != 0) DestroyIcon(large);
            if (small != 0 && small != large) DestroyIcon(small);
        }
        return fallback.Value.GetAwaiter().GetResult();
    }

    private static BitmapSource DefaultIcon()
    {
        // Shell APIs require COM. This worker owns only the initialization it successfully acquires.
        var initialized = CoInitializeEx(0, 0) >= 0;
        try
        {
            var info = new StockIconInfo { Size = (uint)Marshal.SizeOf<StockIconInfo>(), Path = "" };
            try
            {
                // SIID_APPLICATION is Windows' default application icon, not an invented placeholder.
                if (SHGetStockIconInfo(2, 0x100, ref info) >= 0 && info.Icon != 0) return Bitmap(info.Icon);
            }
            finally { if (info.Icon != 0) DestroyIcon(info.Icon); }
            // LoadIcon returns a shared system icon. It is owned by Windows and must not be destroyed.
            var shared = LoadIcon(0, (nint)32512); // IDI_APPLICATION
            if (shared == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return Bitmap(shared);
        }
        finally { if (initialized) CoUninitialize(); }
    }

    private static BitmapSource Bitmap(nint icon)
    {
        var source = Imaging.CreateBitmapSourceFromHIcon(icon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
        source.Freeze(); return source;
    }

    public static ApplicationIconImage Image(string? path, double size = 20) => new() { ExecutablePath = path, Width = size, Height = size };

    /// <summary>A name column with its real icon; copying, sorting and name editing still use the name property.</summary>
    public static DataGridTemplateColumn Column(string header, string nameProperty, string pathProperty, double width, bool editable = false)
    {
        var row = new FrameworkElementFactory(typeof(DockPanel));
        var icon = new FrameworkElementFactory(typeof(ApplicationIconImage));
        icon.SetValue(FrameworkElement.WidthProperty, 20d); icon.SetValue(FrameworkElement.HeightProperty, 20d);
        icon.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 10, 0));
        icon.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        icon.SetValue(DockPanel.DockProperty, Dock.Left);
        icon.SetBinding(ApplicationIconImage.ExecutablePathProperty, new Binding(pathProperty)); row.AppendChild(icon);
        var name = new FrameworkElementFactory(typeof(TextBlock));
        name.SetBinding(TextBlock.TextProperty, new Binding(nameProperty));
        name.SetBinding(FrameworkElement.ToolTipProperty, new Binding(nameProperty));
        name.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        name.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis); row.AppendChild(name);
        var editor = new FrameworkElementFactory(typeof(TextBox));
        editor.SetBinding(TextBox.TextProperty, new Binding(nameProperty) { Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        editor.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        return new ApplicationNameColumn
        {
            Header = header, Width = width, IsReadOnly = !editable, SortMemberPath = nameProperty,
            ClipboardContentBinding = new Binding(nameProperty), CellTemplate = new DataTemplate { VisualTree = row },
            CellEditingTemplate = editable ? new DataTemplate { VisualTree = editor } : null
        };
    }

    private sealed class ApplicationNameColumn : DataGridTemplateColumn
    {
        protected override object PrepareCellForEdit(FrameworkElement editingElement, RoutedEventArgs editingEventArgs)
        {
            editingElement.ApplyTemplate();
            if (Editor(editingElement) is not { } editor) return base.PrepareCellForEdit(editingElement, editingEventArgs);
            var previous = editor.Text; editor.Focus(); editor.SelectAll();
            if (editingEventArgs is TextCompositionEventArgs text && text.Text != "\u001b") { editor.Text = text.Text; editor.CaretIndex = editor.Text.Length; }
            return previous;
        }
        protected override void CancelCellEdit(FrameworkElement editingElement, object uneditedValue)
        {
            if (Editor(editingElement) is { } editor && uneditedValue is string previous) editor.Text = previous;
            base.CancelCellEdit(editingElement, uneditedValue);
        }
        private static TextBox? Editor(DependencyObject root)
        {
            if (root is TextBox editor) return editor;
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
                if (Editor(VisualTreeHelper.GetChild(root, i)) is { } found) return found;
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StockIconInfo
    {
        public uint Size; public nint Icon; public int SystemIndex; public int IconIndex;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "ExtractIconExW")]
    private static extern uint ExtractIconEx(string file, int index, out nint large, out nint small, uint count);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern int SHGetStockIconInfo(uint id, uint flags, ref StockIconInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetDriveTypeW")] private static extern uint GetDriveType(string root);
    [DllImport("ole32.dll")] private static extern int CoInitializeEx(nint reserved, uint mode);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyIcon(nint icon);
    [DllImport("user32.dll", EntryPoint = "LoadIconW", SetLastError = true)] private static extern nint LoadIcon(nint instance, nint name);
}

/// <summary>A recycled row never receives the icon of the executable it displayed before.</summary>
public sealed class ApplicationIconImage : Image
{
    public static readonly DependencyProperty ExecutablePathProperty = DependencyProperty.Register(nameof(ExecutablePath), typeof(string), typeof(ApplicationIconImage),
        new PropertyMetadata(null, (owner, _) => ((ApplicationIconImage)owner).Refresh()));
    public string? ExecutablePath { get => (string?)GetValue(ExecutablePathProperty); set => SetValue(ExecutablePathProperty, value); }
    private int request;
    public ApplicationIconImage()
    {
        IsHitTestVisible = false; Stretch = Stretch.Uniform; SnapsToDevicePixels = true;
        RenderOptions.SetBitmapScalingMode(this, BitmapScalingMode.HighQuality);
        Loaded += (_, _) => Refresh(); Unloaded += (_, _) => request++;
        Source = ApplicationIcons.DefaultIfReady;
    }
    private async void Refresh()
    {
        var version = ++request; Source = ApplicationIcons.DefaultIfReady;
        if (!IsLoaded) return;
        var path = ExecutablePath;
        try
        {
            var placeholder = await ApplicationIcons.DefaultAsync;
            if (version != request || !IsLoaded) return;
            Source = placeholder;
            var icon = await ApplicationIcons.GetAsync(path);
            if (version == request && IsLoaded) Source = icon;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or ExternalException)
        { /* Keep the system placeholder if Windows cannot provide this icon. */ }
    }
}

/// <summary>Deduplicates icon work, bounds queued and retained entries, and limits native reader concurrency.</summary>
public sealed class ApplicationIconCache<T>(int capacity, int concurrency, Func<string, Task<T>> read, Func<Task<T>> fallback)
{
    private readonly object gate = new();
    private readonly Dictionary<string, LinkedListNode<Entry>> entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<Entry> recent = new();
    private readonly SemaphoreSlim workers = new(concurrency > 0 ? concurrency : throw new ArgumentOutOfRangeException(nameof(concurrency)));
    private readonly int limit = capacity > 0 ? capacity : throw new ArgumentOutOfRangeException(nameof(capacity));
    private sealed record Entry(string Key, TaskCompletionSource<T> Result);
    public int Count { get { lock (gate) return entries.Count; } }
    public Task<T> GetAsync(string path)
    {
        Entry entry;
        lock (gate)
        {
            if (entries.TryGetValue(path, out var hit)) { recent.Remove(hit); recent.AddLast(hit); return hit.Value.Result.Task; }
            if (entries.Count >= limit)
            {
                var old = recent.First;
                while (old is not null && !old.Value.Result.Task.IsCompleted) old = old.Next;
                // Never evict in-flight work and then queue another copy. A later realization can retry this path.
                if (old is null) return fallback();
                entries.Remove(old.Value.Key); recent.Remove(old);
            }
            entry = new(path, new(TaskCreationOptions.RunContinuationsAsynchronously)); entries.Add(path, recent.AddLast(entry));
        }
        _ = Resolve(entry); return entry.Result.Task;
    }
    private async Task Resolve(Entry entry)
    {
        await workers.WaitAsync().ConfigureAwait(false);
        try
        {
            try { entry.Result.TrySetResult(await read(entry.Key).ConfigureAwait(false)); }
            catch { entry.Result.TrySetResult(await fallback().ConfigureAwait(false)); }
        }
        catch (Exception error) { entry.Result.TrySetException(error); }
        finally { workers.Release(); }
    }
}
