param([Parameter(Mandatory)][string]$WireGuardMsi, [Parameter(Mandatory)][string]$DnsCrypt, [Parameter(Mandatory)][string]$Output)
# Lays out the backends `build.ps1 -Backends` takes, from the official releases, without running them: the WireGuard
# installer's embedded cabinet is read through the Windows Installer API and unpacked with expand.exe, and the dnscrypt-proxy
# release archive is unpacked. Every input is pinned; the README's Building from source says where each comes from.
$ErrorActionPreference = 'Stop'
$pins = @{
    'wireguard-amd64-1.1.1.msi' = '7BFED60AD61B785C914B38B61555A975488E1D3EC472DBFB2FCDF498FCA75242'
    # Its minisign signature verified with the dnscrypt-proxy release key (RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5).
    'dnscrypt-proxy-win64-2.1.18.zip' = '15F0C8F1F40620A54DDFD8752C327DABE1146F84618D68874F79C4F52490B396'
}
foreach ($source in $WireGuardMsi, $DnsCrypt) {
    $name = Split-Path -Leaf $source
    if (-not $pins.ContainsKey($name) -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $pins[$name]) { throw "$name is not one of the pinned inputs." }
}
if (Test-Path -LiteralPath $Output) { throw "$Output exists; pick a new folder." }

Add-Type -Namespace Backends -Name Msi -MemberDefinition @'
[DllImport("msi.dll", CharSet = CharSet.Unicode)] public static extern uint MsiOpenDatabase(string path, IntPtr persist, out IntPtr database);
[DllImport("msi.dll", CharSet = CharSet.Unicode)] public static extern uint MsiDatabaseOpenView(IntPtr database, string query, out IntPtr view);
[DllImport("msi.dll")] public static extern uint MsiViewExecute(IntPtr view, IntPtr record);
[DllImport("msi.dll")] public static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
[DllImport("msi.dll", CharSet = CharSet.Unicode)] public static extern uint MsiRecordGetString(IntPtr record, uint field, System.Text.StringBuilder value, ref uint size);
[DllImport("msi.dll")] public static extern uint MsiRecordReadStream(IntPtr record, uint field, byte[] buffer, ref uint size);
[DllImport("msi.dll")] public static extern uint MsiRecordDataSize(IntPtr record, uint field);
[DllImport("msi.dll")] public static extern uint MsiCloseHandle(IntPtr handle);
'@

# Unpacks an installer's files into $target by their install paths, as "Product\folder\file", and returns those paths.
function Expand-Installer([string]$path, [string]$target) {
    $database = [IntPtr]::Zero
    if ([Backends.Msi]::MsiOpenDatabase((Resolve-Path -LiteralPath $path).Path, [IntPtr]::Zero, [ref]$database) -ne 0) { throw "$path did not open as an installer." }
    function Rows([string]$sql, [int]$fields) {
        $view = [IntPtr]::Zero
        if ([Backends.Msi]::MsiDatabaseOpenView($database, $sql, [ref]$view) -ne 0) { throw "Query failed: $sql" }
        [void][Backends.Msi]::MsiViewExecute($view, [IntPtr]::Zero)
        $record = [IntPtr]::Zero
        while ([Backends.Msi]::MsiViewFetch($view, [ref]$record) -eq 0) {
            $row = for ($i = 1; $i -le $fields; $i++) { $size = [uint32]4096; $value = New-Object System.Text.StringBuilder 4096; [void][Backends.Msi]::MsiRecordGetString($record, $i, $value, [ref]$size); $value.ToString() }
            , @($row)
            [void][Backends.Msi]::MsiCloseHandle($record)
        }
        [void][Backends.Msi]::MsiCloseHandle($view)
    }
    try {
        $raw = Join-Path $target 'raw'; New-Item -ItemType Directory -Path $raw -Force | Out-Null
        # Embedded cabinets are named with a leading # in the Media table, and stored in _Streams without it.
        foreach ($media in Rows 'SELECT `DiskId`, `Cabinet` FROM `Media`' 2) {
            if (-not $media[1].StartsWith('#')) { continue }
            $name = $media[1].Substring(1)
            $view = [IntPtr]::Zero; $record = [IntPtr]::Zero
            [void][Backends.Msi]::MsiDatabaseOpenView($database, "SELECT ``Data`` FROM ``_Streams`` WHERE ``Name`` = '$name'", [ref]$view)
            [void][Backends.Msi]::MsiViewExecute($view, [IntPtr]::Zero)
            if ([Backends.Msi]::MsiViewFetch($view, [ref]$record) -ne 0) { throw "The cabinet $name is missing from $path." }
            $length = [Backends.Msi]::MsiRecordDataSize($record, 1); $buffer = New-Object byte[] $length; $read = [uint32]$length
            [void][Backends.Msi]::MsiRecordReadStream($record, 1, $buffer, [ref]$read)
            [void][Backends.Msi]::MsiCloseHandle($record); [void][Backends.Msi]::MsiCloseHandle($view)
            $cabinet = Join-Path $target $name; [IO.File]::WriteAllBytes($cabinet, $buffer)
            & "$env:SystemRoot\System32\expand.exe" $cabinet '-F:*' $raw | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "expand.exe could not unpack $name." }
        }
        # A directory's name is the long half of DefaultDir's target part; '.' and SourceDir name no folder of their own.
        $parents = @{}; $names = @{}
        foreach ($row in Rows 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' 3) { $parents[$row[0]] = $row[1]; $names[$row[0]] = $row[2].Split(':')[0].Split('|')[-1] }
        $components = @{}
        foreach ($row in Rows 'SELECT `Component`, `Directory_` FROM `Component`' 2) { $components[$row[0]] = $row[1] }
        foreach ($row in Rows 'SELECT `File`, `Component_`, `FileName` FROM `File`' 3) {
            $parts = @(); $id = $components[$row[1]]
            for ($depth = 0; $id -and $depth -lt 64; $depth++) { if ($names[$id] -and $names[$id] -notin '.', 'SourceDir') { $parts = @($names[$id]) + $parts }; $id = $parents[$id] }
            $relative = ($parts + $row[2].Split('|')[-1]) -join '\'
            $from = Join-Path $raw $row[0]
            if (Test-Path -LiteralPath $from) { $to = Join-Path $target $relative; New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null; Move-Item -LiteralPath $from -Destination $to; $relative }
        }
    } finally { [void][Backends.Msi]::MsiCloseHandle($database) }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('darkwire-backends-' + [guid]::NewGuid().ToString('N'))
try {
    Expand-Installer $WireGuardMsi (Join-Path $work 'wireguard') | Out-Null
    Expand-Archive -LiteralPath $DnsCrypt -DestinationPath (Join-Path $work 'dnscrypt')
    # WireGuard needs only its executable, which carries the WireGuardNT driver; build.ps1 adds its licenses. dnscrypt-proxy
    # is one static executable; the service writes its configuration, so the release's examples stay out.
    $layout = [ordered]@{
        'WireGuard\wireguard.exe' = 'wireguard\WireGuard\wireguard.exe'
        'DnsCrypt\dnscrypt-proxy.exe' = 'dnscrypt\win64\dnscrypt-proxy.exe'
        'DnsCrypt\LICENSE.txt' = 'dnscrypt\win64\LICENSE'
    }
    foreach ($entry in $layout.GetEnumerator()) {
        $from = Join-Path $work $entry.Value
        if (!(Test-Path -LiteralPath $from)) { throw "The installers no longer contain $($entry.Value)." }
        $to = Join-Path $Output $entry.Key
        New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null
        Copy-Item -LiteralPath $from -Destination $to
        $signature = if ($to -match '\.(exe|dll)$') { $s = Get-AuthenticodeSignature -LiteralPath $to; '{0} {1}' -f $s.Status, ($s.SignerCertificate.Subject -replace ',.*$', '') } else { '' }
        '{0}  {1}  {2}' -f $entry.Key, (Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash, $signature
    }
} finally { if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force } }
