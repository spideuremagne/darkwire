param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Icon)
# Fixes the MSI that Visual Studio Installer Projects builds, for what the Setup project cannot express. It runs as the
# project's PostBuildEvent, so builds from Visual Studio and from scripts/build.ps1 produce the same package.
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Path).Path, 1)
$get = [Reflection.BindingFlags]::GetProperty
# Windows PowerShell emits a null for each void automation call, so those results are discarded.
function Invoke-Sql([string]$sql) { $view = $database.OpenView($sql); [void]$view.Execute(); [void]$view.Close() }
# One array per row; callers wrap the result in @() so a single row stays a row.
function Get-Rows([string]$sql, [int]$columns) {
    $view = $database.OpenView($sql); [void]$view.Execute()
    while ($null -ne ($record = $view.Fetch())) {
        , @(for ($i = 1; $i -le $columns; $i++) { $record.GetType().InvokeMember('StringData', $get, $null, $record, [object[]]@([int]$i)) })
    }
    [void]$view.Close()
}
function Set-Property([string]$name, [string]$value) {
    Invoke-Sql "DELETE FROM Property WHERE Property = '$name'"
    Invoke-Sql "INSERT INTO Property (Property, Value) VALUES ('$name', '$value')"
}
function New-Code { [guid]::NewGuid().ToString('B').ToUpperInvariant() }

# Remove the previous version before installing this one. By default the removal runs after this version's install
# actions, so the old version's uninstall action would delete the service the new version just registered.
if (@(Get-Rows "SELECT Action FROM InstallExecuteSequence WHERE Action = 'RemoveExistingProducts'" 1).Count -ne 1) { throw 'RemoveExistingProducts is not scheduled.' }
Invoke-Sql "UPDATE InstallExecuteSequence SET Sequence = 1450 WHERE Action = 'RemoveExistingProducts'"

# Every build is a new product, so a rebuilt package of the same version replaces the installed one; only a newer
# version blocks installation. Attributes are part of the Upgrade key, so the rows are replaced.
$upgrade = @(Get-Rows "SELECT UpgradeCode, VersionMin, VersionMax, ActionProperty FROM Upgrade" 4)
$previous = @($upgrade | Where-Object { $_[3] -eq 'PREVIOUSVERSIONSINSTALLED' })
$newer = @($upgrade | Where-Object { $_[3] -eq 'NEWERPRODUCTFOUND' })
if ($previous.Count -ne 1 -or $newer.Count -ne 1) { throw 'The Upgrade table is missing its RemovePreviousVersions rows.' }
Invoke-Sql "DELETE FROM Upgrade WHERE ActionProperty = 'PREVIOUSVERSIONSINSTALLED' OR ActionProperty = 'NEWERPRODUCTFOUND'"
Invoke-Sql "INSERT INTO Upgrade (UpgradeCode, VersionMax, Attributes, ActionProperty) VALUES ('$($previous[0][0])', '$($previous[0][2])', 512, 'PREVIOUSVERSIONSINSTALLED')"
Invoke-Sql "INSERT INTO Upgrade (UpgradeCode, VersionMin, Attributes, ActionProperty) VALUES ('$($newer[0][0])', '$($newer[0][1])', 2, 'NEWERPRODUCTFOUND')"
Set-Property 'ProductCode' (New-Code)
$summary = $database.GetType().InvokeMember('SummaryInformation', $get, $null, $database, [object[]]@([int]4))
[void]$summary.GetType().InvokeMember('Property', [Reflection.BindingFlags]::SetProperty, $null, $summary, [object[]]@([int]9, (New-Code)))
[void]$summary.Persist()

# Per-machine only, and every file is replaced, including leftovers of an older development installation.
Set-Property 'ALLUSERS' '1'
Set-Property 'REINSTALLMODE' 'amus'

# A repair replaces files the running service holds open, so stop it first; the install action starts it again.
$service = @(@(Get-Rows "SELECT Component_, FileName FROM File" 2) | Where-Object { ($_[1] -split '\|')[-1] -eq 'Darkwire.Service.exe' })
if ($service.Count -ne 1) { throw 'The MSI does not contain exactly one Darkwire.Service.exe.' }
if (@(Get-Rows "SELECT Name FROM _Tables WHERE Name = 'ServiceControl'" 1).Count -eq 0) {
    Invoke-Sql "CREATE TABLE ServiceControl (ServiceControl CHAR(72) NOT NULL, Name CHAR(255) NOT NULL LOCALIZABLE, Event SHORT NOT NULL, Arguments CHAR(255) LOCALIZABLE, Wait SHORT, Component_ CHAR(72) NOT NULL PRIMARY KEY ServiceControl)"
}
Invoke-Sql "DELETE FROM ServiceControl WHERE ServiceControl = 'DarkwireStop'"
Invoke-Sql "INSERT INTO ServiceControl (ServiceControl, Name, Event, Wait, Component_) VALUES ('DarkwireStop', 'Darkwire', 34, 1, '$($service[0][0])')"

# The Setup project drops the lower bound of its file search; without it any older Desktop Runtime would pass.
$runtime = @(@(Get-Rows "SELECT Signature, FileName FROM Signature" 2) | Where-Object { ($_[1] -split '\|')[-1] -eq 'PresentationFramework.dll' })
if ($runtime.Count -ne 1) { throw 'The .NET Desktop Runtime search is missing.' }
Invoke-Sql "UPDATE Signature SET MinVersion = '9.65535.65535.65535' WHERE Signature = '$($runtime[0][0])'"

# An advertised shortcut's icon must be an executable named with its target's extension. The build stores a bare .ico
# under an .exe name, which the Start menu cannot read and shows as a blank page, so the icon becomes Darkwire.exe itself.
# Apps & features shows the same icon.
$shortcutIcon = @(Get-Rows "SELECT Icon_ FROM Shortcut" 1)
if ($shortcutIcon.Count -ne 1 -or !$shortcutIcon[0][0] -or [IO.Path]::GetExtension($shortcutIcon[0][0]) -ne '.exe') { throw 'The Start menu shortcut has no .exe icon.' }
$iconName = $shortcutIcon[0][0]
$executable = (Resolve-Path -LiteralPath $Icon).Path
$header = New-Object byte[] 2; $stream = [IO.File]::OpenRead($executable); try { [void]$stream.Read($header, 0, 2) } finally { $stream.Dispose() }
if ([Text.Encoding]::ASCII.GetString($header) -ne 'MZ') { throw "$executable is not an executable." }
Invoke-Sql "DELETE FROM Icon WHERE Name = '$iconName'"
$view = $database.OpenView('INSERT INTO Icon (Name, Data) VALUES (?, ?)')
$record = $installer.CreateRecord(2)
[void]$record.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::SetProperty, $null, $record, [object[]]@([int]1, $iconName))
[void]$record.SetStream(2, $executable)
[void]$view.Execute($record); [void]$view.Close()
Set-Property 'ARPPRODUCTICON' $iconName

# The default welcome page carries a copyright warning; say what setup does instead.
Invoke-Sql ("UPDATE Control SET Text = '{\VSI_MS_Sans_Serif13.0_0_0}Setup installs the Darkwire service. Windows Firewall stays in control until a policy is applied from the app, and removing Darkwire restores it first.' " +
    "WHERE Dialog_ = 'WelcomeForm' AND Control = 'CopyrightWarningText'")

[void]$database.Commit()
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
"Patched $Path"
