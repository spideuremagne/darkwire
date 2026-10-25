param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$Output,
    [string]$Version = '1.0.0'
)
# Builds the Darkwire MSI from a published install image with Visual Studio and its Installer Projects extension.
# The Setup project is generated beside the image so it installs exactly the published files; open
# artifacts\installer\Darkwire.Setup.vdproj in Visual Studio to inspect or rebuild it. Its PostBuildEvent runs patch-msi.ps1.
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,5}$') { throw 'The version must be major.minor.build.' }
$image = (Resolve-Path -LiteralPath $PackageDirectory).Path.TrimEnd('\')
$service = Join-Path $image 'Service'
if (!(Test-Path -LiteralPath (Join-Path $image 'Darkwire.exe')) -or !(Test-Path -LiteralPath (Join-Path $service 'Darkwire.Service.exe'))) { throw "$image is not a published Darkwire image." }

# Only devenv builds Setup projects, and only with the Installer Projects extension.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$devenv = $null
if (Test-Path -LiteralPath $vswhere) {
    $devenv = @(& $vswhere -all -prerelease -products * -property productPath) | Where-Object {
        $_ -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $_) 'CommonExtensions\Microsoft\VSI\bin\dpplg.dll'))
    } | Select-Object -First 1
}
if (!$devenv) { throw 'Building the installer needs Visual Studio with the Microsoft Visual Studio Installer Projects extension.' }
$devenv = [IO.Path]::ChangeExtension($devenv, '.com')

# The service starts only if this manifest lists exactly the files installed under Service.
$manifest = Join-Path $service 'installation-integrity.json'
$entries = @(Get-ChildItem -LiteralPath $service -File -Recurse | Where-Object { $_.FullName -ne $manifest } | Sort-Object FullName | ForEach-Object {
    [ordered]@{ Path = $_.FullName.Substring($service.Length + 1); Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
[IO.File]::WriteAllText($manifest, ([ordered]@{ Version = 1; Files = $entries } | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))

# Stable keys keep the generated project identical while the published file set is.
$sha = [Security.Cryptography.SHA256]::Create()
function Key([string]$seed) { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed))[0..15] | ForEach-Object { $_.ToString('X2') }) }
function New-Code { [guid]::NewGuid().ToString('B').ToUpperInvariant() }
$lines = New-Object 'System.Collections.Generic.List[string]'
$script:level = 0
function Open-Block([string]$name) { $pad = ' ' * (4 * $script:level); $lines.Add($pad + '"' + $name + '"'); $lines.Add($pad + '{'); $script:level++ }
function Close-Block { $script:level--; $lines.Add((' ' * (4 * $script:level)) + '}') }
function Add-Value([string]$name, [string]$value) { $lines.Add((' ' * (4 * $script:level)) + '"' + $name + '" = "' + $value + '"') }
function Str([string]$text) { '8:' + $text.Replace('\', '\\').Replace('"', '\"') }
function Flag([bool]$value) { if ($value) { '11:TRUE' } else { '11:FALSE' } }
function Num([long]$value) { '3:' + $value }

$directories = @(Get-ChildItem -LiteralPath $image -Directory -Recurse | ForEach-Object { $_.FullName.Substring($image.Length + 1) } | Sort-Object)
$files = @(Get-ChildItem -LiteralPath $image -File -Recurse | ForEach-Object { $_.FullName.Substring($image.Length + 1) } | Sort-Object)
$source = '..\' + (Split-Path -Leaf $image) + '\'
$appFolder = Key 'folder:'
$menuFolder = Key 'folder:menu'
$appExecutable = Key 'file:Darkwire.exe'
$serviceExecutable = Key 'file:Service\Darkwire.Service.exe'
function Get-FolderKey([string]$relative) { if ($relative) { Key "folder:$relative" } else { $appFolder } }
function Add-Folders([string]$parent) {
    foreach ($directory in @($directories | Where-Object { (Split-Path -Parent $_) -eq $parent })) {
        Open-Block "{9EF0B969-E518-4E46-987F-47570745A589}:_$(Get-FolderKey $directory)"
        Add-Value 'Name' (Str (Split-Path -Leaf $directory))
        Add-Value 'AlwaysCreate' (Flag $false); Add-Value 'Condition' (Str ''); Add-Value 'Transitive' (Flag $false)
        Add-Value 'Property' (Str ('_' + (Key "property:$directory")))
        Open-Block 'Folders'; Add-Folders $directory; Close-Block
        Close-Block
    }
}

Open-Block 'DeployProject'
Add-Value 'VSVersion' '3:800'
Add-Value 'ProjectType' (Str '{978C614F-708E-4E1A-B201-565925725DBA}')
Add-Value 'IsWebType' (Str 'FALSE')
Add-Value 'ProjectName' (Str 'Darkwire.Setup')
Add-Value 'LanguageId' (Num 1033); Add-Value 'CodePage' (Num 1252); Add-Value 'UILanguageId' (Num 1033)
foreach ($name in 'SccProjectName', 'SccLocalPath', 'SccAuxPath', 'SccProvider') { Add-Value $name (Str '') }
Open-Block 'Hierarchy'
foreach ($file in $files) { Open-Block 'Entry'; Add-Value 'MsmKey' (Str ('_' + (Key "file:$file"))); Add-Value 'OwnerKey' (Str '_UNDEFINED'); Add-Value 'MsmSig' (Str '_UNDEFINED'); Close-Block }
Close-Block
Open-Block 'Configurations'
Open-Block 'Release'
Add-Value 'DisplayName' (Str 'Release'); Add-Value 'IsDebugOnly' (Flag $false); Add-Value 'IsReleaseOnly' (Flag $true)
Add-Value 'OutputFilename' (Str 'Release\Darkwire.msi')
# Files packed into the MSI itself, with no bootstrapper.
Add-Value 'PackageFilesAs' (Num 2); Add-Value 'PackageFileSize' (Num -2147483648); Add-Value 'CabType' (Num 1); Add-Value 'Compression' (Num 2)
Add-Value 'SignOutput' (Flag $false)
foreach ($name in 'CertificateFile', 'PrivateKeyFile', 'TimeStampServer') { Add-Value $name (Str '') }
Add-Value 'InstallerBootstrapper' (Num 1)
Close-Block
Close-Block
Open-Block 'Deployable'
# Custom actions run deferred, as SYSTEM, and fail setup on a nonzero exit. Phase 1 runs after the files are installed,
# 3 on rollback of that, and 4 before files are removed, with the upgrading product code when an upgrade removes this version.
Open-Block 'CustomAction'
foreach ($action in @(
    @{ Id = 'install'; Name = 'Protect the installation, then register and start the service'; Phase = 1; Arguments = '--install' },
    @{ Id = 'rollback'; Name = 'Remove the service after a failed installation'; Phase = 3; Arguments = '--rollback' },
    @{ Id = 'uninstall'; Name = 'Restore Windows Firewall, then remove the service and its state'; Phase = 4; Arguments = '--uninstall [UPGRADINGPRODUCTCODE]' })) {
    $key = Key "action:$($action.Id)"
    Open-Block "{4AA51A2D-7D85-4A59-BA75-B0809FC8B380}:_$key"
    Add-Value 'Name' (Str $action.Name); Add-Value 'Condition' (Str ''); Add-Value 'Object' (Str "_$serviceExecutable")
    Add-Value 'FileType' (Num 2); Add-Value 'InstallAction' (Num $action.Phase); Add-Value 'Arguments' (Str $action.Arguments)
    Add-Value 'EntryPoint' (Str ''); Add-Value 'Sequence' (Num 1)
    Add-Value 'Identifier' (Str ('_' + $key.Substring(0, 8) + '_' + $key.Substring(8, 4) + '_' + $key.Substring(12, 4) + '_' + $key.Substring(16, 4) + '_' + $key.Substring(20, 12)))
    Add-Value 'InstallerClass' (Flag $false); Add-Value 'CustomActionData' (Str '')
    Close-Block
}
Close-Block
Open-Block 'DefaultFeature'; Add-Value 'Name' (Str 'DefaultFeature'); Add-Value 'Title' (Str ''); Add-Value 'Description' (Str ''); Close-Block
Open-Block 'ExternalPersistence'; Open-Block 'LaunchCondition'; Close-Block; Close-Block
Open-Block 'File'
foreach ($file in $files) {
    Open-Block "{1FB2D0AE-D3B9-43D4-B9DD-F88EC61E35DE}:_$(Key "file:$file")"
    Add-Value 'SourcePath' (Str ($source + $file)); Add-Value 'TargetName' (Str (Split-Path -Leaf $file)); Add-Value 'Tag' (Str '')
    Add-Value 'Folder' (Str ('_' + (Get-FolderKey (Split-Path -Parent $file)))); Add-Value 'Condition' (Str '')
    Add-Value 'Transitive' (Flag $false); Add-Value 'Vital' (Flag $true)
    foreach ($name in 'ReadOnly', 'Hidden', 'System', 'Permanent', 'SharedLegacy') { Add-Value $name (Flag $false) }
    Add-Value 'PackageAs' (Num 1); Add-Value 'Register' (Num 1); Add-Value 'Exclude' (Flag $false); Add-Value 'IsDependency' (Flag $false); Add-Value 'IsolateTo' (Str '')
    Close-Block
}
Close-Block
Open-Block 'FileType'; Close-Block
Open-Block 'Folder'
Open-Block "{1525181F-901A-416C-8A58-119130FE478E}:_$menuFolder"
Add-Value 'Name' (Str '#1919'); Add-Value 'AlwaysCreate' (Flag $false); Add-Value 'Condition' (Str ''); Add-Value 'Transitive' (Flag $false); Add-Value 'Property' (Str 'ProgramMenuFolder')
Open-Block 'Folders'; Close-Block
Close-Block
Open-Block "{3C67513D-01DD-4637-8A68-80971EB9504F}:_$appFolder"
# The service and its clients trust only this location, so setup offers no folder choice.
Add-Value 'DefaultLocation' (Str '[ProgramFiles64Folder]Darkwire')
Add-Value 'Name' (Str '#1925'); Add-Value 'AlwaysCreate' (Flag $false); Add-Value 'Condition' (Str ''); Add-Value 'Transitive' (Flag $false); Add-Value 'Property' (Str 'TARGETDIR')
Open-Block 'Folders'; Add-Folders ''; Close-Block
Close-Block
Close-Block
Open-Block 'LaunchCondition'
Open-Block "{836E08B8-0285-4809-BA42-01DB6754A45D}:_$(Key 'condition:desktop-runtime')"
Add-Value 'Name' (Str '.NET 10 Desktop Runtime'); Add-Value 'Condition' (Str 'DOTNETDESKTOP10')
Add-Value 'Message' (Str 'Darkwire needs the .NET 10 Desktop Runtime (x64). Install it, then run setup again.')
Add-Value 'InstallUrl' (Str 'https://dotnet.microsoft.com/download/dotnet/10.0')
Close-Block
Close-Block
Open-Block 'Locator'
Open-Block "{39E1837C-0DB9-45A2-89C8-438377A77565}:_$(Key 'search:desktop-runtime')"
# Any 10.x WPF in the shared framework; patch-msi.ps1 adds the lower bound, which the Setup project drops.
Add-Value 'Name' (Str '.NET 10 Desktop Runtime'); Add-Value 'Folder' (Str '[ProgramFiles64Folder]dotnet\shared\Microsoft.WindowsDesktop.App')
Add-Value 'FileName' (Str 'PresentationFramework.dll'); Add-Value 'Depth' (Num 1); Add-Value 'MaxVersion' (Str '10.65535.65535.65535')
Add-Value 'Property' (Str 'DOTNETDESKTOP10')
Close-Block
Close-Block
Open-Block 'MsiBootstrapper'; Add-Value 'LangId' (Num 1033); Add-Value 'RequiresElevation' (Flag $false); Close-Block
Open-Block 'Product'
Add-Value 'Name' (Str 'Microsoft Visual Studio'); Add-Value 'ProductName' (Str 'Darkwire')
# patch-msi.ps1 issues new product and package codes after every build; the upgrade code never changes.
Add-Value 'ProductCode' (Str (New-Code)); Add-Value 'PackageCode' (Str (New-Code)); Add-Value 'UpgradeCode' (Str '{EC1E93E3-FE8B-4BC7-AC49-0BEA6CF96E3F}')
Add-Value 'AspNetVersion' (Str '2.0.50727.0'); Add-Value 'RestartWWWService' (Flag $false)
Add-Value 'RemovePreviousVersions' (Flag $true); Add-Value 'DetectNewerInstalledVersion' (Flag $true); Add-Value 'InstallAllUsers' (Flag $true)
Add-Value 'ProductVersion' (Str $Version); Add-Value 'Manufacturer' (Str 'Darkwire')
Add-Value 'ARPHELPTELEPHONE' (Str ''); Add-Value 'ARPHELPLINK' (Str ''); Add-Value 'Title' (Str 'Darkwire'); Add-Value 'Subject' (Str '')
Add-Value 'ARPCONTACT' (Str 'Darkwire'); Add-Value 'Keywords' (Str ''); Add-Value 'ARPCOMMENTS' (Str 'Endpoint firewall'); Add-Value 'ARPURLINFOABOUT' (Str '')
# A file reference here makes the build silently drop the Upgrade rows; patch-msi.ps1 reuses the shortcut's icon instead.
Add-Value 'ARPPRODUCTICON' (Str ''); Add-Value 'ARPIconIndex' (Num 0)
Add-Value 'SearchPath' (Str ''); Add-Value 'UseSystemSearchPath' (Flag $true); Add-Value 'TargetPlatform' (Num 1)
Add-Value 'PreBuildEvent' (Str '')
# patch-msi.ps1 also stores Darkwire.exe as the shortcut's icon, which must be an executable named like its target.
Add-Value 'PostBuildEvent' (Str ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'patch-msi.ps1') + '" "$(BuiltOuputPath)" "' + (Join-Path $image 'Darkwire.exe') + '"'))
Add-Value 'RunPostBuildEvent' (Num 0)
Close-Block
Open-Block 'Registry'; Close-Block
Open-Block 'Sequences'; Close-Block
Open-Block 'Shortcut'
Open-Block "{970C0BB2-C7D0-45D7-ABFA-7EC378858BC0}:_$(Key 'shortcut:menu')"
Add-Value 'Name' (Str 'Darkwire'); Add-Value 'Arguments' (Str ''); Add-Value 'Description' (Str 'Darkwire endpoint firewall')
Add-Value 'ShowCmd' (Num 1); Add-Value 'IconIndex' (Num 0); Add-Value 'Transitive' (Flag $false)
Add-Value 'Target' (Str "_$appExecutable"); Add-Value 'Folder' (Str "_$menuFolder"); Add-Value 'WorkingFolder' (Str "_$appFolder")
# Left empty, the build takes the shortcut's icon from Darkwire.exe; a file reference fails the build.
Add-Value 'Icon' (Str ''); Add-Value 'Feature' (Str '')
Close-Block
Close-Block
Open-Block 'UserInterface'
foreach ($module in 'VsdBasicDialogs.wim', 'VsdUserInterface.wim') {
    Open-Block "{2479F3F5-0309-486D-8047-8187E2CE5BA0}:_$(Key "module:$module")"
    Add-Value 'UseDynamicProperties' (Flag $false); Add-Value 'IsDependency' (Flag $false); Add-Value 'SourcePath' (Str "<VsdDialogDir>\$module")
    Close-Block
}
# Welcome and confirmation, then progress, then the finished page. There is no folder page.
foreach ($group in @(
    @{ Name = '#1900'; Attributes = 1; Dialogs = @(@{ Sequence = 100; Name = 'Welcome'; File = 'VsdWelcomeDlg.wid' }, @{ Sequence = 300; Name = 'Confirm Installation'; File = 'VsdConfirmDlg.wid' }) },
    @{ Name = '#1901'; Attributes = 2; Dialogs = @(@{ Sequence = 100; Name = 'Progress'; File = 'VsdProgressDlg.wid' }) },
    @{ Name = '#1902'; Attributes = 3; Dialogs = @(@{ Sequence = 100; Name = 'Finished'; File = 'VsdFinishedDlg.wid' }) })) {
    Open-Block "{DF760B10-853B-4699-99F2-AFF7185B4A62}:_$(Key "dialogs:$($group.Name)")"
    Add-Value 'Name' (Str $group.Name); Add-Value 'Sequence' (Num 1); Add-Value 'Attributes' (Num $group.Attributes)
    Open-Block 'Dialogs'
    foreach ($dialog in $group.Dialogs) {
        Open-Block "{688940B3-5CA9-4162-8DEE-2993FA9D8CBC}:_$(Key "dialog:$($dialog.File)")"
        Add-Value 'Sequence' (Num $dialog.Sequence); Add-Value 'DisplayName' (Str $dialog.Name)
        Add-Value 'UseDynamicProperties' (Flag $true); Add-Value 'IsDependency' (Flag $false); Add-Value 'SourcePath' (Str "<VsdDialogDir>\$($dialog.File)")
        Close-Block
    }
    Close-Block
    Close-Block
}
Close-Block
Open-Block 'MergeModule'; Close-Block
Open-Block 'ProjectOutput'; Close-Block
Close-Block
Close-Block

$projectDirectory = Join-Path (Split-Path -Parent $image) 'installer'
New-Item -ItemType Directory -Path $projectDirectory -Force | Out-Null
$project = Join-Path $projectDirectory 'Darkwire.Setup.vdproj'
[IO.File]::WriteAllLines($project, $lines, (New-Object Text.UTF8Encoding($false)))
$built = Join-Path $projectDirectory 'Release\Darkwire.msi'
$log = Join-Path $projectDirectory 'build.log'
foreach ($stale in $built, $log) { if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale } }
& $devenv $project /Build Release /Out $log | Out-Null
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $built)) {
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | Write-Host }
    throw "Visual Studio could not build $project. Open it in Visual Studio to see why."
}

# Refuse a package the PostBuildEvent did not patch, or whose shortcut icon is not Darkwire.exe.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($built, 0)
$get = [Reflection.BindingFlags]::GetProperty
function Get-Value([string]$sql, [string]$property) {
    $view = $database.OpenView($sql); [void]$view.Execute(); $record = $view.Fetch()
    $value = if ($null -eq $record) { $null } else { $record.GetType().InvokeMember($property, $get, $null, $record, [object[]]@([int]1)) }
    [void]$view.Close(); $value
}
$sequence = Get-Value "SELECT Sequence FROM InstallExecuteSequence WHERE Action = 'RemoveExistingProducts'" 'IntegerData'
$iconName = Get-Value 'SELECT Icon_ FROM Shortcut' 'StringData'
$iconSize = if ($iconName) { Get-Value "SELECT Data FROM Icon WHERE Name = '$iconName'" 'DataSize' } else { $null }
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
if ($sequence -ne 1450) { throw 'The installer was built without its post-build fixes (installer\patch-msi.ps1).' }
if ($iconSize -ne (Get-Item -LiteralPath (Join-Path $image 'Darkwire.exe')).Length) { throw 'The Start menu shortcut icon is not Darkwire.exe.' }
Copy-Item -LiteralPath $built -Destination $Output -Force
