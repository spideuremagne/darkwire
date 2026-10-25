param([switch]$NativeReadOnly, [switch]$Screenshots)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    dotnet build Darkwire.slnx -c Release -m:1 -nr:false -p:NuGetAudit=false --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    $testArgs = @()
    if ($NativeReadOnly) { $testArgs += '--native-readonly' }
    dotnet native/Darkwire.Checks/bin/Release/net10.0-windows/Darkwire.Checks.dll @testArgs
    if ($LASTEXITCODE -ne 0) { throw 'Checks failed.' }
    dotnet native/Darkwire.Service/bin/Release/net10.0-windows/Darkwire.Service.dll --self-test
    if ($LASTEXITCODE -ne 0) { throw 'Service checks failed.' }
    $vpnArgs = @()
    if ($NativeReadOnly) { $vpnArgs += '--native-loopback' }
    dotnet native/Darkwire.Vpn.Checks/bin/Release/net10.0-windows/Darkwire.Vpn.Checks.dll @vpnArgs
    if ($LASTEXITCODE -ne 0) { throw 'VPN checks failed.' }
    if ($Screenshots) {
        $captureDir = Join-Path $projectRoot 'artifacts/screenshots'
        dotnet native/Darkwire.Host/bin/Release/net10.0-windows/Darkwire.dll --capture $captureDir
        if ($LASTEXITCODE -ne 0) { throw 'Capture failed.' }
        $result = Get-Content -LiteralPath (Join-Path $captureDir 'capture-result.json') | ConvertFrom-Json
        if (-not $result.success) { throw 'Render validation failed.' }
        $result
    }
} finally { Pop-Location }
