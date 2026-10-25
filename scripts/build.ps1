param([switch]$Package, [string]$Wintun, [string]$Backends, [string]$GeoIp, [string]$Version = '1.0.0')
$ErrorActionPreference = 'Stop'
# wintun-0.14.1.zip from https://www.wintun.net/builds/, pinned to the hash the WireGuard Windows build verifies.
$wintunArchiveSha256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    dotnet build Darkwire.slnx -c Release -m:1 -nr:false -p:NuGetAudit=false --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    if ($Package) {
        # artifacts/Darkwire is the install image: the MSI installs every file in it, so it starts empty.
        if (Test-Path -LiteralPath artifacts/Darkwire) { Remove-Item -LiteralPath artifacts/Darkwire -Recurse -Force }
        dotnet publish native/Darkwire.Host/Darkwire.Host.csproj -c Release --no-restore --self-contained false -o artifacts/Darkwire -m:1 -nr:false --nologo
        if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
        dotnet publish native/Darkwire.Service/Darkwire.Service.csproj -c Release --no-restore --self-contained false -o artifacts/Darkwire/Service -m:1 -nr:false --nologo
        if ($LASTEXITCODE -ne 0) { throw 'Service publish failed.' }
        if ($Wintun) {
            # The connection router loads this DLL as LocalSystem: accept only the pinned archive and a valid WireGuard LLC signature.
            $archive = (Resolve-Path -LiteralPath $Wintun).Path
            if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $wintunArchiveSha256) { throw 'The Wintun archive is not the pinned wintun-0.14.1.zip.' }
            $extract = Join-Path ([IO.Path]::GetTempPath()) ('darkwire-wintun-' + [guid]::NewGuid().ToString('N'))
            Expand-Archive -LiteralPath $archive -DestinationPath $extract
            try {
                $dll = Join-Path $extract 'wintun\bin\amd64\wintun.dll'
                $signature = Get-AuthenticodeSignature -LiteralPath $dll
                if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=WireGuard LLC') { throw 'wintun.dll is not validly signed by WireGuard LLC.' }
                $routerBackend = 'artifacts/Darkwire/Service/Backends/Router'
                New-Item -ItemType Directory -Path $routerBackend -Force | Out-Null
                Copy-Item -LiteralPath $dll -Destination $routerBackend -Force
                Copy-Item -LiteralPath (Join-Path $extract 'wintun\LICENSE.txt') -Destination (Join-Path $routerBackend 'wintun-LICENSE.txt') -Force
            } finally { Remove-Item -LiteralPath $extract -Recurse -Force }
        }
        if ($Backends) {
            # Optional runtimes (WireGuard\wireguard.exe, DnsCrypt\dnscrypt-proxy.exe) join the image, so the MSI installs them
            # with protected ACLs and the integrity manifest covers them. The service starts them as LocalSystem, so only the
            # binaries scripts/build-backends.ps1 takes from the official releases are accepted: wireguard.exe validly signed by
            # WireGuard LLC; dnscrypt-proxy, which its project signs with minisign rather than Authenticode, by its pinned hash
            # alone. Their licenses come along. Darkwire runs WireGuard tunnels only, so any other folder in the backends is
            # left out.
            $backendBinaries = @{
                'WireGuard\wireguard.exe' = '04C71FB1A555A6ACE40D3AE9113C90C4829D7CA1D6C903FD20A8D41A0E2BEF94'
                'DnsCrypt\dnscrypt-proxy.exe' = 'D847F834AEF02F8705A649DC1060F520CDB7931D7361035728770DCE2C16EEB6'
            }
            $source = (Resolve-Path -LiteralPath $Backends).Path
            foreach ($kind in 'WireGuard', 'DnsCrypt') {
                $from = Join-Path $source $kind
                if (!(Test-Path -LiteralPath $from)) { continue }
                foreach ($pinned in $backendBinaries.Keys | Where-Object { $_.StartsWith("$kind\") }) {
                    if (!(Test-Path -LiteralPath (Join-Path $source $pinned))) { throw "$pinned is missing from the backends." }
                }
                foreach ($binary in Get-ChildItem -LiteralPath $from -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll', '.sys' }) {
                    $relative = $binary.FullName.Substring($source.TrimEnd('\').Length + 1)
                    if ($backendBinaries[$relative] -ne (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash) { throw "$relative is not a pinned backend binary." }
                    if ($kind -ne 'DnsCrypt' -and (Get-AuthenticodeSignature -LiteralPath $binary.FullName).Status -ne 'Valid') { throw "$($binary.FullName) is not validly signed." }
                }
                New-Item -ItemType Directory -Path artifacts/Darkwire/Service/Backends -Force | Out-Null
                Copy-Item -LiteralPath $from -Destination artifacts/Darkwire/Service/Backends -Recurse -Force
            }
            $wireGuard = 'artifacts/Darkwire/Service/Backends/WireGuard/wireguard.exe'
            if ((Test-Path -LiteralPath $wireGuard) -and (Get-AuthenticodeSignature -LiteralPath $wireGuard).SignerCertificate.Subject -notmatch 'O=WireGuard LLC') { throw 'wireguard.exe is not signed by WireGuard LLC.' }
            # WireGuard's installer carries no license text; its licenses, and those of what wireguard.exe contains, come from here.
            if (Test-Path -LiteralPath $wireGuard) { Copy-Item -LiteralPath installer/WireGuard-LICENSE.txt -Destination 'artifacts/Darkwire/Service/Backends/WireGuard/LICENSE.txt' -Force }
        }
        if ($GeoIp) {
            # DB-IP Lite (dbip-country-lite-YYYY-MM.csv.gz, dbip-asn-lite-YYYY-MM.csv.gz and dbip-city-lite-YYYY-MM.csv.gz),
            # converted into the database the service and the app load at once, and the city data only the app loads, which
            # goes beside the app so the service's integrity check does not hash it. The service refreshes both weekly afterwards.
            $source = (Resolve-Path -LiteralPath $GeoIp).Path
            $countryFile = @(Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Name -match '^dbip-country-lite-\d{4}-\d{2}\.csv\.gz$' })
            if ($countryFile.Count -ne 1) { throw 'Expected exactly one dbip-country-lite-YYYY-MM.csv.gz in the GeoIP folder.' }
            $release = [regex]::Match($countryFile[0].Name, '\d{4}-\d{2}').Value
            $asnFile = Join-Path $source "dbip-asn-lite-$release.csv.gz"
            $cityFile = Join-Path $source "dbip-city-lite-$release.csv.gz"
            foreach ($file in $asnFile, $cityFile) { if (!(Test-Path -LiteralPath $file)) { throw "Expected $(Split-Path -Leaf $file) beside the country release." } }
            Get-FileHash -LiteralPath $countryFile[0].FullName, $asnFile, $cityFile -Algorithm SHA256 | Format-List
            New-Item -ItemType Directory -Path artifacts/Darkwire/Service/Data, artifacts/Darkwire/Data -Force | Out-Null
            dotnet artifacts/Darkwire/Service/Darkwire.Service.dll --build-geoip $countryFile[0].FullName $asnFile $release artifacts/Darkwire/Service/Data/geoip.dat
            if ($LASTEXITCODE -ne 0) { throw 'GeoIP conversion failed.' }
            dotnet artifacts/Darkwire/Service/Darkwire.Service.dll --build-geoip-cities $cityFile $release artifacts/Darkwire/Data/geoip-city.dat
            if ($LASTEXITCODE -ne 0) { throw 'GeoIP city conversion failed.' }
            foreach ($data in 'artifacts/Darkwire/Service/Data', 'artifacts/Darkwire/Data') { Copy-Item -LiteralPath installer/geoip-NOTICE.txt -Destination $data }
        }
        # Darkwire's own license, the MIT License; then what third-party software and data the image holds, under which
        # licenses, with the license files beside them.
        Copy-Item -LiteralPath LICENSE -Destination artifacts/Darkwire/LICENSE.txt
        Copy-Item -LiteralPath THIRD-PARTY-NOTICES.txt -Destination artifacts/Darkwire
        $msi = "artifacts/Darkwire-$Version-x64.msi"
        & (Join-Path $projectRoot 'installer/build-msi.ps1') -PackageDirectory artifacts/Darkwire -Output $msi -Version $Version
        Get-FileHash -LiteralPath $msi -Algorithm SHA256 | Format-List
    }
} finally { Pop-Location }
