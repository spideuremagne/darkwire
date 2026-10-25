param([Parameter(Mandatory)][string]$Source, [string]$Retrieved = (Get-Date -Format 'yyyy-MM-dd'),
    [string]$Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'native\Darkwire.Host\Assets\cities15000.tsv.gz'))
# Converts GeoNames' cities15000.txt (https://download.geonames.org/export/dump/cities15000.zip, CC BY 4.0) into the compact
# list Darkwire bundles for placing this PC on the map: country, name, ASCII name when it differs, a lettered first-level
# region code (US states, for example), latitude, longitude and population; country by country, most populous first.
# The bundled list was made on 2026-10-15 from a cities15000.txt with SHA-256 B5B4355AC000C82B70854BB98F711B110A39834D2B2A9A606B35A5F91A49339D.
$ErrorActionPreference = 'Stop'
$invariant = [Globalization.CultureInfo]::InvariantCulture
$rows = New-Object System.Collections.Generic.List[object]
$number = 0; $skipped = 0
foreach ($line in [IO.File]::ReadLines((Resolve-Path -LiteralPath $Source).Path, [Text.Encoding]::UTF8)) {
    $number++
    $f = $line.Split("`t")
    if ($f.Count -ne 19) { throw "Line ${number}: expected 19 columns, found $($f.Count)." }
    $name = $f[1].Trim(); $ascii = $f[2].Trim(); $country = $f[8]
    $latitude = 0.0; $longitude = 0.0; $population = 0L; $id = 0L
    if ($f[6] -ne 'P' -or $country -cnotmatch '^[A-Z]{2}$' -or $name.Length -eq 0 -or $name.Length -gt 200 -or
        -not [long]::TryParse($f[0], [Globalization.NumberStyles]::None, $invariant, [ref]$id) -or
        -not [double]::TryParse($f[4], [Globalization.NumberStyles]::Float, $invariant, [ref]$latitude) -or
        -not [double]::TryParse($f[5], [Globalization.NumberStyles]::Float, $invariant, [ref]$longitude) -or
        -not [long]::TryParse($f[14], [Globalization.NumberStyles]::None, $invariant, [ref]$population) -or
        [math]::Abs($latitude) -gt 90 -or [math]::Abs($longitude) -gt 180 -or $population -gt [int]::MaxValue) { throw "Line ${number}: not a populated place Darkwire can use." }
    # Sections of a city (its districts), and historical, abandoned or destroyed places, are not where anyone says they live.
    if ($f[7] -cin 'PPLX', 'PPLH', 'PPLQ', 'PPLW') { $skipped++; continue }
    $rows.Add([pscustomobject]@{
        Id = $id; Country = $country; Name = $name; Ascii = $(if ($ascii -ceq $name) { '' } else { $ascii })
        # Lettered codes name the region (IL, ENG); numeric ones mean nothing without GeoNames' code table, which is not bundled.
        Region = $(if ($f[10] -cmatch '^[A-Z]{2,3}$') { $f[10] } else { '' })
        Latitude = $latitude; Longitude = $longitude; Population = $population
    })
}
# GeoNames IDs settle ties, so the output depends on the input alone.
$sorted = $rows | Sort-Object -CaseSensitive @{ Expression = { $_.Country } }, @{ Expression = { $_.Population }; Descending = $true }, @{ Expression = { $_.Id } }
$text = New-Object Text.StringBuilder
[void]$text.Append("#darkwire-cities 1`tGeoNames cities15000`t$Retrieved`n")
foreach ($row in $sorted) {
    [void]$text.Append([string]::Format($invariant, "{0}`t{1}`t{2}`t{3}`t{4:0.####}`t{5:0.####}`t{6}`n",
        $row.Country, $row.Name, $row.Ascii, $row.Region, $row.Latitude, $row.Longitude, $row.Population))
}
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text.ToString())
$file = [IO.File]::Create($Output)
try { $gzip = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionMode]::Compress); try { $gzip.Write($bytes, 0, $bytes.Length) } finally { $gzip.Dispose() } }
finally { $file.Dispose() }
"{0:N0} cities from {1:N0} countries ({2:N0} places left out); {3:N0} bytes, {4:N0} compressed" -f $rows.Count, ($rows | Select-Object -ExpandProperty Country -Unique).Count, $skipped, $bytes.Length, (Get-Item -LiteralPath $Output).Length
(Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash
