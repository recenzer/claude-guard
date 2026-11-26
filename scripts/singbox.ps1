# Downloads the pinned sing-box release for Windows x64 and copies sing-box.exe to -Destination.
# Usage: & scripts\singbox.ps1 -Destination dist\service
# The archive is cached in .cache\ so repeated builds work offline.
param(
    [Parameter(Mandatory = $true)][string]$Destination,
    [string]$Version = '1.12.0',
    # Optional SHA256 of the zip; fill it in to pin the exact binary.
    [string]$Sha256 = ''
)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $root '.cache'
New-Item -ItemType Directory -Force -Path $cache, $Destination | Out-Null

$name = "sing-box-$Version-windows-amd64"
$zip = Join-Path $cache "$name.zip"
$url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$name.zip"

if (-not (Test-Path $zip)) {
    Write-Host "==> Загрузка sing-box $Version" -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile "$zip.part" -UseBasicParsing
    Move-Item "$zip.part" $zip -Force
}

if ($Sha256) {
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash
    if ($actual -ne $Sha256.ToUpperInvariant()) {
        Remove-Item $zip -Force
        throw "SHA256 sing-box не совпадает: $actual"
    }
}

$extract = Join-Path $cache $name
if (-not (Test-Path (Join-Path $extract "$name\sing-box.exe"))) {
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $extract -Force
}
$exe = Join-Path $extract "$name\sing-box.exe"
if (-not (Test-Path $exe)) { throw "В архиве нет sing-box.exe: $zip" }

Copy-Item $exe (Join-Path $Destination 'sing-box.exe') -Force
$license = Join-Path $extract "$name\LICENSE"
if (Test-Path $license) { Copy-Item $license (Join-Path $Destination 'sing-box.LICENSE.txt') -Force }
Write-Host "    sing-box.exe -> $Destination" -ForegroundColor Green
