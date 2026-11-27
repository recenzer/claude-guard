# Builds a self-contained release package: release\ClaudeGuard-<version>-win-x64.zip
# Users do NOT need the .NET SDK/runtime installed.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dotnet = (Get-Command dotnet.exe -ErrorAction Stop).Source

$csproj = [xml](Get-Content (Join-Path $root 'src\ClaudeGuard.Service\ClaudeGuard.Service.csproj') -Raw)
$version = ($csproj.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
if (-not $version) { $version = '1.0.0' }

$stage = Join-Path $root 'release\stage\ClaudeGuard'
$zip = Join-Path $root "release\ClaudeGuard-$version-win-x64.zip"

if (Test-Path (Join-Path $root 'release')) { Remove-Item (Join-Path $root 'release') -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'dist'), (Join-Path $stage 'scripts') | Out-Null

foreach ($p in @(@('Service', 'service'), @('Ui', 'ui'))) {
    Write-Host "==> publish $($p[0])" -ForegroundColor Cyan
    & $dotnet publish (Join-Path $root "src\ClaudeGuard.$($p[0])\ClaudeGuard.$($p[0]).csproj") `
        -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true -p:DebugType=None -p:DebugSymbols=false `
        -o (Join-Path $stage "dist\$($p[1])") --nologo
    if ($LASTEXITCODE -ne 0) { throw "publish $($p[0]) failed ($LASTEXITCODE)" }
}

& (Join-Path $PSScriptRoot 'singbox.ps1') -Destination (Join-Path $stage 'dist\service')

foreach ($f in 'install.ps1', 'install.cmd', 'uninstall.ps1', 'uninstall.cmd', 'singbox.ps1') {
    Copy-Item (Join-Path $root "scripts\$f") (Join-Path $stage "scripts\$f")
}
foreach ($f in 'README.md', 'LICENSE') {
    if (Test-Path (Join-Path $root $f)) { Copy-Item (Join-Path $root $f) $stage }
}

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
$mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "==> Done: $zip ($mb MB)" -ForegroundColor Green
