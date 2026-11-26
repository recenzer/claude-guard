# Сборка Claude Guard в dist\ (framework-dependent, .NET 10).
# Запуск: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'

$dotnet = (Get-Command dotnet.exe -ErrorAction SilentlyContinue)
if ($dotnet) {
    $dotnetExe = $dotnet.Source
} else {
    $dotnetExe = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
}
if (-not (Test-Path $dotnetExe)) {
    throw "Не найден dotnet.exe. Установите .NET SDK 10."
}

Write-Host "==> Сборка Claude Guard" -ForegroundColor Cyan
Write-Host "    dotnet: $dotnetExe"

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }

& $dotnetExe publish (Join-Path $root 'src\ClaudeGuard.Service\ClaudeGuard.Service.csproj') `
    -c Release -o (Join-Path $dist 'service') --nologo
if ($LASTEXITCODE -ne 0) { throw "Сборка службы завершилась с ошибкой ($LASTEXITCODE)" }

& $dotnetExe publish (Join-Path $root 'src\ClaudeGuard.Ui\ClaudeGuard.Ui.csproj') `
    -c Release -o (Join-Path $dist 'ui') --nologo
if ($LASTEXITCODE -ne 0) { throw "Сборка UI завершилась с ошибкой ($LASTEXITCODE)" }

& (Join-Path $PSScriptRoot 'singbox.ps1') -Destination (Join-Path $dist 'service')

foreach ($f in @(
    (Join-Path $dist 'service\sing-box.exe'),
    (Join-Path $dist 'service\ClaudeGuard.Service.exe'),
    (Join-Path $dist 'ui\ClaudeGuard.Ui.exe'))) {
    if (-not (Test-Path $f)) { throw "Не найден результат сборки: $f" }
}

Write-Host "==> Готово: $dist" -ForegroundColor Green
