#requires -RunAsAdministrator
<#
    Удаление Claude Guard (полный откат).
    Запускать через scripts\uninstall.cmd (Windows PowerShell 5.1, с повышением прав).

    Удаляет: задачи автозапуска, службу, правила firewall Claude Guard, ярлык,
    файлы программы. Данные (журналы, конфиг) сохраняются, если не указан -PurgeData.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'ClaudeGuard'),
    [string]$DataDir = (Join-Path $env:ProgramData 'ClaudeGuard'),
    [switch]$KeepRules,
    [switch]$PurgeData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw "Запустите через scripts\uninstall.cmd — нужен Windows PowerShell 5.1 (модуль ScheduledTasks)."
}

$ServiceName = 'ClaudeGuard'
$UiTaskName = 'ClaudeGuardUi'
$WatchdogTaskName = 'ClaudeGuardWatchdog'
$ShortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Claude Guard.lnk'
$svcExe = Join-Path $InstallDir 'ClaudeGuard.Service.exe'

if (-not $Yes) {
    $answer = Read-Host "Удалить Claude Guard? Защита Claude будет снята. [y/N]"
    if ($answer -notmatch '^[yY]') { Write-Host "Отменено."; return }
}

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

Write-Step "Остановка UI"
Get-Process -Name 'ClaudeGuard.Ui' -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Kill(); $_.WaitForExit(3000) } catch { }
}

Write-Step "Удаление задач планировщика"
foreach ($t in @($UiTaskName, $WatchdogTaskName)) {
    Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "    $t" -ForegroundColor DarkGray
}

Write-Step "Остановка и удаление службы"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            $svc.Refresh()
            if ($svc.Status -eq 'Stopped') { break }
        }
    }
    & sc.exe delete $ServiceName | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { break }
    }
    Write-Host "    служба удалена" -ForegroundColor DarkGray
} else {
    Write-Host "    служба не установлена" -ForegroundColor DarkGray
}

if ($KeepRules) {
    Write-Host "==> Правила firewall сохранены (-KeepRules)" -ForegroundColor Yellow
} else {
    Write-Step "Удаление правил firewall Claude Guard"
    if (Test-Path $svcExe) {
        & $svcExe --remove-rules | Out-Null
    } else {
        # файлы уже удалены — чистим правила через COM
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        $names = @()
        foreach ($r in $fw.Rules) {
            if ($r.Name -like 'ClaudeGuard#*') { $names += $r.Name }
        }
        foreach ($n in $names) { $fw.Rules.Remove($n) }
    }
    Write-Host "    правила удалены" -ForegroundColor DarkGray
}

Write-Step "Удаление ярлыка"
if (Test-Path $ShortcutPath) {
    Remove-Item $ShortcutPath -Force
    Write-Host "    $ShortcutPath" -ForegroundColor DarkGray
}

Write-Step "Удаление файлов программы"
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "    $InstallDir" -ForegroundColor DarkGray
}

if ($PurgeData) {
    Write-Step "Удаление данных"
    if (Test-Path $DataDir) {
        Remove-Item $DataDir -Recurse -Force
        Write-Host "    $DataDir" -ForegroundColor DarkGray
    }
} else {
    Write-Host "==> Данные сохранены: $DataDir (удалить: -PurgeData)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Claude Guard удалён. Claude Desktop больше не блокируется." -ForegroundColor Green
