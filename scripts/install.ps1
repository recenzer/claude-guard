#requires -RunAsAdministrator
<#
    Установка Claude Guard.
    Запускать через scripts\install.cmd (Windows PowerShell 5.1, с повышением прав).

    Что делает:
      1. Проверяет Windows Firewall и наличие Claude Desktop.
      2. Делает резервную копию правил firewall и конфигурации.
      3. Копирует файлы в C:\Program Files\ClaudeGuard, выставляет ACL.
      4. Запускает самопроверку (физический блок, sing-box, прокси, TUN).
      5. Создаёт службу ClaudeGuard (LocalSystem, auto, recovery) и задачи:
         ClaudeGuardUi (при входе пользователя) и ClaudeGuardWatchdog (SYSTEM, каждую минуту).
      6. Запускает службу и проверяет IPC.
    При ошибке самопроверки/запуска выполняется откат: служба и задачи удаляются,
    правила Claude Guard снимаются (Claude разблокируется).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'ClaudeGuard'),
    [string]$DataDir = (Join-Path $env:ProgramData 'ClaudeGuard'),
    [switch]$EnableFirewall,
    [switch]$SkipSelfTest,
    [switch]$NoUiAutostart,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw "Запустите через scripts\install.cmd — нужен Windows PowerShell 5.1 (модуль ScheduledTasks)."
}

$ServiceName = 'ClaudeGuard'
$ServiceDisplay = 'Claude Guard'
$UiTaskName = 'ClaudeGuardUi'
$WatchdogTaskName = 'ClaudeGuardWatchdog'
$ShortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Claude Guard.lnk'

$root = Split-Path -Parent $PSScriptRoot
$srcService = Join-Path $root 'dist\service'
$srcUi = Join-Path $root 'dist\ui'
$svcExe = Join-Path $InstallDir 'ClaudeGuard.Service.exe'
$uiExe = Join-Path $InstallDir 'ClaudeGuard.Ui.exe'

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "    $text" -ForegroundColor Green }
function Write-Warn2($text){ Write-Host "    $text" -ForegroundColor Yellow }

function Stop-UiProcess {
    Get-Process -Name 'ClaudeGuard.Ui' -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_.Kill(); $_.WaitForExit(3000) } catch { }
    }
}

function Remove-ServiceIfExists {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }
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
}

function Remove-TasksIfExist {
    foreach ($t in @($UiTaskName, $WatchdogTaskName)) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Remove-Rules {
    if (Test-Path $svcExe) {
        try { & $svcExe --remove-rules | Out-Null } catch { }
    }
}

function Invoke-Rollback([string]$reason) {
    Write-Host ""
    Write-Host "ОТКАТ: $reason" -ForegroundColor Red
    Remove-TasksIfExist
    try { Remove-ServiceIfExists } catch { }
    Stop-UiProcess
    Remove-Rules
    Write-Host "Служба и задачи удалены, правила Claude Guard сняты. Claude разблокирован." -ForegroundColor Yellow
    Write-Host "Файлы оставлены в $InstallDir для диагностики; удалить: scripts\uninstall.cmd -PurgeData" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- проверки

Write-Step "Проверка окружения"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Нужны права администратора."
}

$claude = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $claude) {
    Write-Warn2 "Пакет Claude Desktop не найден через Get-AppxPackage. Служба будет искать его по каталогу WindowsApps."
} else {
    Write-Ok "Claude Desktop: $($claude.PackageFullName)"
}

$disabledProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
if ($disabledProfiles.Count -gt 0) {
    $profileNames = ($disabledProfiles | ForEach-Object { $_.Name }) -join ', '
    if ($EnableFirewall) {
        Set-NetFirewallProfile -All -Enabled True
        Write-Warn2 "Windows Firewall был выключен ($profileNames) — включён для всех профилей."
    } else {
        throw "Windows Firewall выключен (профили: $profileNames). Без него правила не действуют. Включите firewall или запустите с -EnableFirewall."
    }
} else {
    Write-Ok "Windows Firewall включён (domain/private/public)."
}

if (-not $NoBuild -and (Test-Path (Join-Path $root "src"))) {
    $dotnetCmd = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($dotnetCmd) {
        Write-Step "Сборка актуальной версии"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'build.ps1')
        if ($LASTEXITCODE -ne 0) { throw "Сборка не удалась." }
    } else {
        Write-Warn2 "dotnet не найден — используется готовая сборка из dist."
    }
}

foreach ($f in @($srcService, $srcUi, (Join-Path $srcService 'sing-box.exe'))) {
    if (-not (Test-Path $f)) {
        throw "Не найден каталог сборки: $f. Запустите scripts\build.ps1 (нужен .NET SDK 10)."
    }
}

# ---------------------------------------------------------------- каталоги и бэкап

Write-Step "Подготовка каталогов"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
$backupDir = Join-Path $DataDir 'backup'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$fwBackup = Join-Path $backupDir "firewall-$stamp.wfx"
try {
    & netsh.exe advfirewall export $fwBackup | Out-Null
    Write-Ok "Резервная копия firewall: $fwBackup"
} catch {
    Write-Warn2 "Не удалось экспортировать firewall: $($_.Exception.Message)"
}
$cfgPath = Join-Path $DataDir 'config.json'
if (Test-Path $cfgPath) {
    Copy-Item $cfgPath (Join-Path $backupDir "config-$stamp.json") -Force
    Write-Ok "Резервная копия config.json"
}

# ---------------------------------------------------------------- файлы

Write-Step "Остановка прежней версии и копирование файлов"
Stop-UiProcess
Remove-TasksIfExist
try { Remove-ServiceIfExists } catch { }

Copy-Item -Path (Join-Path $srcService '*') -Destination $InstallDir -Recurse -Force
Copy-Item -Path (Join-Path $srcUi '*') -Destination $InstallDir -Recurse -Force
if (-not (Test-Path $svcExe) -or -not (Test-Path $uiExe)) {
    throw "После копирования не найдены $svcExe / $uiExe"
}
Write-Ok "Файлы скопированы в $InstallDir"

Write-Step "Настройка ACL"
# SYSTEM и Administrators — полный доступ; Users — только чтение.
# Это не позволяет обычному пользователю подменить exe, который служба запускает от SYSTEM.
foreach ($d in @($InstallDir, $DataDir)) {
    & icacls.exe $d /inheritance:r `
        /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls завершился с ошибкой: $d" }
}
# Profile and generated sing-box config contain proxy credentials: SYSTEM/Administrators only.
$secretsDir = Join-Path $DataDir 'secrets'
New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null
& icacls.exe $secretsDir /inheritance:r `
    /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls (secrets) завершился с ошибкой." }
Write-Ok "ACL: SYSTEM/Administrators — запись, Users — чтение; secrets — только SYSTEM/Administrators"

# ---------------------------------------------------------------- самопроверка

$selftestOk = $false
if (-not $SkipSelfTest) {
    Write-Step "Самопроверка (физический блок + sing-box + прокси + TUN)"
    $out = (& $svcExe --selftest 2>&1 | Out-String)
    $selftestFile = Join-Path $DataDir 'install-selftest.json'
    Set-Content -Path $selftestFile -Value $out -Encoding UTF8
    $json = $null
    $start = $out.IndexOf('{'); $end = $out.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
        try { $json = $out.Substring($start, $end - $start + 1) | ConvertFrom-Json } catch { }
    }
    if ($json -and $json.Ok) {
        $selftestOk = $true
        Write-Ok "Самопроверка пройдена"
        foreach ($s in $json.Steps) { Write-Host "      $s" -ForegroundColor DarkGray }
    } elseif ($json -and ($json.Error -match 'нет профиля прокси')) {
        Write-Warn2 "Профиль прокси ещё не задан — физический блок проверен, проверка прокси пропущена."
        Write-Warn2 "Claude будет заблокирован, пока вы не импортируете профиль в окне Claude Guard."
        foreach ($s in $json.Steps) { Write-Host "      $s" -ForegroundColor DarkGray }
        $selftestOk = $true
    } else {
        $err = if ($json) { $json.Error } else { 'не удалось разобрать результат' }
        Invoke-Rollback "самопроверка не пройдена: $err"
        throw "Самопроверка не пройдена: $err (подробности: $selftestFile)"
    }
} else {
    Write-Warn2 "Самопроверка пропущена (-SkipSelfTest)."
}

# ---------------------------------------------------------------- служба

Write-Step "Создание службы $ServiceName"
try {
    $binPath = '"' + $svcExe + '" --service'
    New-Service -Name $ServiceName -BinaryPathName $binPath `
        -DisplayName $ServiceDisplay `
        -Description 'Claude Desktop только через свой прокси (sing-box TUN + fail-closed firewall).' `
        -StartupType Automatic | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null
    Write-Ok "Служба создана (LocalSystem, автозапуск, recovery: 5с/10с/30с)"
} catch {
    Invoke-Rollback "не удалось создать службу: $($_.Exception.Message)"
    throw
}

# ---------------------------------------------------------------- задачи

if (-not $NoUiAutostart) {
    Write-Step "Создание задачи автозапуска UI"
    # The tray UI must run for the person sitting at the console, not for the admin account
    # that approved UAC (over-the-shoulder elevation).
    $user = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    if (-not $user) { $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    $uiAction = New-ScheduledTaskAction -Execute $uiExe -Argument '--minimized' -WorkingDirectory $InstallDir
    $uiTrigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $uiSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    $uiPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $UiTaskName -Action $uiAction -Trigger $uiTrigger `
        -Settings $uiSettings -Principal $uiPrincipal `
        -Description 'Claude Guard: значок в трее при входе пользователя.' -Force | Out-Null
    Write-Ok "Задача $UiTaskName для $user"
}

Write-Step "Создание задачи watchdog"
$wdAction = New-ScheduledTaskAction -Execute $svcExe -Argument '--watchdog' -WorkingDirectory $InstallDir
$wdTrigger1 = New-ScheduledTaskTrigger -AtStartup
$wdTrigger2 = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$wdSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$wdPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $WatchdogTaskName -Action $wdAction -Trigger @($wdTrigger1, $wdTrigger2) `
    -Settings $wdSettings -Principal $wdPrincipal `
    -Description 'Claude Guard: проверка службы; при отказе — аварийная блокировка.' -Force | Out-Null
Write-Ok "Задача $WatchdogTaskName (SYSTEM, каждую минуту)"

# ---------------------------------------------------------------- ярлык

Write-Step "Ярлык в меню «Пуск»"
try {
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($ShortcutPath)
    $lnk.TargetPath = $uiExe
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = 'Claude Guard'
    $lnk.Save()
    Write-Ok $ShortcutPath
} catch {
    Write-Warn2 "Не удалось создать ярлык: $($_.Exception.Message)"
}

# ---------------------------------------------------------------- запуск

Write-Step "Запуск службы"
try {
    Start-Service -Name $ServiceName
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        & $svcExe --status *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    if (-not $ready) { throw "служба не отвечает по IPC (ClaudeGuard.v1)" }
    Write-Ok "Служба запущена, IPC доступен"
} catch {
    Invoke-Rollback "служба не запустилась: $($_.Exception.Message)"
    throw
}

$statusText = (& $svcExe --status 2>$null | Out-String)
$state = 'неизвестно'; $reason = ''
try {
    $st = $statusText | ConvertFrom-Json
    $state = $st.status.state
    $reason = $st.status.reasonText
} catch { }
Write-Host ""
Write-Host "Состояние: $state" -ForegroundColor Green
if ($reason) { Write-Host "Причина:   $reason" }

if (-not $NoUiAutostart) {
    try {
        Start-ScheduledTask -TaskName $UiTaskName
        Write-Ok "UI запущен (иконка в трее)"
    } catch {
        Write-Warn2 "UI не запустился автоматически: $($_.Exception.Message). Запустите «Claude Guard» из меню «Пуск»."
    }
}

Write-Host ""
Write-Host "Установка завершена." -ForegroundColor Green
Write-Host "  Служба:  Get-Service $ServiceName"
Write-Host "  Статус:  & '$svcExe' --status"
Write-Host "  Журнал:  $DataDir\logs"
Write-Host "  Удалить: scripts\uninstall.cmd"
