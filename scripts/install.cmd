@echo off
chcp 65001 >nul
setlocal
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Запрос прав администратора...
    rem paths/arguments go through env vars so quotes and apostrophes cannot break the command;
    rem Start-Process rejects an empty -ArgumentList, so pass it only when there are arguments
    set "CG_SELF=%~f0"
    set "CG_ARGS=%*"
    if "%~1"=="" (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:CG_SELF -Verb RunAs"
    ) else (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:CG_SELF -Verb RunAs -ArgumentList $env:CG_ARGS"
    )
    exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" (
    echo Установка завершилась с ошибкой. Код: %RC%
) else (
    echo Готово.
)
pause
exit /b %RC%
