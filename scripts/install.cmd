@echo off
chcp 65001 >nul
setlocal
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Запрос прав администратора...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
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
