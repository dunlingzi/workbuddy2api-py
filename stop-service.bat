@echo off
REM ASCII only: a UTF-8 Chinese .bat shows as mojibake under the GBK console
REM code page (936) and cmd then tries to run the comment as a command.
title workbuddy2api - Stop
cd /d "%~dp0"
setlocal

echo ========================================
echo   workbuddy2api Stop Service
echo ========================================
echo.

REM Stop both the watchdog and the service (including any leftover main.py).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\daemon.ps1" -Stop

netstat -ano | findstr ":8790" | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo Failed to stop! Trying taskkill fallback...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8790" ^| findstr "LISTENING"') do (
        taskkill /PID %%a /F >nul 2>&1
        echo Killed PID=%%a
    )
) else (
    echo Service stopped.
)

echo.
pause
