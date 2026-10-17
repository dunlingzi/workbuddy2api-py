@echo off
REM ASCII only: a UTF-8 Chinese .bat shows as mojibake under the GBK console
REM code page (936) and cmd then tries to run the comment as a command.
title workbuddy2api - Start
cd /d "%~dp0"
setlocal

echo ========================================
echo   workbuddy2api Start Service
echo ========================================
echo.

REM Stop any old instance / old watchdog first.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\daemon.ps1" -Stop >nul 2>&1

REM -Detach: relaunch the watchdog in a hidden window that is fully detached
REM from this console. Do NOT use "start /B": that keeps the service tied to
REM this console, so closing the window kills the service.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\daemon.ps1" -Detach

echo Starting detached daemon + service, please wait...

REM Poll port 8790 until it listens. uvicorn boot plus the DB migrations can
REM take 10-30s, so a single fixed wait reports a false failure.
set /a tries=0
:wait
set /a tries+=1
netstat -ano | findstr ":8790" | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 goto ready
if %tries% GEQ 30 goto failed
timeout /t 2 /nobreak >nul
goto wait

:ready
echo Service started OK!
goto done

:failed
echo Start FAILED - check logs\daemon.log and logs\service.err.log

:done
echo.
echo ========================================
echo   Admin UI : http://127.0.0.1:8790/admin
echo   Username : ADMIN_USERNAME in .env
echo   Password : ADMIN_PASSWORD in .env
echo ========================================
echo.
echo Service runs detached. You can close this window now.
echo The watchdog auto-restarts the service if it dies.
echo To stop: double-click stop-service.bat
echo.
pause
