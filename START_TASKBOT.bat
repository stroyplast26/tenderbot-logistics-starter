@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Explicit foreground launch.  Autostart is intentionally not configured by recovery.
call "%~dp0python_runtime.bat" -m taskbot.supervisor
exit /b %errorlevel%
