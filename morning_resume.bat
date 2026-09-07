@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Legacy state mutation.  The v7 authority remains default-off; this script
rem only updates the local legacy pause flag when explicitly invoked.
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" -c "import tb_control; tb_control.update(paused=False); print('resume ok')" >> "logs\morning_resume.log" 2>&1
exit /b %errorlevel%
