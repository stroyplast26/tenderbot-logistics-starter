@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" tb_builder_campaign.py --poll >> "logs\builder_poll.log" 2>&1
exit /b %errorlevel%
