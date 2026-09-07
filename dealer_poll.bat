@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Check the inbox, process dealer replies, and update the stop list.
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" tb_dealer_campaign.py --poll >> "logs\dealer_poll.log" 2>&1
exit /b %errorlevel%
