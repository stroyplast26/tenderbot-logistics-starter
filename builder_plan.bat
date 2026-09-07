@echo off
cd /d "%~dp0"
call "%~dp0python_runtime.bat" tb_builder_campaign.py --plan
set "RC=%errorlevel%"
pause
exit /b %RC%
