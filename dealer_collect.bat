@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" tb_dealers_pool.py --target 100000 --max-searches 120 >> "logs\dealer_collect.log" 2>&1
exit /b %errorlevel%
