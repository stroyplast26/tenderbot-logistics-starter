@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Утренний сид-тест доставки (перед стартом дилерской рассылки). Пишет pool/seed_result.json.
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" tb_seed_test.py >> "logs\seed_test.log" 2>&1
exit /b %errorlevel%
