@echo off
chcp 65001 >nul
cd /d "%~dp0"
call "%~dp0python_runtime.bat" tb_main.py %*
exit /b %errorlevel%
