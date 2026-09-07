@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Legacy engine.  External effects remain blocked by the v7 authority.
call "%~dp0python_runtime.bat" tb_bot.py
exit /b %errorlevel%
