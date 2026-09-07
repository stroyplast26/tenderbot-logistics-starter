@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Ежедневная партия дилерской рассылки (раннер сам чтит прогрев, каданс, будни и ПРЕДОХРАНИТЕЛЬ).
rem Пока кампания не включена (--enable) — ничего не отправляется.
if not exist "logs" mkdir "logs"
call "%~dp0python_runtime.bat" tb_dealer_campaign.py --send --new-first >> "logs\dealer_send.log" 2>&1
exit /b %errorlevel%
