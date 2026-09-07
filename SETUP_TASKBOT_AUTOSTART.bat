@echo off
chcp 65001 >nul
cd /d "%~dp0"
if /i not "%TENDERBOT_ENABLE_TASKBOT_AUTOSTART%"=="YES" (
  echo BLOCKED: TaskBot autostart remains disabled by the v7 recovery baseline.
  echo To review it later, require an explicit owner decision and set
  echo TENDERBOT_ENABLE_TASKBOT_AUTOSTART=YES for that one command.
  exit /b 77
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TenderBotTaskBot" /t REG_SZ /d "%~dp0START_TASKBOT.bat" /f
