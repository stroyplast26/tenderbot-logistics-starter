@echo off
chcp 65001 >nul
cd /d "%~dp0"
if /i not "%TENDERBOT_ENABLE_LEGACY_SCHEDULES%"=="YES" (
  echo BLOCKED: legacy autostart remains disabled by the v7 recovery baseline.
  echo To review it later, require an explicit owner decision and set
  echo TENDERBOT_ENABLE_LEGACY_SCHEDULES=YES for that one command.
  exit /b 77
)
rem Регистрирует автозапуск движка кампании при входе в Windows (Планировщик задач).
schtasks /create /tn "TenderBotEngine" /tr "\"%~dp0START_BOT.bat\"" /sc onlogon /rl limited /f
echo.
echo Готово. Движок "TenderBotEngine" будет стартовать при входе в систему.
echo Запустить прямо сейчас: schtasks /run /tn "TenderBotEngine"
echo Остановить задачу:     schtasks /end /tn "TenderBotEngine"
echo Удалить автозапуск:    schtasks /delete /tn "TenderBotEngine" /f
pause
