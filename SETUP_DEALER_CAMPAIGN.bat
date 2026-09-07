@echo off
chcp 65001 >nul
cd /d "%~dp0"
if /i not "%TENDERBOT_ENABLE_LEGACY_SCHEDULES%"=="YES" (
  echo BLOCKED: legacy dealer/builder schedules remain disabled by the v7 recovery baseline.
  echo To review them later, require an explicit owner decision and set
  echo TENDERBOT_ENABLE_LEGACY_SCHEDULES=YES for that one command.
  exit /b 77
)
rem ── Регистрирует авто-расписание дилерской кампании в Планировщике задач Windows ──
rem   ALT_DealerSend — ежедневно 10:00 отправляет партию дня (раннер сам пропускает выходные
rem                    и НЕ шлёт, пока кампания на предохранителе; включить: --enable).
rem   ALT_DealerPoll — каждые 20 минут забирает ответы -> лид в Bitrix + пинг в Telegram.

schtasks /create /tn "ALT_DealerSend" /tr "\"%~dp0dealer_send.bat\"" /sc daily /st 10:00 /f
schtasks /create /tn "ALT_DealerPoll" /tr "\"%~dp0dealer_poll.bat\"" /sc minute /mo 5 /f
schtasks /create /tn "ALT_BuilderPoll" /tr "\"%~dp0builder_poll_scheduled.bat\"" /sc minute /mo 5 /f

echo.
echo ── Готово. Задачи созданы (кампания ПОКА ВЫКЛЮЧЕНА предохранителем — рассылка не идёт). ──
echo.
echo Когда решишь запускать:   python_runtime.bat tb_dealer_campaign.py --enable
echo Поставить на паузу:       python_runtime.bat tb_dealer_campaign.py --disable
echo Статус кампании:          python_runtime.bat tb_dealer_campaign.py --status
echo Проверить план на сегодня: python_runtime.bat tb_dealer_campaign.py --plan
echo.
echo Запустить задачи прямо сейчас: schtasks /run /tn "ALT_DealerPoll"
echo Удалить расписание:  schtasks /delete /tn "ALT_DealerSend" /f  ^&  schtasks /delete /tn "ALT_DealerPoll" /f
pause
