@echo off
chcp 65001 >nul
set PYTHONUTF8=1
cd /d "%~dp0"
echo ============================================================
echo  TenderBot - ловец доставки Unisender (видимость mail.ru)
echo  Поднимает: ловец + Serveo HTTPS-туннель + авто-регистрацию.
echo  Оставь это окно открытым. Ctrl+C - остановить.
echo ============================================================
call "%~dp0python_runtime.bat" tb_webhook.py run-serveo
set "RC=%errorlevel%"
echo.
echo (Ловец остановлен. Регистрация вебхука снята.)
pause
exit /b %RC%
