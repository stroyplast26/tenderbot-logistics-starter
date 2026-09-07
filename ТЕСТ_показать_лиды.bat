@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ТЕСТОВЫЙ ПРОГОН: программа найдёт лиды и покажет на экране. Письмо НЕ отправляется.
echo.
call "%~dp0python_runtime.bat" tb_main.py --test
set "RC=%errorlevel%"
echo.
echo Готово. Окно можно закрыть.
pause
exit /b %RC%
