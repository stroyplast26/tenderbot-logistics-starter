@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ПОСЕВ: пометит все текущие завершённые тендеры как "уже виденные".
echo Запустите ОДИН раз перед первым боевым запуском, чтобы не прислать сразу весь архив.
echo.
call "%~dp0python_runtime.bat" tb_main.py --seed
set "RC=%errorlevel%"
echo.
pause
exit /b %RC%
