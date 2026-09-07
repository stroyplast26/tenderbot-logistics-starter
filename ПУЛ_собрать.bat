@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ЛЕЙНА-2: сбор пула победителей за год (это отдельно от дневного бота).
echo Это может занять 20-40 минут. По окончании смотрите папку pool\.
call "%~dp0python_runtime.bat" tb_pool.py %*
set "RC=%errorlevel%"
echo.
echo Готово. Результаты в папке pool\ (pool_report_*.html, call_list_*.csv, email_list_*.csv).
pause
exit /b %RC%
