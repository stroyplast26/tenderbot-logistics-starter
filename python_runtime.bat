@echo off
setlocal EnableExtensions
if not defined PYTHONUTF8 set "PYTHONUTF8=1"

rem Resolve a real CPython 3.11 interpreter.  A copied venv may still contain
rem python.exe launch stubs whose base interpreter disappeared after reinstall.
set "PROJECT_ROOT=%~dp0"
set "VENV_PYTHON=%PROJECT_ROOT%.venv\Scripts\python.exe"
set "LOCAL_PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

if exist "%VENV_PYTHON%" (
  "%VENV_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 goto run_venv
)

if defined TENDERBOT_PYTHON if exist "%TENDERBOT_PYTHON%" (
  "%TENDERBOT_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 goto run_override
)

if exist "%LOCAL_PYTHON%" (
  "%LOCAL_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 goto run_local
)

where py.exe >nul 2>&1
if not errorlevel 1 (
  py -3.11 -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 goto run_launcher
)

where python.exe >nul 2>&1
if not errorlevel 1 (
  python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 goto run_path
)

>&2 echo ERROR: working Python 3.11 was not found.
>&2 echo Recreate "%PROJECT_ROOT%.venv" or set TENDERBOT_PYTHON to python.exe.
exit /b 9009

:run_venv
"%VENV_PYTHON%" %*
exit /b %errorlevel%

:run_override
"%TENDERBOT_PYTHON%" %*
exit /b %errorlevel%

:run_local
"%LOCAL_PYTHON%" %*
exit /b %errorlevel%

:run_launcher
py -3.11 %*
exit /b %errorlevel%

:run_path
python %*
exit /b %errorlevel%
