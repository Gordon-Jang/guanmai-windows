@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem Keep this launcher ASCII-only so cmd.exe can parse it on every code page.
set "PYTHON_CMD="
where python.exe >nul 2>nul
if not errorlevel 1 set "PYTHON_CMD=python.exe"
if not defined PYTHON_CMD (
    where py.exe >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py.exe"
)

if not defined PYTHON_CMD (
    echo Python 3.8 or newer was not found.
    echo Install Python and run this file again.
    pause
    exit /b 1
)

echo Starting Windows Thread Monitor...
%PYTHON_CMD% "%~dp0thread_monitor.py"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo The monitor exited with code %EXIT_CODE%.
    echo Run this command for diagnostics:
    echo %PYTHON_CMD% "%~dp0thread_monitor.py" --self-test
    pause
)

endlocal
