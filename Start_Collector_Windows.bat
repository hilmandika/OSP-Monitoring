@echo off
REM ==============================================================================
REM OSP Monitoring - Local Laptop Collector & Publisher Launcher (Windows)
REM Double-click this file in File Explorer to launch the local collector app.
REM ==============================================================================

cd /d "%~dp0"

echo ========================================================
echo   OSP Monitoring - Local Laptop Collector ^& Publisher
echo ========================================================

echo [1/3] Checking for latest updates from GitHub...
git pull --no-rebase origin main 2>nul

if not exist ".venv" (
    echo [2/3] Creating Python virtual environment ^(.venv^)...
    python -m venv .venv
    call .venv\Scripts\pip install --upgrade pip
    call .venv\Scripts\pip install -r requirements.txt
) else (
    echo [2/3] Virtual environment ^(.venv^) ready.
)

echo [3/3] Starting local collector server at http://localhost:8000 ...
start "" http://localhost:8000
call .venv\Scripts\python -m backend.main
pause
