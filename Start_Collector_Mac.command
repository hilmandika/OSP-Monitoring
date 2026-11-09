#!/bin/zsh
# ==============================================================================
# OSP Monitoring - Local Laptop Collector & Publisher Launcher (macOS)
# Double-click this file in Finder (or run ./Start_Collector_Mac.command)
# ==============================================================================

cd "$(dirname "$0")"

echo "========================================================"
echo "  OSP Monitoring - Local Laptop Collector & Publisher"
echo "========================================================"

# 1. Sync latest repository data from GitHub (non-blocking if offline)
echo "[1/3] Checking for latest updates from GitHub..."
git pull --no-rebase origin main 2>/dev/null || echo "      (Proceeding with current local files)"

# 2. Setup Python virtual environment if missing
if [ ! -d ".venv" ]; then
    echo "[2/3] Creating Python virtual environment (.venv)..."
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip
    ./.venv/bin/pip install -r requirements.txt
else
    echo "[2/3] Virtual environment (.venv) ready."
fi

# 3. Open browser after 2 seconds and launch FastAPI server
echo "[3/3] Starting local collector server at http://localhost:8000 ..."
(sleep 2 && open "http://localhost:8000") &

./.venv/bin/python -m backend.main
