#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Offensive Security MCP Agent — Launcher
# Cybermarks Solutions // Daniyal Ahmed
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ── Check requirements ────────────────────────────────────────────────────
echo "[*] Checking Python dependencies..."
pip install -r requirements.txt --break-system-packages -q 2>&1 | tail -2

# ── Warn if no API key ────────────────────────────────────────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "[!] WARNING: ANTHROPIC_API_KEY not set."
  echo "    AI agent will not function without it."
  echo "    Set with: export ANTHROPIC_API_KEY='sk-ant-...'"
  echo ""
fi

# ── Start FastAPI ─────────────────────────────────────────────────────────
echo "[+] Starting Offensive MCP Agent API server..."
echo "[+] Dashboard: http://localhost:8000"
echo "[+] API Docs:  http://localhost:8000/docs"
echo "[+] MCP stdio: python3 mcp_server/mcp_server.py"
echo ""

python3 -m uvicorn api_server:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  --app-dir "$SCRIPT_DIR"
