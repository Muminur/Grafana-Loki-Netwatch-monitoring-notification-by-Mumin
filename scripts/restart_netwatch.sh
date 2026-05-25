#!/usr/bin/env bash
#
# Cold-restart the BSCCL NetWatch server on macOS / Linux.
#   1. Stops every NetWatch uvicorn process (matched by "uvicorn ... src.main:app")
#      and frees the target port. Unrelated Python processes are left untouched.
#   2. Starts a fresh detached uvicorn process, logging to logs/netwatch.log.
#   3. Waits for /health to confirm it came up.
#
# The SQLite database is PRESERVED by default. Use --reset-db to wipe alert history.
#
# Usage:
#   ./scripts/restart_netwatch.sh [--port 8080] [--reload] [--reset-db]
#
set -euo pipefail

PORT=8080
RELOAD=0
RESET_DB=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port)     PORT="${2:?--port needs a value}"; shift 2 ;;
    --port=*)   PORT="${1#*=}"; shift ;;
    --reload)   RELOAD=1; shift ;;
    --reset-db) RESET_DB=1; shift ;;
    -h|--help)
      cat <<'USAGE'
Usage: restart_netwatch.sh [--port N] [--reload] [--reset-db]
  --port N     Port to bind (default 8080)
  --reload     Start uvicorn with --reload (dev auto-reload)
  --reset-db   DESTRUCTIVE: delete bsccl_netwatch.db* before start (wipes alert history)
USAGE
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# --- Locate project root (this script lives in <root>/scripts) -----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Choose interpreter: prefer .venv, fall back to python3 / python -----
if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
  PYTHON="$PROJECT_ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  PYTHON="$(command -v python)"
fi

echo "== NetWatch restart =="
echo "Project : $PROJECT_ROOT"
echo "Python  : $PYTHON"
echo "Port    : $PORT"

# --- 1. Stop existing NetWatch server(s) ---------------------------------
echo
echo "[1/3] Stopping running NetWatch server ..."

ALL_PIDS=""
# (a) by command line — our app only (catches a --reload parent + workers)
ALL_PIDS="$ALL_PIDS $(pgrep -f 'uvicorn.*src\.main:app' 2>/dev/null || true)"
# (b) by port — fallback for anything still holding it
if command -v lsof >/dev/null 2>&1; then
  ALL_PIDS="$ALL_PIDS $(lsof -ti tcp:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
elif command -v fuser >/dev/null 2>&1; then
  ALL_PIDS="$ALL_PIDS $(fuser "$PORT/tcp" 2>/dev/null || true)"
fi

# keep only numeric PIDs, dedupe, and never target this script
PIDS="$(printf '%s\n' $ALL_PIDS | grep -E '^[0-9]+$' | sort -u | grep -vx "$$" || true)"

if [ -n "$PIDS" ]; then
  echo "  Stopping PID(s): $(echo $PIDS | tr '\n' ' ')"
  kill -TERM $PIDS 2>/dev/null || true
  for ((i=0; i<20; i++)); do
    still=""
    for pid in $PIDS; do kill -0 "$pid" 2>/dev/null && still="$still $pid"; done
    [ -z "$still" ] && break
    sleep 0.25
  done
  # force any survivors
  for pid in $PIDS; do
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
  done
else
  echo "  No running NetWatch process found."
fi

# wait up to 5s for the port to free (best effort)
if command -v lsof >/dev/null 2>&1; then
  for ((i=0; i<20; i++)); do
    lsof -ti tcp:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 0.25
  done
fi

# --- optional: wipe the database (opt-in, destructive) -------------------
if [ "$RESET_DB" -eq 1 ]; then
  echo "  --reset-db: deleting bsccl_netwatch.db* (alert history will be lost) ..."
  rm -f "$PROJECT_ROOT"/bsccl_netwatch.db* || true
fi

# --- 2. Start a fresh instance, detached, logging to file ----------------
echo
echo "[2/3] Starting fresh NetWatch server ..."
mkdir -p "$PROJECT_ROOT/logs"
LOG="$PROJECT_ROOT/logs/netwatch.log"

UV_ARGS="-m uvicorn src.main:app --host 0.0.0.0 --port $PORT"
[ "$RELOAD" -eq 1 ] && UV_ARGS="$UV_ARGS --reload"

# nohup + & detaches the server so it survives this shell / terminal closing
# shellcheck disable=SC2086
nohup "$PYTHON" $UV_ARGS > "$LOG" 2>&1 &
NEW_PID=$!
disown "$NEW_PID" 2>/dev/null || true

sleep 3
if ! kill -0 "$NEW_PID" 2>/dev/null; then
  echo "  Server exited immediately. Last log lines:" >&2
  tail -n 20 "$LOG" >&2 || true
  exit 1
fi
echo "  Started PID $NEW_PID  ->  http://localhost:$PORT"
echo "  Logs: $LOG"

# --- 3. Health check -----------------------------------------------------
echo
echo "[3/3] Waiting for /health ..."
OK=0
for ((i=0; i<15; i++)); do
  sleep 0.6
  if HEALTH="$(curl -fsS "http://127.0.0.1:$PORT/health" 2>/dev/null)"; then
    echo "  OK: $HEALTH"
    OK=1; break
  fi
done
if [ "$OK" -ne 1 ]; then
  echo "  Health not responding yet. Tail logs with:  tail -f \"$LOG\"" >&2
  exit 1
fi

echo
echo "NetWatch is running. Re-run this script anytime; it stops the old process first."
