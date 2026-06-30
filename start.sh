#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${AUTHNODE_CONFIG:-"$ROOT_DIR/authnode.local.json"}"
PYTHON_BIN="${AUTHNODE_PYTHON:-}"
HOST_OVERRIDE="${AUTHNODE_HOST:-}"
PORT_OVERRIDE="${AUTHNODE_PORT:-}"
LOG_DIR="$ROOT_DIR/logs"
RUN_DIR="$ROOT_DIR/run"
PID_FILE="$RUN_DIR/authnode.pid"
LOG_FILE="$LOG_DIR/authnode.log"

usage() {
  cat <<'USAGE'
Usage:
  ./start.sh             Start AuthNode in the foreground
  ./start.sh --daemon    Start AuthNode in the background
  ./start.sh --status    Show daemon PID or foreground HTTP status
  ./start.sh --stop      Stop background AuthNode process started with --daemon

Environment:
  AUTHNODE_CONFIG        Config path, defaults to ./authnode.local.json
  AUTHNODE_HOST          Optional serve host override
  AUTHNODE_PORT          Optional serve port override
  AUTHNODE_PYTHON        Optional Python executable override

First run creates ./authnode.local.json and local-only secrets automatically.
FastReAct and PSKA are started separately from their own repositories or
containers.
USAGE
}

select_python() {
  if [[ -n "$PYTHON_BIN" ]]; then
    printf '%s\n' "$PYTHON_BIN"
    return
  fi
  if [[ -x "$ROOT_DIR/.venv/bin/python3" ]]; then
    printf '%s\n' "$ROOT_DIR/.venv/bin/python3"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi
  echo "python3 was not found. Set AUTHNODE_PYTHON=/path/to/python." >&2
  exit 1
}

ensure_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    ensure_local_secrets
    return
  fi
  if [[ "$CONFIG_FILE" == "$ROOT_DIR/authnode.local.json" ]]; then
    cp "$ROOT_DIR/authnode.example.json" "$CONFIG_FILE"
    echo "Created $CONFIG_FILE from authnode.example.json."
    ensure_local_secrets
    return
  fi
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
}

ensure_local_secrets() {
  if [[ "$CONFIG_FILE" != "$ROOT_DIR/authnode.local.json" ]]; then
    return
  fi
  local python
  python="$(select_python)"
  "$python" - "$CONFIG_FILE" <<'PY'
from pathlib import Path
import json
import secrets
import sys

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
changed = False
if not data.get("jwt_secret") or data.get("jwt_secret") == "change-me-local-authnode-secret":
    data["jwt_secret"] = secrets.token_urlsafe(48)
    changed = True
if not data.get("admin_token") or data.get("admin_token") in {"local-admin-token", "change-me-local-admin-token"}:
    data["admin_token"] = secrets.token_urlsafe(32)
    changed = True
if changed:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Initialized local jwt_secret/admin_token in authnode.local.json.")
PY
}

authnode_url() {
  local python
  python="$(select_python)"
  "$python" - "$CONFIG_FILE" <<'PY'
from pathlib import Path
import json
import os
import sys

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
host = os.getenv("AUTHNODE_HOST") or data.get("host") or "127.0.0.1"
port = os.getenv("AUTHNODE_PORT") or data.get("port") or 8788
display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
print(f"http://{display_host}:{int(port)}")
PY
}

print_urls() {
  local url
  url="$(authnode_url)"
  echo "AuthNode ready:       $url/ready"
  echo "Admin console:        $url/admin"
  echo "FastReAct proxy:      $url/proxy/fastreact"
  echo "PSKA proxy:           $url/proxy/pska"
  echo "Config:               $CONFIG_FILE"
}

build_command() {
  local python
  python="$(select_python)"
  CMD=("$python" -m authnode --config "$CONFIG_FILE" serve)
  if [[ -n "$HOST_OVERRIDE" ]]; then
    CMD+=(--host "$HOST_OVERRIDE")
  fi
  if [[ -n "$PORT_OVERRIDE" ]]; then
    CMD+=(--port "$PORT_OVERRIDE")
  fi
}

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" >/dev/null 2>&1
}

ready_probe() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    return 1
  fi
  local url python
  url="$(authnode_url)"
  python="$(select_python)"
  "$python" - "$url/ready" <<'PY' >/dev/null 2>&1
from urllib.request import urlopen
import sys

try:
    with urlopen(sys.argv[1], timeout=2) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

start_foreground() {
  ensure_config
  build_command
  print_urls
  cd "$ROOT_DIR"
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
  export AUTHNODE_CONFIG="$CONFIG_FILE"
  exec "${CMD[@]}"
}

start_daemon() {
  ensure_config
  mkdir -p "$LOG_DIR" "$RUN_DIR"
  if is_running; then
    echo "AuthNode is already running with pid $(cat "$PID_FILE")."
    print_urls
    exit 0
  fi
  build_command
  cd "$ROOT_DIR"
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
  export AUTHNODE_CONFIG="$CONFIG_FILE"
  nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
  echo "$!" >"$PID_FILE"
  echo "AuthNode started with pid $(cat "$PID_FILE")."
  echo "Log: $LOG_FILE"
  print_urls
}

show_status() {
  if is_running; then
    echo "AuthNode is running with pid $(cat "$PID_FILE")."
    echo "Log: $LOG_FILE"
    print_urls
    return
  fi
  if ready_probe; then
    echo "AuthNode is responding, but it was not started via ./start.sh --daemon."
    echo "No daemon PID file is present at $PID_FILE."
    echo "If you started it with ./start.sh in the foreground, stop it with Ctrl-C in that terminal."
    print_urls
    return
  fi
  echo "AuthNode is not running via $PID_FILE, and /ready is not responding."
}

stop_daemon() {
  if ! is_running; then
    rm -f "$PID_FILE"
    if ready_probe; then
      echo "AuthNode is responding, but it was not started via ./start.sh --daemon."
      echo "Stop the foreground process with Ctrl-C in the terminal where ./start.sh is running."
      return
    fi
    echo "AuthNode is not running."
    return
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid"
  for _ in {1..30}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$PID_FILE"
      echo "Stopped AuthNode pid $pid."
      return
    fi
    sleep 0.2
  done
  echo "AuthNode pid $pid did not stop after SIGTERM." >&2
  exit 1
}

case "${1:-}" in
  "")
    start_foreground
    ;;
  --daemon)
    start_daemon
    ;;
  --status)
    show_status
    ;;
  --stop)
    stop_daemon
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac
