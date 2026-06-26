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
  ./start.sh --status    Show background process status
  ./start.sh --stop      Stop background AuthNode process

Environment:
  AUTHNODE_CONFIG        Config path, defaults to ./authnode.local.json
  AUTHNODE_HOST          Optional serve host override
  AUTHNODE_PORT          Optional serve port override
  AUTHNODE_PYTHON        Optional Python executable override

This script only starts AuthNode. FastReAct and PSKA remain separate projects
and should be started from their own repositories.
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
    return
  fi
  if [[ "$CONFIG_FILE" == "$ROOT_DIR/authnode.local.json" ]]; then
    cp "$ROOT_DIR/authnode.example.json" "$CONFIG_FILE"
    echo "Created $CONFIG_FILE from authnode.example.json."
    echo "Edit jwt_secret/admin_token before using this beyond local development."
    return
  fi
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
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

start_foreground() {
  ensure_config
  build_command
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
}

show_status() {
  if is_running; then
    echo "AuthNode is running with pid $(cat "$PID_FILE")."
    echo "Log: $LOG_FILE"
    return
  fi
  echo "AuthNode is not running via $PID_FILE."
}

stop_daemon() {
  if ! is_running; then
    rm -f "$PID_FILE"
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

