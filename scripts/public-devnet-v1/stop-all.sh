#!/usr/bin/env bash
# Stop public-devnet processes recorded by start-all.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
DRY_RUN=0
ALL_MFND=0
REMOVE_PORTS_FILE=0

usage() {
  cat <<'EOF'
usage: stop-all.sh [--dry-run] [--all-mfnd] [--remove-ports-file]

Stops public-devnet PIDs recorded in scripts/public-devnet-v1/devnet-ports.env.

Options:
  --dry-run             print what would be stopped
  --all-mfnd            also stop every running mfnd process owned by this user
  --remove-ports-file   delete devnet-ports.env after stopping (default: keep file)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --all-mfnd)
      ALL_MFND=1
      shift
      ;;
    --remove-ports-file)
      REMOVE_PORTS_FILE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "stop-all: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

stop_pid() {
  local name="$1" pid="$2"
  if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
    echo "stop-all: skip $name invalid_pid=$pid"
    return
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "stop-all: skip $name pid=$pid not_running"
    return
  fi
  if (( DRY_RUN )); then
    echo "stop-all: dry_run stop $name pid=$pid"
    return
  fi
  kill "$pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  echo "stop-all: stopped $name pid=$pid"
}

if [[ -f "$PORTS_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$PORTS_FILE"
  stop_pid OBSERVER_PID "${OBSERVER_PID:-}"
  stop_pid V2_PID "${V2_PID:-}"
  stop_pid V1_PID "${V1_PID:-}"
  stop_pid HUB_PID "${HUB_PID:-}"
else
  echo "stop-all: no $PORTS_FILE found"
fi

if (( ALL_MFND )); then
  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && stop_pid mfnd "$pid"
    done < <(pgrep -x mfnd 2>/dev/null || true)
  else
    echo "stop-all: pgrep not found; cannot enumerate --all-mfnd"
  fi
fi

if (( ! DRY_RUN )) && (( REMOVE_PORTS_FILE )) && [[ -f "$PORTS_FILE" ]]; then
  rm -f "$PORTS_FILE"
  echo "stop-all: removed $PORTS_FILE"
fi

echo "stop-all: done"
