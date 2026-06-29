#!/usr/bin/env bash
# Long-running local public-devnet soak for hub + voters + observer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
LOG_DIR="$SCRIPT_DIR/logs"
DURATION_MINUTES=30
CHECK_INTERVAL_SECONDS=60
STALL_SAMPLES=2
STALL_INTERVAL_SECONDS=35
MIN_HEIGHT_DELTA=1
NO_START=0

usage() {
  cat >&2 <<'USAGE'
usage: soak.sh [--duration-minutes N] [--check-interval-seconds N]
               [--stall-samples N] [--stall-interval-seconds N]
               [--min-height-delta N] [--no-start]
USAGE
}

require_uint_min() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "soak: $name must be an integer >= $min" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration-minutes)
      DURATION_MINUTES="${2:?missing value for $1}"
      shift 2
      ;;
    --check-interval-seconds)
      CHECK_INTERVAL_SECONDS="${2:?missing value for $1}"
      shift 2
      ;;
    --stall-samples)
      STALL_SAMPLES="${2:?missing value for $1}"
      shift 2
      ;;
    --stall-interval-seconds)
      STALL_INTERVAL_SECONDS="${2:?missing value for $1}"
      shift 2
      ;;
    --min-height-delta)
      MIN_HEIGHT_DELTA="${2:?missing value for $1}"
      shift 2
      ;;
    --no-start)
      NO_START=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      echo "soak: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

require_uint_min duration-minutes "$DURATION_MINUTES" 1
require_uint_min check-interval-seconds "$CHECK_INTERVAL_SECONDS" 0
require_uint_min stall-samples "$STALL_SAMPLES" 1
require_uint_min stall-interval-seconds "$STALL_INTERVAL_SECONDS" 0
require_uint_min min-height-delta "$MIN_HEIGHT_DELTA" 1

read_ports() {
  if [[ ! -f "$PORTS_FILE" ]]; then
    echo "soak: missing $PORTS_FILE - run start-all.sh first" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$PORTS_FILE"
}

assert_pid_alive() {
  local name="$1" pid="${2:-}"
  if [[ -z "$pid" ]]; then
    echo "soak: $name missing in $PORTS_FILE" >&2
    exit 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "soak: process $name=$pid is not running" >&2
    exit 1
  fi
}

assert_log_contains() {
  local name="$1" path="$2" pattern="$3"
  if [[ ! -f "$path" ]]; then
    echo "soak: missing $name log at $path" >&2
    exit 1
  fi
  if ! grep -qF "$pattern" "$path"; then
    echo "soak: $name log missing '$pattern'" >&2
    exit 1
  fi
}

assert_p2p_logs() {
  assert_log_contains v1 "$LOG_DIR/v1.log" "mfnd_p2p_dial_ok="
  assert_log_contains v2 "$LOG_DIR/v2.log" "mfnd_p2p_dial_ok="
  assert_log_contains observer "$LOG_DIR/observer.log" "mfnd_p2p_dial_ok="
}

if (( NO_START == 0 )); then
  echo "soak: starting public-devnet-v1 mesh"
  "$SCRIPT_DIR/start-all.sh"
else
  echo "soak: using existing public-devnet-v1 mesh"
fi

deadline=$(( $(date +%s) + DURATION_MINUTES * 60 ))
iteration=0
while (( $(date +%s) < deadline )); do
  iteration=$((iteration + 1))
  echo "soak: iteration=$iteration deadline_epoch=$deadline"
  read_ports
  assert_pid_alive HUB_PID "${HUB_PID:-}"
  assert_pid_alive V1_PID "${V1_PID:-}"
  assert_pid_alive V2_PID "${V2_PID:-}"
  assert_pid_alive OBSERVER_PID "${OBSERVER_PID:-}"
  assert_p2p_logs

  MFN_HEALTH_STALL_SAMPLES="$STALL_SAMPLES" \
    MFN_HEALTH_STALL_INTERVAL_SECONDS="$STALL_INTERVAL_SECONDS" \
    MFN_HEALTH_MIN_HEIGHT_DELTA="$MIN_HEIGHT_DELTA" \
    "$SCRIPT_DIR/health-check.sh"

  if (( $(date +%s) + CHECK_INTERVAL_SECONDS < deadline && CHECK_INTERVAL_SECONDS > 0 )); then
    sleep "$CHECK_INTERVAL_SECONDS"
  fi
done

echo "soak: PASS duration_minutes=$DURATION_MINUTES iterations=$iteration"
