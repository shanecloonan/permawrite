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
RESTART_OBSERVER_ONCE=0
RESTART_TIMEOUT_SECONDS=180
P2P_LOG_TIMEOUT_SECONDS=120

usage() {
  cat >&2 <<'USAGE'
usage: soak.sh [--duration-minutes N] [--check-interval-seconds N]
               [--stall-samples N] [--stall-interval-seconds N]
               [--min-height-delta N] [--restart-observer-once]
               [--restart-timeout-seconds N] [--no-start]
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
    --restart-observer-once)
      RESTART_OBSERVER_ONCE=1
      shift
      ;;
    --restart-timeout-seconds)
      RESTART_TIMEOUT_SECONDS="${2:?missing value for $1}"
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
require_uint_min restart-timeout-seconds "$RESTART_TIMEOUT_SECONDS" 1

START_EPOCH=$(date +%s)
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SOAK_SAMPLES=()
SOAK_RESTARTS=()
LAST_FAILURE=""

record_health_sample() {
  local iteration="$1" output="$2"
  local roles="" genesis="unknown" final_height="unknown" final_id="unknown"
  local line role height sessions peers line_genesis pass_height pass_id
  while IFS= read -r line; do
    case "$line" in
      hub\ tip_height=*|v1\ tip_height=*|v2\ tip_height=*|observer\ tip_height=*)
        role="${line%% *}"
        height=$(printf '%s\n' "$line" | sed -n 's/.*tip_height=\([^ ]*\).*/\1/p')
        sessions=$(printf '%s\n' "$line" | sed -n 's/.*p2p_sessions=\([^ ]*\).*/\1/p')
        peers=$(printf '%s\n' "$line" | sed -n 's/.*p2p_peers=\([^ ]*\).*/\1/p')
        line_genesis=$(printf '%s\n' "$line" | sed -n 's/.*genesis_id=\([^ ]*\).*/\1/p')
        if [[ "$genesis" == "unknown" && -n "$line_genesis" ]]; then
          genesis="$line_genesis"
        fi
        roles="${roles}${roles:+;}${role}:height=${height:-unknown},sessions=${sessions:-unknown},peers=${peers:-unknown}"
        ;;
      health-check:\ PASS\ shared\ tip\ height=*)
        pass_height=$(printf '%s\n' "$line" | sed -n 's/.*height=\([0-9]*\).*/\1/p')
        pass_id=$(printf '%s\n' "$line" | sed -n 's/.* id=\([^ ]*\).*/\1/p')
        final_height="${pass_height:-$final_height}"
        final_id="${pass_id:-$final_id}"
        ;;
    esac
  done <<< "$output"
  SOAK_SAMPLES+=("iteration=$iteration final_height=$final_height final_tip_id=$final_id genesis_id=$genesis roles=${roles:-none}")
}

health_role_field() {
  local output="$1" role="$2" field="$3"
  printf '%s\n' "$output" | awk -v role="$role" -v field="$field" '
    $1 == role {
      for (i = 2; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == field) {
          print kv[2]
          exit
        }
      }
    }
  '
}

latest_log_value() {
  local path="$1" prefix="$2"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  awk -v prefix="$prefix" 'index($0, prefix) == 1 { value = substr($0, length(prefix) + 1) } END { if (value != "") print value }' "$path"
}

restart_observer_probe() {
  local restart_iteration="$1" pre_output="$2"
  read_ports
  local old_pid="${OBSERVER_PID:-}" old_rpc="${OBSERVER_RPC:-unknown}"
  local pre_hub_height pre_observer_height marker new_pid observer_rpc restart_deadline health_status health_output post_hub_height post_observer_height restart_record
  pre_hub_height="$(health_role_field "$pre_output" hub tip_height)"
  pre_observer_height="$(health_role_field "$pre_output" observer tip_height)"
  marker="iteration-${restart_iteration}-$(date +%s)"
  echo "soak: restarting observer iteration=$restart_iteration old_pid=${old_pid:-unknown} old_rpc=$old_rpc marker=$marker"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    kill "$old_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$old_pid" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    if kill -0 "$old_pid" 2>/dev/null; then
      kill -9 "$old_pid" 2>/dev/null || true
    fi
  fi
  if [[ -f "$LOG_DIR/observer.log" ]]; then
    mv "$LOG_DIR/observer.log" "$LOG_DIR/observer.before-restart-$marker.log"
  fi
  if [[ -f "$LOG_DIR/observer.err.log" ]]; then
    mv "$LOG_DIR/observer.err.log" "$LOG_DIR/observer.before-restart-$marker.err.log"
  fi
  export HUB_P2P="${HUB_P2P:?}"
  "$SCRIPT_DIR/start-observer.sh" >"$LOG_DIR/observer.log" 2>"$LOG_DIR/observer.err.log" &
  new_pid=$!
  echo "OBSERVER_PID=$new_pid" >>"$PORTS_FILE"
  restart_deadline=$(( $(date +%s) + RESTART_TIMEOUT_SECONDS ))
  observer_rpc=""
  while (( $(date +%s) < restart_deadline )); do
    if ! kill -0 "$new_pid" 2>/dev/null; then
      LAST_FAILURE="iteration=$restart_iteration command=restart-observer pid=$new_pid exited_early"
      exit 1
    fi
    observer_rpc="$(latest_log_value "$LOG_DIR/observer.log" "mfnd_serve_listening=")"
    if [[ -n "$observer_rpc" ]]; then
      break
    fi
    sleep 1
  done
  if [[ -z "$observer_rpc" ]]; then
    LAST_FAILURE="iteration=$restart_iteration command=restart-observer missing_observer_rpc timeout_seconds=$RESTART_TIMEOUT_SECONDS"
    exit 1
  fi
  echo "OBSERVER_RPC=$observer_rpc" >>"$PORTS_FILE"
  while (( $(date +%s) < restart_deadline )); do
    health_status=0
    health_output=$(MFN_HEALTH_STALL_SAMPLES=1 \
      MFN_HEALTH_MIN_HEIGHT_DELTA="$MIN_HEIGHT_DELTA" \
      "$SCRIPT_DIR/health-check.sh" 2>&1) || health_status=$?
    if (( health_status == 0 )); then
      post_hub_height="$(health_role_field "$health_output" hub tip_height)"
      post_observer_height="$(health_role_field "$health_output" observer tip_height)"
      printf '%s\n' "$health_output"
      restart_record="iteration=$restart_iteration role=observer old_pid=${old_pid:-unknown} new_pid=$new_pid old_rpc=$old_rpc new_rpc=$observer_rpc pre_hub_height=${pre_hub_height:-unknown} pre_observer_height=${pre_observer_height:-unknown} post_hub_height=${post_hub_height:-unknown} post_observer_height=${post_observer_height:-unknown}"
      SOAK_RESTARTS+=("$restart_record")
      echo "soak: RESTART $restart_record"
      return
    fi
    sleep 2
  done
  printf '%s\n' "$health_output"
  LAST_FAILURE="iteration=$restart_iteration command=restart-observer catchup_timeout_seconds=$RESTART_TIMEOUT_SECONDS"
  exit 1
}

print_soak_summary() {
  local status="$1"
  local ended_epoch ended_at elapsed
  ended_epoch=$(date +%s)
  ended_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  elapsed=$((ended_epoch - START_EPOCH))
  echo "soak: SUMMARY status=$status started_at=$STARTED_AT ended_at=$ended_at elapsed_seconds=$elapsed duration_minutes=$DURATION_MINUTES iterations=$iteration"
  local sample
  for sample in "${SOAK_SAMPLES[@]}"; do
    echo "soak: SAMPLE $sample"
  done
  local restart
  for restart in "${SOAK_RESTARTS[@]}"; do
    echo "soak: RESTART $restart"
  done
  if [[ -n "$LAST_FAILURE" ]]; then
    echo "soak: FAILURE $LAST_FAILURE"
  fi
}

on_exit() {
  local code=$?
  if (( code != 0 )); then
    if [[ -z "$LAST_FAILURE" ]]; then
      LAST_FAILURE="iteration=${iteration:-0} exit_code=$code"
    fi
    print_soak_summary FAIL
  fi
}
trap on_exit EXIT

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
  local deadline
  deadline=$(( $(date +%s) + P2P_LOG_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if [[ -f "$LOG_DIR/v1.log" && -f "$LOG_DIR/v2.log" && -f "$LOG_DIR/observer.log" ]] &&
      grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/v1.log" &&
      grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/v2.log" &&
      grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/observer.log"; then
      return
    fi
    sleep 1
  done
  assert_log_contains v1 "$LOG_DIR/v1.log" "mfnd_p2p_dial_ok="
  assert_log_contains v2 "$LOG_DIR/v2.log" "mfnd_p2p_dial_ok="
  assert_log_contains observer "$LOG_DIR/observer.log" "mfnd_p2p_dial_ok="
}

wait_for_mesh_production() {
  local timeout=$(( STALL_INTERVAL_SECONDS * 4 + 60 ))
  if (( timeout < 120 )); then
    timeout=120
  fi
  local deadline=$(( $(date +%s) + timeout ))
  echo "soak: waiting for converged first block (timeout=${timeout}s)"
  while (( $(date +%s) < deadline )); do
    read_ports
    assert_pid_alive HUB_PID "${HUB_PID:-}"
    assert_pid_alive V1_PID "${V1_PID:-}"
    assert_pid_alive V2_PID "${V2_PID:-}"
    assert_pid_alive OBSERVER_PID "${OBSERVER_PID:-}"
    assert_p2p_logs
    if health_output=$(
      MFN_HEALTH_STALL_SAMPLES=1 \
        MFN_HEALTH_STALL_INTERVAL_SECONDS=0 \
        MFN_HEALTH_MIN_HEIGHT_DELTA=1 \
        "$SCRIPT_DIR/health-check.sh" 2>&1
    ); then
      hub_height="$(health_role_field "$health_output" hub tip_height)"
      if [[ "$hub_height" =~ ^[0-9]+$ ]] && (( hub_height >= 1 )); then
        printf '%s\n' "$health_output"
        echo "soak: WARMUP hub_tip_height=$hub_height"
        return 0
      fi
    fi
    sleep 5
  done
  echo "soak: FAIL mesh did not converge to tip_height>=1 within ${timeout}s" >&2
  exit 1
}

if (( NO_START == 0 )); then
  echo "soak: starting public-devnet-v1 mesh"
  "$SCRIPT_DIR/start-all.sh"
else
  echo "soak: using existing public-devnet-v1 mesh"
fi

wait_for_mesh_production

if (( STALL_INTERVAL_SECONDS > 0 )); then
  echo "soak: post-warmup stabilization sleep=${STALL_INTERVAL_SECONDS}s"
  sleep "$STALL_INTERVAL_SECONDS"
fi

deadline=$(( $(date +%s) + DURATION_MINUTES * 60 ))
iteration=0
observer_restart_done=0
while (( $(date +%s) < deadline )); do
  iteration=$((iteration + 1))
  echo "soak: iteration=$iteration deadline_epoch=$deadline"
  read_ports
  assert_pid_alive HUB_PID "${HUB_PID:-}"
  assert_pid_alive V1_PID "${V1_PID:-}"
  assert_pid_alive V2_PID "${V2_PID:-}"
  assert_pid_alive OBSERVER_PID "${OBSERVER_PID:-}"
  assert_p2p_logs

  health_status=0
  health_output=$(MFN_HEALTH_STALL_SAMPLES="$STALL_SAMPLES" \
    MFN_HEALTH_STALL_INTERVAL_SECONDS="$STALL_INTERVAL_SECONDS" \
    MFN_HEALTH_MIN_HEIGHT_DELTA="$MIN_HEIGHT_DELTA" \
    "$SCRIPT_DIR/health-check.sh" 2>&1) || health_status=$?
  if (( health_status != 0 )); then
    printf '%s\n' "$health_output"
    LAST_FAILURE="iteration=$iteration command=health-check exit_code=$health_status"
    exit "$health_status"
  fi
  printf '%s\n' "$health_output"
  record_health_sample "$iteration" "$health_output"
  if (( RESTART_OBSERVER_ONCE == 1 && observer_restart_done == 0 )); then
    restart_observer_probe "$iteration" "$health_output"
    observer_restart_done=1
  fi

  if (( $(date +%s) + CHECK_INTERVAL_SECONDS < deadline && CHECK_INTERVAL_SECONDS > 0 )); then
    sleep "$CHECK_INTERVAL_SECONDS"
  fi
done

print_soak_summary PASS
