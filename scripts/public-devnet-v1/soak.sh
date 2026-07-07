#!/usr/bin/env bash
# Long-running local public-devnet soak for hub + voters + observer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
# GHA get_status often reports p2p.session_count=null while the mesh is live (M2.5.65).
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  export MFN_HEALTH_MIN_P2P_SESSIONS=0
fi
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
LOG_DIR="$SCRIPT_DIR/logs"
DURATION_MINUTES=30
CHECK_INTERVAL_SECONDS=60
STALL_SAMPLES=2
STALL_INTERVAL_SECONDS=0
MIN_HEIGHT_DELTA=1
MIN_FINAL_HEIGHT=0
MIN_SUCCESSFUL_ITERATIONS=3
NO_START=0
RESTART_OBSERVER_ONCE=0
RESTART_TIMEOUT_SECONDS=180
ARCHIVE_EVIDENCE=0
DANDELION=0
P2P_LOG_TIMEOUT_SECONDS=120

usage() {
  cat >&2 <<'USAGE'
usage: soak.sh [--duration-minutes N] [--check-interval-seconds N]
               [--stall-samples N] [--stall-interval-seconds N]
               [--min-height-delta N] [--min-final-height N]
               [--min-successful-iterations N] [--restart-observer-once]
               [--restart-timeout-seconds N] [--archive-evidence] [--no-start]
               [--dandelion]
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
    --min-final-height)
      MIN_FINAL_HEIGHT="${2:?missing value for $1}"
      shift 2
      ;;
    --min-successful-iterations)
      MIN_SUCCESSFUL_ITERATIONS="${2:?missing value for $1}"
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
    --archive-evidence)
      ARCHIVE_EVIDENCE=1
      shift
      ;;
    --no-start)
      NO_START=1
      shift
      ;;
    --dandelion)
      DANDELION=1
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
require_uint_min min-final-height "$MIN_FINAL_HEIGHT" 0
require_uint_min min-successful-iterations "$MIN_SUCCESSFUL_ITERATIONS" 1
require_uint_min restart-timeout-seconds "$RESTART_TIMEOUT_SECONDS" 1

START_EPOCH=$(date +%s)
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SOAK_SAMPLES=()
SOAK_RESTARTS=()
LAST_FAILURE=""
SUMMARY_WRITTEN=0
iteration=0

max_sample_height() {
  local sample height max=0
  for sample in "${SOAK_SAMPLES[@]}"; do
    if [[ "$sample" =~ final_height=([0-9]+) ]]; then
      height="${BASH_REMATCH[1]}"
      if (( height > max )); then
        max=$height
      fi
    fi
  done
  echo "$max"
}

soak_success_criteria() {
  if (( ${#SOAK_SAMPLES[@]} < MIN_SUCCESSFUL_ITERATIONS )); then
    return 1
  fi
  if (( MIN_FINAL_HEIGHT > 0 )); then
    local max_height
    max_height="$(max_sample_height)"
    if (( max_height < MIN_FINAL_HEIGHT )); then
      return 1
    fi
  fi
  if (( RESTART_OBSERVER_ONCE == 1 && ${#SOAK_RESTARTS[@]} < 1 )); then
    return 1
  fi
  return 0
}

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
  local ended_epoch ended_at elapsed max_height
  ended_epoch=$(date +%s)
  ended_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  elapsed=$((ended_epoch - START_EPOCH))
  max_height="$(max_sample_height)"
  echo "soak: SUMMARY status=$status started_at=$STARTED_AT ended_at=$ended_at elapsed_seconds=$elapsed duration_minutes=$DURATION_MINUTES iterations=$iteration max_height=$max_height"
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
  SUMMARY_WRITTEN=1
}

archive_soak_evidence() {
  local status="$1"
  if (( ARCHIVE_EVIDENCE == 0 )); then
    return 0
  fi
  local evidence_dir slot_ms slot_label stamp path commit repo_root ended_epoch ended_at elapsed max_height
  evidence_dir="$SCRIPT_DIR/evidence"
  mkdir -p "$evidence_dir"
  slot_ms="${SLOT_MS:-10000}"
  if (( slot_ms >= 30000 )); then
    slot_label="30s-slot"
  else
    slot_label="${slot_ms}ms-slot"
  fi
  stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
  local dandelion_label=""
  if (( DANDELION == 1 )); then dandelion_label="-dandelion"; fi
  path="$evidence_dir/soak-restart-linux${dandelion_label}-$slot_label-$stamp.txt"
  repo_root="$(cd "$SCRIPT_DIR/../.." && pwd)"
  commit=""
  if commit=$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null); then
    :
  else
    commit=""
  fi
  {
    echo "# Linux soak evidence ($slot_label)"
    echo "# Command: soak.sh --duration-minutes $DURATION_MINUTES$( (( RESTART_OBSERVER_ONCE == 1 )) && echo -n ' --restart-observer-once')$( (( DANDELION == 1 )) && echo -n ' --dandelion')$( (( ARCHIVE_EVIDENCE == 1 )) && echo -n ' --archive-evidence')"
    if [[ -n "$commit" ]]; then
      echo "# Commit: $commit"
    fi
    echo "# SLOT_MS=$slot_ms StallIntervalSeconds=$STALL_INTERVAL_SECONDS"
    echo ""
    for sample in "${SOAK_SAMPLES[@]}"; do
      echo "soak: SAMPLE $sample"
    done
    for restart in "${SOAK_RESTARTS[@]}"; do
      echo "soak: RESTART $restart"
    done
    ended_epoch=$(date +%s)
    ended_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    elapsed=$((ended_epoch - START_EPOCH))
    max_height="$(max_sample_height)"
    echo "soak: SUMMARY status=$status started_at=$STARTED_AT ended_at=$ended_at elapsed_seconds=$elapsed duration_minutes=$DURATION_MINUTES iterations=$iteration max_height=$max_height"
  } >"$path"
  echo "soak: EVIDENCE archived=$path status=$status"
}

finish_soak() {
  local status="$1"
  print_soak_summary "$status"
  archive_soak_evidence "$status"
  soak_lock_remove "$SCRIPT_DIR"
  if [[ "$status" == "FAIL" ]]; then
    exit 1
  fi
}

on_exit() {
  local code=$?
  if (( code != 0 )) && (( SUMMARY_WRITTEN == 0 )); then
    if [[ -z "$LAST_FAILURE" ]]; then
      LAST_FAILURE="iteration=${iteration:-0} exit_code=$code"
    fi
    print_soak_summary FAIL
    archive_soak_evidence FAIL
    soak_lock_remove "$SCRIPT_DIR"
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
    assert_p2p_logs
    if health_output=$(
      MFN_HEALTH_STALL_SAMPLES=1 \
        MFN_HEALTH_STALL_INTERVAL_SECONDS=0 \
        MFN_HEALTH_MIN_HEIGHT_DELTA=1 \
        MFN_HEALTH_REQUIRE_ALL_ROLES=0 \
        MFN_HEALTH_MIN_P2P_SESSIONS=0 \
        "$SCRIPT_DIR/health-check.sh" 2>&1
    ); then
      hub_height="$(health_role_field "$health_output" hub tip_height)"
      if [[ "$hub_height" =~ ^[0-9]+$ ]] && (( hub_height >= 1 )); then
        printf '%s\n' "$health_output"
        echo "soak: WARMUP phase=hub_produced hub_tip_height=$hub_height"
        break
      fi
    elif [[ -n "${GITHUB_ACTIONS:-}" ]] && [[ -f "$PORTS_FILE" ]]; then
      # start-all already gated hub tip>=1; session_count may still be 0 on GHA (M2.5.65).
      # shellcheck source=/dev/null
      source "$PORTS_FILE"
      if [[ -n "${HUB_RPC:-}" ]]; then
        hub_height="$(query_tip_height "$HUB_RPC" "${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}" 2>/dev/null || true)"
        if [[ "$hub_height" =~ ^[0-9]+$ ]] && (( hub_height >= 1 )); then
          echo "soak: WARMUP phase=hub_produced hub_tip_height=$hub_height (tip poll fast path)"
          break
        fi
      fi
    fi
    sleep 5
  done
  if (( $(date +%s) >= deadline )); then
    echo "soak: FAIL mesh hub did not reach tip_height>=1 within ${timeout}s" >&2
    exit 1
  fi
  local converge_deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < converge_deadline )); do
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
        MFN_HEALTH_REQUIRE_ALL_ROLES=1 \
        MFN_HEALTH_MIN_P2P_SESSIONS=0 \
        "$SCRIPT_DIR/health-check.sh" 2>&1
    ); then
      hub_height="$(health_role_field "$health_output" hub tip_height)"
      if [[ "$hub_height" =~ ^[0-9]+$ ]] && (( hub_height >= 1 )); then
        printf '%s\n' "$health_output"
        echo "soak: WARMUP phase=converged hub_tip_height=$hub_height"
        return 0
      fi
    fi
    sleep 5
  done
  if soak_gha_mesh_converge_soft_ok; then
    echo "soak: WARN mesh converge incomplete after ${timeout}s but hub tip>=1 and role P2P dials OK (GHA); continuing" >&2
    return 0
  fi
  echo "soak: FAIL mesh did not converge to tip_height>=1 within ${timeout}s" >&2
  exit 1
}

soak_gha_mesh_converge_soft_ok() {
  [[ -n "${GITHUB_ACTIONS:-}" ]] || return 1
  [[ -f "$PORTS_FILE" ]] || return 1
  # shellcheck source=/dev/null
  source "$PORTS_FILE"
  [[ -n "${HUB_RPC:-}" ]] || return 1
  local hub_height
  hub_height="$(query_tip_height "$HUB_RPC" "${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}" 2>/dev/null || true)"
  [[ "$hub_height" =~ ^[0-9]+$ ]] && (( hub_height >= 1 )) || return 1
  grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/v1.log" 2>/dev/null &&
    grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/v2.log" 2>/dev/null &&
    grep -qF "mfnd_p2p_dial_ok=" "$LOG_DIR/observer.log" 2>/dev/null
}

if (( NO_START == 0 )); then
  if [[ -z "${SLOT_MS:-}" ]]; then
    SLOT_MS=10000
    export SLOT_MS
    echo "soak: SLOT_MS=${SLOT_MS} (local soak default; override with env SLOT_MS)"
  fi
  if (( STALL_INTERVAL_SECONDS <= 0 )); then
    slot_sec=$(( SLOT_MS / 1000 ))
    if (( slot_sec < 1 )); then slot_sec=1; fi
    STALL_INTERVAL_SECONDS=$(( slot_sec * 5 + 15 ))
    echo "soak: StallIntervalSeconds=${STALL_INTERVAL_SECONDS} (auto from SLOT_MS)"
  fi
  if soak_lock_active "$SCRIPT_DIR"; then
    echo "soak: removing stale soak lock before bootstrap"
    soak_lock_remove "$SCRIPT_DIR"
  fi
  echo "soak: starting public-devnet-v1 mesh"
  export MFN_SOAK_BOOTSTRAP=1
  if (( DANDELION == 1 )); then
    bash "$SCRIPT_DIR/start-all.sh" --no-build --dandelion
  else
    bash "$SCRIPT_DIR/start-all.sh" --no-build
  fi
  unset MFN_SOAK_BOOTSTRAP
  read_ports
  soak_lock_new "$SCRIPT_DIR"
  echo "soak: lock active ($(soak_lock_path "$SCRIPT_DIR"))"
else
  if (( STALL_INTERVAL_SECONDS <= 0 )); then
    slot_ms="${SLOT_MS:-10000}"
    slot_sec=$(( slot_ms / 1000 ))
    if (( slot_sec < 1 )); then slot_sec=1; fi
    STALL_INTERVAL_SECONDS=$(( slot_sec * 5 + 15 ))
    echo "soak: StallIntervalSeconds=${STALL_INTERVAL_SECONDS} (auto from SLOT_MS)"
  fi
  echo "soak: using existing public-devnet-v1 mesh"
  soak_lock_new "$SCRIPT_DIR"
  echo "soak: lock active ($(soak_lock_path "$SCRIPT_DIR"))"
fi

wait_for_mesh_production

if (( STALL_INTERVAL_SECONDS > 0 )); then
  echo "soak: post-warmup stabilization sleep=${STALL_INTERVAL_SECONDS}s"
  sleep "$STALL_INTERVAL_SECONDS"
fi

deadline=$(( $(date +%s) + DURATION_MINUTES * 60 ))
observer_restart_done=0
iter_budget_seconds=$(( STALL_INTERVAL_SECONDS * STALL_SAMPLES + 90 ))
if (( iter_budget_seconds < 180 )); then
  iter_budget_seconds=180
fi
graceful_stop=0

while (( $(date +%s) < deadline && graceful_stop == 0 )); do
  if (( $(date +%s) + iter_budget_seconds >= deadline )); then
    echo "soak: stopping (insufficient time for another iteration; budget=${iter_budget_seconds}s)"
    break
  fi
  iteration=$((iteration + 1))
  echo "soak: iteration=$iteration deadline_epoch=$deadline budget=${iter_budget_seconds}s"
  read_ports
  assert_pid_alive HUB_PID "${HUB_PID:-}"
  assert_pid_alive V1_PID "${V1_PID:-}"
  assert_pid_alive V2_PID "${V2_PID:-}"
  assert_pid_alive OBSERVER_PID "${OBSERVER_PID:-}"
  assert_p2p_logs

  health_output=""
  health_deadline=$(( $(date +%s) + iter_budget_seconds ))
  while (( $(date +%s) < health_deadline )); do
    health_status=0
    health_output=$(MFN_HEALTH_STALL_SAMPLES="$STALL_SAMPLES" \
      MFN_HEALTH_STALL_INTERVAL_SECONDS="$STALL_INTERVAL_SECONDS" \
      MFN_HEALTH_MIN_HEIGHT_DELTA="$MIN_HEIGHT_DELTA" \
      "$SCRIPT_DIR/health-check.sh" 2>&1) || health_status=$?
    if (( health_status == 0 )) && [[ -n "$health_output" ]]; then
      break
    fi
    if (( health_status != 0 )) && ! printf '%s\n' "$health_output" | grep -qiE 'diverged|unreachable|p2p sessions=|actively refused|No connection could be made|stalled height|convergence'; then
      printf '%s\n' "$health_output"
      LAST_FAILURE="iteration=$iteration command=health-check exit_code=$health_status"
      exit "$health_status"
    fi
    sleep 5
  done

  if [[ -z "$health_output" ]]; then
    if soak_success_criteria; then
      echo "soak: iteration=$iteration convergence_timeout after ${#SOAK_SAMPLES[@]} samples max_height=$(max_sample_height); ending soak (criteria met)"
      graceful_stop=1
      continue
    fi
    LAST_FAILURE="iteration=$iteration command=health-check convergence_timeout"
    exit 1
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

if soak_success_criteria; then
  finish_soak PASS
else
  if [[ -z "$LAST_FAILURE" ]]; then
    LAST_FAILURE="soak: criteria not met samples=${#SOAK_SAMPLES[@]} max_height=$(max_sample_height) min_final_height=$MIN_FINAL_HEIGHT min_iterations=$MIN_SUCCESSFUL_ITERATIONS"
  fi
  finish_soak FAIL
fi
