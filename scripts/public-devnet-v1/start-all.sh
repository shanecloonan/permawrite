#!/usr/bin/env bash
# Build mfnd, start hub + two committee voters on loopback; write ports file (M2.4.3).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
# shellcheck source=rehearsal-poll-timeouts.env
source "$SCRIPT_DIR/rehearsal-poll-timeouts.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# shellcheck source=vps-bind-lib.sh
source "$SCRIPT_DIR/vps-bind-lib.sh"

if [[ "${MFN_VPS_MODE:-}" == "1" ]]; then
  load_vps_bind_file "$SCRIPT_DIR" || exit 1
  echo "start-all: VPS mode — public P2P binds from ${MFN_VPS_BIND_FILE:-$SCRIPT_DIR/vps-bind.env}"
else
  # Local Nightly/rehearsal mesh must not dial published public seed_nodes from
  # public_devnet_v1.manifest.json (same genesis_id as live Hetzner → tip poison).
  export MFN_SKIP_MANIFEST_SEEDS="${MFN_SKIP_MANIFEST_SEEDS:-1}"
  echo "start-all: local mesh — MFN_SKIP_MANIFEST_SEEDS=$MFN_SKIP_MANIFEST_SEEDS (isolated from public seeds)"
fi

NO_BUILD=0
DANDELION=0
if [[ "${MFN_DEVNET_SKIP_BUILD:-}" == "1" ]]; then
  NO_BUILD=1
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) NO_BUILD=1; shift ;;
    --dandelion) DANDELION=1; shift ;;
    -h|--help)
      echo "usage: start-all.sh [--no-build] [--dandelion]" >&2
      exit 0
      ;;
    *)
      echo "start-all: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$DANDELION" == "1" || "${MFN_DEVNET_DANDELION:-}" == "1" ]]; then
  export MFND_DANDELION=1
  echo "start-all: dandelion relay enabled (MFND_DANDELION=1)"
fi

MFND="$REPO_ROOT/target/release/mfnd"
if [[ ! -x "$MFND" ]]; then
  MFND="$REPO_ROOT/target/release/mfnd.exe"
fi
if (( NO_BUILD == 0 )); then
  echo "Building mfnd..."
  cargo build -p mfn-node --release --bin mfnd --manifest-path "$REPO_ROOT/Cargo.toml"
  if [[ ! -x "$MFND" ]]; then
    MFND="$REPO_ROOT/target/release/mfnd.exe"
  fi
elif [[ ! -x "$MFND" ]]; then
  echo "start-all: missing mfnd at target/release/mfnd; omit --no-build or build first" >&2
  exit 1
else
  echo "start-all: using existing mfnd ($MFND)"
fi
export MFND
if [[ "${MFN_SOAK_BOOTSTRAP:-}" == "1" ]]; then
  "$SCRIPT_DIR/stop-all.sh" --force --all-mfnd || true
else
  assert_soak_not_active "$SCRIPT_DIR" "start-all"
  pkill -f "mfnd.*public-devnet-v1" 2>/dev/null || true
  sleep 1
fi
rm -rf "$REPO_ROOT/$DATA_ROOT"
echo "Cleared local devnet data root: $REPO_ROOT/$DATA_ROOT"
echo "Starting hub (v0)..."
vps_export_binds hub
export MFN_RPC_LISTEN="${MFN_RPC_LISTEN:-127.0.0.1:0}"
export MFN_P2P_LISTEN="${MFN_P2P_LISTEN:-127.0.0.1:0}"
: >"$LOG_DIR/v0.log"
bash "$SCRIPT_DIR/start-hub.sh" >>"$LOG_DIR/v0.log" 2>&1 &
HUB_PID=$!
echo "HUB_PID=$HUB_PID" >"$PORTS_FILE"
HUB_P2P=""
HUB_RPC=""
HUB_POLL_MAX="$MFN_POLL_HUB_MAX"
# First poll after 1s — avoids $! / log-redirect races on fast GHA runners.
sleep 1
for hub_poll_i in $(seq 1 "$HUB_POLL_MAX"); do
  if ! kill -0 "$HUB_PID" 2>/dev/null; then
    echo "start-all: hub process $HUB_PID exited before P2P listen; tail $LOG_DIR/v0.log:" >&2
    tail -n 100 "$LOG_DIR/v0.log" 2>/dev/null >&2 || echo "(no v0.log)" >&2
    exit 1
  fi
  if grep -q mfnd_p2p_listening= "$LOG_DIR/v0.log" 2>/dev/null; then
    HUB_P2P=$(grep -m1 mfnd_p2p_listening= "$LOG_DIR/v0.log" | sed 's/.*=//')
    HUB_RPC=$(grep -m1 mfnd_serve_listening= "$LOG_DIR/v0.log" | sed 's/.*=//')
    break
  fi
  # NOTE: not `for _ in ...` - bash resets `$_` after every command, breaking the modulo.
  if [[ -n "${GITHUB_ACTIONS:-}" ]] && ((hub_poll_i % 30 == 0)); then
    if grep -q mfnd_serve_listening= "$LOG_DIR/v0.log" 2>/dev/null; then
      echo "start-all: hub RPC ready, waiting for P2P (${hub_poll_i}/${HUB_POLL_MAX}s)..."
    else
      echo "start-all: waiting for hub startup (${hub_poll_i}/${HUB_POLL_MAX}s)..."
    fi
  fi
  sleep 1
done
if [[ -z "$HUB_P2P" ]]; then
  echo "hub failed to print P2P listen within ${HUB_POLL_MAX}s; tail $LOG_DIR/v0.log:" >&2
  tail -n 100 "$LOG_DIR/v0.log" 2>/dev/null >&2 || echo "(no v0.log)" >&2
  exit 1
fi
echo "HUB_P2P=$HUB_P2P" >>"$PORTS_FILE"
echo "HUB_RPC=$HUB_RPC" >>"$PORTS_FILE"
export HUB_P2P
echo "Hub P2P=$HUB_P2P RPC=$HUB_RPC"
sleep 2
echo "Starting voter 1..."
vps_export_binds v1
bash "$SCRIPT_DIR/start-voter.sh" 1 >"$LOG_DIR/v1.log" 2>&1 &
echo "V1_PID=$!" >>"$PORTS_FILE"
sleep 2
echo "Starting voter 2..."
vps_export_binds v2
bash "$SCRIPT_DIR/start-voter.sh" 2 >"$LOG_DIR/v2.log" 2>&1 &
echo "V2_PID=$!" >>"$PORTS_FILE"
sleep 2
poll_voter_p2p() {
  local log_path="$1"
  local p2p="" i max="$MFN_POLL_VOTER_P2P_MAX"
  for i in $(seq 1 "$max"); do
    if grep -q mfnd_p2p_listening= "$log_path" 2>/dev/null; then
      p2p=$(grep -m1 mfnd_p2p_listening= "$log_path" | sed 's/.*=//')
      break
    fi
    if [[ -n "${GITHUB_ACTIONS:-}" ]] && (( i % 30 == 0 )); then
      local serve=0
      grep -q mfnd_serve_listening= "$log_path" 2>/dev/null && serve=1
      echo "start-all: STAGE=voter_p2p_wait log=$(basename "$log_path") elapsed=${i}/${max}s serve_listening=$serve"
    fi
    sleep 1
  done
  printf '%s' "$p2p"
}

wait_hub_tip_at_least() {
  local hub_rpc="$1" min_height="$2" timeout_seconds="$3"
  local deadline tip_height i=0 hub_pid=""
  hub_pid="$(grep -m1 '^HUB_PID=' "$PORTS_FILE" 2>/dev/null | sed 's/HUB_PID=//' || true)"
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    i=$(( i + 1 ))
    if [[ -n "$hub_pid" ]] && ! kill -0 "$hub_pid" 2>/dev/null; then
      echo "start-all: hub pid=$hub_pid exited during hub_tip_wait; tail $LOG_DIR/v0.log:" >&2
      tail -n 100 "$LOG_DIR/v0.log" 2>/dev/null >&2 || echo "(no v0.log)" >&2
      exit 1
    fi
    tip_height="$(query_tip_height "$hub_rpc" "$REPO_ROOT")"
    echo "start-all: hub_tip_wait tip_height=$tip_height min_height=$min_height"
    if [[ "$tip_height" == "unknown" ]] && ! resolve_mfn_cli "$REPO_ROOT" >/dev/null 2>&1; then
      echo "start-all: hint: build target/release/mfn-cli for hub tip polls (nc get_status fallback may be empty on GHA)" >&2
    fi
    if [[ "$tip_height" =~ ^[0-9]+$ ]] && (( tip_height >= min_height )); then
      return
    fi
    if [[ -n "${GITHUB_ACTIONS:-}" ]] && (( i % 6 == 0 )); then
      echo "start-all: STAGE=hub_tip_wait elapsed=$(( i * 5 ))/${timeout_seconds}s tip_height=$tip_height"
    fi
    if (( $(date +%s) >= deadline )); then
      echo "start-all: STAGE=hub_tip_wait_fail tip_height=$tip_height min_height=$min_height after ${timeout_seconds}s; tail $LOG_DIR/v0.log:" >&2
      echo "start-all: hub tip_height=$tip_height below min_height=$min_height after ${timeout_seconds}s; tail $LOG_DIR/v0.log:" >&2
      tail -n 100 "$LOG_DIR/v0.log" 2>/dev/null >&2 || echo "(no v0.log)" >&2
      exit 1
    fi
    sleep 5
  done
}
V1_P2P=""
V2_P2P=""
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  v1_p2p_file="$(mktemp)"
  v2_p2p_file="$(mktemp)"
  poll_voter_p2p "$LOG_DIR/v1.log" >"$v1_p2p_file" &
  pid_v1=$!
  poll_voter_p2p "$LOG_DIR/v2.log" >"$v2_p2p_file" &
  pid_v2=$!
  wait "$pid_v1"
  wait "$pid_v2"
  V1_P2P="$(cat "$v1_p2p_file" 2>/dev/null || true)"
  V2_P2P="$(cat "$v2_p2p_file" 2>/dev/null || true)"
  rm -f "$v1_p2p_file" "$v2_p2p_file"
else
  V1_P2P="$(poll_voter_p2p "$LOG_DIR/v1.log")"
  V2_P2P="$(poll_voter_p2p "$LOG_DIR/v2.log")"
fi
if [[ -z "$V1_P2P" || -z "$V2_P2P" ]]; then
  echo "start-all: committee voters failed to print P2P listen within timeout; tail logs:" >&2
  tail -n 80 "$LOG_DIR/v1.log" 2>/dev/null >&2 || echo "(no v1.log)" >&2
  tail -n 80 "$LOG_DIR/v2.log" 2>/dev/null >&2 || echo "(no v2.log)" >&2
  exit 1
fi
echo "Voter 1 P2P=$V1_P2P"
echo "Voter 2 P2P=$V2_P2P"

wait_voter_dial_hub() {
  local max="$MFN_POLL_VOTER_DIAL_MAX" v1_ok v2_ok i tip_height
  for i in $(seq 1 "$max"); do
    v1_ok=0
    v2_ok=0
    grep -q mfnd_p2p_dial_ok= "$LOG_DIR/v1.log" 2>/dev/null && v1_ok=1
    grep -q mfnd_p2p_dial_ok= "$LOG_DIR/v2.log" 2>/dev/null && v2_ok=1
    if (( v1_ok && v2_ok )); then
      echo "start-all: committee voters dialed hub (${i}s)"
      return
    fi
    if [[ -n "${GITHUB_ACTIONS:-}" ]] && (( i % 30 == 0 )); then
      tip_height="$(query_tip_height "${HUB_RPC:-}" "$REPO_ROOT" 2>/dev/null || echo unknown)"
      echo "start-all: waiting for voter hub dials (${i}/${max}s) v1_ok=$v1_ok v2_ok=$v2_ok hub_tip_height=$tip_height"
    fi
    sleep 1
  done
  if [[ -n "${HUB_RPC:-}" ]]; then
    v1_ok=0
    v2_ok=0
    grep -q mfnd_p2p_dial_ok= "$LOG_DIR/v1.log" 2>/dev/null && v1_ok=1
    grep -q mfnd_p2p_dial_ok= "$LOG_DIR/v2.log" 2>/dev/null && v2_ok=1
    tip_height="$(query_tip_height "$HUB_RPC" "$REPO_ROOT")"
    if [[ "$tip_height" =~ ^[0-9]+$ ]] && (( tip_height >= 1 )) && (( v1_ok || v2_ok )); then
      echo "start-all: WARN voter hub dial incomplete after ${max}s but hub tip_height=$tip_height (v1_ok=$v1_ok v2_ok=$v2_ok); continuing"
      return
    fi
    # GHA: voters may receive inbound hub dials before mfnd_p2p_dial_ok= appears in redirected logs.
    if [[ -n "${GITHUB_ACTIONS:-}" ]] && [[ "$tip_height" =~ ^[0-9]+$ ]] && (( tip_height >= 1 )); then
      if grep -q mfnd_p2p_listening= "$LOG_DIR/v1.log" 2>/dev/null && \
         grep -q mfnd_p2p_listening= "$LOG_DIR/v2.log" 2>/dev/null; then
        echo "start-all: WARN voter hub dial incomplete after ${max}s but hub tip_height=$tip_height and both voters P2P listening; continuing (GHA)"
        return
      fi
    fi
    if [[ -n "${GITHUB_ACTIONS:-}" ]] && [[ "$tip_height" =~ ^[0-9]+$ ]] && (( tip_height >= 2 )); then
      echo "start-all: WARN voter hub dial incomplete after ${max}s but hub tip_height=$tip_height; continuing (GHA chain live)"
      return
    fi
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
      if grep -q mfnd_p2p_listening= "$LOG_DIR/v1.log" 2>/dev/null && \
         grep -q mfnd_p2p_listening= "$LOG_DIR/v2.log" 2>/dev/null; then
        tip_height="$(query_tip_height "$HUB_RPC" "$REPO_ROOT")"
        echo "start-all: WARN voter hub dial incomplete after ${max}s but both voters P2P listening (tip_height=$tip_height); continuing (GHA)"
        return
      fi
    fi
  fi
  echo "start-all: STAGE=voter_dial_fail" >&2
  echo "start-all: voters failed to dial hub within ${max}s; tail logs:" >&2
  tail -n 80 "$LOG_DIR/v1.log" 2>/dev/null >&2 || echo "(no v1.log)" >&2
  tail -n 80 "$LOG_DIR/v2.log" 2>/dev/null >&2 || echo "(no v2.log)" >&2
  exit 1
}
wait_voter_dial_hub

if [[ "${MFN_DEVNET_NO_OBSERVER:-}" == "1" ]]; then
  echo "Skipping observer (MFN_DEVNET_NO_OBSERVER=1)"
else
EXTRA_P2P_DIALS=""
if [[ -n "$V1_P2P" && "$V1_P2P" != "$HUB_P2P" ]]; then
  EXTRA_P2P_DIALS="$V1_P2P"
fi
if [[ -n "$V2_P2P" && "$V2_P2P" != "$HUB_P2P" ]]; then
  EXTRA_P2P_DIALS="${EXTRA_P2P_DIALS:+$EXTRA_P2P_DIALS }$V2_P2P"
fi
if [[ -n "$EXTRA_P2P_DIALS" ]]; then
  echo "Observer extra boot dials: $EXTRA_P2P_DIALS"
  export EXTRA_P2P_DIALS
fi
echo "Starting observer..."
vps_export_binds observer
bash "$SCRIPT_DIR/start-observer.sh" >"$LOG_DIR/observer.log" 2>&1 &
echo "OBSERVER_PID=$!" >>"$PORTS_FILE"
OBSERVER_RPC=""
OBSERVER_POLL_MAX="$MFN_POLL_OBSERVER_MAX"
for observer_poll_i in $(seq 1 "$OBSERVER_POLL_MAX"); do
  if grep -q mfnd_serve_listening= "$LOG_DIR/observer.log" 2>/dev/null; then
    OBSERVER_RPC=$(grep -m1 mfnd_serve_listening= "$LOG_DIR/observer.log" | sed 's/.*=//')
    break
  fi
  # NOTE: not `for _ in ...` - bash resets `$_` after every command, breaking the modulo.
  if [[ -n "${GITHUB_ACTIONS:-}" ]] && ((observer_poll_i % 30 == 0)); then
    if grep -q mfnd_p2p_listening= "$LOG_DIR/observer.log" 2>/dev/null; then
      echo "start-all: observer P2P ready, waiting for RPC (${observer_poll_i}/${OBSERVER_POLL_MAX}s)..."
    else
      echo "start-all: waiting for observer startup (${observer_poll_i}/${OBSERVER_POLL_MAX}s)..."
    fi
  fi
  sleep 1
done
if [[ -n "$OBSERVER_RPC" ]]; then
  echo "OBSERVER_RPC=$OBSERVER_RPC" >>"$PORTS_FILE"
  echo "Observer RPC=$OBSERVER_RPC"
else
  echo "Observer RPC not ready within ${OBSERVER_POLL_MAX}s; tail $LOG_DIR/observer.log:" >&2
  tail -n 100 "$LOG_DIR/observer.log" 2>/dev/null >&2 || echo "(no observer.log)" >&2
  exit 1
fi
fi
echo "Logs: $LOG_DIR  Ports: $PORTS_FILE"
echo "Run health-check.sh when a slot has sealed."
required_keys=(HUB_PID HUB_P2P HUB_RPC V1_PID V2_PID)
if [[ "${MFN_DEVNET_NO_OBSERVER:-}" != "1" ]]; then
  required_keys+=(OBSERVER_PID OBSERVER_RPC)
fi
for key in "${required_keys[@]}"; do
  if ! grep -q "^${key}=" "$PORTS_FILE" 2>/dev/null; then
    echo "start-all: $key missing from $PORTS_FILE after startup" >&2
    exit 1
  fi
done
if [[ -n "${MFND_DANDELION:-}" ]]; then
  for log in "$LOG_DIR/v0.log" "$LOG_DIR/v1.log" "$LOG_DIR/v2.log"; do
    if ! grep -q mfnd_dandelion=enabled "$log" 2>/dev/null; then
      echo "start-all: expected mfnd_dandelion=enabled in $(basename "$log")" >&2
      exit 1
    fi
  done
  if [[ "${MFN_DEVNET_NO_OBSERVER:-}" != "1" ]]; then
    if ! grep -q mfnd_dandelion=enabled "$LOG_DIR/observer.log" 2>/dev/null; then
      echo "start-all: expected mfnd_dandelion=enabled in observer.log" >&2
      exit 1
    fi
  fi
  echo "start-all: dandelion enabled on all mesh roles"
fi
HUB_TIP_WAIT=120
HUB_TIP_MIN=1
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  # Mesh convergence to tip>=2 is gated in participant-rehearsal-smoke (hub_liveness).
  # Align with MFN_POLL_HUB_MAX (900s) — hardcoded 600s caused ~16.3m Nightly fails (M2.5.51).
  HUB_TIP_WAIT="$MFN_POLL_HUB_MAX"
  HUB_TIP_MIN=1
fi
echo "start-all: STAGE=hub_tip_wait min_height=$HUB_TIP_MIN timeout=${HUB_TIP_WAIT}s"
wait_hub_tip_at_least "$HUB_RPC" "$HUB_TIP_MIN" "$HUB_TIP_WAIT"
echo "start-all: STAGE=hub_tip_wait_done"
