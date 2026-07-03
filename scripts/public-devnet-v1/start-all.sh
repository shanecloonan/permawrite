#!/usr/bin/env bash
# Build mfnd, start hub + two committee voters on loopback; write ports file (M2.4.3).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
echo "Building mfnd..."
cargo build -p mfn-node --release --bin mfnd --manifest-path "$REPO_ROOT/Cargo.toml"
MFND="$REPO_ROOT/target/release/mfnd"
if [[ ! -x "$MFND" ]]; then
  MFND="$REPO_ROOT/target/release/mfnd.exe"
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
"$SCRIPT_DIR/start-hub.sh" >"$LOG_DIR/v0.log" 2>&1 &
HUB_PID=$!
echo "HUB_PID=$HUB_PID" >"$PORTS_FILE"
HUB_P2P=""
HUB_RPC=""
HUB_POLL_MAX=60
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  HUB_POLL_MAX=120
fi
for _ in $(seq 1 "$HUB_POLL_MAX"); do
  if grep -q mfnd_p2p_listening= "$LOG_DIR/v0.log" 2>/dev/null; then
    HUB_P2P=$(grep -m1 mfnd_p2p_listening= "$LOG_DIR/v0.log" | sed 's/.*=//')
    HUB_RPC=$(grep -m1 mfnd_serve_listening= "$LOG_DIR/v0.log" | sed 's/.*=//')
    break
  fi
  sleep 1
done
if [[ -z "$HUB_P2P" ]]; then
  echo "hub failed to print P2P listen; see $LOG_DIR/v0.log" >&2
  exit 1
fi
echo "HUB_P2P=$HUB_P2P" >>"$PORTS_FILE"
echo "HUB_RPC=$HUB_RPC" >>"$PORTS_FILE"
export HUB_P2P
echo "Hub P2P=$HUB_P2P RPC=$HUB_RPC"
sleep 2
echo "Starting voter 1..."
"$SCRIPT_DIR/start-voter.sh" 1 >"$LOG_DIR/v1.log" 2>&1 &
echo "V1_PID=$!" >>"$PORTS_FILE"
sleep 2
echo "Starting voter 2..."
"$SCRIPT_DIR/start-voter.sh" 2 >"$LOG_DIR/v2.log" 2>&1 &
echo "V2_PID=$!" >>"$PORTS_FILE"
sleep 2
if [[ "${MFN_DEVNET_NO_OBSERVER:-}" == "1" ]]; then
  echo "Skipping observer (MFN_DEVNET_NO_OBSERVER=1)"
else
echo "Starting observer..."
"$SCRIPT_DIR/start-observer.sh" >"$LOG_DIR/observer.log" 2>&1 &
echo "OBSERVER_PID=$!" >>"$PORTS_FILE"
OBSERVER_RPC=""
OBSERVER_POLL_MAX=60
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  OBSERVER_POLL_MAX=120
fi
for _ in $(seq 1 "$OBSERVER_POLL_MAX"); do
  if grep -q mfnd_serve_listening= "$LOG_DIR/observer.log" 2>/dev/null; then
    OBSERVER_RPC=$(grep -m1 mfnd_serve_listening= "$LOG_DIR/observer.log" | sed 's/.*=//')
    break
  fi
  sleep 1
done
if [[ -n "$OBSERVER_RPC" ]]; then
  echo "OBSERVER_RPC=$OBSERVER_RPC" >>"$PORTS_FILE"
  echo "Observer RPC=$OBSERVER_RPC"
else
  echo "Observer RPC not ready within 60s; health-check may skip observer (see $LOG_DIR/observer.log)" >&2
fi
fi
echo "Logs: $LOG_DIR  Ports: $PORTS_FILE"
echo "Run health-check.sh when a slot has sealed."
