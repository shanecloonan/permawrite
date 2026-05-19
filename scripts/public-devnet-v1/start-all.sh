#!/usr/bin/env bash
# Build mfnd, start hub + two voters on loopback; write ports file (M2.4.3).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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
pkill -f "mfnd.*public-devnet-v1" 2>/dev/null || true
sleep 1
echo "Starting hub (v0)..."
"$SCRIPT_DIR/start-hub.sh" >"$LOG_DIR/v0.log" 2>&1 &
HUB_PID=$!
echo "HUB_PID=$HUB_PID" >"$PORTS_FILE"
HUB_P2P=""
HUB_RPC=""
for _ in $(seq 1 60); do
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
echo "Logs: $LOG_DIR  Ports: $PORTS_FILE"
echo "Run health-check.sh when a slot has sealed."
