#!/usr/bin/env bash
# Start non-validator observer; requires HUB_P2P in environment (M2.4.9).
set -euo pipefail
if [[ -z "${HUB_P2P:-}" ]]; then
  echo "start-observer: set HUB_P2P to hub mfnd_p2p_listening address" >&2
  exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MFND="${MFND:-$REPO_ROOT/target/release/mfnd}"
if [[ ! -x "$MFND" ]]; then
  MFND="$REPO_ROOT/target/release/mfnd.exe"
fi
GENESIS="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.json"
DATA_DIR="${DATA_DIR:-$REPO_ROOT/.permawrite-devnet-v1/observer}"
mkdir -p "$DATA_DIR"
unset MFND_VALIDATOR_INDEX MFND_VRF_SEED_HEX MFND_BLS_SEED_HEX
SLOT_MS="${SLOT_MS:-30000}"
exec "$MFND" --data-dir "$DATA_DIR" --genesis "$GENESIS" --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --p2p-dial "$HUB_P2P" --slot-duration-ms "$SLOT_MS" serve
