#!/usr/bin/env bash
# Start validator 0 (hub producer) for public-devnet-v1 (M2.4.3).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MFND="${MFND:-$REPO_ROOT/target/release/mfnd}"
GENESIS="$REPO_ROOT/$GENESIS_SPEC"
DATA_DIR="${DATA_DIR:-$REPO_ROOT/$DATA_ROOT/v0}"
mkdir -p "$DATA_DIR"
export MFND_VALIDATOR_INDEX=0
export MFND_VRF_SEED_HEX=0101010101010101010101010101010101010101010101010101010101010101
export MFND_BLS_SEED_HEX=6565656565656565656565656565656565656565656565656565656565656565
exec "$MFND" --data-dir "$DATA_DIR" --genesis "$GENESIS" --store fs \
  --rpc-listen "${MFN_RPC_LISTEN:-127.0.0.1:0}" --p2p-listen "${MFN_P2P_LISTEN:-127.0.0.1:0}" \
  --slot-duration-ms "$SLOT_MS" serve --produce
