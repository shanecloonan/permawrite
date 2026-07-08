#!/usr/bin/env bash
# Start non-validator observer; requires HUB_P2P in environment (M2.4.9).
# Optional EXTRA_P2P_DIALS (whitespace-separated) adds committee peer boot dials (M2.4.88).
set -euo pipefail
if [[ -z "${HUB_P2P:-}" ]]; then
  echo "start-observer: set HUB_P2P to hub mfnd_p2p_listening address" >&2
  exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MFND="${MFND:-$REPO_ROOT/target/release/mfnd}"
if [[ ! -x "$MFND" ]]; then
  MFND="$REPO_ROOT/target/release/mfnd.exe"
fi
GENESIS="$REPO_ROOT/$GENESIS_SPEC"
DATA_DIR="${DATA_DIR:-$REPO_ROOT/$DATA_ROOT/observer}"
mkdir -p "$DATA_DIR"
unset MFND_VALIDATOR_INDEX MFND_VRF_SEED_HEX MFND_BLS_SEED_HEX

DIAL_ARGS=(--p2p-dial "$HUB_P2P")
if [[ -n "${EXTRA_P2P_DIALS:-}" ]]; then
  read -r -a _extra_dials <<< "$EXTRA_P2P_DIALS"
  for peer in "${_extra_dials[@]}"; do
    if [[ -z "$peer" || "$peer" == "$HUB_P2P" ]]; then
      continue
    fi
    DIAL_ARGS+=(--p2p-dial "$peer")
  done
fi

exec "$MFND" --data-dir "$DATA_DIR" --genesis "$GENESIS" --store fs \
  --rpc-listen "${MFN_RPC_LISTEN:-127.0.0.1:0}" --p2p-listen "${MFN_P2P_LISTEN:-127.0.0.1:0}" \
  "${DIAL_ARGS[@]}" --slot-duration-ms "$SLOT_MS" serve
