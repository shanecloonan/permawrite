#!/usr/bin/env bash
# Start committee voter 1 or 2; requires HUB_P2P=host:port (M2.4.3).
set -euo pipefail
INDEX="${1:?usage: start-voter.sh 1|2}"
if [[ "$INDEX" != "1" && "$INDEX" != "2" ]]; then
  echo "validator index must be 1 or 2" >&2
  exit 1
fi
HUB_P2P="${HUB_P2P:?set HUB_P2P to hub mfnd_p2p_listening address}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MFND="${MFND:-$REPO_ROOT/target/release/mfnd}"
GENESIS="$REPO_ROOT/$GENESIS_SPEC"
DATA_DIR="${DATA_DIR:-$REPO_ROOT/$DATA_ROOT/v$INDEX}"
mkdir -p "$DATA_DIR"
export MFND_VALIDATOR_INDEX="$INDEX"
if [[ "$INDEX" == "1" ]]; then
  export MFND_VRF_SEED_HEX=0202020202020202020202020202020202020202020202020202020202020202
  export MFND_BLS_SEED_HEX=7676767676767676767676767676767676767676767676767676767676767676
else
  export MFND_VRF_SEED_HEX=0303030303030303030303030303030303030303030303030303030303030303
  export MFND_BLS_SEED_HEX=8787878787878787878787878787878787878787878787878787878787878787
fi
exec "$MFND" --data-dir "$DATA_DIR" --genesis "$GENESIS" --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --p2p-dial "$HUB_P2P" --slot-duration-ms "$SLOT_MS" serve --committee-vote
