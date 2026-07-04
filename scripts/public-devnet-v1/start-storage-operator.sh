#!/usr/bin/env bash
# One-command storage operator: prove loop against any synced RPC (M6 / decentralization Phase A).
# RPC-only path — no local mfnd required when MFN_RPC or manifest observer_rpc is set.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.env"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MFNO="${MFNO:-$REPO_ROOT/target/release/mfn-storage-operator}"
if [[ ! -x "$MFNO" ]]; then
  MFNO="$REPO_ROOT/target/release/mfn-storage-operator.exe"
fi
MANIFEST_PATH="$REPO_ROOT/$MANIFEST"
WALLET="${1:-${MFN_WALLET:-$REPO_ROOT/wallet.json}}"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
if [[ -z "${MFN_RPC:-}" && -f "$PORTS_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$PORTS_FILE"
  if [[ -n "${OBSERVER_RPC:-}" ]]; then
    export MFN_RPC="$OBSERVER_RPC"
  fi
fi
export MFN_OPERATOR_MANIFEST="${MFN_OPERATOR_MANIFEST:-$MANIFEST_PATH}"
EXTRA=()
if [[ -n "${MFN_CHUNK_LISTEN:-}" ]]; then
  EXTRA+=(--chunk-listen "$MFN_CHUNK_LISTEN")
fi
if [[ "${MFN_ONCE:-}" == "1" ]]; then
  EXTRA+=(--once)
fi
if [[ "${MFN_JSON:-}" == "1" ]]; then
  EXTRA+=(--json)
fi
exec "$MFNO" run --wallet "$WALLET" "${EXTRA[@]}"