#!/usr/bin/env bash
# Compute or verify genesis validator BLS register PoP signatures (Path B ceremony).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<EOF
usage: $(basename "$0") --genesis PATH.json [--verify]

  --verify   Run genesis_config_from_json_bytes PoP gate (no stdout sigs).
  (default)  Print expected bls_register_sig_hex per validator row.
EOF
}

GENESIS=""
VERIFY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --genesis) GENESIS="${2:-}"; shift 2 ;;
    --verify) VERIFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$GENESIS" ]]; then
  echo "$(basename "$0"): --genesis PATH.json is required" >&2
  exit 1
fi

cd "$REPO_ROOT"
args=(--example genesis_validator_bls_pop -- --genesis "$GENESIS")
if [[ "$VERIFY" -eq 1 ]]; then
  args+=(--verify)
fi
exec cargo run --quiet --release -p mfn-runtime "${args[@]}"
