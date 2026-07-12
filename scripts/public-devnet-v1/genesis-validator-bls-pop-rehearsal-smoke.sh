#!/usr/bin/env bash
# Plan-only gate: genesis validator BLS PoP ceremony tooling (PROBLEMS.md § 13).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/TESTNET_GENESIS_CEREMONY.md"
GENESIS="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.json"
TOOL="$SCRIPT_DIR/genesis-validator-bls-pop.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates genesis-validator-bls-pop tooling + Path B doc wiring (no secrets).
EOF
}

PLAN_ONLY=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

for f in "$DOC" "$GENESIS" "$TOOL"; do
  if [[ ! -f "$f" ]]; then
    echo "genesis-validator-bls-pop-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "require_validator_bls_pop" \
  "bls_register_sig_hex" \
  "genesis-validator-bls-pop" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "genesis-validator-bls-pop-rehearsal-smoke: TESTNET_GENESIS_CEREMONY.md missing: $needle" >&2
    exit 1
  fi
done

cd "$REPO_ROOT"
out="$(bash "$TOOL" --genesis "$GENESIS" 2>&1)" || {
  echo "genesis-validator-bls-pop-rehearsal-smoke: compute failed" >&2
  echo "$out" >&2
  exit 1
}
if [[ "$out" != *"validators[0]"* ]] || [[ "$out" != *"bls_register_sig_hex="* ]]; then
  echo "genesis-validator-bls-pop-rehearsal-smoke: unexpected compute output" >&2
  echo "$out" >&2
  exit 1
fi

bash "$TOOL" --genesis "$GENESIS" --verify >/dev/null

echo "genesis-validator-bls-pop-rehearsal-smoke: PASS plan-only"
