#!/usr/bin/env bash
# B-15: plan-only JOIN_TESTNET rehearsal evidence assert + doc wiring gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
JOIN_DOC="$REPO_ROOT/docs/JOIN_TESTNET.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
ASSERT="$SCRIPT_DIR/assert-join-testnet-rehearsal-evidence.sh"
SMOKE="$SCRIPT_DIR/join-testnet-rehearsal-smoke.sh"
FIXTURE="$SCRIPT_DIR/fixtures/join-testnet-rehearsal-evidence-v1/join-testnet-rehearsal-linux-20260719T000000Z.txt"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates assert-join-testnet-rehearsal-evidence + JOIN_TESTNET doc wiring (no live mesh).
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

for f in "$JOIN_DOC" "$OPS" "$ASSERT" "$SMOKE" "$FIXTURE"; do
  if [[ ! -f "$f" ]]; then
    echo "join-testnet-rehearsal-evidence-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "join-testnet-rehearsal-smoke" \
  "fund-wallet-http" \
  "8788" \
  "8787/rpc" \
  "light-scan" \
  ; do
  if ! grep -qF -- "$needle" "$JOIN_DOC"; then
    echo "join-testnet-rehearsal-evidence-rehearsal-smoke: JOIN_TESTNET.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "assert-join-testnet-rehearsal-evidence" "$OPS"; then
  echo "join-testnet-rehearsal-evidence-rehearsal-smoke: OPERATORS.md missing assert-join-testnet-rehearsal-evidence" >&2
  exit 1
fi

bash "$ASSERT" "$FIXTURE"

echo "join-testnet-rehearsal-evidence-rehearsal-smoke: plan"
echo "  assert=assert-join-testnet-rehearsal-evidence.sh"
echo "  fixture=fixtures/join-testnet-rehearsal-evidence-v1/"
echo "  docs=docs/JOIN_TESTNET.md"
echo "join-testnet-rehearsal-evidence-rehearsal-smoke: PASS plan-only"
exit 0
