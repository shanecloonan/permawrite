#!/usr/bin/env bash
# Lane 7 / TL-8: plan-only TESTNET_INVITE.md packet rehearsal gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INVITE="$REPO_ROOT/docs/TESTNET_INVITE.md"
GENESIS="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.json"
MANIFEST="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
CHECKPOINT_DOC="$REPO_ROOT/docs/CHECKPOINT_LOG.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-8 invite packet docs (no VPS or published seeds required).
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

for f in "$INVITE" "$GENESIS" "$MANIFEST" "$OPS" "$CHECKPOINT_DOC"; do
  if [[ ! -f "$f" ]]; then
    echo "testnet-invite-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

expected_genesis="$(python3 -c "
import json
with open('$MANIFEST', encoding='utf-8') as f:
    print(json.load(f)['genesis_id'])
")"

for needle in \
  "public-devnet-v1" \
  "$expected_genesis" \
  "public_devnet_v1.manifest.json" \
  "public_devnet_v1.checkpoints.jsonl" \
  "checkpointLogVerify" \
  "checkpointLogCrossCheck" \
  "What we do not publish" \
  "Never share" \
  "host:port" \
  ; do
  if ! grep -qF -- "$needle" "$INVITE"; then
    echo "testnet-invite-rehearsal-smoke: TESTNET_INVITE.md missing: $needle" >&2
    exit 1
  fi
done

if grep -qE 'seed_nodes.*1873[0-9]' "$INVITE"; then
  echo "testnet-invite-rehearsal-smoke: invite must not advertise RPC ports in seed_nodes examples" >&2
  exit 1
fi

for needle in "TESTNET_INVITE.md" "publish-seed-nodes"; do
  if ! grep -qF -- "$needle" "$OPS"; then
    echo "testnet-invite-rehearsal-smoke: OPERATORS.md missing: $needle" >&2
    exit 1
  fi
done

echo "testnet-invite-rehearsal-smoke: plan"
echo "  invite=docs/TESTNET_INVITE.md"
echo "  genesis_id=$expected_genesis"
echo "  live_rehearsal=share invite after TL-8 publish-seed-nodes --apply + checkpoint log"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "testnet-invite-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "testnet-invite-rehearsal-smoke: live mode not implemented" >&2
exit 1
