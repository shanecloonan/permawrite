#!/usr/bin/env bash
# Lane 7 / TL-8 / F12: plan-only publish-checkpoint-log rehearsal gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/CHECKPOINT_LOG.md"
INVITE="$REPO_ROOT/docs/TESTNET_INVITE.md"
OPS="$SCRIPT_DIR/OPERATORS.md"
PUBLISH="$SCRIPT_DIR/publish-checkpoint-log.sh"
DEFAULT_LOG="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-8 publish-checkpoint-log docs + plan-only helper (no RPC or maintainer seed).
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

for f in "$DOC" "$INVITE" "$OPS" "$PUBLISH"; do
  if [[ ! -f "$f" ]]; then
    echo "publish-checkpoint-log-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "publish-checkpoint-log" \
  "checkpoint-log sign" \
  "MFN_CHECKPOINT_LOG_SIGNER" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "publish-checkpoint-log-rehearsal-smoke: CHECKPOINT_LOG.md missing: $needle" >&2
    exit 1
  fi
done

for needle in \
  "public_devnet_v1.checkpoints.jsonl" \
  "checkpointLogVerify" \
  ; do
  if ! grep -qF -- "$needle" "$INVITE"; then
    echo "publish-checkpoint-log-rehearsal-smoke: TESTNET_INVITE.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "publish-checkpoint-log" "$OPS"; then
  echo "publish-checkpoint-log-rehearsal-smoke: OPERATORS.md missing publish-checkpoint-log" >&2
  exit 1
fi

plan_out="$(bash "$PUBLISH" --plan-only 2>&1)" || {
  echo "publish-checkpoint-log-rehearsal-smoke: publish-checkpoint-log.sh --plan-only failed" >&2
  exit 1
}
if [[ "$plan_out" != *"publish-checkpoint-log: plan"* ]] || [[ "$plan_out" != *"PASS plan-only"* ]]; then
  echo "publish-checkpoint-log-rehearsal-smoke: unexpected plan-only output" >&2
  exit 1
fi

echo "publish-checkpoint-log-rehearsal-smoke: plan"
echo "  flow=publish-checkpoint-log.sh --rpc HOST:PORT [--apply]"
echo "  default_log=$DEFAULT_LOG"
echo "  docs=docs/CHECKPOINT_LOG.md"
echo "  live_rehearsal=human VPS after TL-7 sign-off + TL-8 seeds"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "publish-checkpoint-log-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "publish-checkpoint-log-rehearsal-smoke: live mode not implemented" >&2
exit 1
