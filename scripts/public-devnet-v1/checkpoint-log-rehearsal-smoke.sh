#!/usr/bin/env bash
# F12 phase 1: plan-only signed checkpoint log rehearsal (bash parity).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/CHECKPOINT_LOG.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates F12 checkpoint log doc + CLI strings (no live maintainer publish).
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

if [[ ! -f "$DOC" ]]; then
  echo "checkpoint-log-rehearsal-smoke: missing $DOC" >&2
  exit 1
fi

for needle in \
  "checkpoint-log sign" \
  "checkpoint-log verify" \
  "MFN:checkpoint-log-signer:v1" \
  "MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX" \
  ; do
  if ! grep -qF "$needle" "$DOC"; then
    echo "checkpoint-log-rehearsal-smoke: CHECKPOINT_LOG.md missing: $needle" >&2
    exit 1
  fi
done

echo "checkpoint-log-rehearsal-smoke: plan"
echo "  flow=export-trusted-summary -> checkpoint-log sign -> checkpoint-log verify"
echo "  docs=docs/CHECKPOINT_LOG.md"
echo "  cli=mfn-cli checkpoint-log sign|verify"
echo "  live_rehearsal=deferred (publish log at TL-8 invite)"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "checkpoint-log-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "checkpoint-log-rehearsal-smoke: live mode not implemented" >&2
exit 1
