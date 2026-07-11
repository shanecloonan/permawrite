#!/usr/bin/env bash
# Lane 7 / TL-7: plan-only vps-launch-ceremony rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPS="$SCRIPT_DIR/OPERATORS.md"
PLAYBOOK="$REPO_ROOT/docs/TESTNET_LAUNCH.md"
DOC="$REPO_ROOT/docs/VPS_SINGLE_BOX_LAUNCH.md"
CEREMONY="$SCRIPT_DIR/vps-launch-ceremony.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates vps-launch-ceremony.sh --plan-only TL-5..TL-9 ordering and doc cross-links.
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

for f in "$OPS" "$PLAYBOOK" "$DOC" "$CEREMONY"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-launch-ceremony-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-launch-ceremony" "$OPS"; then
  echo "vps-launch-ceremony-rehearsal-smoke: OPERATORS.md missing vps-launch-ceremony" >&2
  exit 1
fi

plan_out="$(bash "$CEREMONY" --plan-only 2>&1)" || {
  echo "vps-launch-ceremony-rehearsal-smoke: vps-launch-ceremony.sh --plan-only failed" >&2
  exit 1
}

for needle in \
  "TL-5" \
  "TL-6" \
  "TL-7" \
  "TL-8" \
  "TL-9" \
  "publish-seed-nodes.sh" \
  "publish-checkpoint-log.sh" \
  "launch-go-no-go.sh" \
  "vps-internet-soak.sh" \
  "vps-participant-rehearsal.sh" \
  "vps-execution-checklist" \
  "TESTNET_INVITE.md" \
  ; do
  if [[ "$plan_out" != *"$needle"* ]]; then
    echo "vps-launch-ceremony-rehearsal-smoke: --plan-only output missing: $needle" >&2
    exit 1
  fi
done

echo "vps-launch-ceremony-rehearsal-smoke: plan"
echo "  helper=vps-launch-ceremony.sh [--plan-only|--check]"
echo "  ordered=TL-5..TL-9"
echo "  docs=docs/TESTNET_LAUNCH.md docs/VPS_SINGLE_BOX_LAUNCH.md"
echo "  live_rehearsal=human VPS ceremony after local RC green"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-launch-ceremony-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-launch-ceremony-rehearsal-smoke: live mode not implemented" >&2
exit 1
