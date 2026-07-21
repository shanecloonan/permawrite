#!/usr/bin/env bash
# CI plan gate for B-127 outside-in tip-ckpt lag assert.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: assert-outside-in-tip-ckpt-lag-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done

for f in \
  "$SCRIPT_DIR/assert-outside-in-tip-ckpt-lag.sh" \
  "$SCRIPT_DIR/assert-outside-in-tip-ckpt-lag.ps1"
do
  [[ -f "$f" ]] || { echo "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: missing $f" >&2; exit 1; }
done

needles=(B-127 B-129 B-134 outside-in-tip-ckpt-lag never=faucet-http path-a-publish tip-ckpt-lag MFN_CKPT_LAG_THRESHOLD EVIDENCE auto-archive STALENESS published_at ckpt_entries)
for n in "${needles[@]}"; do
  grep -qF -- "$n" "$SCRIPT_DIR/assert-outside-in-tip-ckpt-lag.sh" || {
    echo "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: assert missing $n" >&2
    exit 1
  }
done

plan="$(bash "$SCRIPT_DIR/assert-outside-in-tip-ckpt-lag.sh" --plan-only)"
[[ "$plan" == *"assert-outside-in-tip-ckpt-lag: PASS plan-only"* ]] || {
  printf '%s\n' "$plan" >&2
  exit 1
}

echo "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: plan"
echo "  unit=B-127+B-129+B-134"
echo "  assert=assert-outside-in-tip-ckpt-lag.sh"
echo "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: PASS plan-only"
exit 0
