#!/usr/bin/env bash
# B-42 invite-load smoke — plan gate (live load after B-15 faucet lock clears).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: invite-load-smoke-rehearsal.sh [--plan-only]"; exit 0 ;;
    *) echo "invite-load-smoke-rehearsal: unknown $1" >&2; exit 1 ;;
  esac
done
echo "invite-load-smoke-rehearsal: plan"
echo "  unit=B-42"
echo "  flow=staggered join-testnet-rehearsal x2 against live faucet+observer after B-15 lock"
echo "  checks=SUMMARY PASS or serialize-with-reason; R-4 cooldown; proxy healthy; light-scan-checkpoint-soft (F45)"
echo "  evidence=invite-load-smoke-YYYYMMDD.txt under scripts/public-devnet-v1/evidence/"
echo "  docs=docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9"
echo "  conflict=do not run during B-15 faucet lock"
echo "invite-load-smoke-rehearsal: PASS plan-only"