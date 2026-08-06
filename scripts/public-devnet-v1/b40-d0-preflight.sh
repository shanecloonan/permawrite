#!/usr/bin/env bash
# Lane 6 / B-40: D0 preflight - treasury sample + B-28 floors + checklist needles.
# Plan-only by default; --rpc HOST:PORT|http(s)://... runs live helpers.
# Does NOT enable subsidy_to_treasury_bps (B-33 human gate).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPC=""
PLAN_ONLY=1

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only] [--rpc HOST:PORT|http(s)://...]

B-40 D0 preflight (lane 6):
  1) treasury-telemetry-watch (subsidy_bps expect 0 pre-enable)
  2) assert-b28-treasury-thresholds (floors)
  3) print D0 checklist reminders (claim board, B-13a ancestry, B-32 ping, no B-13c)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --rpc) RPC="${2:?}"; PLAN_ONLY=0; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "b40-d0-preflight: plan"
  echo "  steps=treasury-telemetry-watch,assert-b28-treasury-thresholds,d0-checklist"
  echo "  pre_enable=true"
  echo "  no_b13c_enable=true"
  echo "  docs=docs/B40_PERMANENCE_WEEK.md"
  echo "  command=$(basename "$0") --rpc http://5.161.201.73:8787/rpc"
  echo "b40-d0-preflight: PASS plan-only"
  exit 0
fi

echo "b40-d0-preflight: live rpc=$RPC"
bash "$SCRIPT_DIR/treasury-telemetry-watch.sh" --rpc "$RPC"
bash "$SCRIPT_DIR/assert-b28-treasury-thresholds.sh" --rpc "$RPC"
echo "b40-d0-preflight: checklist"
echo "  [ ] Claim B-40 in AGENTS.md section 5 (lane 6 Doing); claim base = L4 tip SHA"
echo "  [ ] Archive evidence/b40-d0-treasury-<UTC>.md from telemetry output"
echo "  [ ] Confirm B-13a sims still in tip ancestry (256+512)"
echo "  [ ] Ping lane 4+7: B-32 arm status (>=2 distinct hosts)"
echo "  [ ] Confirm B-33 human cells open - do NOT enable B-13c on D0"
echo "b40-d0-preflight: PASS"