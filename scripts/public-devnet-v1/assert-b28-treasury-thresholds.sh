#!/usr/bin/env bash
# Lane 6 / B-28: assert draft treasury thresholds (OPERATORS). Pre-enable Path A.
# Plan-only by default; --rpc HOST:PORT|http(s)://… runs live checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPC=""
PLAN_ONLY=1
JSON=0

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only] [--json] [--rpc HOST:PORT|http(s)://…]

Asserts draft B-28 floors from OPERATORS (pre-enable):
  subsidy_to_treasury_bps == 0
  fee_to_treasury_bps == 9000
  treasury_base_units >= 1000000
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --json) JSON=1; shift ;;
    --rpc) RPC="${2:?}"; PLAN_ONLY=0; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "assert-b28-treasury-thresholds: plan"
  echo "  checks=subsidy_bps==0,fee_bps==9000,treasury>=1000000"
  echo "  helper=treasury-telemetry-watch"
  echo "  pre_enable=true"
  echo "  command=$(basename "$0") --rpc http://127.0.0.1:8787/rpc"
  if [[ "$JSON" -eq 1 ]]; then
    python3 - <<'PY'
import json
print(json.dumps({
    "schema_version": "assert-b28-treasury-thresholds.v1",
    "mode": "plan-only",
    "pre_enable": True,
    "checks": ["subsidy_bps==0", "fee_bps==9000", "treasury>=1000000"],
}, indent=2))
PY
  fi
  echo "assert-b28-treasury-thresholds: PASS plan-only"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  echo "assert-b28-treasury-thresholds: --rpc required unless --plan-only" >&2
  exit 1
fi

report="$(bash "$SCRIPT_DIR/treasury-telemetry-watch.sh" --rpc "$RPC" --json)"
export REPORT="$report"
python3 - <<'PY'
import json, os, sys
d = json.loads(os.environ["REPORT"])
subsidy = d.get("subsidy_to_treasury_bps")
fee = d.get("fee_to_treasury_bps")
treasury = int(d.get("treasury_base_units") or 0)
tip = d.get("tip_height")
fails = []
if subsidy != 0:
    fails.append(f"subsidy_bps={subsidy} want 0 (pre-enable)")
if fee != 9000:
    fails.append(f"fee_bps={fee} want 9000")
if treasury < 1_000_000:
    fails.append(f"treasury={treasury} below floor 1000000")
print(
    f"assert-b28-treasury-thresholds: tip={tip} treasury={treasury} "
    f"fee_bps={fee} subsidy_bps={subsidy}"
)
if fails:
    for f in fails:
        print(f"assert-b28-treasury-thresholds: FAIL {f}", file=sys.stderr)
    sys.exit(1)
print("assert-b28-treasury-thresholds: PASS")
PY