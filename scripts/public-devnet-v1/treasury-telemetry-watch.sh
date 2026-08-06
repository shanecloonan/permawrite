#!/usr/bin/env bash
# Lane 6 / F6: read-only treasury telemetry for fee-drought revisit triggers (FEES.md §5).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"

RPC=""
PLAN_ONLY=0
JSON=0

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only] [--json] [--rpc HOST:PORT|http(s)://HOST:PORT/path]

Reads get_chain_params.treasury_base_units + tip_height when --rpc is set.
Accepts NDJSON HOST:PORT (mfnd) or HTTP(S) JSON-RPC URLs (observer proxy).
Default --plan-only prints FEES.md revisit triggers without a live node.
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

FEES_DOC="$REPO_ROOT/docs/FEES.md"
if [[ ! -f "$FEES_DOC" ]]; then
  echo "treasury-telemetry-watch: missing $FEES_DOC" >&2
  exit 1
fi

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "treasury-telemetry-watch: plan"
  echo "  rpc_method=get_chain_params"
  echo "  fields=treasury_base_units,tip_height,emission.fee_to_treasury_bps,emission.subsidy_to_treasury_bps"
  echo "  triggers=docs/FEES.md §5.4 revisit (treasury pinned near zero + backstop majority blocks)"
  echo "  command=$(basename "$0") --rpc 127.0.0.1:18731"
  echo "  http_example=$(basename "$0") --rpc http://127.0.0.1:8787/rpc"
  if [[ "$JSON" -eq 1 ]]; then
    python3 - <<'PY'
import json
print(json.dumps({
    "schema_version": "treasury-telemetry-watch.v1",
    "mode": "plan-only",
    "rpc_method": "get_chain_params",
    "revisit_doc": "docs/FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury",
}, indent=2))
PY
  fi
  echo "treasury-telemetry-watch: PASS plan-only"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  echo "treasury-telemetry-watch: --rpc required unless --plan-only" >&2
  exit 1
fi

req='{"jsonrpc":"2.0","method":"get_chain_params","id":1}'
line=""
if [[ "$RPC" == http://* || "$RPC" == https://* ]]; then
  if command -v curl >/dev/null 2>&1; then
    line="$(curl -sS -m 60 -H "Content-Type: application/json" -d "$req" "$RPC" 2>/dev/null || true)"
  elif command -v python3 >/dev/null 2>&1; then
    line="$(RPC_URL="$RPC" REQ_JSON="$req" python3 - <<'PY'
import json, os, urllib.request
req = urllib.request.Request(
    os.environ["RPC_URL"],
    data=os.environ["REQ_JSON"].encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=60) as resp:
    print(resp.read().decode())
PY
)" || true
  else
    echo "treasury-telemetry-watch: HTTP --rpc needs curl or python3" >&2
    exit 1
  fi
else
  line="$(query_rpc_json_line "$RPC" "$req")"
fi
if [[ -z "$line" ]]; then
  echo "treasury-telemetry-watch: RPC query failed for $RPC" >&2
  exit 1
fi

export LINE="$line"
export RPC_ADDR="$RPC"
report="$(python3 - <<'PY'
import json, os
raw = json.loads(os.environ["LINE"])
result = raw.get("result", raw)
treasury = result.get("treasury_base_units", "")
tip = result.get("tip_height", result.get("height", ""))
emission = result.get("emission") or {}
bps = emission.get("fee_to_treasury_bps", "")
subsidy_bps = emission.get("subsidy_to_treasury_bps", "")
print(json.dumps({
    "schema_version": "treasury-telemetry-watch.v1",
    "mode": "live",
    "rpc": os.environ["RPC_ADDR"],
    "treasury_base_units": str(treasury),
    "tip_height": tip,
    "fee_to_treasury_bps": bps,
    "subsidy_to_treasury_bps": subsidy_bps,
    "revisit_doc": "docs/FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury",
}, indent=2))
PY
)"

if [[ "$JSON" -eq 1 ]]; then
  echo "$report"
else
  treasury="$(python3 -c "import json,sys; print(json.load(sys.stdin)['treasury_base_units'])" <<<"$report")"
  tip="$(python3 -c "import json,sys; print(json.load(sys.stdin)['tip_height'])" <<<"$report")"
  bps="$(python3 -c "import json,sys; print(json.load(sys.stdin)['fee_to_treasury_bps'])" <<<"$report")"
  subsidy_bps="$(python3 -c "import json,sys; print(json.load(sys.stdin)['subsidy_to_treasury_bps'])" <<<"$report")"
  echo "treasury-telemetry-watch: rpc=$RPC treasury_base_units=$treasury tip_height=$tip fee_to_treasury_bps=$bps subsidy_to_treasury_bps=$subsidy_bps"
  echo "treasury-telemetry-watch: revisit triggers in docs/FEES.md §5.4"
fi
