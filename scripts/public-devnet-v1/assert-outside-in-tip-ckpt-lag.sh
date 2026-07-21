#!/usr/bin/env bash
# B-127 / B-129 / B-134 / B-135 / lane 1: outside-in tip vs Path A checkpoint lag (public proxy + local jsonl).
# B-15-safe: never restarts faucet/mfnd/proxy; never runs JOIN. Does not publish Path A (lane 7).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
LOG_PATH="${MFN_CHECKPOINT_LOG:-$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
PROXY_URL="${MFN_OUTSIDE_IN_PROXY_URL:-http://5.161.201.73:8787/rpc}"
EXPECTED_GENESIS="${MFN_EXPECTED_GENESIS_ID:-454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005}"
LAG_THRESHOLD="${MFN_CKPT_LAG_THRESHOLD:-16}"
EVIDENCE_DIR="${MFN_OUTSIDE_IN_LAG_EVIDENCE_DIR:-$SCRIPT_DIR/evidence}"
PROXY_HEALTH_URL="${MFN_OUTSIDE_IN_PROXY_HEALTH_URL:-${PROXY_URL%/rpc}/health}"
FAUCET_HEALTH_URL="${MFN_OUTSIDE_IN_FAUCET_HEALTH_URL:-http://5.161.201.73:8788/health}"
NO_ARCHIVE=0
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: assert-outside-in-tip-ckpt-lag.sh [--plan-only|--apply] [--no-archive]

Outside-in permanence lag probe:
  - get_tip via public observer proxy
  - max tip_height from local Path A checkpoint jsonl
  - FAIL if tip - ckpt_max >= MFN_CKPT_LAG_THRESHOLD (default 16)
  - B-134: report ckpt_entries + last published_at + last tip_block_id (staleness)
  - B-135: age_sec from published_at + remote public proxy/faucet /health pings
Never publishes checkpoints (lane 7 Path A). Never restarts services.
B-129: --apply archives evidence under evidence/ (disable with --no-archive).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --no-archive) NO_ARCHIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-outside-in-tip-ckpt-lag: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "assert-outside-in-tip-ckpt-lag: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "assert-outside-in-tip-ckpt-lag: plan"
  echo "  unit=B-127+B-129+B-134+B-135"
  echo "  proxy=$PROXY_URL"
  echo "  checkpoint_log=$LOG_PATH"
  echo "  lag_threshold=$LAG_THRESHOLD"
  echo "  staleness=ckpt_entries,published_at,tip_block_id,age_sec"
  echo "  remote_health=proxy+faucet"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal path-a-publish"
  echo "assert-outside-in-tip-ckpt-lag: PASS plan-only"
  exit 0
fi

if [[ ! -f "$LOG_PATH" ]]; then
  echo "assert-outside-in-tip-ckpt-lag: missing checkpoint log $LOG_PATH" >&2
  exit 1
fi

tip_json="$(curl -fsS --max-time 30 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}' "$PROXY_URL")"

eval "$(
  python3 - "$tip_json" "$EXPECTED_GENESIS" <<'PY'
import json,sys
d=json.loads(sys.argv[1])["result"]
exp=sys.argv[2]
g=d.get("genesis_id") or ""
if g != exp:
    print(f'echo "assert-outside-in-tip-ckpt-lag: FAIL genesis_id mismatch got={g}" >&2; exit 1')
    sys.exit(0)
print(f'tip_h={int(d["tip_height"])}')
print(f'tip_id={d.get("tip_id","")}')
PY
)"

eval "$(
  python3 - "$LOG_PATH" <<'PY'
import json,sys,time
from pathlib import Path
p=Path(sys.argv[1])
mx=0
entries=0
last_pub=""
last_tip_block=""
for line in p.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    o=json.loads(line)
    entries+=1
    s=o.get("summary") or {}
    h=int(s.get("tip_height") or 0)
    if h>=mx:
        mx=h
        last_pub=str(o.get("published_at") or "")
        last_tip_block=str(s.get("tip_block_id") or "")
age_sec=-1
raw=last_pub.rstrip("Zz")
if raw.isdigit():
    age_sec=max(0, int(time.time())-int(raw))
print(f"ckpt_max={mx}")
print(f"ckpt_entries={entries}")
print(f"ckpt_published_at={last_pub}")
print(f"ckpt_tip_block_id={last_tip_block}")
print(f"ckpt_age_sec={age_sec}")
PY
)"

lag=$((tip_h - ckpt_max))
line="assert-outside-in-tip-ckpt-lag: tip=$tip_h ckpt_max=$ckpt_max lag=$lag threshold=$LAG_THRESHOLD tip_id=$tip_id"
staleness="assert-outside-in-tip-ckpt-lag: STALENESS ckpt_entries=$ckpt_entries published_at=$ckpt_published_at tip_block_id=$ckpt_tip_block_id age_sec=$ckpt_age_sec"
echo "$line"
echo "$staleness"

# B-135: remote public health (informational; lag still owns FAIL)
proxy_health_status="unknown"
faucet_health_status="unknown"
if proxy_body="$(curl -fsS --max-time 15 "$PROXY_HEALTH_URL" 2>/dev/null)"; then
  if [[ "$proxy_body" == *'"ok":true'* ]] || [[ "$proxy_body" == *'"ok": true'* ]]; then
    proxy_health_status=ok
  else
    proxy_health_status=bad_body
  fi
else
  proxy_health_status=unreachable
fi
if faucet_body="$(curl -fsS --max-time 15 "$FAUCET_HEALTH_URL" 2>/dev/null)"; then
  if [[ "$faucet_body" == *'"ok":true'* ]] || [[ "$faucet_body" == *'"ok": true'* ]]; then
    faucet_health_status=ok
  else
    faucet_health_status=bad_body
  fi
else
  faucet_health_status=unreachable
fi
health="assert-outside-in-tip-ckpt-lag: HEALTH proxy=$proxy_health_status faucet=$faucet_health_status proxy_url=$PROXY_HEALTH_URL faucet_url=$FAUCET_HEALTH_URL"
echo "$health"
status=OK
reason=ok
if (( lag >= LAG_THRESHOLD )); then
  status=FAIL
  reason="tip_lag>=threshold"
fi

if (( NO_ARCHIVE == 0 )); then
  mkdir -p "$EVIDENCE_DIR"
  head_sha="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  out="$EVIDENCE_DIR/outside-in-tip-ckpt-lag-${stamp}.txt"
  {
    echo "# B-127 outside-in tip-ckpt lag probe (public observer proxy)"
    echo "# B-129 auto-archive"
    echo "# B-134 Path A staleness"
    echo "# B-135 age_sec + remote public health"
    echo "# head_sha=$head_sha"
    echo "# proxy=$PROXY_URL"
    echo "# checkpoint_log=$LOG_PATH"
    echo "# lag_threshold=$LAG_THRESHOLD"
    echo "# never=faucet-http mfnd restart join-testnet-rehearsal path-a-publish"
    echo "$line"
    echo "$staleness"
    echo "$health"
    if [[ "$status" == FAIL ]]; then
      echo "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold (lane7: publish-near-tip-checkpoint-if-lag --apply then land jsonl)"
    else
      echo "assert-outside-in-tip-ckpt-lag: OK tip=$tip_h ckpt_max=$ckpt_max lag=$lag"
    fi
    echo "assert-outside-in-tip-ckpt-lag: SUMMARY status=$status tip=$tip_h ckpt_max=$ckpt_max lag=$lag ckpt_entries=$ckpt_entries published_at=$ckpt_published_at age_sec=$ckpt_age_sec proxy_health=$proxy_health_status faucet_health=$faucet_health_status reason=$reason"
  } >"$out"
  echo "assert-outside-in-tip-ckpt-lag: EVIDENCE archived=$out status=$status"
fi

if [[ "$status" == FAIL ]]; then
  echo "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold (lane7: publish-near-tip-checkpoint-if-lag --apply then land jsonl)" >&2
  exit 1
fi
echo "assert-outside-in-tip-ckpt-lag: OK tip=$tip_h ckpt_max=$ckpt_max lag=$lag"
