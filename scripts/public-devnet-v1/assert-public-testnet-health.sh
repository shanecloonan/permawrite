#!/usr/bin/env bash
# B-91 / lane 7: composite public-testnet health (Path A timer + proxy tip-align + faucet + ckpt lag).
# B-15-safe: never restarts faucet/mfnd/proxy. Run on VPS with --apply.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
LOG_PATH="${MFN_CHECKPOINT_LOG:-$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
PROXY_HEALTH="${MFN_PROXY_HEALTH:-http://127.0.0.1:8787/health}"
FAUCET_HEALTH="${MFN_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"
HUB_RPC="${MFN_ROLL_RPC:-127.0.0.1:18731}"
LAG_THRESHOLD="${MFN_CKPT_LAG_THRESHOLD:-16}"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: assert-public-testnet-health.sh [--plan-only|--apply]

Checks (apply, on VPS):
  - path-a-near-tip-ckpt.timer healthy (B-89)
  - observer-rpc-proxy /health ok + hub_tip_rpc set (B-90)
  - faucet /health ok (busy allowed during B-15)
  - tip - ckpt_max < MFN_CKPT_LAG_THRESHOLD (default 16)
Never restarts units.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-public-testnet-health: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "assert-public-testnet-health: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "assert-public-testnet-health: plan"
  echo "  unit=B-91"
  echo "  checks=timer proxy-tip-align faucet tip-ckpt-lag"
  echo "  never=faucet-http mfnd restart observer-rpc-proxy join-testnet-rehearsal"
  echo "assert-public-testnet-health: PASS plan-only"
  exit 0
fi

fail=0
bash "$SCRIPT_DIR/assert-path-a-near-tip-timer.sh" --apply || fail=1

proxy_json="$(curl -fsS --max-time 8 "$PROXY_HEALTH" || true)"
if [[ -z "$proxy_json" ]]; then
  echo "assert-public-testnet-health: FAIL proxy health unreachable $PROXY_HEALTH" >&2
  fail=1
else
  python3 - "$proxy_json" <<'PY' || fail=1
import json,sys
d=json.loads(sys.argv[1])
ok=d.get("ok") is True
hub=d.get("hub_tip_rpc")
if not ok:
    print("assert-public-testnet-health: FAIL proxy ok!=true", file=sys.stderr); sys.exit(1)
if not hub:
    print("assert-public-testnet-health: FAIL proxy hub_tip_rpc unset (B-90 not deployed?)", file=sys.stderr); sys.exit(1)
print(f"assert-public-testnet-health: proxy ok hub_tip_rpc={hub} tip_align_ms={d.get('tip_align_ms')} waits={d.get('tip_align_waits')} timeouts={d.get('tip_align_timeouts')}")
PY
fi

faucet_json="$(curl -fsS --max-time 8 "$FAUCET_HEALTH" || true)"
if [[ -z "$faucet_json" ]]; then
  echo "assert-public-testnet-health: FAIL faucet health unreachable $FAUCET_HEALTH" >&2
  fail=1
else
  python3 - "$faucet_json" <<'PY' || fail=1
import json,sys
d=json.loads(sys.argv[1])
if d.get("ok") is not True:
    print("assert-public-testnet-health: FAIL faucet ok!=true", file=sys.stderr); sys.exit(1)
busy=d.get("busy"); pending=d.get("pending_jobs")
print(f"assert-public-testnet-health: faucet ok busy={busy} pending_jobs={pending}")
PY
fi

tip_h="$(
  python3 - "$HUB_RPC" <<'PY'
import json,socket,sys
rpc=sys.argv[1]; host,port=rpc.rsplit(":",1)
s=socket.create_connection((host,int(port)),12)
s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}}\n')
buf=b""
while b"\n" not in buf and len(buf)<2_000_000:
    c=s.recv(65536)
    if not c: break
    buf+=c
print(json.loads(buf)["result"]["tip_height"])
PY
)"
ckpt_max="$(
  python3 - "$LOG_PATH" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
mx=0
if p.is_file():
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        h=int((json.loads(line).get("summary") or {}).get("tip_height") or 0)
        if h>mx: mx=h
print(mx)
PY
)"
lag=$((tip_h - ckpt_max))
echo "assert-public-testnet-health: tip=$tip_h ckpt_max=$ckpt_max lag=$lag threshold=$LAG_THRESHOLD"
if (( lag >= LAG_THRESHOLD )); then
  echo "assert-public-testnet-health: FAIL tip lag >= threshold (run publish-near-tip-checkpoint-if-lag --apply then land jsonl)" >&2
  fail=1
fi

if (( fail )); then
  exit 1
fi
echo "assert-public-testnet-health: OK"