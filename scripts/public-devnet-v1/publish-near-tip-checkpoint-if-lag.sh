#!/usr/bin/env bash
# B-85 / lane 7: republish Path A near-tip checkpoint when tip lags the log max.
# Safe during B-15: never touches faucet/mfnd. Requires ~/.mfn/checkpoint-signer.env.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
LOG_PATH="${MFN_CHECKPOINT_LOG:-$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
RPC="${MFN_ROLL_RPC:-127.0.0.1:18731}"
# Publish when live tip is at least this many blocks ahead of log max tip.
LAG_THRESHOLD="${MFN_CKPT_LAG_THRESHOLD:-16}"
SEED_ENV="${MFN_CHECKPOINT_SIGNER_ENV:-$HOME/.mfn/checkpoint-signer.env}"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: publish-near-tip-checkpoint-if-lag.sh [--plan-only|--apply]

If live tip - checkpoint_log_max_tip >= MFN_CKPT_LAG_THRESHOLD (default 16),
runs bootstrap-path-a-checkpoint-signer.sh --apply.
Never restarts faucet/mfnd. Exit 0 on publish or lag-below-threshold skip.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "publish-near-tip-checkpoint-if-lag: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "publish-near-tip-checkpoint-if-lag: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "publish-near-tip-checkpoint-if-lag: plan"
  echo "  unit=B-85"
  echo "  lag_threshold=\$MFN_CKPT_LAG_THRESHOLD (default 16)"
  echo "  flow=tip vs jsonl max -> bootstrap-path-a-checkpoint-signer --apply"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "publish-near-tip-checkpoint-if-lag: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"

tip_h="$(
  python3 - "$RPC" <<'PY'
import json, socket, sys
rpc = sys.argv[1]
host, port = rpc.rsplit(":", 1)
s = socket.create_connection((host, int(port)), 12)
s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}}\n')
buf = b""
while b"\n" not in buf and len(buf) < 2_000_000:
    c = s.recv(65536)
    if not c:
        break
    buf += c
print(json.loads(buf)["result"]["tip_height"])
PY
)"

ckpt_max="$(
  python3 - "$LOG_PATH" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print(0)
    raise SystemExit
mx = 0
for line in p.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
        continue
    d = json.loads(line)
    h = int((d.get("summary") or {}).get("tip_height") or 0)
    if h > mx:
        mx = h
print(mx)
PY
)"

lag=$((tip_h - ckpt_max))
echo "publish-near-tip-checkpoint-if-lag: tip=$tip_h ckpt_max=$ckpt_max lag=$lag threshold=$LAG_THRESHOLD"

if (( lag < LAG_THRESHOLD )); then
  echo "publish-near-tip-checkpoint-if-lag: SKIP lag below threshold"
  exit 0
fi

if [[ ! -f "$SEED_ENV" ]]; then
  echo "publish-near-tip-checkpoint-if-lag: FAIL missing $SEED_ENV (run bootstrap-path-a-checkpoint-signer once)" >&2
  exit 1
fi

echo "publish-near-tip-checkpoint-if-lag: publishing via bootstrap-path-a-checkpoint-signer"
bash "$SCRIPT_DIR/bootstrap-path-a-checkpoint-signer.sh" --apply --rpc "$RPC"
echo "publish-near-tip-checkpoint-if-lag: OK tip=$tip_h (commit $LOG_PATH only)"