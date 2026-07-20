#!/usr/bin/env bash
# B-89 / lane 7: copy Path A checkpoint log from VPS when remote tip > local tip.
# B-15-safe: never touches faucet/mfnd. Does not commit (agent commits).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
LOG_PATH="${MFN_CHECKPOINT_LOG:-$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
VPS_HOST="${MFN_VPS_HOST:-root@5.161.201.73}"
VPS_LOG="${MFN_VPS_CHECKPOINT_LOG:-/root/permawrite/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: land-path-a-checkpoint-from-vps.sh [--plan-only|--apply]

If VPS jsonl max tip_height > local, scp the remote log over local.
Never commits. Never restarts faucet/mfnd.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "land-path-a-checkpoint-from-vps: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "land-path-a-checkpoint-from-vps: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "land-path-a-checkpoint-from-vps: plan"
  echo "  unit=B-89"
  echo "  flow=compare tip_height -> scp VPS jsonl if remote ahead"
  echo "  never=faucet-http mfnd restart git-commit"
  echo "land-path-a-checkpoint-from-vps: PASS plan-only"
  exit 0
fi

max_tip() {
  python3 - "$1" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
if not p.is_file():
    print(0); raise SystemExit
mx=0
for line in p.read_text(encoding="utf-8").splitlines():
    if not line.strip(): continue
    h=int((json.loads(line).get("summary") or {}).get("tip_height") or 0)
    if h>mx: mx=h
print(mx)
PY
}

local_tip="$(max_tip "$LOG_PATH")"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
scp -o BatchMode=yes -o ConnectTimeout=15 "$VPS_HOST:$VPS_LOG" "$tmp"
remote_tip="$(max_tip "$tmp")"
echo "land-path-a-checkpoint-from-vps: local_tip=$local_tip remote_tip=$remote_tip"
if (( remote_tip <= local_tip )); then
  echo "land-path-a-checkpoint-from-vps: SKIP remote not ahead"
  exit 0
fi
cp "$tmp" "$LOG_PATH"
echo "land-path-a-checkpoint-from-vps: OK updated $LOG_PATH to tip=$remote_tip (commit when ready)"