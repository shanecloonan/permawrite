#!/usr/bin/env bash
# B-50: pin a wallet to the signed checkpoint tip via get_light_snapshot, then light-scan.
# Honesty: `wallet light-scan --checkpoint-log` only *cross-checks after sync* — it does NOT
# skip genesis→tip. Fresh wallets still walk every header (~0.5s/block at tip 4k+).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-python3.sh
source "$SCRIPT_DIR/lib-python3.sh"
mfn_require_python3
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
RPC="${MFN_BOOTSTRAP_RPC:-127.0.0.1:18731}"
WALLET=""
LOG="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
MCLI="${MCLI:-$(mfn_resolve_release_bin "$REPO_ROOT/target/release/mfn-cli")}"

usage() {
  cat <<'EOF'
usage: bootstrap-wallet-from-checkpoint-log.sh [--plan-only|--apply] --wallet PATH [--rpc HOST:PORT] [--log PATH]

Pins scan_height + light_checkpoint_hex from get_light_snapshot(log_max_tip), then
runs light-scan --checkpoint-log for the remaining tip delta + F12 cross-check.

Requires a synced node RPC (hub or local observer). Retries snapshot on EAGAIN.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --wallet) WALLET="${2:?}"; shift 2 ;;
    --rpc) RPC="${2:?}"; shift 2 ;;
    --log) LOG="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "bootstrap-wallet-from-checkpoint-log: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "bootstrap-wallet-from-checkpoint-log: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "bootstrap-wallet-from-checkpoint-log: plan"
  echo "  unit=B-50/B-54/B-59"
  echo "  flow=log max tip -> get_light_snapshot(height) -> patch wallet -> light-scan --checkpoint-log"
  echo "  honesty=checkpoint-log alone does not bootstrap; see JOIN_TESTNET.md"
  echo "  f45=soft-pass via light-scan-checkpoint-soft.sh when tip races past log max
  f67=pin BEFORE faucet fund — pin skips heights <= scan_height"
  echo "  conflict=heavy snapshot may EAGAIN under faucet keepalive — retry"
  echo "bootstrap-wallet-from-checkpoint-log: PASS plan-only"
  exit 0
fi

if [[ -z "$WALLET" ]]; then
  echo "bootstrap-wallet-from-checkpoint-log: --wallet required" >&2
  exit 1
fi
if [[ ! -x "$MCLI" ]]; then
  if command -v mfn-cli >/dev/null 2>&1; then MCLI="$(command -v mfn-cli)"; else
    echo "bootstrap-wallet-from-checkpoint-log: mfn-cli missing" >&2; exit 1
  fi
fi
if [[ ! -f "$LOG" ]]; then
  echo "bootstrap-wallet-from-checkpoint-log: log missing: $LOG" >&2
  exit 1
fi
if [[ ! -f "$WALLET" ]]; then
  echo "bootstrap-wallet-from-checkpoint-log: wallet missing: $WALLET" >&2
  exit 1
fi

MAX_TIP="$(python3 - "$LOG" <<'PY'
import json, sys
from pathlib import Path
tips = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if line.strip():
        tips.append(int(json.loads(line)["summary"]["tip_height"]))
print(max(tips))
PY
)"
echo "bootstrap-wallet-from-checkpoint-log: log_max_tip=$MAX_TIP rpc=$RPC"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/mfn-ckpt-boot.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
SNAP_ERR="$TMP/snap.err"
SNAP_OUT="$TMP/snap.json"

ok=0
for i in 1 2 3 4 5 6 7 8; do
  if "$MCLI" --rpc "$RPC" call get_light_snapshot --params "{\"height\":$MAX_TIP}" >"$SNAP_OUT" 2>"$SNAP_ERR"; then
    ok=1
    echo "bootstrap-wallet-from-checkpoint-log: snapshot_ok attempt=$i"
    break
  fi
  echo "bootstrap-wallet-from-checkpoint-log: snapshot_retry=$i $(head -c 160 "$SNAP_ERR" | tr '\n' ' ')"
  sleep $((i + 1))
done
if (( ok == 0 )); then
  echo "bootstrap-wallet-from-checkpoint-log: get_light_snapshot failed (hub EAGAIN under load?). Retry when tip is quiet." >&2
  exit 2
fi

python3 - "$WALLET" "$SNAP_OUT" "$MAX_TIP" <<'PY'
import json, sys
from pathlib import Path
wallet_path, snap_path, expect = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
snap = json.loads(snap_path.read_text(encoding="utf-8"))
r = snap.get("result", snap)
if not isinstance(r, dict) or "checkpoint_hex" not in r:
    raise SystemExit(f"unexpected snapshot payload: {str(snap)[:300]}")
tip = int(r["tip_height"])
if tip != expect:
    raise SystemExit(f"snapshot tip {tip} != log max {expect}")
w = json.loads(wallet_path.read_text(encoding="utf-8"))
w["scan_height"] = tip
w["light_checkpoint_hex"] = r["checkpoint_hex"]
if r.get("summary"):
    w["trusted_light_summary"] = r["summary"]
wallet_path.write_text(json.dumps(w, indent=2) + "\n", encoding="utf-8")
print(f"bootstrap-wallet-from-checkpoint-log: pinned scan_height={tip}")
PY

bash "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" --rpc "$RPC" --wallet "$WALLET" --log "$LOG"
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet status --json
echo "bootstrap-wallet-from-checkpoint-log: OK"
