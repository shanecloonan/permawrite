#!/usr/bin/env bash
# B-50: pin a wallet to the signed checkpoint tip via get_light_snapshot, then light-scan.
# Honesty: B-50 follow-up — Rust light-scan --checkpoint-log auto-bootstraps from
# log max tip when the wallet lacks a light checkpoint. This helper remains the explicit
# pin/retry path (EAGAIN, Windows TCP snapshot, F67 pin-before-fund).
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

# B-145: tall-tip get_light_snapshot can exceed mfn-cli default 30s I/O timeout (~145s at tip~5290).
# Prefer a long-timeout NDJSON fetch (MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS, default 300).
SNAP_TIMEOUT_SECS="${MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS:-300}"
ok=0
for i in 1 2 3 4 5 6 7 8; do
  if python3 - "$RPC" "$MAX_TIP" "$SNAP_OUT" "$SNAP_TIMEOUT_SECS" <<'PY' 2>"$SNAP_ERR"
import json, socket, sys, time
from pathlib import Path

rpc, height_s, out_path, timeout_s = sys.argv[1], sys.argv[2], Path(sys.argv[3]), int(sys.argv[4])
host, port_s = rpc.rsplit(":", 1)
port = int(port_s)
height = int(height_s)
req = {"jsonrpc": "2.0", "id": 1, "method": "get_light_snapshot", "params": {"height": height}}
deadline = time.time() + timeout_s
s = socket.create_connection((host, port), timeout=min(30, timeout_s))
s.settimeout(min(60, timeout_s))
s.sendall((json.dumps(req) + "\n").encode())
buf = b""
while time.time() < deadline:
    remaining = max(1.0, deadline - time.time())
    s.settimeout(min(60.0, remaining))
    try:
        chunk = s.recv(1024 * 1024)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
    if buf.endswith(b"\n"):
        break
else:
    raise SystemExit(f"get_light_snapshot timed out after {timeout_s}s bytes={len(buf)}")
s.close()
if not buf.strip():
    raise SystemExit("empty get_light_snapshot response")
payload = json.loads(buf.decode().split("\n", 1)[0])
if "error" in payload:
    raise SystemExit(payload["error"])
out_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
print(f"snapshot_bytes={out_path.stat().st_size}")
PY
  then
    ok=1
    echo "bootstrap-wallet-from-checkpoint-log: snapshot_ok attempt=$i via=python timeout_secs=$SNAP_TIMEOUT_SECS"
    break
  fi
  echo "bootstrap-wallet-from-checkpoint-log: snapshot_retry=$i $(head -c 160 "$SNAP_ERR" | tr '\n' ' ')"
  sleep $((i + 1))
done
if (( ok == 0 )); then
  echo "bootstrap-wallet-from-checkpoint-log: get_light_snapshot failed (timeout/EAGAIN?). Raise MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS or retry when tip is quiet." >&2
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
