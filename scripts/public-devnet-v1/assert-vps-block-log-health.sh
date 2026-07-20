#!/usr/bin/env bash
# B-53: detect F62-class tip vs durable block-log split-brain (get_block must work at tip).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
RPC="${MFN_ASSERT_RPC:-127.0.0.1:18734}"
MCLI="${MCLI:-$REPO_ROOT/target/release/mfn-cli}"
MIN_BLOCKS_BYTES="${MFN_ASSERT_MIN_BLOCKS_BYTES:-1000000}"
DATA_DIR="${MFN_ASSERT_DATA_DIR:-}"

usage() {
  cat <<'EOF'
usage: assert-vps-block-log-health.sh [--plan-only] [--rpc HOST:PORT] [--data-dir PATH]

Fails if get_tip/get_block disagree (F62: tip ahead of chain.blocks) or chain.blocks is tiny.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --rpc) RPC="${2:?}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:?}"; shift 2 ;;
    --min-blocks-bytes) MIN_BLOCKS_BYTES="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-vps-block-log-health: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "assert-vps-block-log-health: plan"
  echo "  unit=B-53"
  echo "  checks=get_tip + get_block(tip) + optional chain.blocks size"
  echo "  finding=F62 tip/block-log split-brain"
  echo "assert-vps-block-log-health: PASS plan-only"
  exit 0
fi

if [[ ! -x "$MCLI" ]]; then
  if command -v mfn-cli >/dev/null 2>&1; then MCLI="$(command -v mfn-cli)"; else
    echo "assert-vps-block-log-health: mfn-cli missing" >&2; exit 1
  fi
fi

TIP_JSON="$("$MCLI" --rpc "$RPC" call get_tip --params '{}')"
TIP_H="$(python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("result",d); print(int(r["tip_height"]))' <<<"$TIP_JSON")"
echo "assert-vps-block-log-health: rpc=$RPC tip_height=$TIP_H"

BLK_ERR="$(mktemp)"
if ! "$MCLI" --rpc "$RPC" call get_block --params "{\"height\":$TIP_H}" >"/tmp/mfn-assert-blk.json" 2>"$BLK_ERR"; then
  echo "assert-vps-block-log-health: FAIL get_block($TIP_H): $(head -c 240 "$BLK_ERR")" >&2
  rm -f "$BLK_ERR"
  exit 2
fi
rm -f "$BLK_ERR"
python3 - <<PY
import json
from pathlib import Path
r=json.loads(Path("/tmp/mfn-assert-blk.json").read_text()).get("result")
if r is None:
    r=json.loads(Path("/tmp/mfn-assert-blk.json").read_text())
h=int(r.get("height") or 0)
hx=r.get("block_hex") or ""
if h != $TIP_H or len(hx) < 32:
    raise SystemExit(f"bad get_block payload height={h} hexlen={len(hx)}")
print(f"assert-vps-block-log-health: get_block_ok height={h} hexlen={len(hx)}")
PY

if [[ -n "$DATA_DIR" ]]; then
  BLOCKS="$DATA_DIR/chain.blocks"
  if [[ ! -f "$BLOCKS" ]]; then
    echo "assert-vps-block-log-health: FAIL missing $BLOCKS" >&2
    exit 3
  fi
  SZ="$(wc -c <"$BLOCKS" | tr -d ' ')"
  echo "assert-vps-block-log-health: chain.blocks_bytes=$SZ min=$MIN_BLOCKS_BYTES"
  if (( SZ < MIN_BLOCKS_BYTES )); then
    echo "assert-vps-block-log-health: FAIL chain.blocks too small (F62 class)" >&2
    exit 4
  fi
fi

echo "assert-vps-block-log-health: PASS tip=$TIP_H"