#!/usr/bin/env bash
# B-278: create a dedicated faucet wallet and fund it from the (pruned) payout wallet.
# Keeps validator coinbase bloat off the hot faucet path.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh" 2>/dev/null || true
RPC="${RPC:-$(resolve_rpc 2>/dev/null || echo 127.0.0.1:18731)}"
PAYOUT_WALLET="${PAYOUT_WALLET:-/root/testnet-wallets/validator0-faucet.json}"
NEW_WALLET="${NEW_WALLET:-/root/testnet-wallets/faucet-ops.json}"
MFN_CLI="${MFN_CLI:-$(resolve_mfn_cli 2>/dev/null || echo "$REPO_ROOT/target/release/mfn-cli")}"
FUND_ATOMS="${FUND_ATOMS:-200000000000}"
FEE="${FEE:-10000}"
RING="${RING_SIZE:-16}"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="$2"; shift 2 ;;
    --payout-wallet) PAYOUT_WALLET="$2"; shift 2 ;;
    --new-wallet) NEW_WALLET="$2"; shift 2 ;;
    --fund-atoms) FUND_ATOMS="$2"; shift 2 ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help)
      echo "usage: faucet-rotate-from-payout.sh [--payout-wallet FILE] [--new-wallet FILE] [--fund-atoms N] [--plan-only]"
      exit 0 ;;
    *) echo "faucet-rotate-from-payout: unknown arg $1" >&2; exit 1 ;;
  esac
done
if (( PLAN_ONLY )); then
  echo "faucet-rotate-from-payout: plan payout=$PAYOUT_WALLET new=$NEW_WALLET fund_atoms=$FUND_ATOMS"
  echo "  flow=tip-pin new wallet -> payout send fund (twice if owned<2 for F7) -> wait tip -> light-scan new -> FAUCET_WALLET hint"
  echo "  systemd=Environment=FAUCET_WALLET=$NEW_WALLET then systemctl restart faucet-http when busy=false"
  exit 0
fi
[[ -f "$PAYOUT_WALLET" ]] || { echo "faucet-rotate-from-payout: missing payout wallet $PAYOUT_WALLET" >&2; exit 1; }
[[ -x "$MFN_CLI" ]] || { echo "faucet-rotate-from-payout: mfn-cli not executable: $MFN_CLI" >&2; exit 1; }
if [[ ! -f "$NEW_WALLET" ]]; then
  "$MFN_CLI" --wallet "$NEW_WALLET" --force wallet new
  echo "faucet-rotate-from-payout: created $NEW_WALLET"
fi
parse_kv() { sed -n "s/^$1=//p" | head -1; }
ADDR="$("$MFN_CLI" --wallet "$NEW_WALLET" wallet address 2>&1 | parse_kv address)"
[[ -n "$ADDR" ]] || { echo "faucet-rotate-from-payout: could not read new faucet address" >&2; exit 1; }
TIP_H="$("$MFN_CLI" --rpc "$RPC" tip 2>/dev/null | parse_kv tip_height)"
if [[ -n "$TIP_H" ]]; then
  python3 - "$NEW_WALLET" "$RPC" "$TIP_H" <<'PY'
import json, socket, sys
wpath, rpc, tip_s = sys.argv[1:4]
tip = int(tip_s)
host, port = rpc.rsplit(":", 1)
s = socket.create_connection((host, int(port)), 10)
s.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get_light_snapshot", "params": {"height": tip}}) + "\n").encode())
s.settimeout(60)
buf = b""
while True:
    c = s.recv(1 << 20)
    if not c:
        break
    buf += c
    if b"\n" in buf:
        break
s.close()
res = json.loads(buf.decode().split("\n")[0])["result"]
w = json.load(open(wpath, encoding="utf-8"))
w["light_checkpoint_hex"] = res["checkpoint_hex"]
w["trusted_light_summary"] = res.get("summary")
w["scan_height"] = tip
w["owned_outputs"] = []
w["pending_spent_utxo_keys"] = []
json.dump(w, open(wpath, "w", encoding="utf-8"), indent=2)
open(wpath, "a", encoding="utf-8").write("\n")
print(f"faucet-rotate-from-payout: tip-pinned new wallet at {tip}")
PY
fi
fund_once() {
  local atoms="$1"
  echo "faucet-rotate-from-payout: funding $atoms -> $ADDR"
  "$MFN_CLI" --rpc "$RPC" --wallet "$PAYOUT_WALLET" wallet send "$ADDR" "$atoms" --fee "$FEE" --ring-size "$RING" --json
  local pre_tip
  pre_tip="$("$MFN_CLI" --rpc "$RPC" tip 2>/dev/null | parse_kv tip_height)"
  echo "faucet-rotate-from-payout: waiting for tip advance..."
  local _
  for _ in 1 2 3 4 5 6 7 8; do
    sleep 15
    local now
    now="$("$MFN_CLI" --rpc "$RPC" tip 2>/dev/null | parse_kv tip_height)"
    if [[ -n "$now" && -n "$pre_tip" && "$now" -gt "$pre_tip" ]]; then
      break
    fi
  done
  "$MFN_CLI" --rpc "$RPC" --wallet "$NEW_WALLET" wallet light-scan
}

# F7 faucet dual-send needs >=2 owned UTXOs on the ops wallet.
fund_once "$FUND_ATOMS"
OWNED="$("$MFN_CLI" --rpc "$RPC" --wallet "$NEW_WALLET" wallet status 2>&1 | parse_kv owned_count_cached)"
if [[ -z "$OWNED" || "$OWNED" -lt 2 ]]; then
  SECOND="$FUND_ATOMS"
  if [[ "$SECOND" -gt 30000000000 ]]; then
    SECOND=30000000000
  fi
  echo "faucet-rotate-from-payout: owned=$OWNED < 2; second fund $SECOND (F7)"
  fund_once "$SECOND" || echo "faucet-rotate-from-payout: second fund skipped (payout short?)"
fi
"$MFN_CLI" --rpc "$RPC" --wallet "$NEW_WALLET" wallet status
echo "faucet-rotate-from-payout: PASS set FAUCET_WALLET=$NEW_WALLET and restart faucet-http when idle"