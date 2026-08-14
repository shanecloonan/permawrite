#!/usr/bin/env bash
# B-278 / F122: prune operator faucet owned_outputs cache to the largest N UTXOs.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh" 2>/dev/null || true
RPC="${RPC:-$(resolve_rpc 2>/dev/null || echo 127.0.0.1:18731)}"
FAUCET_WALLET="${FAUCET_WALLET:-/root/testnet-wallets/validator0-faucet.json}"
MFN_CLI="${MFN_CLI:-$(resolve_mfn_cli 2>/dev/null || echo "$REPO_ROOT/target/release/mfn-cli")}"
KEEP="${KEEP:-32}"
CLEAR_PENDING=1
PLAN_ONLY=0
BACKUP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="$2"; shift 2 ;;
    --wallet|--faucet-wallet) FAUCET_WALLET="$2"; shift 2 ;;
    --keep) KEEP="$2"; shift 2 ;;
    --keep-pending) CLEAR_PENDING=0; shift ;;
    --backup) BACKUP="$2"; shift 2 ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help)
      echo "usage: faucet-wallet-prune.sh [--wallet FILE] [--keep N] [--backup FILE] [--keep-pending] [--plan-only]"
      exit 0 ;;
    *) echo "faucet-wallet-prune: unknown arg $1" >&2; exit 1 ;;
  esac
done
if (( PLAN_ONLY )); then
  echo "faucet-wallet-prune: plan wallet=$FAUCET_WALLET keep=$KEEP clear_pending=$CLEAR_PENDING"
  echo "  flow=backup -> keep largest N owned_outputs -> clear pending_spent (default) -> status"
  echo "  note=leaves scan_height/tip pin intact so light-scan does not re-add pruned rows"
  exit 0
fi
[[ -f "$FAUCET_WALLET" ]] || { echo "faucet-wallet-prune: missing wallet $FAUCET_WALLET" >&2; exit 1; }
[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "faucet-wallet-prune: --keep must be integer >= 2 (F7 floor)" >&2
  exit 1
}
if [[ -z "$BACKUP" ]]; then
  BACKUP="${FAUCET_WALLET}.bak-prePrune-$(date -u +%Y%m%dT%H%M%SZ)"
fi
python3 - "$FAUCET_WALLET" "$BACKUP" "$KEEP" "$CLEAR_PENDING" <<'PY'
import json, shutil, sys
src, backup, keep_s, clear_s = sys.argv[1:5]
keep = int(keep_s)
clear_pending = clear_s == "1"
shutil.copy2(src, backup)
with open(src, encoding="utf-8") as f:
    w = json.load(f)
owned = w.get("owned_outputs") or []
before = len(owned)
owned_sorted = sorted(owned, key=lambda o: int(o.get("value") or 0), reverse=True)
kept = owned_sorted[:keep]
dropped = before - len(kept)
w["owned_outputs"] = kept
pend_before = len(w.get("pending_spent_utxo_keys") or [])
if clear_pending:
    w["pending_spent_utxo_keys"] = []
with open(src, "w", encoding="utf-8") as f:
    json.dump(w, f, indent=2)
    f.write("\n")
bal = sum(int(o.get("value") or 0) for o in kept)
print(
    f"faucet-wallet-prune: backup={backup} owned {before}->{len(kept)} "
    f"(dropped={dropped}) balance_kept={bal} pending {pend_before}->{len(w.get('pending_spent_utxo_keys') or [])}"
)
PY
if [[ -x "$MFN_CLI" ]]; then
  "$MFN_CLI" --rpc "$RPC" --wallet "$FAUCET_WALLET" wallet status || true
fi
echo "faucet-wallet-prune: PASS keep=$KEEP wallet=$FAUCET_WALLET"