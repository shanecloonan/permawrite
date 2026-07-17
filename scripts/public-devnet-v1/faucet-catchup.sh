#!/usr/bin/env bash
# Background light-scan for the operator faucet wallet (keeps HTTP faucet send fast).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
RPC="${RPC:-$(resolve_rpc 2>/dev/null || echo 127.0.0.1:18731)}"
FAUCET_WALLET="${FAUCET_WALLET:-/root/testnet-wallets/validator0-faucet.json}"
MFN_CLI="${MFN_CLI:-$(resolve_mfn_cli 2>/dev/null || echo "$REPO_ROOT/target/release/mfn-cli")}"
LOG="${LOG:-/var/log/faucet-catchup.log}"
if pgrep -f "wallet light-scan.*$(basename "$FAUCET_WALLET")" >/dev/null 2>&1; then
  echo "faucet-catchup: already running for $(basename "$FAUCET_WALLET")"
  exit 0
fi
echo "faucet-catchup: starting at $(date -u +%Y-%m-%dT%H:%M:%SZ) rpc=$RPC wallet=$FAUCET_WALLET" | tee -a "$LOG"
nohup "$MFN_CLI" --rpc "$RPC" --wallet "$FAUCET_WALLET" wallet light-scan >>"$LOG" 2>&1 &
echo "faucet-catchup: pid=$! log=$LOG"
echo "faucet-catchup: tail -f $LOG"
