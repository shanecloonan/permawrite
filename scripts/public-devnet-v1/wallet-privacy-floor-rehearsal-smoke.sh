#!/usr/bin/env bash
# B-172: fail-closed gate for B-167 ring floor + B-168 F7 input floor needles.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

grep -q "WALLET_MIN_RING_SIZE: usize = 16" "$REPO_ROOT/mfn-wallet/src/lib.rs" || {
  echo "missing WALLET_MIN_RING_SIZE=16 in mfn-wallet lib.rs (B-167)" >&2
  exit 1
}
grep -q "WALLET_MIN_TX_INPUTS: usize = 2" "$REPO_ROOT/mfn-wallet/src/lib.rs" || {
  echo "missing WALLET_MIN_TX_INPUTS=2 in mfn-wallet lib.rs (B-168)" >&2
  exit 1
}
grep -q "RingSizeBelowMinimum" "$REPO_ROOT/mfn-wallet/src/error.rs" || {
  echo "missing RingSizeBelowMinimum (B-167)" >&2
  exit 1
}
grep -q "RingSizeBelowMinimum" "$REPO_ROOT/mfn-wallet/src/spend.rs" || {
  echo "missing RingSizeBelowMinimum use in spend.rs (B-167)" >&2
  exit 1
}
grep -q "wallet/consensus floor" "$REPO_ROOT/mfn-cli/src/cli/parse.rs" || {
  echo "missing CLI ring-floor usage text (B-167)" >&2
  exit 1
}
grep -q "WALLET_MIN_RING_SIZE" "$REPO_ROOT/mfn-wasm/src/transfer_core.rs" || {
  echo "missing WASM transfer ring floor (B-167)" >&2
  exit 1
}
grep -q "WALLET_MIN_TX_INPUTS" "$REPO_ROOT/mfn-wasm/src/transfer_core.rs" || {
  echo "missing WASM transfer F7 floor (B-168)" >&2
  exit 1
}
grep -q "WALLET_MIN_TX_INPUTS" "$REPO_ROOT/mfn-wasm/src/upload_core.rs" || {
  echo "missing WASM upload F7 floor (B-168)" >&2
  exit 1
}
grep -q "F7 privacy floor" "$REPO_ROOT/mfn-wasm/src/transfer_core.rs" || {
  echo "missing F7 privacy floor needle in transfer_core (B-168)" >&2
  exit 1
}
grep -q "DEFAULT_RING_SIZE: usize = WALLET_MIN_RING_SIZE" "$REPO_ROOT/mfn-cli/src/wallet_cmd.rs" || {
  echo "missing DEFAULT_RING_SIZE=WALLET_MIN_RING_SIZE (B-174)" >&2
  exit 1
}
grep -q "CLI-only" "$REPO_ROOT/docs/PRIVACY.md" || {
  echo "missing F45 CLI-only honesty in PRIVACY.md (B-168)" >&2
  exit 1
}
grep -q "Honesty (B-168)" "$REPO_ROOT/docs/CHECKPOINT_LOG.md" || {
  echo "missing B-168 honesty in CHECKPOINT_LOG.md" >&2
  exit 1
}
# B-177: WASM happy-path fixtures must not hardcode ring_size: 16
if grep -n "ring_size: 16," "$REPO_ROOT/mfn-wasm/src/transfer_core.rs" "$REPO_ROOT/mfn-wasm/src/upload_core.rs" >/dev/null 2>&1; then
  echo "WASM still hardcodes ring_size: 16 (B-177)" >&2
  exit 1
fi
# B-180: wallet upload fixtures must not hardcode ring_size: 16
if grep -n "ring_size: 16," "$REPO_ROOT/mfn-wallet/src/upload.rs" >/dev/null 2>&1; then
  echo "mfn-wallet upload.rs still hardcodes ring_size: 16 (B-180)" >&2
  exit 1
fi
grep -q "default 16, wallet/consensus floor" "$REPO_ROOT/mfn-cli/src/cli/parse.rs" || {
  echo "missing CLI usage wallet/consensus floor for ring-size (B-182)" >&2
  exit 1
}
if grep -n "consensus min" "$REPO_ROOT/mfn-cli/src/cli/parse.rs" >/dev/null 2>&1; then
  echo "CLI usage still says consensus min (B-182)" >&2
  exit 1
fi
grep -q "TxInputCountBelowMinimum" "$REPO_ROOT/mfn-wallet/src/error.rs" || {
  echo "missing TxInputCountBelowMinimum (B-185)" >&2
  exit 1
}
grep -q "TxInputCountBelowMinimum" "$REPO_ROOT/mfn-wallet/src/spend.rs" || {
  echo "missing TxInputCountBelowMinimum in spend.rs (B-185)" >&2
  exit 1
}
grep -q "TxInputCountBelowMinimum" "$REPO_ROOT/mfn-wallet/src/upload.rs" || {
  echo "missing TxInputCountBelowMinimum in upload.rs (B-185)" >&2
  exit 1
}
grep -q "TxInputCountBelowMinimum" "$REPO_ROOT/mfn-wallet/src/wallet.rs" || {
  echo "missing TxInputCountBelowMinimum in wallet.rs high-level select (B-186)" >&2
  exit 1
}
grep -q "select_inputs_for_tx_single_utxo_fails_closed" "$REPO_ROOT/mfn-wallet/src/wallet.rs" || {
  echo "missing B-186 single-UTXO fail-closed unit (B-186)" >&2
  exit 1
}
grep -q "require_f7_owned_input_floor" "$REPO_ROOT/mfn-cli/src/wallet_cmd.rs" || {
  echo "missing CLI F7 owned-UTXO preflight (B-189)" >&2
  exit 1
}
grep -q "require_f7_owned_input_floor_rejects_below_two" "$REPO_ROOT/mfn-cli/src/wallet_cmd.rs" || {
  echo "missing B-189 CLI F7 preflight unit (B-189)" >&2
  exit 1
}
grep -q "faucet dual-send" "$REPO_ROOT/mfn-wasm/src/transfer_core.rs" || {
  echo "missing WASM transfer F7 faucet dual-send message (B-197)" >&2
  exit 1
}
grep -q "faucet dual-send" "$REPO_ROOT/mfn-wasm/src/upload_core.rs" || {
  echo "missing WASM upload F7 faucet dual-send message (B-197)" >&2
  exit 1
}
grep -q "map_wallet_build_err" "$REPO_ROOT/mfn-cli/src/wallet_cmd.rs" || {
  echo "missing CLI map_wallet_build_err F7 rewrite (B-197)" >&2
  exit 1
}
grep -q "F7: need" "$REPO_ROOT/mfn-cli/src/cli/parse.rs" || {
  echo "missing CLI usage F7 owned-UTXO note (B-216)" >&2
  exit 1
}
grep -q "disabled - use wallet upload --message" "$REPO_ROOT/mfn-cli/src/cli/parse.rs" || {
  echo "missing CLI usage disabled wallet claim honesty (B-216)" >&2
  exit 1
}
grep -q "hard-refuses so operators cannot publish unbound" "$REPO_ROOT/mfn-cli/README.md" || {
  echo "missing CLI README disabled wallet claim honesty (B-216)" >&2
  exit 1
}
grep -q "faucet dual-send" "$REPO_ROOT/mfn-cli/README.md" || {
  echo "missing CLI README F7 faucet dual-send honesty (B-216)" >&2
  exit 1
}
echo "wallet-privacy-floor-rehearsal-smoke: PASS plan-only"
