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
grep -q "CLI-only" "$REPO_ROOT/docs/PRIVACY.md" || {
  echo "missing F45 CLI-only honesty in PRIVACY.md (B-168)" >&2
  exit 1
}
grep -q "Honesty (B-168)" "$REPO_ROOT/docs/CHECKPOINT_LOG.md" || {
  echo "missing B-168 honesty in CHECKPOINT_LOG.md" >&2
  exit 1
}
echo "wallet-privacy-floor-rehearsal-smoke: PASS plan-only"