#!/usr/bin/env bash
# B-165: fail-closed gate for F45 soft twin + B-161 privacy JOIN needles.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" ]] || { echo "missing light-scan-checkpoint-soft.sh" >&2; exit 1; }
[[ -f "$SCRIPT_DIR/light-scan-checkpoint-soft.ps1" ]] || { echo "missing light-scan-checkpoint-soft.ps1 (B-164)" >&2; exit 1; }
grep -q "B-161" "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" || { echo "missing B-161 in soft.sh" >&2; exit 1; }
grep -q "B-161" "$SCRIPT_DIR/light-scan-checkpoint-soft.ps1" || { echo "missing B-161 in soft.ps1" >&2; exit 1; }
grep -q "f45-soft" "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" || { echo "missing f45-soft needle" >&2; exit 1; }
grep -q "MFN_HEAVY_RPC_TIMEOUT_MS" "$REPO_ROOT/mfn-cli/src/rpc.rs" || { echo "missing MFN_HEAVY_RPC_TIMEOUT_MS (B-161)" >&2; exit 1; }
grep -q "checkpoint_log_f45_soft_pass" "$REPO_ROOT/mfn-cli/src/light_wallet.rs" || { echo "missing f45 soft needle in light_wallet.rs" >&2; exit 1; }
grep -q "maybe_auto_bootstrap_from_checkpoint_log" "$REPO_ROOT/mfn-cli/src/light_wallet.rs" || { echo "missing B-50 auto-bootstrap" >&2; exit 1; }
plan="$(bash "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" --plan-only)"
[[ "$plan" == *"light-scan-checkpoint-soft: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
[[ "$plan" == *"B-161"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "light-scan-checkpoint-soft-rehearsal-smoke: PASS plan-only"