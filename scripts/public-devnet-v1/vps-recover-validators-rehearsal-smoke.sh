#!/usr/bin/env bash
# Plan gate for vps-recover-validators.sh. Does not touch a VPS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: vps-recover-validators-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "vps-recover-validators-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done

script="$SCRIPT_DIR/vps-recover-validators.sh"
needles=(
  vps-recover-validators
  53728
  git pull --ff-only origin main
  "cargo build -p mfn-node --release --bin mfnd"
  "cargo build -p mfn-cli --release --bin mfn-cli"
  scrub-vps-peers-json
  mfnd-v1.service
  mfnd-v2.service
  mfnd-hub.service
  mfnd-observer.service
  observer-rpc-proxy.service
  faucet-http.service
  get_block_txs_range
  "never=delete chain data"
  lib-cargo-env
)
for n in "${needles[@]}"; do
  grep -q -- "$n" "$script" || { echo "missing needle $n" >&2; exit 1; }
done
# Voters are restarted before the hub.
voters_line="$(grep -n 'systemctl restart mfnd-v1.service' "$script" | head -1 | cut -d: -f1)"
hub_line="$(grep -n 'systemctl restart mfnd-hub.service' "$script" | head -1 | cut -d: -f1)"
observer_line="$(grep -n 'systemctl restart mfnd-observer.service' "$script" | head -1 | cut -d: -f1)"
proxy_line="$(grep -n 'systemctl restart observer-rpc-proxy.service' "$script" | head -1 | cut -d: -f1)"
faucet_line="$(grep -n 'systemctl restart faucet-http.service' "$script" | head -1 | cut -d: -f1)"
if ! (( voters_line < hub_line && hub_line < observer_line && observer_line < proxy_line && proxy_line < faucet_line )); then
  echo "restart order is not voters -> hub -> observer -> proxy -> faucet" >&2
  exit 1
fi

grep -q 'result.methods' "$SCRIPT_DIR/observer-rpc-proxy.mjs" || {
  echo "observer proxy does not patch list_methods result.methods" >&2
  exit 1
}
grep -q 'augmentListMethodsLine' "$SCRIPT_DIR/observer-rpc-proxy.mjs" || {
  echo "observer proxy missing augmentListMethodsLine" >&2
  exit 1
}

if command -v node >/dev/null 2>&1; then
  (cd "$SCRIPT_DIR" && node --input-type=module -e '
import { augmentListMethodsLine } from "./observer-rpc-proxy.mjs";
const wrapped = JSON.parse(augmentListMethodsLine(JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  result: { methods: ["get_tip", "list_methods"], method_classes: { get_tip: "public-safe" } },
})));
const names = wrapped.result.methods;
if (!names.includes("get_block_txs_range") || !names.includes("get_tx_count_totals")) {
  console.error("wrapped methods", names);
  process.exit(1);
}
if (names.join(",") !== [...names].sort().join(",")) {
  console.error("methods not sorted", names);
  process.exit(1);
}
if (wrapped.result.method_classes.get_block_txs_range !== "public-safe") {
  console.error("missing class", wrapped.result.method_classes);
  process.exit(1);
}
const bare = JSON.parse(augmentListMethodsLine(JSON.stringify({
  jsonrpc: "2.0", id: 1, result: ["get_tip"],
})));
if (!bare.result.includes("get_block_txs_range")) process.exit(1);
')
else
  echo "vps-recover-validators-rehearsal-smoke: node not installed; source needles only" >&2
fi

plan="$(bash "$script" --plan-only)"
[[ "$plan" == *"vps-recover-validators: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
[[ "$plan" == *"get_block_txs_range"* ]] || { echo "plan missing method check" >&2; exit 1; }
[[ "$plan" == *"never=delete chain data"* ]] || { echo "plan missing chain-data guard" >&2; exit 1; }
echo "vps-recover-validators-rehearsal-smoke: PASS plan-only"
