#!/usr/bin/env bash
# Plan gate and decision tests for vps-auto-deploy. Does not touch a VPS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=vps-auto-deploy-lib.sh
source "$SCRIPT_DIR/vps-auto-deploy-lib.sh"

fail() {
  echo "vps-auto-deploy-rehearsal-smoke: $*" >&2
  exit 1
}

scope_of() {
  printf '%s\n' "$1" | mfn_deploy_scope_for_paths
}

[[ "$(scope_of "docs/VPS_SINGLE_BOX_LAUNCH.md")" == "none" ]] || fail "docs must not roll"
[[ "$(scope_of "AGENTS.md")" == "none" ]] || fail "board must not roll"
[[ "$(scope_of "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl")" == "none" ]] || fail "checkpoint log is not a deploy"
[[ "$(scope_of "mfn-consensus/src/lib.rs")" == "consensus" ]] || fail "mfn-consensus must skip"
[[ "$(scope_of "mfn-crypto/src/lib.rs")" == "consensus" ]] || fail "mfn-crypto must skip"
[[ "$(scope_of "mfn-bls/src/lib.rs")" == "consensus" ]] || fail "mfn-bls must skip"
[[ "$(scope_of "mfn-node/testdata/public_devnet_v1.json")" == "consensus" ]] || fail "genesis json must skip"
[[ "$(scope_of "mfn-node/testdata/public_devnet_fa.json")" == "consensus" ]] || fail "fa genesis must skip"
[[ "$(scope_of "mfn-node/testdata/public_devnet_v1.manifest.json")" == "consensus" ]] || fail "manifest must skip"
[[ "$(mfn_deploy_class_for_path "mfn-node/src/bin/mfnd.rs")" == "full" ]] || fail "mfnd is a full roll"
[[ "$(scope_of "mfn-cli/src/main.rs")" == "faucet" ]] || fail "cli is faucet"
[[ "$(scope_of "scripts/public-devnet-v1/observer-rpc-proxy.mjs")" == "proxy" ]] || fail "proxy script"
[[ "$(scope_of "scripts/public-devnet-v1/start-hub.sh")" == "full" ]] || fail "start-hub is full"
combined="$(printf '%s\n' "mfn-cli/src/main.rs" "mfn-consensus/src/block/apply.rs" | mfn_deploy_scope_for_paths)"
[[ "$combined" == "consensus" ]] || fail "consensus wins over cli, got $combined"
edge="$(printf '%s\n' "mfn-wallet/src/lib.rs" "scripts/public-devnet-v1/observer-rpc-proxy.mjs" | mfn_deploy_scope_for_paths)"
[[ "$edge" == "faucet+proxy" ]] || fail "faucet+proxy, got $edge"

crates="$(printf '%s\n' "mfn-node/src/bin/mfnd.rs" "mfn-node/src/lib.rs" "mfn-cli/src/main.rs" | mfn_deploy_crates_for_paths)"
[[ "$crates" == $'mfn-node\nmfn-cli' ]] || fail "crate list: $crates"
ckpt_crates="$(printf '%s\n' "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl" | mfn_deploy_crates_for_paths)"
[[ -z "$ckpt_crates" ]] || fail "checkpoint log must not select a crate test"

mem="$(mktemp)"
trap 'rm -f "$mem"' EXIT
cat >"$mem" <<'EOF'
MemTotal:        4000000 kB
MemAvailable:    2000000 kB
SwapFree:         512000 kB
EOF
free_kib="$(mfn_deploy_free_kib "$mem")"
[[ "$free_kib" == "2512000" ]] || fail "free kib $free_kib"
mfn_deploy_memory_sufficient "$free_kib" 1536 || fail "2512000 KiB should pass 1536 MiB"
if mfn_deploy_memory_sufficient 100000 1536; then
  fail "100000 KiB must fail 1536 MiB"
fi

marker="$(mktemp)"
trap 'rm -f "$mem" "$marker"' EXIT
printf '%s\n' "abcdefabcdefabcdefabcdefabcdefabcdefabcd" >"$marker"
mfn_deploy_marker_allows "$marker" "abcdefabcdefabcdefabcdefabcdefabcdefabcd" || fail "marker should allow"
if mfn_deploy_marker_allows "$marker" "1111111111111111111111111111111111111111"; then
  fail "marker should reject a different SHA"
fi
rm -f "$marker"
if mfn_deploy_marker_allows "$marker" "abcdefabcdefabcdefabcdefabcdefabcdefabcd"; then
  fail "missing marker must reject"
fi

state="$(mktemp -d)"
trap 'rm -f "$mem" "$marker"; rm -rf "$state"' EXIT
mfn_deploy_write_status "$state" "aaa" "bbb" "skipped-consensus" "need marker" "ccc"
[[ "$(mfn_deploy_status_get "$state/status.json" result)" == "skipped-consensus" ]] || fail "status result"
[[ "$(mfn_deploy_status_get "$state/status.json" last_deployed_sha)" == "aaa" ]] || fail "status deployed"
[[ "$(mfn_deploy_status_get "$state/status.json" last_attempt_sha)" == "bbb" ]] || fail "status attempt"
[[ "$(mfn_deploy_status_get "$state/status.json" schema)" == "pfpchain-deploy-status.v1" ]] || fail "status schema"
python3 - "$state/status.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("schema", "last_deployed_sha", "last_attempt_sha", "time", "result", "detail", "previous_sha"):
    if key not in doc:
        raise SystemExit("missing " + key)
if not str(doc["time"]).endswith("Z"):
    raise SystemExit("time is not UTC Z")
PY

live="$(mktemp -d)"
prev="$(mktemp -d)"
printf 'old-mfnd' >"$live/mfnd"
printf 'new-mfnd' >"$state/new-mfnd"
mfn_deploy_atomic_install "$state/new-mfnd" "$live" mfnd "$prev"
[[ "$(cat "$live/mfnd")" == "new-mfnd" ]] || fail "swap did not install"
[[ "$(cat "$prev/mfnd")" == "old-mfnd" ]] || fail "swap did not keep previous"
mfn_deploy_restore_previous "$live" mfnd "$prev"
[[ "$(cat "$live/mfnd")" == "old-mfnd" ]] || fail "restore failed"
rm -rf "$live" "$prev" "$state"

deploy="$SCRIPT_DIR/vps-auto-deploy.sh"
install="$SCRIPT_DIR/vps-install-auto-deploy.sh"
for banned in "rm -rf" "git clean"; do
  if grep -n -- "$banned" "$deploy" "$SCRIPT_DIR/vps-auto-deploy-lib.sh" "$install"; then
    fail "found banned command: $banned"
  fi
done
grep -q 'never=delete chain data' "$deploy" || fail "deploy plan missing chain-data promise"
grep -q 'git reset --hard' "$deploy" || fail "rollback must reset tracked sources"
grep -q 'flock -n' "$deploy" || fail "missing flock"
grep -q 'CARGO_BUILD_JOBS' "$deploy" || fail "missing CARGO_BUILD_JOBS"
grep -q 'cargo build --release -p mfn-node --bin mfnd -p mfn-cli --bin mfn-cli' "$deploy" || fail "missing release build"
# The needle is a literal source fragment, including the quotes around $crate.
# shellcheck disable=SC2016
grep -q 'cargo test -p "$crate" --lib --release' "$deploy" || fail "missing fast subset"
grep -q 'status --porcelain' "$deploy" || fail "missing dirty-worktree check"
grep -q 'vps-roll-mfnd.sh' "$deploy" || fail "missing vps-roll-mfnd"
grep -q 'vps-update-observer-rpc-proxy.sh' "$deploy" || fail "missing proxy updater"
grep -q 'systemctl restart mfnd-observer.service' "$deploy" || fail "missing observer restart"
grep -q 'systemctl restart faucet-http.service' "$deploy" || fail "missing faucet restart"

voters_line="$(grep -n 'vps-roll-mfnd.sh" --apply --skip-pull --skip-build' "$deploy" | head -1 | cut -d: -f1)"
observer_line="$(grep -n 'systemctl restart mfnd-observer.service' "$deploy" | head -1 | cut -d: -f1)"
proxy_line="$(grep -n 'vps-update-observer-rpc-proxy.sh" --apply' "$deploy" | head -1 | cut -d: -f1)"
faucet_line="$(grep -n 'systemctl restart faucet-http.service' "$deploy" | head -1 | cut -d: -f1)"
if ! (( voters_line < observer_line && observer_line < proxy_line && proxy_line < faucet_line )); then
  fail "roll order is not voters -> observer -> proxy -> faucet"
fi

unit_dir="$SCRIPT_DIR/systemd"
test -f "$unit_dir/pfpchain-auto-deploy.service" || fail "missing service"
test -f "$unit_dir/pfpchain-auto-deploy.timer" || fail "missing timer"
grep -q 'CARGO_BUILD_JOBS=2' "$unit_dir/pfpchain-auto-deploy.service" || fail "unit jobs"
grep -q 'vps-auto-deploy.sh --apply' "$unit_dir/pfpchain-auto-deploy.service" || fail "unit exec"
grep -q 'TimeoutStartSec=infinity' "$unit_dir/pfpchain-auto-deploy.service" || fail "unit timeout"
grep -q 'OnCalendar=\*-\*-\* \*:00/15:00' "$unit_dir/pfpchain-auto-deploy.timer" || fail "timer interval"
grep -q 'Persistent=false' "$unit_dir/pfpchain-auto-deploy.timer" || fail "timer must not fire on enable"

plan="$(bash "$deploy" --plan-only)"
[[ "$plan" == *"vps-auto-deploy: PASS plan-only"* ]] || fail "deploy plan: $plan"
[[ "$plan" == *"CARGO_BUILD_JOBS=2"* ]] || fail "plan jobs"
[[ "$plan" == *"never=delete chain data"* ]] || fail "plan chain data"
[[ "$plan" == *"order=voters then hub then observer then proxy then faucet"* ]] || fail "plan order"
[[ "$plan" == *"allow-consensus"* ]] || fail "plan marker"

install_plan="$(bash "$install" --plan-only)"
[[ "$install_plan" == *"vps-install-auto-deploy: PASS plan-only"* ]] || fail "install plan: $install_plan"
[[ "$install_plan" == *"OnCalendar=*-*-* *:00/15:00"* ]] || fail "install interval"
[[ "$install_plan" == *"never=delete chain data"* ]] || fail "install chain data"

echo "vps-auto-deploy-rehearsal-smoke: PASS plan-only"
