#!/usr/bin/env bash
# Mirror .github/workflows/ci.yml locally before pushing to main.
set -euo pipefail
cd "$(dirname "$0")/.."
repo_root="$(pwd)"

docs_only=0
rust_only=0
for arg in "$@"; do
  case "$arg" in
    --docs-only) docs_only=1 ;;
    --rust-only) rust_only=1 ;;
    *)
      echo "unknown ci-check argument: $arg (use --docs-only or --rust-only)" >&2
      exit 2
      ;;
  esac
done
if (( docs_only && rust_only )); then
  echo "Use only one of --docs-only or --rust-only" >&2
  exit 2
fi
run_docs=$(( ! rust_only ))
run_rust=$(( ! docs_only ))

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-D warnings"

missing_tools=()
add_missing_command() {
  local name="$1"
  local hint="$2"
  if ! command -v "$name" >/dev/null 2>&1; then
    missing_tools+=("missing required command '$name'. $hint")
  fi
}

add_missing_command bash "Install bash and reopen the shell."
if (( run_rust )); then
  add_missing_command cargo "Install Rust from https://rustup.rs/ and reopen the shell."
  add_missing_command rustup "Install Rust from https://rustup.rs/ and reopen the shell."
  add_missing_command wasm-pack "Install with: cargo install wasm-pack --locked."
  add_missing_command cargo-audit "Install with: cargo install cargo-audit --locked."
fi
if (( run_docs )); then
  add_missing_command pwsh "Install PowerShell 7+ to parse-check Windows helper scripts."
  add_missing_command python3 "Install Python 3 to validate release-evidence JSON output."
fi
if ((${#missing_tools[@]} > 0)); then
  printf '%s\n' "${missing_tools[@]}" >&2
  exit 127
fi

echo "==> workflow YAML encoding (UTF-8)"
bash scripts/validate-workflow-encoding.sh
echo "==> consensus f64 lint (B-36 / F10)"
bash scripts/validate-consensus-f64-lint.sh
echo "==> RC helper scripts smoke"
bash scripts/validate-rc-helper-scripts.sh
if (( run_docs )); then
echo "==> public-devnet scripts"
schema_venv="$repo_root/.permawrite-ci-venv"
if [[ ! -x "$schema_venv/bin/python" ]]; then
  python3 -m venv "$schema_venv"
fi
schema_python="$schema_venv/bin/python"
"$schema_python" -m pip install --disable-pip-version-check --require-hashes -r scripts/public-devnet-v1/requirements-release-schema.txt -q
export PERMAWRITE_RELEASE_SCHEMA_PYTHON="$schema_python"
for script in scripts/*.sh scripts/public-devnet-v1/*.sh; do
  bash -n "$script"
done
bash scripts/public-devnet-v1/vps-bind-lib-smoke.sh
http_plan="$(bash scripts/public-devnet-v1/recovery-walkthrough.sh --plan-only --rpc 127.0.0.1:18731 --wallet ./alice.json --commit ababab --peer 127.0.0.1:18780 --expected-sha256 cdcd --prove)"
if [[ "$http_plan" != *"restore_mode=http"* || "$http_plan" != *"optional sha256 verify"* || "$http_plan" != *"only proves when --prove is set"* ]]; then
  printf '%s\n' "$http_plan" >&2
  exit 1
fi
p2p_plan="$(bash scripts/public-devnet-v1/recovery-walkthrough.sh --plan-only --rpc 127.0.0.1:18731 --wallet ./alice.json --commit ababab --data-dir /tmp/replica --expected-sha256 cdcd)"
if [[ "$p2p_plan" != *"restore_mode=p2p-inbox"* || "$p2p_plan" != *"support-bundle -> recovery-plan -> restore"* ]]; then
  printf '%s\n' "$p2p_plan" >&2
  exit 1
fi
rehearsal_plan="$(bash scripts/public-devnet-v1/participant-rehearsal.sh --plan-only --rpc 127.0.0.1:18731 --faucet-wallet ./faucet.json --evidence-dir ./participant-evidence)"
if [[ "$rehearsal_plan" != *"flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle"* || "$rehearsal_plan" != *"public-devnet/test funds only"* || "$rehearsal_plan" != *"outputs end with support_bundle=<dir> and evidence_log=<file>"* || "$rehearsal_plan" != *"evidence_dir=./participant-evidence"* || "$rehearsal_plan" != *"evidence_log=./participant-evidence/participant-rehearsal.log"* || "$rehearsal_plan" != *"support_bundle=./participant-evidence/support-bundle"* ]]; then
  printf '%s\n' "$rehearsal_plan" >&2
  exit 1
fi
smoke_plan="$(bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only --rpc 127.0.0.1:18731)"
if [[ "$smoke_plan" != *"flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh"* || "$smoke_plan" != *"custom faucet wallets are never overwritten"* || "$smoke_plan" != *"evidence_dir="*"participant-rehearsal-smoke/evidence"* || "$smoke_plan" != *"dandelion=false"* ]]; then
  printf '%s\n' "$smoke_plan" >&2
  exit 1
fi
dandelion_smoke_plan="$(bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only --dandelion --rpc 127.0.0.1:18731)"
if [[ "$dandelion_smoke_plan" != *"dandelion=true"* || "$dandelion_smoke_plan" != *"flow=stop stale mesh -> start-all"* ]]; then
  printf '%s\n' "$dandelion_smoke_plan" >&2
  exit 1
fi
dandelion_wrapper_plan="$(bash scripts/public-devnet-v1/dandelion-rehearsal-smoke.sh --plan-only --rpc 127.0.0.1:18731)"
if [[ "$dandelion_wrapper_plan" != *"dandelion=true"* ]]; then
  printf '%s\n' "$dandelion_wrapper_plan" >&2
  exit 1
fi
tor_rpc_plan="$(bash scripts/public-devnet-v1/tor-rpc-rehearsal-smoke.sh --rpc abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:18731)"
if [[ "$tor_rpc_plan" != *"flow=mfn-cli --tor --rpc"* || "$tor_rpc_plan" != *"PASS plan-only"* ]]; then
  printf '%s\n' "$tor_rpc_plan" >&2
  exit 1
fi
ref_topo_plan="$(bash scripts/public-devnet-v1/reference-topology-rehearsal-smoke.sh --plan-only)"
if [[ "$ref_topo_plan" != *"REFERENCE_TOPOLOGY.md"* || "$ref_topo_plan" != *"PASS plan-only"* ]]; then
  printf '%s\n' "$ref_topo_plan" >&2
  exit 1
fi
checkpoint_log_plan="$(bash scripts/public-devnet-v1/checkpoint-log-rehearsal-smoke.sh --plan-only)"
if [[ "$checkpoint_log_plan" != *"CHECKPOINT_LOG.md"* || "$checkpoint_log_plan" != *"PASS plan-only"* ]]; then
  printf '%s\n' "$checkpoint_log_plan" >&2
  exit 1
fi
publish_checkpoint_log_plan="$(bash scripts/public-devnet-v1/publish-checkpoint-log-rehearsal-smoke.sh --plan-only)"
if [[ "$publish_checkpoint_log_plan" != *"publish-checkpoint-log-rehearsal-smoke: PASS plan-only"* ]]; then
  printf '%s\n' "$publish_checkpoint_log_plan" >&2
  exit 1
fi
launch_status_plan="$(bash scripts/public-devnet-v1/launch-status-rehearsal-smoke.sh --plan-only)"
[[ "$launch_status_plan" == *"launch-status-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$launch_status_plan" >&2; exit 1; }
pm23_plan="$(bash scripts/public-devnet-v1/pm23-operator-manifest-rehearsal-smoke.sh --plan-only)"
[[ "$pm23_plan" == *"pm23-operator-manifest-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$pm23_plan" >&2; exit 1; }
treasury_plan="$(bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --plan-only)"
[[ "$treasury_plan" == *"treasury-telemetry-watch: PASS plan-only"* ]] || { printf '%s\n' "$treasury_plan" >&2; exit 1; }
[[ "$treasury_plan" == *"subsidy_to_treasury_bps"* ]] || { echo "ci-check: treasury-telemetry-watch missing subsidy_to_treasury_bps" >&2; exit 1; }
vps_checklist_plan="$(bash scripts/public-devnet-v1/vps-execution-checklist-rehearsal-smoke.sh --plan-only)"
[[ "$vps_checklist_plan" == *"vps-execution-checklist-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_checklist_plan" >&2; exit 1; }
[[ "$vps_checklist_plan" == *"vps-execution-checklist.v2"* ]] || { printf '%s\n' "$vps_checklist_plan" >&2; exit 1; }
launch_go_no_go_plan="$(bash scripts/public-devnet-v1/launch-go-no-go-rehearsal-smoke.sh --plan-only)"
[[ "$launch_go_no_go_plan" == *"launch-go-no-go-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$launch_go_no_go_plan" >&2; exit 1; }
vps_soak_plan="$(bash scripts/public-devnet-v1/vps-internet-soak-rehearsal-smoke.sh --plan-only)"
[[ "$vps_soak_plan" == *"vps-internet-soak-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_soak_plan" >&2; exit 1; }
vps_soak_evidence_plan="$(bash scripts/public-devnet-v1/vps-internet-soak-evidence-rehearsal-smoke.sh --plan-only)"
[[ "$vps_soak_evidence_plan" == *"vps-internet-soak-evidence-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_soak_evidence_plan" >&2; exit 1; }
[[ "$vps_soak_evidence_plan" == *"vps_soak_evidence=true"* ]] || { printf '%s\n' "$vps_soak_evidence_plan" >&2; exit 1; }
vps_participant_plan="$(bash scripts/public-devnet-v1/vps-participant-rehearsal-rehearsal-smoke.sh --plan-only)"
[[ "$vps_participant_plan" == *"vps-participant-rehearsal-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_participant_plan" >&2; exit 1; }
[[ "$vps_participant_plan" == *"assert-vps-participant-rehearsal-evidence"* ]] || { printf '%s\n' "$vps_participant_plan" >&2; exit 1; }
vps_participant_evidence_plan="$(bash scripts/public-devnet-v1/vps-participant-rehearsal-evidence-rehearsal-smoke.sh --plan-only)"
[[ "$vps_participant_evidence_plan" == *"vps-participant-rehearsal-evidence-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_participant_evidence_plan" >&2; exit 1; }
[[ "$vps_participant_evidence_plan" == *"vps_rehearsal_evidence=true"* ]] || { printf '%s\n' "$vps_participant_evidence_plan" >&2; exit 1; }
join_testnet_plan="$(bash scripts/public-devnet-v1/join-testnet-rehearsal-smoke.sh --plan-only)"
[[ "$join_testnet_plan" == *"join-testnet-rehearsal-smoke: plan"* ]] || { printf '%s\n' "$join_testnet_plan" >&2; exit 1; }
[[ "$join_testnet_plan" == *"fund-wallet-http"* ]] || { printf '%s\n' "$join_testnet_plan" >&2; exit 1; }
[[ "$join_testnet_plan" == *"assert-join-testnet-rehearsal-evidence.sh"* ]] || { printf '%s\n' "$join_testnet_plan" >&2; exit 1; }
join_testnet_evidence_plan="$(bash scripts/public-devnet-v1/join-testnet-rehearsal-evidence-rehearsal-smoke.sh --plan-only)"
[[ "$join_testnet_evidence_plan" == *"join-testnet-rehearsal-evidence-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$join_testnet_evidence_plan" >&2; exit 1; }
repair_vps_p2p_plan="$(bash scripts/public-devnet-v1/repair-vps-p2p-binds-rehearsal-smoke.sh --plan-only)"
[[ "$repair_vps_p2p_plan" == *"repair-vps-p2p-binds-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$repair_vps_p2p_plan" >&2; exit 1; }
bootstrap_ckpt_plan="$(bash scripts/public-devnet-v1/bootstrap-path-a-checkpoint-signer.sh --plan-only)"
[[ "$bootstrap_ckpt_plan" == *"bootstrap-path-a-checkpoint-signer: PASS plan-only"* ]] || { printf '%s\n' "$bootstrap_ckpt_plan" >&2; exit 1; }
invite_load_plan="$(bash scripts/public-devnet-v1/invite-load-smoke-rehearsal.sh --plan-only)"
[[ "$invite_load_plan" == *"invite-load-smoke-rehearsal: PASS plan-only"* ]] || { printf '%s\n' "$invite_load_plan" >&2; exit 1; }
vps_roll_mfnd_plan="$(bash scripts/public-devnet-v1/vps-roll-mfnd-rehearsal-smoke.sh --plan-only)"
[[ "$vps_roll_mfnd_plan" == *"vps-roll-mfnd-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_roll_mfnd_plan" >&2; exit 1; }
boot_ckpt_plan="$(bash scripts/public-devnet-v1/bootstrap-wallet-from-checkpoint-log-rehearsal-smoke.sh --plan-only)"
[[ "$boot_ckpt_plan" == *"bootstrap-wallet-from-checkpoint-log-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$boot_ckpt_plan" >&2; exit 1; }
block_log_health_plan="$(bash scripts/public-devnet-v1/assert-vps-block-log-health-rehearsal-smoke.sh --plan-only)"
[[ "$block_log_health_plan" == *"assert-vps-block-log-health-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$block_log_health_plan" >&2; exit 1; }
vps_preflight_plan="$(bash scripts/public-devnet-v1/vps-preflight-rehearsal-smoke.sh --plan-only)"
[[ "$vps_preflight_plan" == *"vps-preflight-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_preflight_plan" >&2; exit 1; }
vps_provision_plan="$(bash scripts/public-devnet-v1/vps-provision-rehearsal-smoke.sh --plan-only)"
[[ "$vps_provision_plan" == *"vps-provision-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_provision_plan" >&2; exit 1; }
vps_role_templates_plan="$(bash scripts/public-devnet-v1/vps-role-templates-rehearsal-smoke.sh --plan-only)"
[[ "$vps_role_templates_plan" == *"vps-role-templates-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_role_templates_plan" >&2; exit 1; }
testnet_invite_plan="$(bash scripts/public-devnet-v1/testnet-invite-rehearsal-smoke.sh --plan-only)"
[[ "$testnet_invite_plan" == *"testnet-invite-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$testnet_invite_plan" >&2; exit 1; }
publish_seed_plan="$(bash scripts/public-devnet-v1/publish-seed-nodes-rehearsal-smoke.sh --plan-only)"
[[ "$publish_seed_plan" == *"publish-seed-nodes-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$publish_seed_plan" >&2; exit 1; }
vps_ceremony_plan="$(bash scripts/public-devnet-v1/vps-launch-ceremony-rehearsal-smoke.sh --plan-only)"
[[ "$vps_ceremony_plan" == *"vps-launch-ceremony-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$vps_ceremony_plan" >&2; exit 1; }
demo_f12_plan="$(bash scripts/public-devnet-v1/demo-web-f12-rehearsal-smoke.sh --plan-only)"
[[ "$demo_f12_plan" == *"demo-web-f12-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$demo_f12_plan" >&2; exit 1; }
genesis_bls_pop_plan="$(bash scripts/public-devnet-v1/genesis-validator-bls-pop-rehearsal-smoke.sh --plan-only)"
[[ "$genesis_bls_pop_plan" == *"genesis-validator-bls-pop-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$genesis_bls_pop_plan" >&2; exit 1; }
genesis_header_version_plan="$(bash scripts/public-devnet-v1/genesis-header-version-rehearsal-smoke.sh --plan-only)"
[[ "$genesis_header_version_plan" == *"genesis-header-version-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$genesis_header_version_plan" >&2; exit 1; }
[[ "$genesis_header_version_plan" == *"HEADER_VERSION_UTXO_QUORUM"* ]] || { printf '%s\n' "$genesis_header_version_plan" >&2; exit 1; }
fraud_proof_plan="$(bash scripts/public-devnet-v1/fraud-proof-rehearsal-smoke.sh --plan-only)"
[[ "$fraud_proof_plan" == *"fraud-proof-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$fraud_proof_plan" >&2; exit 1; }
[[ "$fraud_proof_plan" == *"FRAUD_PROOF_V1_TAG"* ]] || { printf '%s\n' "$fraud_proof_plan" >&2; exit 1; }
validity_proof_plan="$(bash scripts/public-devnet-v1/validity-proof-rehearsal-smoke.sh --plan-only)"
[[ "$validity_proof_plan" == *"validity-proof-rehearsal-smoke: PASS plan-only"* ]] || { printf '%s\n' "$validity_proof_plan" >&2; exit 1; }
[[ "$validity_proof_plan" == *"VALIDITY_PROOF_V1_TAG"* ]] || { printf '%s\n' "$validity_proof_plan" >&2; exit 1; }
bash scripts/public-devnet-v1/assert-participant-smoke-evidence.sh scripts/public-devnet-v1/fixtures/participant-rehearsal-evidence-v1
bad_evidence_dir="$(mktemp -d)"
if bash scripts/public-devnet-v1/assert-participant-smoke-evidence.sh "$bad_evidence_dir" >/dev/null 2>&1; then
  echo "assert-participant-smoke-evidence.sh accepted missing evidence directory" >&2
  rm -rf "$bad_evidence_dir"
  exit 1
fi
rm -rf "$bad_evidence_dir"
vps_soak_fixture="scripts/public-devnet-v1/fixtures/vps-internet-soak-evidence-v1/vps-internet-soak-linux-30s-slot-20260712T000000Z.txt"
bash scripts/public-devnet-v1/assert-vps-internet-soak-evidence.sh "$vps_soak_fixture"
bad_soak_evidence="$(mktemp)"
printf 'soak: SUMMARY status=FAIL\n' >"$bad_soak_evidence"
if bash scripts/public-devnet-v1/assert-vps-internet-soak-evidence.sh "$bad_soak_evidence" >/dev/null 2>&1; then
  echo "assert-vps-internet-soak-evidence.sh accepted invalid soak evidence" >&2
  rm -f "$bad_soak_evidence"
  exit 1
fi
rm -f "$bad_soak_evidence"
vps_participant_fixture="scripts/public-devnet-v1/fixtures/vps-participant-rehearsal-evidence-v1/vps-participant-rehearsal-observer-linux-20260712T000000Z.txt"
bash scripts/public-devnet-v1/assert-vps-participant-rehearsal-evidence.sh "$vps_participant_fixture"
bad_participant_evidence="$(mktemp)"
printf 'SUMMARY: FAIL\n' >"$bad_participant_evidence"
if bash scripts/public-devnet-v1/assert-vps-participant-rehearsal-evidence.sh "$bad_participant_evidence" >/dev/null 2>&1; then
  echo "assert-vps-participant-rehearsal-evidence.sh accepted invalid participant evidence" >&2
  rm -f "$bad_participant_evidence"
  exit 1
fi
rm -f "$bad_participant_evidence"
join_testnet_fixture="scripts/public-devnet-v1/fixtures/join-testnet-rehearsal-evidence-v1/join-testnet-rehearsal-linux-20260719T000000Z.txt"
bash scripts/public-devnet-v1/assert-join-testnet-rehearsal-evidence.sh "$join_testnet_fixture"
bad_join_testnet_evidence="$(mktemp)"
printf 'SUMMARY: FAIL\n' >"$bad_join_testnet_evidence"
if bash scripts/public-devnet-v1/assert-join-testnet-rehearsal-evidence.sh "$bad_join_testnet_evidence" >/dev/null 2>&1; then
  echo "assert-join-testnet-rehearsal-evidence.sh accepted invalid JOIN_TESTNET evidence" >&2
  rm -f "$bad_join_testnet_evidence"
  exit 1
fi
rm -f "$bad_join_testnet_evidence"
bash scripts/public-devnet-v1/release-participant-smoke-policy-check.sh >/dev/null
if bash scripts/public-devnet-v1/release-participant-smoke-policy-check.sh \
  --path scripts/public-devnet-v1/fixtures/policy-negative-participant-smoke-ci-snippet.yml >/dev/null 2>&1; then
  echo "release-participant-smoke-policy-check.sh accepted a real-run participant smoke invocation" >&2
  exit 1
fi
rc_audit_output="$(mktemp -t permawrite-rc-audit-dry-run.XXXXXX.json)"
pwsh -NoProfile -File scripts/public-devnet-v1/release-rc-audit-dry-run.ps1 -OutputPath "$rc_audit_output" -Json >/dev/null
if [[ "$?" -ne 0 ]]; then
  rm -f "$rc_audit_output"
  exit 1
fi
if ! python3 - <<'PY' "$rc_audit_output"
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    obj = json.load(fh)
if obj.get("decision") != "go":
    print(f"release-rc-audit-dry-run.ps1 returned decision={obj.get('decision')}", file=sys.stderr)
    sys.exit(1)
PY
then
  rm -f "$rc_audit_output"
  exit 1
fi
rm -f "$rc_audit_output"
refresh_dir="$(mktemp -d -t permawrite-evidence-refresh.XXXXXX)"
pwsh -NoProfile -File scripts/public-devnet-v1/release-evidence-refresh-for-head.ps1 \
  -AllowPendingCi \
  -Notes "ci-check smoke" \
  -OutputDir "$refresh_dir" >/dev/null
short_head="$(git rev-parse --short HEAD)"
if [[ ! -f "$refresh_dir/release-evidence-${short_head}.json" || ! -f "$refresh_dir/release-evidence-${short_head}.md" ]]; then
  echo "release-evidence-refresh-for-head.ps1 did not write expected evidence files" >&2
  rm -rf "$refresh_dir"
  exit 1
fi
rm -rf "$refresh_dir"
pwsh -NoProfile -Command '
  $errors = @()
  foreach ($script in Get-ChildItem scripts -Filter *.ps1 -Recurse) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
      $errors += $parseErrors | ForEach-Object { "$($script.FullName): $_" }
    }
  }
  if ($errors.Count -gt 0) {
    $errors | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
'
pwsh -NoProfile -Command '
  $httpPlan = (pwsh -NoProfile -File scripts/public-devnet-v1/recovery-walkthrough.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -Wallet ./alice.json -CommitHash ababab -Peer 127.0.0.1:18780 -ExpectedSha256 cdcd -Prove) -join "`n"
  if ($httpPlan -notmatch "restore_mode=http" -or $httpPlan -notmatch "optional sha256 verify" -or $httpPlan -notmatch "only proves when -Prove is set") {
    $httpPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
  $p2pPlan = (pwsh -NoProfile -File scripts/public-devnet-v1/recovery-walkthrough.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -Wallet ./alice.json -CommitHash ababab -DataDir /tmp/replica -ExpectedSha256 cdcd) -join "`n"
  if ($p2pPlan -notmatch "restore_mode=p2p-inbox" -or $p2pPlan -notmatch "support-bundle -> recovery-plan -> restore") {
    $p2pPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
  $rehearsalPlan = (pwsh -NoProfile -File scripts/public-devnet-v1/participant-rehearsal.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -FaucetWallet ./faucet.json -EvidenceDir ./participant-evidence) -join "`n"
  if ($rehearsalPlan -notmatch "flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle" -or $rehearsalPlan -notmatch "public-devnet/test funds only" -or $rehearsalPlan -notmatch "outputs end with support_bundle=<dir> and evidence_log=<file>" -or $rehearsalPlan -notmatch "evidence_dir=./participant-evidence" -or $rehearsalPlan -notmatch "evidence_log=.*participant-rehearsal.log" -or $rehearsalPlan -notmatch "support_bundle=.*support-bundle") {
    $rehearsalPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
  $smokePlan = (pwsh -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly -Rpc 127.0.0.1:18731) -join "`n"
  if ($smokePlan -notmatch "flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh" -or $smokePlan -notmatch "custom faucet wallets are never overwritten" -or $smokePlan -notmatch "evidence_dir=.*participant-rehearsal-smoke.*evidence") {
    $smokePlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
'
evidence_md="$(bash scripts/public-devnet-v1/release-evidence.sh --operator ci-smoke --skip-ci-lookup)"
for required in "# Permawrite Release-Candidate Evidence" "## Commit And CI" "## RPC Posture" "## Operator Sign-Off"; do
  if [[ "$evidence_md" != *"$required"* ]]; then
    echo "release-evidence.sh Markdown output missing '$required'" >&2
    exit 1
  fi
done
evidence_json="$(bash scripts/public-devnet-v1/release-evidence.sh --operator ci-smoke --json --skip-ci-lookup)"
EVIDENCE_JSON="$evidence_json" python3 - <<'PY'
import json
import os
import sys

doc = json.loads(os.environ["EVIDENCE_JSON"])
required_paths = [
    ("schema_version",),
    ("generated_utc",),
    ("commit", "head"),
    ("ci", "status"),
    ("chain", "expected_genesis_id"),
    ("health", "status"),
    ("rpc", "endpoint"),
    ("rpc", "current_in_flight"),
    ("rpc", "max_in_flight"),
    ("rpc", "p2p_session_count"),
    ("rpc", "p2p_peer_count"),
]
for path in required_paths:
    current = doc
    for key in path:
        current = current.get(key) if isinstance(current, dict) else None
    if current in (None, ""):
        print(f"release-evidence.sh JSON output missing required schema field: {'.'.join(path)}", file=sys.stderr)
        sys.exit(1)
if doc.get("operator_signoff", {}).get("operator") != "ci-smoke":
    print("release-evidence.sh JSON output did not preserve operator sign-off metadata", file=sys.stderr)
    sys.exit(1)
if doc.get("schema_version") != "release-evidence.v1":
    print("release-evidence.sh JSON output has unexpected schema_version", file=sys.stderr)
    sys.exit(1)
for path in (
    "docs/release-evidence-v1.schema.json",
    "docs/release-evidence-v1.sample.json",
    "docs/release-signoff-manifest-v1.schema.json",
    "docs/release-signoff-manifest-v1.sample.json",
    "docs/release-audit-packet-v1.schema.json",
    "docs/release-audit-packet-v1.sample.json",
):
    with open(path, "r", encoding="utf-8") as handle:
        json.load(handle)
with open("docs/release-signoff-manifest-v1.sample.json", "r", encoding="utf-8") as handle:
    signoff = json.load(handle)
if (
    signoff.get("schema_version") != "release-signoff-manifest.v1"
    or signoff.get("release_evidence", {}).get("schema_version") != "release-evidence.v1"
    or signoff.get("gates", {}).get("ci", {}).get("conclusion") != "success"
):
    print("release-signoff-manifest-v1.sample.json has unexpected gate or schema metadata", file=sys.stderr)
    sys.exit(1)
PY
bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-evidence-v1.schema.json --json docs/release-evidence-v1.sample.json >/dev/null
bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-signoff-manifest-v1.schema.json --json docs/release-signoff-manifest-v1.sample.json >/dev/null
bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-audit-packet-v1.schema.json --json docs/release-audit-packet-v1.sample.json >/dev/null
for strict_pair in \
  "docs/release-evidence-v1.schema.json docs/release-evidence-v1.sample.json" \
  "docs/release-signoff-manifest-v1.schema.json docs/release-signoff-manifest-v1.sample.json" \
  "docs/release-audit-packet-v1.schema.json docs/release-audit-packet-v1.sample.json"; do
  set -- $strict_pair
  bash scripts/public-devnet-v1/release-json-schema-draft202012.sh --schema "$1" --json "$2" >/dev/null
done
schema_validate_dir="$(mktemp -d)"
python3 - "$schema_validate_dir/bad-evidence.json" <<'PY'
import json
import sys

with open("docs/release-evidence-v1.sample.json", "r", encoding="utf-8") as handle:
    doc = json.load(handle)
doc["unexpected_release_field"] = True
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2)
    handle.write("\n")
PY
if bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-evidence-v1.schema.json --json "$schema_validate_dir/bad-evidence.json" >/dev/null 2>&1; then
  echo "release-json-schema-validate.sh accepted an unexpected release evidence field" >&2
  exit 1
fi
python3 - "$schema_validate_dir/bad-audit.json" <<'PY'
import json
import sys

with open("docs/release-audit-packet-v1.sample.json", "r", encoding="utf-8") as handle:
    doc = json.load(handle)
doc["unexpected_audit_field"] = True
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2)
    handle.write("\n")
PY
if bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-audit-packet-v1.schema.json --json "$schema_validate_dir/bad-audit.json" >/dev/null 2>&1; then
  echo "release-json-schema-validate.sh accepted an unexpected release audit packet field" >&2
  exit 1
fi
if bash scripts/public-devnet-v1/release-json-schema-draft202012.sh --schema docs/release-audit-packet-v1.schema.json --json "$schema_validate_dir/bad-audit.json" >/dev/null 2>&1; then
  echo "release-json-schema-draft202012.sh accepted an unexpected release audit packet field" >&2
  exit 1
fi
rm -rf "$schema_validate_dir"
bash scripts/public-devnet-v1/release-signoff-manifest-validate.sh --manifest docs/release-signoff-manifest-v1.sample.json >/dev/null
signoff_validate_dir="$(mktemp -d)"
python3 - "$signoff_validate_dir/bad-signoff.json" <<'PY'
import json
import sys

with open("docs/release-signoff-manifest-v1.sample.json", "r", encoding="utf-8") as handle:
    doc = json.load(handle)
doc["gates"]["ci"]["conclusion"] = "failure"
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2)
    handle.write("\n")
PY
if bash scripts/public-devnet-v1/release-signoff-manifest-validate.sh --manifest "$signoff_validate_dir/bad-signoff.json" >/dev/null 2>&1; then
  echo "release-signoff-manifest-validate.sh accepted a go manifest with failing CI" >&2
  exit 1
fi
rm -rf "$signoff_validate_dir"
ci_watch_dir="$(mktemp -d)"
ci_watch_commit="0123456789abcdef0123456789abcdef01234567"
cat > "$ci_watch_dir/success.json" <<EOF
[
  {"headSha":"$ci_watch_commit","status":"completed","conclusion":"success","url":"https://example.invalid/success"},
  {"headSha":"ffffffffffffffffffffffffffffffffffffffff","status":"completed","conclusion":"success","url":"https://example.invalid/wrong"}
]
EOF
bash scripts/public-devnet-v1/release-ci-watch.sh --commit "$ci_watch_commit" --mock-runs "$ci_watch_dir/success.json" >/dev/null
cat > "$ci_watch_dir/failure.json" <<EOF
[
  {"headSha":"$ci_watch_commit","status":"completed","conclusion":"failure","url":"https://example.invalid/failure"}
]
EOF
if bash scripts/public-devnet-v1/release-ci-watch.sh --commit "$ci_watch_commit" --mock-runs "$ci_watch_dir/failure.json" >/dev/null 2>&1; then
  echo "release-ci-watch.sh accepted failing CI for the exact commit" >&2
  exit 1
fi
bash scripts/public-devnet-v1/release-ci-watch.sh \
  --commit "$ci_watch_commit" \
  --mock-api-error-status 403 \
  --mock-api-error-message "API rate limit exceeded" \
  --json > "$ci_watch_dir/rate-limited.json" 2>/dev/null && {
  echo "release-ci-watch.sh accepted rate-limited GitHub API as green" >&2
  exit 1
}
python3 - "$ci_watch_dir/rate-limited.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    doc = json.load(handle)
if doc.get("status") != "rate_limited":
    print("release-ci-watch.sh did not emit structured rate_limited JSON", file=sys.stderr)
    sys.exit(1)
PY
GH_TOKEN="ci-watch-test-token" bash scripts/public-devnet-v1/release-ci-watch.sh \
  --commit "$ci_watch_commit" \
  --mock-api-error-status 500 \
  --json > "$ci_watch_dir/auth-api.json" 2>/dev/null && {
  echo "release-ci-watch.sh accepted mocked GitHub API failure as green" >&2
  exit 1
}
python3 - "$ci_watch_dir/auth-api.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    text = handle.read()
doc = json.loads(text)
if doc.get("status") != "api_error" or "auth" not in doc.get("source", ""):
    print("release-ci-watch.sh did not report authenticated API fallback source", file=sys.stderr)
    sys.exit(1)
if "ci-watch-test-token" in text:
    print("release-ci-watch.sh leaked GH_TOKEN in JSON output", file=sys.stderr)
    sys.exit(1)
PY
rm -rf "$ci_watch_dir"
support_plan="$(bash scripts/public-devnet-v1/support-bundle.sh --rpc 127.0.0.1:18731 --release-evidence docs/release-evidence-v1.sample.json --plan-only)"
if [[ "$support_plan" != *"valid release-evidence.v1"* ]]; then
  echo "support-bundle.sh did not validate release-evidence.v1 in plan mode" >&2
  exit 1
fi
dry_run="$(bash scripts/public-devnet-v1/release-signoff-dry-run.sh)"
if [[ "$dry_run" != *"release-signoff-dry-run: OK"* ]]; then
  echo "release-signoff-dry-run.sh did not complete successfully" >&2
  exit 1
fi
checksum_rows="$(bash scripts/public-devnet-v1/artifact-checksums.sh docs/release-evidence-v1.sample.json docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md)"
for required in "| Path | SHA-256 | Bytes |" "release-evidence-v1.sample.json" "RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md"; do
  if [[ "$checksum_rows" != *"$required"* ]]; then
    echo "artifact-checksums.sh output missing '$required'" >&2
    exit 1
  fi
done
archive_plan="$(bash scripts/public-devnet-v1/release-archive-dry-run.sh --plan-only --release-evidence-json docs/release-evidence-v1.sample.json --include-release-schema-wheelhouse)"
if [[ "$archive_plan" != *"release-archive-dry-run: PLAN OK"* ]]; then
  echo "release-archive-dry-run.sh plan mode did not complete successfully" >&2
  exit 1
fi
if [[ "$archive_plan" != *"toolchain/wheelhouse-release-schema"* ]]; then
  echo "release-archive-dry-run.sh plan mode did not include release-schema wheelhouse staging" >&2
  exit 1
fi
if [[ "$archive_plan" != *"participant smoke CI policy helpers"* ]]; then
  echo "release-archive-dry-run.sh plan mode did not include participant smoke CI policy helpers" >&2
  exit 1
fi
archive_dir="$(mktemp -d)"
archive_run="$(bash scripts/public-devnet-v1/release-archive-dry-run.sh --output-dir "$archive_dir" --release-evidence-json docs/release-evidence-v1.sample.json --include-release-schema-wheelhouse)"
archive_root="$(printf '%s\n' "$archive_run" | awk -F'path=' '/release-archive-dry-run: OK path=/{print $2}' | tail -n 1)"
if [[ -z "$archive_root" ]]; then
  echo "release-archive-dry-run.sh did not report an output path" >&2
  exit 1
fi
for required_path in \
  README.md \
  network/genesis.json \
  network/checksums.sha256 \
  docs/SECURITY.md \
  docs/OPERATORS.md \
  evidence/release-evidence.json \
  evidence/checksums.sha256 \
  toolchain/requirements-release-schema.txt \
  toolchain/release-participant-smoke-policy-check.py \
  toolchain/release-participant-smoke-policy-check.sh; do
  if [[ ! -f "$archive_root/$required_path" ]]; then
    echo "release-archive-dry-run.sh missing staged artifact '$required_path'" >&2
    exit 1
  fi
done
if [[ ! -d "$archive_root/toolchain/wheelhouse-release-schema" ]]; then
  echo "release-archive-dry-run.sh missing staged release-schema wheelhouse directory" >&2
  exit 1
fi
wheel_count="$(find "$archive_root/toolchain/wheelhouse-release-schema" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
if ((wheel_count < 3)); then
  echo "release-archive-dry-run.sh staged fewer than 3 release-schema wheels" >&2
  exit 1
fi
bash scripts/public-devnet-v1/release-archive-validate.sh --archive-dir "$archive_root" --allow-dry-run --require-release-schema-wheelhouse >/dev/null
offline_venv="$(mktemp -d)"
python3 -m venv "$offline_venv"
offline_python="$offline_venv/bin/python"
PERMAWRITE_RELEASE_SCHEMA_PYTHON="$offline_python" \
  bash "$archive_root/toolchain/release-schema-install-offline.sh" \
  --wheelhouse "$archive_root/toolchain/wheelhouse-release-schema"
PERMAWRITE_RELEASE_SCHEMA_PYTHON="$offline_python" \
  bash "$archive_root/toolchain/release-json-schema-draft202012.sh" \
  --schema docs/release-audit-packet-v1.schema.json \
  --json docs/release-audit-packet-v1.sample.json >/dev/null
rm -rf "$offline_venv"
signoff_commit="0000000000000000000000000000000000000000"
cat > "$archive_dir/signoff-ci-success.json" <<EOF
[
  {"headSha":"$signoff_commit","status":"completed","conclusion":"success","url":"https://example.invalid/signoff-success"}
]
EOF
cat > "$archive_dir/signoff-inventory.md" <<'EOF'
# Inventory

- Path or URL: ./artifact
- SHA-256: 0000000000000000000000000000000000000000000000000000000000000000
- Reviewer: ci-smoke

Decision: go
EOF
signoff_json="$(bash scripts/public-devnet-v1/release-signoff-manifest.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-success.json" \
  --decision go \
  --operator ci-smoke \
  --reviewer ci-reviewer \
  --allow-dry-run \
  --threat-model-reviewed \
  --residual-risks-have-owners \
  --rpc-exposure-approved \
  --backups-restore-rehearsed \
  --halt-rollback-authority-agreed)"
SIGNOFF_JSON="$signoff_json" python3 - <<'PY'
import json
import os
import sys

doc = json.loads(os.environ["SIGNOFF_JSON"])
if doc.get("schema_version") != "release-signoff-manifest.v1" or doc.get("decision") != "go" or doc.get("issues"):
    print("release-signoff-manifest.sh did not emit a clean go manifest", file=sys.stderr)
    sys.exit(1)
PY
participant_commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
participant_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
participant_bundle="$archive_dir/participant-support-bundle"
mkdir -p "$participant_bundle"
cat > "$archive_dir/participant-rehearsal.log" <<EOF
participant-rehearsal: PASS commitment_hash=$participant_commit restored_sha256=$participant_sha restored_path=restored.bin support_bundle=$participant_bundle
EOF
cat > "$participant_bundle/manifest.json" <<EOF
{
  "commit_hash": "$participant_commit",
  "read_only": true,
  "commands": [
    {"name": "node-status", "exit_code": 0},
    {"name": "uploads-list", "exit_code": 0},
    {"name": "operator-pool", "exit_code": 0},
    {"name": "operator-challenge", "exit_code": 0}
  ]
}
EOF
audit_json="$(bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --signoff-manifest docs/release-signoff-manifest-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-success.json" \
  --participant-rehearsal-log "$archive_dir/participant-rehearsal.log" \
  --participant-support-bundle "$participant_bundle" \
  --allow-dry-run \
  --json)"
AUDIT_JSON="$audit_json" python3 - <<'PY'
import json
import os
import sys

doc = json.loads(os.environ["AUDIT_JSON"])
if doc.get("schema_version") != "release-audit-packet.v1" or doc.get("decision") != "go":
    print("release-audit-packet.sh did not emit a clean go packet", file=sys.stderr)
    sys.exit(1)
checks = {check.get("name"): check for check in doc.get("checks", [])}
participant = checks.get("participant rehearsal evidence")
if not participant or participant.get("status") != "pass" or "commitment_hash=" not in participant.get("message", ""):
    print("release-audit-packet.sh did not validate participant rehearsal evidence", file=sys.stderr)
    sys.exit(1)
policy = checks.get("participant smoke CI policy")
if not policy or policy.get("status") != "pass":
    print("release-audit-packet.sh did not validate participant smoke CI policy", file=sys.stderr)
    sys.exit(1)
PY
printf '%s\n' "$audit_json" > "$archive_dir/release-audit-packet.generated.json"
bash scripts/public-devnet-v1/release-json-schema-validate.sh --schema docs/release-audit-packet-v1.schema.json --json "$archive_dir/release-audit-packet.generated.json" >/dev/null
bash scripts/public-devnet-v1/release-json-schema-draft202012.sh --schema docs/release-audit-packet-v1.schema.json --json "$archive_dir/release-audit-packet.generated.json" >/dev/null
cat > "$archive_dir/participant-rehearsal-bad-bundle.log" <<EOF
participant-rehearsal: PASS commitment_hash=$participant_commit restored_sha256=$participant_sha restored_path=restored.bin support_bundle=$archive_dir/wrong-support-bundle
EOF
if bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --signoff-manifest docs/release-signoff-manifest-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-success.json" \
  --participant-rehearsal-log "$archive_dir/participant-rehearsal-bad-bundle.log" \
  --participant-support-bundle "$participant_bundle" \
  --allow-dry-run \
  --json >/dev/null 2>&1; then
  echo "release-audit-packet.sh accepted mismatched participant support bundle evidence" >&2
  exit 1
fi
fixture_root="scripts/public-devnet-v1/fixtures/participant-rehearsal-evidence-v1"
fixture_audit_json="$(bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --signoff-manifest docs/release-signoff-manifest-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-success.json" \
  --participant-rehearsal-log "$fixture_root/participant-rehearsal.log" \
  --participant-support-bundle "$fixture_root/support-bundle" \
  --allow-dry-run \
  --json)"
FIXTURE_AUDIT_JSON="$fixture_audit_json" python3 - <<'PY'
import json
import os
import sys

doc = json.loads(os.environ["FIXTURE_AUDIT_JSON"])
checks = {check.get("name"): check for check in doc.get("checks", [])}
participant = checks.get("participant rehearsal evidence")
if not participant or participant.get("status") != "pass":
    print("release-audit-packet.sh did not validate participant-rehearsal-evidence-v1 fixture", file=sys.stderr)
    sys.exit(1)
PY
fixture_via_dir_json="$(bash scripts/public-devnet-v1/release-audit-packet.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --signoff-manifest docs/release-signoff-manifest-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-success.json" \
  --participant-evidence-dir "$fixture_root" \
  --allow-dry-run \
  --json)"
FIXTURE_VIA_DIR_JSON="$fixture_via_dir_json" FIXTURE_ROOT="$fixture_root" python3 - <<'PY'
import json
import os
import sys

doc = json.loads(os.environ["FIXTURE_VIA_DIR_JSON"])
if doc.get("participant_evidence_dir") != os.environ["FIXTURE_ROOT"]:
    print("release-audit-packet.sh did not emit participant_evidence_dir from --participant-evidence-dir", file=sys.stderr)
    sys.exit(1)
checks = {check.get("name"): check for check in doc.get("checks", [])}
participant = checks.get("participant rehearsal evidence")
if not participant or participant.get("status") != "pass":
    print("release-audit-packet.sh did not validate participant evidence via --participant-evidence-dir", file=sys.stderr)
    sys.exit(1)
PY
cat > "$archive_dir/signoff-ci-failure.json" <<EOF
[
  {"headSha":"$signoff_commit","status":"completed","conclusion":"failure","url":"https://example.invalid/signoff-failure"}
]
EOF
if bash scripts/public-devnet-v1/release-signoff-manifest.sh \
  --release-evidence-json docs/release-evidence-v1.sample.json \
  --archive-dir "$archive_root" \
  --inventory "$archive_dir/signoff-inventory.md" \
  --ci-mock-runs "$archive_dir/signoff-ci-failure.json" \
  --decision go \
  --operator ci-smoke \
  --reviewer ci-reviewer \
  --allow-dry-run \
  --threat-model-reviewed \
  --residual-risks-have-owners \
  --rpc-exposure-approved \
  --backups-restore-rehearsed \
  --halt-rollback-authority-agreed >/dev/null 2>&1; then
  echo "release-signoff-manifest.sh accepted failing CI for a go decision" >&2
  exit 1
fi
printf '\ncorrupt\n' >> "$archive_root/network/genesis.json"
if bash scripts/public-devnet-v1/release-archive-validate.sh --archive-dir "$archive_root" --allow-dry-run >/dev/null 2>&1; then
  echo "release-archive-validate.sh accepted a corrupted checksum" >&2
  exit 1
fi
rm -rf "$archive_dir"
inventory_dir="$(mktemp -d)"
trap 'rm -rf "$inventory_dir"' EXIT
cat > "$inventory_dir/valid.md" <<'EOF'
# Inventory

- Path or URL: ./artifact
- SHA-256: 0000000000000000000000000000000000000000000000000000000000000000
- Reviewer: ci-smoke

Decision: go
EOF
bash scripts/public-devnet-v1/artifact-inventory-validate.sh "$inventory_dir/valid.md" >/dev/null
cat > "$inventory_dir/invalid.md" <<'EOF'
# Inventory

- Path or URL:
- SHA-256:
- Reviewer:

Decision:
EOF
if bash scripts/public-devnet-v1/artifact-inventory-validate.sh "$inventory_dir/invalid.md" >/dev/null 2>&1; then
  echo "artifact-inventory-validate.sh accepted an incomplete inventory" >&2
  exit 1
fi
fi

if (( run_rust )); then
echo "==> rustfmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release

echo "==> test (release)"
# M2.4.90 / M2.4.89 parity: heavy M5.36–M5.39 proptest + emission sims OOM at threads=4
# on contended runners (Windows local mirror, Linux GHA). Match ci-check.ps1 + GHA Linux.
# One retry after 15s on flake (M2.4.89).
for attempt in 1 2; do
  if cargo test --workspace --release -- --test-threads=2; then
    break
  fi
  if [ "$attempt" -eq 2 ]; then
    exit 1
  fi
  echo "cargo test attempt $attempt failed; retrying once after 15s..."
  sleep 15
done

echo "==> wasm32 build"
rustup target add wasm32-unknown-unknown
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
cargo test -p mfn-wasm --release --features wasm-full
# wasm-pack 0.15 mis-parses a prior package.json when `files`/`sideEffects` are arrays.
rm -rf mfn-wasm/demo/web/pkg
wasm-pack --log-level warn build --no-opt mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full

echo "==> cargo audit"
cargo audit
fi

echo "ci-check: OK"
