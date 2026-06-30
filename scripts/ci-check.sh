#!/usr/bin/env bash
# Mirror .github/workflows/ci.yml locally before pushing to main.
set -euo pipefail
cd "$(dirname "$0")/.."

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

add_missing_command cargo "Install Rust from https://rustup.rs/ and reopen the shell."
add_missing_command rustup "Install Rust from https://rustup.rs/ and reopen the shell."
add_missing_command pwsh "Install PowerShell 7+ to parse-check Windows helper scripts."
add_missing_command python3 "Install Python 3 to validate release-evidence JSON output."
add_missing_command wasm-pack "Install with: cargo install wasm-pack --locked."
add_missing_command cargo-audit "Install with: cargo install cargo-audit --locked."
if ((${#missing_tools[@]} > 0)); then
  printf '%s\n' "${missing_tools[@]}" >&2
  exit 127
fi

echo "==> public-devnet scripts"
for script in scripts/*.sh scripts/public-devnet-v1/*.sh; do
  bash -n "$script"
done
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
rehearsal_plan="$(bash scripts/public-devnet-v1/participant-rehearsal.sh --plan-only --rpc 127.0.0.1:18731 --faucet-wallet ./faucet.json)"
if [[ "$rehearsal_plan" != *"flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle"* || "$rehearsal_plan" != *"public-devnet/test funds only"* ]]; then
  printf '%s\n' "$rehearsal_plan" >&2
  exit 1
fi
smoke_plan="$(bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only --rpc 127.0.0.1:18731)"
if [[ "$smoke_plan" != *"flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh"* || "$smoke_plan" != *"custom faucet wallets are never overwritten"* ]]; then
  printf '%s\n' "$smoke_plan" >&2
  exit 1
fi
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
  $rehearsalPlan = (pwsh -NoProfile -File scripts/public-devnet-v1/participant-rehearsal.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -FaucetWallet ./faucet.json) -join "`n"
  if ($rehearsalPlan -notmatch "flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle" -or $rehearsalPlan -notmatch "public-devnet/test funds only") {
    $rehearsalPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
  $smokePlan = (pwsh -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly -Rpc 127.0.0.1:18731) -join "`n"
  if ($smokePlan -notmatch "flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh" -or $smokePlan -notmatch "custom faucet wallets are never overwritten") {
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
for path in ("docs/release-evidence-v1.schema.json", "docs/release-evidence-v1.sample.json"):
    with open(path, "r", encoding="utf-8") as handle:
        json.load(handle)
PY
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
archive_plan="$(bash scripts/public-devnet-v1/release-archive-dry-run.sh --plan-only --release-evidence-json docs/release-evidence-v1.sample.json)"
if [[ "$archive_plan" != *"release-archive-dry-run: PLAN OK"* ]]; then
  echo "release-archive-dry-run.sh plan mode did not complete successfully" >&2
  exit 1
fi
archive_dir="$(mktemp -d)"
archive_run="$(bash scripts/public-devnet-v1/release-archive-dry-run.sh --output-dir "$archive_dir" --release-evidence-json docs/release-evidence-v1.sample.json)"
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
  evidence/checksums.sha256; do
  if [[ ! -f "$archive_root/$required_path" ]]; then
    echo "release-archive-dry-run.sh missing staged artifact '$required_path'" >&2
    exit 1
  fi
done
bash scripts/public-devnet-v1/release-archive-validate.sh --archive-dir "$archive_root" --allow-dry-run >/dev/null
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

echo "==> rustfmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release

echo "==> test (release)"
cargo test --workspace --release -- --test-threads=4

echo "==> wasm32 build"
rustup target add wasm32-unknown-unknown
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
cargo test -p mfn-wasm --release --features wasm-full
wasm-pack build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full

echo "==> cargo audit"
cargo audit

echo "ci-check: OK"
