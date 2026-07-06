#!/usr/bin/env bash
# Guided recovery: support bundle -> recovery plan -> restore -> hash verify -> optional proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RPC="127.0.0.1:<RPC>"
RPC_API_KEY=""
WALLET="./wallet.json"
COMMIT_HASH="<COMMIT_HASH_HEX>"
OUTPUT_PATH="./restored.bin"
EXPECTED_SHA256=""
BUNDLE_DIR=""
DATA_DIR=""
REPLACE=0
PROVE=0
NO_BUILD=0
PLAN_ONLY=0
PEERS=()

usage() {
  cat <<'EOF'
usage: recovery-walkthrough.sh [options]

Options:
  --rpc HOST:PORT          mfnd JSON-RPC address
  --rpc-api-key KEY        RPC API key for auth-enabled nodes (not written to plans)
  --wallet FILE            wallet used for local upload artifacts
  --commit HASH            storage commitment hash
  --peer HOST:PORT         HTTP chunk peer; repeat for quorum peers
  --data-dir DIR           replica mfnd data dir for P2P inbox assembly
  --output FILE            restored payload output path
  --expected-sha256 HEX    expected restored payload SHA-256
  --bundle-dir DIR         support bundle output directory
  --replace                allow artifact/output overwrite commands
  --prove                  submit operator proof after restore and verification
  --no-build               use existing release mfn-cli binary
  --plan-only              print the guided flow without requiring binaries
  -h, --help               show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --rpc-api-key) RPC_API_KEY="${2:-}"; shift 2 ;;
    --wallet) WALLET="${2:-}"; shift 2 ;;
    --commit) COMMIT_HASH="${2:-}"; shift 2 ;;
    --peer) PEERS+=("${2:-}"); shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --output) OUTPUT_PATH="${2:-}"; shift 2 ;;
    --expected-sha256) EXPECTED_SHA256="${2:-}"; shift 2 ;;
    --bundle-dir) BUNDLE_DIR="${2:-}"; shift 2 ;;
    --replace) REPLACE=1; shift ;;
    --prove) PROVE=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "recovery-walkthrough: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

restore_mode="none"
if (( ${#PEERS[@]} > 0 )); then
  restore_mode="http"
elif [[ -n "$DATA_DIR" ]]; then
  restore_mode="p2p-inbox"
fi

if (( PLAN_ONLY )); then
  cat <<EOF
recovery-walkthrough: plan
  rpc=$RPC
  rpc_api_key_set=$([[ -n "$RPC_API_KEY" ]] && echo true || echo false)
  wallet=$WALLET
  commit_hash=$COMMIT_HASH
  restore_mode=$restore_mode
  output_path=$OUTPUT_PATH
  expected_sha256=${EXPECTED_SHA256:-<not checked>}
  flow=support-bundle -> recovery-plan -> restore -> optional sha256 verify -> optional operator prove
  note=real mode mutates only wallet-local artifact/output files, and only proves when --prove is set
EOF
  exit 0
fi

if [[ "$restore_mode" == "none" ]]; then
  echo "recovery-walkthrough: pass at least one --peer for HTTP restore or --data-dir for P2P inbox restore" >&2
  exit 1
fi

resolve_bin() {
  local bin="$REPO_ROOT/target/release/mfn-cli"
  if [[ ! -x "$bin" ]]; then
    bin="$REPO_ROOT/target/release/mfn-cli.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    echo "recovery-walkthrough: missing target/release/mfn-cli; rerun without --no-build or build mfn-cli --release" >&2
    exit 1
  fi
  printf '%s\n' "$bin"
}

run_checked() {
  local label="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then
    printf '%s\n' "$out"
  else
    local code=$?
    echo "recovery-walkthrough: $label failed with exit=$code" >&2
    echo "$out" >&2
    exit "$code"
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print tolower($1)}'
  else
    python3 - "$path" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
  fi
}

cd "$REPO_ROOT"
if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
fi
MFN_CLI="$(resolve_bin)"

support_args=(--rpc "$RPC" --wallet "$WALLET" --commit "$COMMIT_HASH" --no-build)
if [[ -n "$RPC_API_KEY" ]]; then
  support_args+=(--rpc-api-key "$RPC_API_KEY")
fi
if (( ${#PEERS[@]} > 0 )); then
  support_args+=(--peer "${PEERS[0]}")
fi
if [[ -n "$DATA_DIR" ]]; then
  support_args+=(--data-dir "$DATA_DIR")
fi
if [[ -n "$BUNDLE_DIR" ]]; then
  support_args+=(--output-dir "$BUNDLE_DIR")
fi
bash "$SCRIPT_DIR/support-bundle.sh" "${support_args[@]}"

plan_args=(--rpc "$RPC" --wallet "$WALLET" --commit "$COMMIT_HASH" --output "$OUTPUT_PATH")
for peer in "${PEERS[@]}"; do
  plan_args+=(--peer "$peer")
done
if [[ -n "$DATA_DIR" ]]; then
  plan_args+=(--data-dir "$DATA_DIR")
fi
if (( REPLACE )); then
  plan_args+=(--replace)
fi
bash "$SCRIPT_DIR/recovery-plan.sh" "${plan_args[@]}"

rpc_args=(--rpc "$RPC")
if [[ -n "$RPC_API_KEY" ]]; then
  rpc_args+=(--rpc-api-key "$RPC_API_KEY")
fi

if [[ "$restore_mode" == "http" ]]; then
  restore_args=("${rpc_args[@]}" --wallet "$WALLET" uploads fetch-http "$COMMIT_HASH" "$OUTPUT_PATH" "${PEERS[@]}")
  if (( REPLACE )); then
    restore_args+=(replace)
  fi
  restore_args+=(--json)
  run_checked "uploads fetch-http" "$MFN_CLI" "${restore_args[@]}"
else
  run_checked "operator inbox-status" "$MFN_CLI" "${rpc_args[@]}" operator inbox-status "$COMMIT_HASH" "$DATA_DIR" --json
  assemble_args=("${rpc_args[@]}" --wallet "$WALLET" operator assemble-inbox "$COMMIT_HASH" "$DATA_DIR")
  if (( REPLACE )); then
    assemble_args+=(replace)
  fi
  assemble_args+=(--json)
  run_checked "operator assemble-inbox" "$MFN_CLI" "${assemble_args[@]}"
  retrieve_args=(--wallet "$WALLET" uploads retrieve "$COMMIT_HASH" "$OUTPUT_PATH")
  if (( REPLACE )); then
    retrieve_args+=(replace)
  fi
  run_checked "uploads retrieve" "$MFN_CLI" "${retrieve_args[@]}"
fi

restored_sha="$(sha256_file "$OUTPUT_PATH")"
expected_sha_lower="$(printf '%s' "$EXPECTED_SHA256" | tr '[:upper:]' '[:lower:]')"
if [[ -n "$EXPECTED_SHA256" && "$expected_sha_lower" != "$restored_sha" ]]; then
  echo "recovery-walkthrough: restored hash mismatch expected=$expected_sha_lower restored=$restored_sha" >&2
  exit 1
fi
echo "recovery-walkthrough: restored_sha256=$restored_sha"

if (( PROVE )); then
  run_checked "operator prove" "$MFN_CLI" "${rpc_args[@]}" --wallet "$WALLET" operator prove "$COMMIT_HASH" --json
fi

echo "recovery-walkthrough: PASS output_path=$OUTPUT_PATH"
