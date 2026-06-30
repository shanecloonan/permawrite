#!/usr/bin/env bash
# End-to-end permanence demo: upload -> discover -> HTTP replicate -> retrieve -> prove.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
LOG_DIR="$SCRIPT_DIR/logs"
DEMO_ROOT="$SCRIPT_DIR/permanence-demo"
PAYLOAD_PATH=""
CHUNK_LISTEN="127.0.0.1:18780"
WAIT_UPLOAD_SECONDS=180
WAIT_PROOF_SECONDS=180
RPC=""
NO_BUILD=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: permanence-demo.sh [options]

Options:
  --rpc HOST:PORT             mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --wallet-dir DIR            demo wallet/payload directory (default: permanence-demo/)
  --payload FILE              payload to upload (default: generated 4096-byte sample)
  --chunk-listen HOST:PORT    local HTTP chunk server address (default: 127.0.0.1:18780)
  --wait-upload-seconds N     wait for upload discovery (default: 180)
  --wait-proof-seconds N      optional proof-list wait window (default: 180; 0 disables)
  --no-build                  use existing release binaries
  --plan-only                 print resolved flow without requiring binaries or funded wallets
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)
      RPC="${2:-}"
      shift 2
      ;;
    --wallet-dir)
      DEMO_ROOT="${2:-}"
      shift 2
      ;;
    --payload)
      PAYLOAD_PATH="${2:-}"
      shift 2
      ;;
    --chunk-listen)
      CHUNK_LISTEN="${2:-}"
      shift 2
      ;;
    --wait-upload-seconds)
      WAIT_UPLOAD_SECONDS="${2:-}"
      shift 2
      ;;
    --wait-proof-seconds)
      WAIT_PROOF_SECONDS="${2:-}"
      shift 2
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --plan-only)
      PLAN_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "permanence-demo: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_uint() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "permanence-demo: $name must be an integer >= $min" >&2
    exit 1
  fi
}

validate_uint wait-upload-seconds "$WAIT_UPLOAD_SECONDS" 1
validate_uint wait-proof-seconds "$WAIT_PROOF_SECONDS" 0

UPLOADER_WALLET="$DEMO_ROOT/uploader.json"
REPLICA_WALLET="$DEMO_ROOT/replica.json"
RESTORED_PATH="$DEMO_ROOT/restored.bin"
CHUNK_LOG="$LOG_DIR/permanence-demo-chunks.log"

resolve_rpc() {
  if [[ -n "$RPC" ]]; then
    printf '%s\n' "$RPC"
    return
  fi
  if [[ -f "$PORTS_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$PORTS_FILE"
    if [[ -n "${HUB_RPC:-}" ]]; then
      printf '%s\n' "$HUB_RPC"
      return
    fi
  fi
  echo "permanence-demo: pass --rpc HOST:PORT or run start-all.sh first" >&2
  return 1
}

resolve_bin() {
  local name="$1"
  local bin="$REPO_ROOT/target/release/$name"
  if [[ ! -x "$bin" ]]; then
    bin="$REPO_ROOT/target/release/$name.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    echo "permanence-demo: missing target/release/$name; rerun without --no-build or build release binaries" >&2
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
    echo "permanence-demo: $label failed with exit=$code" >&2
    echo "$out" >&2
    exit "$code"
  fi
}

parse_field() {
  local text="$1" key="$2" prefix="${2}="
  while IFS= read -r line; do
    if [[ "$line" == "$prefix"* ]]; then
      printf '%s\n' "${line#"$prefix"}"
      return
    fi
  done <<<"$text"
  echo "permanence-demo: stdout missing $prefix" >&2
  echo "$text" >&2
  exit 1
}

ensure_wallet() {
  local mfn_cli="$1" wallet_path="$2" label="$3"
  if [[ -f "$wallet_path" ]]; then
    echo "permanence-demo: using existing $label wallet at $wallet_path"
    return
  fi
  mkdir -p "$(dirname "$wallet_path")"
  run_checked "$label wallet new" "$mfn_cli" --wallet "$wallet_path" wallet new >/dev/null
  echo "permanence-demo: created $label wallet at $wallet_path"
}

ensure_payload() {
  if [[ -n "$PAYLOAD_PATH" ]]; then
    printf '%s\n' "$PAYLOAD_PATH"
    return
  fi
  local path="$DEMO_ROOT/payload.bin"
  if [[ ! -f "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    local py
    py="$(python_cmd)"
    "$py" - "$path" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes((i % 251 for i in range(4096))))
PY
  fi
  printf '%s\n' "$path"
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print tolower($1)}'
  else
    local py
    py="$(python_cmd)"
    "$py" - "$path" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
  fi
}

python_cmd() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
  elif command -v python >/dev/null 2>&1; then
    printf '%s\n' python
  else
    echo "permanence-demo: python3 or python is required to generate sample payloads without --payload" >&2
    exit 1
  fi
}

wait_uploads_list_contains() {
  local mfn_cli="$1" rpc_addr="$2" commit_hash="$3" timeout_seconds="$4"
  local deadline=$(( $(date +%s) + timeout_seconds ))
  local last_error=""
  while (( $(date +%s) <= deadline )); do
    local out
    if ! out="$("$mfn_cli" --rpc "$rpc_addr" uploads list --limit 50 2>&1)"; then
      last_error="uploads list failed: $out"
      echo "permanence-demo: uploads_list_wait retry_after_error=${last_error//$'\n'/ }"
      sleep 5
      continue
    fi
    if [[ "$out" == *"$commit_hash"* ]]; then
      return
    fi
    last_error=""
    sleep 5
  done
  local suffix=""
  if [[ -n "$last_error" ]]; then
    suffix="; last_error=$last_error"
  fi
  echo "permanence-demo: commitment $commit_hash was not indexed within ${timeout_seconds}s$suffix" >&2
  exit 1
}

wait_uploads_list_proven() {
  local mfn_cli="$1" rpc_addr="$2" commit_hash="$3" timeout_seconds="$4"
  local deadline=$(( $(date +%s) + timeout_seconds ))
  while (( $(date +%s) <= deadline )); do
    local out
    if ! out="$("$mfn_cli" --rpc "$rpc_addr" uploads list --limit 50 2>&1)"; then
      echo "permanence-demo: uploads_list_after_proof_wait retry_after_error=${out//$'\n'/ }"
      sleep 5
      continue
    fi
    if [[ "$out" == *"$commit_hash"* && "$out" == *"last_proven_height="* ]]; then
      return
    fi
    sleep 5
  done
}

if (( PLAN_ONLY )); then
  PLAN_RPC="$(resolve_rpc 2>/dev/null || printf '<pass --rpc HOST:PORT or run start-all.sh>')"
  echo "permanence-demo: plan"
  echo "  rpc=$PLAN_RPC"
  echo "  demo_dir=$DEMO_ROOT"
  echo "  chunk_listen=$CHUNK_LISTEN"
  echo "  flow=create/reuse wallets -> wallet upload -> uploads list -> serve-chunks -> uploads fetch-http -> operator prove -> uploads list"
  echo "  note=real mode requires the uploader wallet to hold enough devnet funds; use fund-wallet.sh with an operator faucet wallet first"
  exit 0
fi

RPC_ADDR="$(resolve_rpc)"
mkdir -p "$DEMO_ROOT" "$LOG_DIR"

if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
  cargo build -p mfn-storage-operator --release --bin mfn-storage-operator --manifest-path "$REPO_ROOT/Cargo.toml"
fi

MFN_CLI="$(resolve_bin mfn-cli)"
STORAGE_OPERATOR="$(resolve_bin mfn-storage-operator)"
PAYLOAD="$(ensure_payload)"

ensure_wallet "$MFN_CLI" "$UPLOADER_WALLET" uploader
ensure_wallet "$MFN_CLI" "$REPLICA_WALLET" replica

UPLOAD_OUT="$(run_checked "wallet upload" "$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$UPLOADER_WALLET" wallet upload "$PAYLOAD" --replication 3)"
COMMIT_HASH="$(parse_field "$UPLOAD_OUT" storage_commitment_hash)"
TX_ID="$(parse_field "$UPLOAD_OUT" tx_id)"
echo "permanence-demo: upload tx_id=$TX_ID commitment_hash=$COMMIT_HASH"

wait_uploads_list_contains "$MFN_CLI" "$RPC_ADDR" "$COMMIT_HASH" "$WAIT_UPLOAD_SECONDS"
echo "permanence-demo: discover=ok commitment_hash=$COMMIT_HASH"

rm -f "$CHUNK_LOG"
"$STORAGE_OPERATOR" serve-chunks --wallet "$UPLOADER_WALLET" --listen "$CHUNK_LISTEN" >"$CHUNK_LOG" 2>&1 &
CHUNK_PID=$!
cleanup_chunk_server() {
  if kill -0 "$CHUNK_PID" 2>/dev/null; then
    kill "$CHUNK_PID" 2>/dev/null || true
    wait "$CHUNK_PID" 2>/dev/null || true
  fi
}
trap cleanup_chunk_server EXIT
sleep 1
if ! kill -0 "$CHUNK_PID" 2>/dev/null; then
  echo "permanence-demo: chunk server exited early" >&2
  if [[ -f "$CHUNK_LOG" ]]; then
    cat "$CHUNK_LOG" >&2
  fi
  exit 1
fi

rm -f "$RESTORED_PATH"
RESTORE_OUT="$(run_checked "uploads fetch-http" "$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$REPLICA_WALLET" uploads fetch-http "$COMMIT_HASH" "$RESTORED_PATH" "$CHUNK_LISTEN")"
if [[ "$RESTORE_OUT" != *"fetch_http=ok"* ]]; then
  echo "permanence-demo: fetch-http did not report ok" >&2
  echo "$RESTORE_OUT" >&2
  exit 1
fi

PROOF_OUT="$(run_checked "operator prove" "$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$REPLICA_WALLET" operator prove "$COMMIT_HASH")"
POOL_LEN="$(parse_field "$PROOF_OUT" pool_len)"
echo "permanence-demo: prove=ok pool_len=$POOL_LEN"

SRC_HASH="$(sha256_file "$PAYLOAD")"
DST_HASH="$(sha256_file "$RESTORED_PATH")"
if [[ "$SRC_HASH" != "$DST_HASH" ]]; then
  echo "permanence-demo: restored hash mismatch source=$SRC_HASH restored=$DST_HASH" >&2
  exit 1
fi

if (( WAIT_PROOF_SECONDS > 0 )); then
  wait_uploads_list_proven "$MFN_CLI" "$RPC_ADDR" "$COMMIT_HASH" "$WAIT_PROOF_SECONDS"
fi

echo "permanence-demo: PASS commitment_hash=$COMMIT_HASH restored_sha256=$DST_HASH restored_path=$RESTORED_PATH"
