#!/usr/bin/env bash
# Full participant rehearsal: fund wallet -> upload -> restore -> verify -> prove -> support bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"

RPC=""
FAUCET_WALLET=""
REHEARSAL_DIR="$SCRIPT_DIR/participant-rehearsal"
PAYLOAD_PATH=""
CHUNK_LISTEN="127.0.0.1:18780"
AMOUNT=1000000
FEE=10000
RING_SIZE=8
WAIT_MINED_SECONDS=180
WAIT_UPLOAD_SECONDS=180
WAIT_PROOF_SECONDS=180
BUNDLE_DIR=""
NO_BUILD=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: participant-rehearsal.sh [options]

Options:
  --rpc HOST:PORT             mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --faucet-wallet FILE        funded operator wallet used as sender (required outside --plan-only)
  --rehearsal-dir DIR         wallet/payload/output directory (default: participant-rehearsal/)
  --payload FILE              payload to upload (default: generated permanence-demo sample)
  --chunk-listen HOST:PORT    local HTTP chunk server address (default: 127.0.0.1:18780)
  --amount N                  amount to fund uploader wallet (default: 1000000)
  --fee N                     funding transfer fee (default: 10000)
  --ring-size N               funding transfer ring size (default: 8)
  --wait-mined-seconds N      wait for funding balance delta (default: 180; 0 disables)
  --wait-upload-seconds N     wait for upload discovery (default: 180)
  --wait-proof-seconds N      optional proof-list wait window (default: 180; 0 disables)
  --bundle-dir DIR            support bundle output directory
  --no-build                  use existing release binaries
  --plan-only                 print the full rehearsal flow without requiring binaries or a faucet wallet
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-wallet) FAUCET_WALLET="${2:-}"; shift 2 ;;
    --rehearsal-dir) REHEARSAL_DIR="${2:-}"; shift 2 ;;
    --payload) PAYLOAD_PATH="${2:-}"; shift 2 ;;
    --chunk-listen) CHUNK_LISTEN="${2:-}"; shift 2 ;;
    --amount) AMOUNT="${2:-}"; shift 2 ;;
    --fee) FEE="${2:-}"; shift 2 ;;
    --ring-size) RING_SIZE="${2:-}"; shift 2 ;;
    --wait-mined-seconds) WAIT_MINED_SECONDS="${2:-}"; shift 2 ;;
    --wait-upload-seconds) WAIT_UPLOAD_SECONDS="${2:-}"; shift 2 ;;
    --wait-proof-seconds) WAIT_PROOF_SECONDS="${2:-}"; shift 2 ;;
    --bundle-dir) BUNDLE_DIR="${2:-}"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "participant-rehearsal: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_uint() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "participant-rehearsal: $name must be an integer >= $min" >&2
    exit 1
  fi
}

validate_uint amount "$AMOUNT" 1
validate_uint fee "$FEE" 0
validate_uint ring-size "$RING_SIZE" 2
validate_uint wait-mined-seconds "$WAIT_MINED_SECONDS" 0
validate_uint wait-upload-seconds "$WAIT_UPLOAD_SECONDS" 1
validate_uint wait-proof-seconds "$WAIT_PROOF_SECONDS" 0

UPLOADER_WALLET="$REHEARSAL_DIR/uploader.json"
REPLICA_WALLET="$REHEARSAL_DIR/replica.json"

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
  echo "participant-rehearsal: pass --rpc HOST:PORT or run start-all.sh first" >&2
  return 1
}

run_checked() {
  local label="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then
    printf '%s\n' "$out"
  else
    local code=$?
    echo "participant-rehearsal: $label failed with exit=$code" >&2
    echo "$out" >&2
    exit "$code"
  fi
}

parse_token_field() {
  local text="$1" key="$2" line token
  while IFS= read -r line; do
    for token in $line; do
      if [[ "$token" == "$key="* ]]; then
        printf '%s\n' "${token#"$key="}"
        return
      fi
    done
  done <<<"$text"
  echo "participant-rehearsal: stdout missing $key=<value>" >&2
  echo "$text" >&2
  exit 1
}

if (( PLAN_ONLY )); then
  PLAN_RPC="$(resolve_rpc 2>/dev/null || printf '<pass --rpc HOST:PORT or run start-all.sh>')"
  PLAN_FAUCET="${FAUCET_WALLET:-<required --faucet-wallet FILE for real run>}"
  echo "participant-rehearsal: plan"
  echo "  rpc=$PLAN_RPC"
  echo "  rehearsal_dir=$REHEARSAL_DIR"
  echo "  faucet_wallet=$PLAN_FAUCET"
  echo "  uploader_wallet=$UPLOADER_WALLET"
  echo "  replica_wallet=$REPLICA_WALLET"
  echo "  chunk_listen=$CHUNK_LISTEN"
  echo "  flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle"
  echo "  note=real mode requires a funded faucet wallet with public-devnet/test funds only"
  echo "  next=rerun without --plan-only after choosing a funded operator faucet wallet; outputs end with support_bundle=<dir>"
  exit 0
fi

if [[ -z "$FAUCET_WALLET" ]]; then
  echo "participant-rehearsal: --faucet-wallet FILE is required outside --plan-only" >&2
  exit 1
fi
if [[ ! -f "$FAUCET_WALLET" ]]; then
  echo "participant-rehearsal: faucet wallet not found: $FAUCET_WALLET" >&2
  exit 1
fi

RPC_ADDR="$(resolve_rpc)"
mkdir -p "$REHEARSAL_DIR"
cd "$REPO_ROOT"

if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
  cargo build -p mfn-storage-operator --release --bin mfn-storage-operator --manifest-path "$REPO_ROOT/Cargo.toml"
fi

fund_args=(--rpc "$RPC_ADDR" --faucet-wallet "$FAUCET_WALLET" --recipient-wallet "$UPLOADER_WALLET" --amount "$AMOUNT" --fee "$FEE" --ring-size "$RING_SIZE" --wait-mined-seconds "$WAIT_MINED_SECONDS" --no-build)
run_checked "fund-wallet" bash "$SCRIPT_DIR/fund-wallet.sh" "${fund_args[@]}"

demo_args=(--rpc "$RPC_ADDR" --wallet-dir "$REHEARSAL_DIR" --chunk-listen "$CHUNK_LISTEN" --wait-upload-seconds "$WAIT_UPLOAD_SECONDS" --wait-proof-seconds "$WAIT_PROOF_SECONDS" --no-build)
if [[ -n "$PAYLOAD_PATH" ]]; then
  demo_args+=(--payload "$PAYLOAD_PATH")
fi
DEMO_OUT="$(run_checked "permanence-demo" bash "$SCRIPT_DIR/permanence-demo.sh" "${demo_args[@]}")"
printf '%s\n' "$DEMO_OUT"
COMMIT_HASH="$(parse_token_field "$DEMO_OUT" commitment_hash)"
RESTORED_SHA="$(parse_token_field "$DEMO_OUT" restored_sha256)"
RESTORED_PATH="$(parse_token_field "$DEMO_OUT" restored_path)"

support_args=(--rpc "$RPC_ADDR" --wallet "$REPLICA_WALLET" --commit "$COMMIT_HASH" --no-build)
if [[ -n "$BUNDLE_DIR" ]]; then
  support_args+=(--output-dir "$BUNDLE_DIR")
fi
SUPPORT_OUT="$(run_checked "support-bundle" bash "$SCRIPT_DIR/support-bundle.sh" "${support_args[@]}")"
printf '%s\n' "$SUPPORT_OUT"
SUPPORT_BUNDLE="$(parse_token_field "$SUPPORT_OUT" output_dir)"

echo "participant-rehearsal: PASS commitment_hash=$COMMIT_HASH restored_sha256=$RESTORED_SHA restored_path=$RESTORED_PATH support_bundle=$SUPPORT_BUNDLE"
