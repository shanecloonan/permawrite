#!/usr/bin/env bash
# B-15 / lane 3: outside-in JOIN_TESTNET rehearsal (HTTP faucet + light-scan + permanence).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"

RPC=""
FAUCET_URL="http://127.0.0.1:8788"
OBSERVER_PROXY_URL="http://127.0.0.1:8787/rpc"
CHECKPOINT_LOG="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
REHEARSAL_DIR="$SCRIPT_DIR/join-testnet-rehearsal"
EVIDENCE_DIR=""
EVIDENCE_LOG=""
WAIT_MINED_SECONDS=300
WAIT_UPLOAD_SECONDS=360
WAIT_PROOF_SECONDS=240
NO_BUILD=0
PLAN_ONLY=0
SKIP_PERMANENCE=0

EXPECTED_GENESIS="454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"

usage() {
  cat <<'EOF'
usage: join-testnet-rehearsal.sh [options]

Options:
  --rpc HOST:PORT             synced local mfnd JSON-RPC (required outside --plan-only)
  --faucet-url URL            public testnet HTTP faucet (default: http://127.0.0.1:8788)
  --observer-proxy-url URL    read-only observer proxy for cross-check (default: http://127.0.0.1:8787/rpc)
  --checkpoint-log FILE       signed checkpoint log for light-scan (default: public_devnet_v1.checkpoints.jsonl)
  --rehearsal-dir DIR         wallet/payload directory (default: join-testnet-rehearsal/)
  --evidence-dir DIR          optional evidence directory
  --evidence-log FILE         optional evidence log path
  --wait-mined-seconds N      faucet funding wait (default: 300)
  --wait-upload-seconds N     upload discovery wait (default: 360)
  --wait-proof-seconds N      proof wait (default: 240)
  --skip-permanence           stop after faucet + light-scan (no upload demo)
  --no-build                  use existing release binaries
  --plan-only                 print resolved flow without network I/O
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-url) FAUCET_URL="${2:-}"; shift 2 ;;
    --observer-proxy-url) OBSERVER_PROXY_URL="${2:-}"; shift 2 ;;
    --checkpoint-log) CHECKPOINT_LOG="${2:-}"; shift 2 ;;
    --rehearsal-dir) REHEARSAL_DIR="${2:-}"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --evidence-log) EVIDENCE_LOG="${2:-}"; shift 2 ;;
    --wait-mined-seconds) WAIT_MINED_SECONDS="${2:-}"; shift 2 ;;
    --wait-upload-seconds) WAIT_UPLOAD_SECONDS="${2:-}"; shift 2 ;;
    --wait-proof-seconds) WAIT_PROOF_SECONDS="${2:-}"; shift 2 ;;
    --skip-permanence) SKIP_PERMANENCE=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "join-testnet-rehearsal: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

UPLOADER_WALLET="$REHEARSAL_DIR/uploader.json"
REPLICA_WALLET="$REHEARSAL_DIR/replica.json"
if [[ -z "$EVIDENCE_LOG" ]]; then
  if [[ -n "$EVIDENCE_DIR" ]]; then
    EVIDENCE_LOG="$EVIDENCE_DIR/join-testnet-rehearsal.log"
  else
    EVIDENCE_LOG="$REHEARSAL_DIR/join-testnet-rehearsal.log"
  fi
fi

if (( PLAN_ONLY )); then
  plan_rpc="${RPC:-<required --rpc HOST:PORT (synced local observer>}"
  echo "join-testnet-rehearsal: plan"
  echo "  rpc=$plan_rpc"
  echo "  faucet_url=$FAUCET_URL"
  echo "  observer_proxy_url=$OBSERVER_PROXY_URL"
  echo "  checkpoint_log=$CHECKPOINT_LOG"
  echo "  rehearsal_dir=$REHEARSAL_DIR"
  echo "  uploader_wallet=$UPLOADER_WALLET"
  echo "  evidence_log=$EVIDENCE_LOG"
  echo "  flow=verify genesis -> checkpoint-log verify -> wallet new -> fund-wallet-http -> wallet light-scan --checkpoint-log -> observer proxy cross-check -> permanence-demo -> support-bundle"
  echo "  note=matches docs/JOIN_TESTNET.md outside-user path after local sync"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  echo "join-testnet-rehearsal: --rpc HOST:PORT is required outside --plan-only" >&2
  exit 1
fi
if [[ ! -f "$CHECKPOINT_LOG" ]]; then
  echo "join-testnet-rehearsal: checkpoint log missing: $CHECKPOINT_LOG" >&2
  exit 1
fi

MFN_CLI="$REPO_ROOT/target/release/mfn-cli"
if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
  cargo build -p mfn-storage-operator --release --bin mfn-storage-operator --manifest-path "$REPO_ROOT/Cargo.toml"
fi

parse_kv() {
  local key="$1" text="$2"
  printf '%s\n' "$text" | tr -d '\r' | sed -n "s/^${key}=//p" | head -1
}

mkdir -p "$REHEARSAL_DIR"
if [[ -n "$EVIDENCE_DIR" ]]; then
  mkdir -p "$EVIDENCE_DIR"
fi

tip_out="$("$MFN_CLI" --rpc "$RPC" tip 2>&1)"
genesis_id="$(parse_kv genesis_id "$tip_out")"
tip_height="$(parse_kv tip_height "$tip_out")"
echo "join-testnet-rehearsal: local genesis_id=$genesis_id tip_height=$tip_height"
if [[ "$genesis_id" != "$EXPECTED_GENESIS" ]]; then
  echo "join-testnet-rehearsal: wrong genesis_id (expected $EXPECTED_GENESIS)" >&2
  exit 1
fi
if [[ ! "$tip_height" =~ ^[0-9]+$ ]] || (( tip_height <= 0 )); then
  echo "join-testnet-rehearsal: local node not synced (tip_height=$tip_height)" >&2
  exit 1
fi

"$MFN_CLI" checkpoint-log verify "$CHECKPOINT_LOG"
echo "join-testnet-rehearsal: checkpoint_log_verify=PASS"

if [[ ! -f "$UPLOADER_WALLET" ]]; then
  "$MFN_CLI" --wallet "$UPLOADER_WALLET" wallet new >/dev/null
fi
if [[ ! -f "$REPLICA_WALLET" ]]; then
  "$MFN_CLI" --wallet "$REPLICA_WALLET" wallet new >/dev/null
fi

fund_args=(
  --rpc "$RPC"
  --faucet-url "$FAUCET_URL"
  --recipient-wallet "$UPLOADER_WALLET"
  --checkpoint-log "$CHECKPOINT_LOG"
  --wait-mined-seconds "$WAIT_MINED_SECONDS"
  --min-owned-count 2
)
if (( NO_BUILD )); then fund_args+=(--no-build); fi
bash "$SCRIPT_DIR/fund-wallet-http.sh" "${fund_args[@]}"
echo "join-testnet-rehearsal: fund_wallet_http=PASS"

"$MFN_CLI" --rpc "$RPC" --wallet "$UPLOADER_WALLET" wallet light-scan \
  --checkpoint-log "$CHECKPOINT_LOG"
echo "join-testnet-rehearsal: light_scan_checkpoint=PASS"

if command -v curl >/dev/null 2>&1; then
  proxy_body='{"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}}'
  proxy_resp="$(curl -fsS -X POST "$OBSERVER_PROXY_URL" \
    -H "Content-Type: application/json" \
    --data-binary "$proxy_body" 2>&1)" || {
    echo "join-testnet-rehearsal: observer proxy get_tip failed" >&2
    echo "$proxy_resp" >&2
    exit 1
  }
  proxy_genesis="$(printf '%s' "$proxy_resp" | sed -n 's/.*"genesis_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  proxy_tip="$(printf '%s' "$proxy_resp" | sed -n 's/.*"tip_height"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)"
  echo "join-testnet-rehearsal: observer_proxy genesis_id=$proxy_genesis tip_height=$proxy_tip"
  if [[ "$proxy_genesis" != "$EXPECTED_GENESIS" ]]; then
    echo "join-testnet-rehearsal: observer proxy genesis mismatch" >&2
    exit 1
  fi
  if [[ "$proxy_tip" =~ ^[0-9]+$ ]] && (( proxy_tip + 8 >= tip_height )); then
    echo "join-testnet-rehearsal: observer_proxy_cross_check=PASS"
  else
    echo "join-testnet-rehearsal: observer proxy lag too high (local=$tip_height proxy=$proxy_tip)" >&2
    exit 1
  fi
else
  echo "join-testnet-rehearsal: WARN curl missing — skipped observer proxy cross-check"
fi

commit=""
restored_sha=""
restored_path=""
bundle=""

if (( ! SKIP_PERMANENCE )); then
  demo_args=(
    --rpc "$RPC"
    --wallet-dir "$REHEARSAL_DIR"
    --wait-upload-seconds "$WAIT_UPLOAD_SECONDS"
    --wait-proof-seconds "$WAIT_PROOF_SECONDS"
  )
  if (( NO_BUILD )); then demo_args+=(--no-build); fi
  demo_out="$(bash "$SCRIPT_DIR/permanence-demo.sh" "${demo_args[@]}")"
  printf '%s\n' "$demo_out"
  commit="$(printf '%s' "$demo_out" | sed -n 's/.*commitment_hash=\([0-9a-fA-F]*\).*/\1/p' | head -1)"
  restored_sha="$(printf '%s' "$demo_out" | sed -n 's/.*restored_sha256=\([0-9a-fA-F]*\).*/\1/p' | head -1)"
  restored_path="$(printf '%s' "$demo_out" | sed -n 's/.*restored_path=\([^ ]*\).*/\1/p' | head -1)"
  if [[ -z "$commit" || -z "$restored_sha" ]]; then
    echo "join-testnet-rehearsal: permanence-demo missing commitment_hash/restored_sha256" >&2
    exit 1
  fi

  support_args=(
    --rpc "$RPC"
    --wallet "$REPLICA_WALLET"
    --commit "$commit"
  )
  if [[ -n "$EVIDENCE_DIR" ]]; then
    support_args+=(--output-dir "$EVIDENCE_DIR/support-bundle")
  fi
  if (( NO_BUILD )); then support_args+=(--no-build); fi
  support_out="$(bash "$SCRIPT_DIR/support-bundle.sh" "${support_args[@]}")"
  printf '%s\n' "$support_out"
  bundle="$(printf '%s' "$support_out" | sed -n 's/^output_dir=//p' | head -1)"
fi

pass_line="join-testnet-rehearsal: PASS genesis_id=$genesis_id tip_height=$tip_height faucet_http=true light_scan_checkpoint=true"
if [[ -n "$commit" ]]; then
  pass_line+=" commitment_hash=$commit restored_sha256=$restored_sha restored_path=$restored_path support_bundle=$bundle"
fi
mkdir -p "$(dirname "$EVIDENCE_LOG")"
printf '%s\n' "$pass_line" >"$EVIDENCE_LOG"
echo "$pass_line"
echo "join-testnet-rehearsal: evidence_log=$EVIDENCE_LOG"
