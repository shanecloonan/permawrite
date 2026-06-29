#!/usr/bin/env bash
# Collect participant-safe JSON diagnostics for public-devnet support.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"

RPC=""
RPC_API_KEY=""
WALLET=""
COMMIT_HASH=""
PEER=""
CHUNK_INDEX=0
DATA_DIR=""
DATA_ROOT=""
CLAIM_PUBKEY=""
RELEASE_EVIDENCE=""
OUTPUT_DIR=""
NO_BUILD=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: support-bundle.sh [options]

Options:
  --rpc HOST:PORT          mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --rpc-api-key KEY        RPC API key for auth-enabled nodes (not written to manifest)
  --wallet FILE            wallet for wallet-local diagnostics
  --commit HASH            storage commitment hash for challenge diagnostics
  --peer HOST:PORT         HTTP chunk peer for fetch-chunk diagnostics
  --chunk-index N          chunk index for fetch-chunk diagnostics (default: 0)
  --data-dir DIR           replica mfnd data dir for inbox diagnostics
  --data-root HEX          data root for claims-for diagnostics
  --claim-pubkey HEX       claim public key for claims-by-pubkey diagnostics
  --release-evidence FILE  release-evidence.v1 JSON to validate and copy into the bundle
  --output-dir DIR         bundle output directory (default: support-bundle/<UTC timestamp>)
  --no-build               use existing release mfn-cli binary
  --plan-only              print planned read-only captures without requiring binaries
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)
      RPC="${2:-}"
      shift 2
      ;;
    --rpc-api-key)
      RPC_API_KEY="${2:-}"
      shift 2
      ;;
    --wallet)
      WALLET="${2:-}"
      shift 2
      ;;
    --commit)
      COMMIT_HASH="${2:-}"
      shift 2
      ;;
    --peer)
      PEER="${2:-}"
      shift 2
      ;;
    --chunk-index)
      CHUNK_INDEX="${2:-}"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="${2:-}"
      shift 2
      ;;
    --data-root)
      DATA_ROOT="${2:-}"
      shift 2
      ;;
    --claim-pubkey)
      CLAIM_PUBKEY="${2:-}"
      shift 2
      ;;
    --release-evidence)
      RELEASE_EVIDENCE="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
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
      echo "support-bundle: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! "$CHUNK_INDEX" =~ ^[0-9]+$ ]]; then
  echo "support-bundle: --chunk-index must be an integer >= 0" >&2
  exit 1
fi

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
  echo "support-bundle: pass --rpc HOST:PORT or run start-all.sh first" >&2
  return 1
}

resolve_bin() {
  local bin="$REPO_ROOT/target/release/mfn-cli"
  if [[ ! -x "$bin" ]]; then
    bin="$REPO_ROOT/target/release/mfn-cli.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    echo "support-bundle: missing target/release/mfn-cli; rerun without --no-build or build mfn-cli --release" >&2
    exit 1
  fi
  printf '%s\n' "$bin"
}

COMMAND_NAMES=()

add_command() {
  local name="$1"
  COMMAND_NAMES+=("$name")
}

build_plan() {
  add_command "node-status"
  add_command "uploads-list"
  add_command "operator-pool"
  if [[ -n "$WALLET" ]]; then
    add_command "wallet-status"
    add_command "wallet-backup-info"
    add_command "uploads-local"
    add_command "uploads-status"
    add_command "operator-artifacts"
  fi
  if [[ -n "$COMMIT_HASH" ]]; then
    add_command "operator-challenge"
    if [[ -n "$PEER" ]]; then
      add_command "operator-fetch-chunk"
    fi
    if [[ -n "$DATA_DIR" ]]; then
      add_command "operator-inbox-status"
    fi
  fi
  if [[ -n "$DATA_ROOT" ]]; then
    add_command "claims-for"
  fi
  if [[ -n "$CLAIM_PUBKEY" ]]; then
    add_command "claims-by-pubkey"
  fi
}

print_plan_command() {
  local name="$1"
  local auth=""
  if [[ -n "$RPC_API_KEY" ]]; then
    auth=" --rpc-api-key <KEY>"
  fi
  local wallet_arg=""
  if [[ -n "$WALLET" ]]; then
    wallet_arg=" --wallet $WALLET"
  fi
  case "$name" in
    node-status) echo "mfn-cli --rpc $RPC_ADDR$auth status" ;;
    uploads-list) echo "mfn-cli --rpc $RPC_ADDR$auth uploads list --include-claims --json" ;;
    operator-pool) echo "mfn-cli --rpc $RPC_ADDR$auth operator pool --json" ;;
    wallet-status) echo "mfn-cli --rpc $RPC_ADDR$auth --wallet $WALLET wallet status --json" ;;
    wallet-backup-info) echo "mfn-cli --wallet $WALLET wallet backup-info --json" ;;
    uploads-local) echo "mfn-cli --wallet $WALLET uploads local --json" ;;
    uploads-status) echo "mfn-cli --rpc $RPC_ADDR$auth --wallet $WALLET uploads status --json" ;;
    operator-artifacts) echo "mfn-cli --wallet $WALLET operator artifacts --json" ;;
    operator-challenge) echo "mfn-cli --rpc $RPC_ADDR$auth operator challenge $COMMIT_HASH --json" ;;
    operator-fetch-chunk) echo "mfn-cli --rpc $RPC_ADDR$auth$wallet_arg operator fetch-chunk $COMMIT_HASH $CHUNK_INDEX $PEER --json" ;;
    operator-inbox-status) echo "mfn-cli --rpc $RPC_ADDR$auth operator inbox-status $COMMIT_HASH $DATA_DIR --json" ;;
    claims-for) echo "mfn-cli --rpc $RPC_ADDR$auth claims for $DATA_ROOT --json" ;;
    claims-by-pubkey) echo "mfn-cli --rpc $RPC_ADDR$auth claims by-pubkey $CLAIM_PUBKEY --json" ;;
    *) echo "support-bundle: internal error: unknown command $name" >&2; return 1 ;;
  esac
}

run_bundle_command() {
  local name="$1"
  local rpc_prefix=(--rpc "$RPC_ADDR")
  if [[ -n "$RPC_API_KEY" ]]; then
    rpc_prefix+=(--rpc-api-key "$RPC_API_KEY")
  fi
  local wallet_prefix=()
  if [[ -n "$WALLET" ]]; then
    wallet_prefix=(--wallet "$WALLET")
  fi
  case "$name" in
    node-status) "$MFN_CLI" "${rpc_prefix[@]}" status ;;
    uploads-list) "$MFN_CLI" "${rpc_prefix[@]}" uploads list --include-claims --json ;;
    operator-pool) "$MFN_CLI" "${rpc_prefix[@]}" operator pool --json ;;
    wallet-status) "$MFN_CLI" "${rpc_prefix[@]}" --wallet "$WALLET" wallet status --json ;;
    wallet-backup-info) "$MFN_CLI" --wallet "$WALLET" wallet backup-info --json ;;
    uploads-local) "$MFN_CLI" --wallet "$WALLET" uploads local --json ;;
    uploads-status) "$MFN_CLI" "${rpc_prefix[@]}" --wallet "$WALLET" uploads status --json ;;
    operator-artifacts) "$MFN_CLI" --wallet "$WALLET" operator artifacts --json ;;
    operator-challenge) "$MFN_CLI" "${rpc_prefix[@]}" operator challenge "$COMMIT_HASH" --json ;;
    operator-fetch-chunk) "$MFN_CLI" "${rpc_prefix[@]}" "${wallet_prefix[@]}" operator fetch-chunk "$COMMIT_HASH" "$CHUNK_INDEX" "$PEER" --json ;;
    operator-inbox-status) "$MFN_CLI" "${rpc_prefix[@]}" operator inbox-status "$COMMIT_HASH" "$DATA_DIR" --json ;;
    claims-for) "$MFN_CLI" "${rpc_prefix[@]}" claims for "$DATA_ROOT" --json ;;
    claims-by-pubkey) "$MFN_CLI" "${rpc_prefix[@]}" claims by-pubkey "$CLAIM_PUBKEY" --json ;;
    *) echo "support-bundle: internal error: unknown command $name" >&2; return 1 ;;
  esac
}

json_string() {
  local value="$1"
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$value"
}

json_nullable_string() {
  local value="$1"
  if [[ -n "$value" ]]; then
    json_string "$value"
  else
    printf 'null\n'
  fi
}

validate_release_evidence() {
  if [[ -z "$RELEASE_EVIDENCE" ]]; then
    cat <<'JSON'
{"provided":false,"valid":false,"source":null,"copied_file":null,"schema_version":null,"generated_utc":null,"commit_head":null,"rpc_endpoint":null,"note":"not provided"}
JSON
    return
  fi
  python3 - "$RELEASE_EVIDENCE" <<'PY'
import json
import os
import sys

path = os.path.abspath(sys.argv[1])
with open(path, "r", encoding="utf-8") as handle:
    doc = json.load(handle)
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
    ("operator_signoff", "operator"),
]
for field_path in required_paths:
    current = doc
    for key in field_path:
        current = current.get(key) if isinstance(current, dict) else None
    if current in (None, ""):
        raise SystemExit(
            "support-bundle: release evidence is missing a required release-evidence.v1 field: "
            + ".".join(field_path)
        )
if doc.get("schema_version") != "release-evidence.v1":
    raise SystemExit("support-bundle: release evidence schema_version must be release-evidence.v1")
print(json.dumps({
    "provided": True,
    "valid": True,
    "source": path,
    "copied_file": "release-evidence.json",
    "schema_version": doc["schema_version"],
    "generated_utc": doc["generated_utc"],
    "commit_head": doc["commit"]["head"],
    "rpc_endpoint": doc["rpc"]["endpoint"],
    "note": "",
}, separators=(",", ":")))
PY
}

RPC_ADDR="$(resolve_rpc)"
build_plan
RELEASE_EVIDENCE_JSON="$(validate_release_evidence)"

if (( PLAN_ONLY )); then
  echo "support-bundle: plan"
  echo "  rpc=$RPC_ADDR"
  if [[ -n "$RPC_API_KEY" ]]; then
    echo "  rpc_api_key_set=true"
  else
    echo "  rpc_api_key_set=false"
  fi
  echo "  wallet=${WALLET:-<none; wallet-local diagnostics skipped>}"
  echo "  commit_hash=${COMMIT_HASH:-<none; challenge diagnostics skipped>}"
  echo "  peer=${PEER:-<none; fetch-chunk skipped>}"
  echo "  chunk_index=$CHUNK_INDEX"
  echo "  data_dir=${DATA_DIR:-<none; inbox diagnostics skipped>}"
  echo "  data_root=${DATA_ROOT:-<none; claims-for skipped>}"
  echo "  claim_pubkey=${CLAIM_PUBKEY:-<none; claims-by-pubkey skipped>}"
  if [[ -n "$RELEASE_EVIDENCE" ]]; then
    echo "  release_evidence=$RELEASE_EVIDENCE (valid release-evidence.v1)"
  else
    echo "  release_evidence=<none; release sign-off evidence not bundled>"
  fi
  for i in "${!COMMAND_NAMES[@]}"; do
    echo "  $(print_plan_command "${COMMAND_NAMES[$i]}") > ${COMMAND_NAMES[$i]}.json"
  done
  echo "  note=commands are read-only/local-inspection; this script does not send funds, scan wallets, upload data, or submit proofs"
  exit 0
fi

cd "$REPO_ROOT"
if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli
fi
MFN_CLI="$(resolve_bin)"

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$SCRIPT_DIR/support-bundle/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUTPUT_DIR"
if [[ -n "$RELEASE_EVIDENCE" ]]; then
  cp "$RELEASE_EVIDENCE" "$OUTPUT_DIR/release-evidence.json"
fi

RESULT_LINES=()
HAS_FAILURE=0
for i in "${!COMMAND_NAMES[@]}"; do
  name="${COMMAND_NAMES[$i]}"
  stdout_file="$OUTPUT_DIR/$name.json"
  stderr_file="$OUTPUT_DIR/$name.err.txt"
  echo "support-bundle: capture=$name"
  if run_bundle_command "$name" >"$stdout_file" 2>"$stderr_file"; then
    code=0
  else
    code=$?
    HAS_FAILURE=1
  fi
  stderr_leaf="null"
  if [[ -s "$stderr_file" ]]; then
    stderr_leaf="$(json_string "$(basename "$stderr_file")")"
  else
    rm -f "$stderr_file"
  fi
  RESULT_LINES+=("    {\"name\":$(json_string "$name"),\"exit_code\":$code,\"stdout\":$(json_string "$(basename "$stdout_file")"),\"stderr\":$stderr_leaf}")
done

{
  echo "{"
  echo "  \"generated_at_utc\": $(json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),"
  echo "  \"rpc\": $(json_string "$RPC_ADDR"),"
  if [[ -n "$RPC_API_KEY" ]]; then
    echo "  \"rpc_api_key_set\": true,"
  else
    echo "  \"rpc_api_key_set\": false,"
  fi
  echo "  \"wallet\": $(json_nullable_string "$WALLET"),"
  echo "  \"commit_hash\": $(json_nullable_string "$COMMIT_HASH"),"
  echo "  \"peer\": $(json_nullable_string "$PEER"),"
  echo "  \"chunk_index\": $CHUNK_INDEX,"
  echo "  \"data_dir\": $(json_nullable_string "$DATA_DIR"),"
  echo "  \"data_root\": $(json_nullable_string "$DATA_ROOT"),"
  echo "  \"claim_pubkey\": $(json_nullable_string "$CLAIM_PUBKEY"),"
  echo "  \"release_evidence\": $RELEASE_EVIDENCE_JSON,"
  echo "  \"read_only\": true,"
  echo "  \"commands\": ["
  for i in "${!RESULT_LINES[@]}"; do
    suffix=","
    if (( i == ${#RESULT_LINES[@]} - 1 )); then
      suffix=""
    fi
    echo "${RESULT_LINES[$i]}$suffix"
  done
  echo "  ]"
  echo "}"
} >"$OUTPUT_DIR/manifest.json"

echo "support-bundle: output_dir=$OUTPUT_DIR"
if (( HAS_FAILURE )); then
  echo "support-bundle: one or more captures failed; inspect manifest.json and *.err.txt" >&2
  exit 1
fi
