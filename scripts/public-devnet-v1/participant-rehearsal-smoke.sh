#!/usr/bin/env bash
# Real-run local smoke for participant-rehearsal against the public-devnet helper mesh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"

RPC=""
SMOKE_ROOT="$SCRIPT_DIR/participant-rehearsal-smoke"
FAUCET_WALLET=""
WAIT_AFTER_START_SECONDS=30
WAIT_MINED_SECONDS=240
WAIT_UPLOAD_SECONDS=240
WAIT_PROOF_SECONDS=240
NO_START=0
NO_STOP=0
NO_BUILD=0
PLAN_ONLY=0
TEST_FAUCET_SEED="6565656565656565656565656565656565656565656565656565656565656565"
USE_BUNDLED_TEST_FAUCET=1

usage() {
  cat <<'EOF'
usage: participant-rehearsal-smoke.sh [options]

Options:
  --rpc HOST:PORT             existing mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --faucet-wallet FILE        faucet wallet to restore/use (default: participant-rehearsal-smoke/validator0-faucet.json)
  --smoke-dir DIR             smoke directory (default: participant-rehearsal-smoke/)
  --wait-after-start-seconds N wait after start-all before rehearsal (default: 30)
  --wait-mined-seconds N      wait for funding balance delta (default: 240)
  --wait-upload-seconds N     wait for upload discovery (default: 240)
  --wait-proof-seconds N      proof-list wait window (default: 240; 0 disables)
  --no-start                  use an already-started mesh
  --no-stop                   leave mesh running after this script started it
  --no-build                  use existing release binaries
  --plan-only                 print the local smoke flow without starting processes
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-wallet) FAUCET_WALLET="${2:-}"; USE_BUNDLED_TEST_FAUCET=0; shift 2 ;;
    --smoke-dir) SMOKE_ROOT="${2:-}"; shift 2 ;;
    --wait-after-start-seconds) WAIT_AFTER_START_SECONDS="${2:-}"; shift 2 ;;
    --wait-mined-seconds) WAIT_MINED_SECONDS="${2:-}"; shift 2 ;;
    --wait-upload-seconds) WAIT_UPLOAD_SECONDS="${2:-}"; shift 2 ;;
    --wait-proof-seconds) WAIT_PROOF_SECONDS="${2:-}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --no-stop) NO_STOP=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "participant-rehearsal-smoke: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_uint() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "participant-rehearsal-smoke: $name must be an integer >= $min" >&2
    exit 1
  fi
}

validate_uint wait-after-start-seconds "$WAIT_AFTER_START_SECONDS" 0
validate_uint wait-mined-seconds "$WAIT_MINED_SECONDS" 0
validate_uint wait-upload-seconds "$WAIT_UPLOAD_SECONDS" 1
validate_uint wait-proof-seconds "$WAIT_PROOF_SECONDS" 0

if [[ -z "$FAUCET_WALLET" ]]; then
  FAUCET_WALLET="$SMOKE_ROOT/validator0-faucet.json"
fi
REHEARSAL_DIR="$SMOKE_ROOT/run"

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
  echo "participant-rehearsal-smoke: missing HUB_RPC; run start-all.sh or omit --no-start" >&2
  return 1
}

resolve_mfn_cli() {
  local bin="$REPO_ROOT/target/release/mfn-cli"
  if [[ ! -x "$bin" ]]; then
    bin="$REPO_ROOT/target/release/mfn-cli.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    echo "participant-rehearsal-smoke: missing target/release/mfn-cli after build" >&2
    exit 1
  fi
  printf '%s\n' "$bin"
}

if (( PLAN_ONLY )); then
  if (( NO_START )); then
    PLAN_RPC="$(resolve_rpc 2>/dev/null || printf '<existing HUB_RPC or --rpc required>')"
  else
    PLAN_RPC="${RPC:-<start-all.sh will write HUB_RPC>}"
  fi
  echo "participant-rehearsal-smoke: plan"
  echo "  rpc=$PLAN_RPC"
  echo "  smoke_dir=$SMOKE_ROOT"
  echo "  faucet_wallet=$FAUCET_WALLET"
  echo "  rehearsal_dir=$REHEARSAL_DIR"
  echo "  flow=stop stale mesh -> start-all -> restore/check test faucet -> participant-rehearsal -> stop mesh"
  echo "  warning=default wallet uses public validator-0 test payout seed only for local/public devnet rehearsal; custom faucet wallets are never overwritten"
  exit 0
fi

cd "$REPO_ROOT"
mkdir -p "$SMOKE_ROOT"
STARTED_MESH=0
cleanup() {
  if (( STARTED_MESH == 1 && NO_STOP == 0 )); then
    bash "$SCRIPT_DIR/stop-all.sh" || true
  fi
}
trap cleanup EXIT

if (( NO_START == 0 )); then
  bash "$SCRIPT_DIR/stop-all.sh" --all-mfnd
  bash "$SCRIPT_DIR/start-all.sh"
  STARTED_MESH=1
  if (( WAIT_AFTER_START_SECONDS > 0 )); then
    sleep "$WAIT_AFTER_START_SECONDS"
  fi
fi
RPC_ADDR="$(resolve_rpc)"

if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
  cargo build -p mfn-storage-operator --release --bin mfn-storage-operator --manifest-path "$REPO_ROOT/Cargo.toml"
fi
MFN_CLI="$(resolve_mfn_cli)"
if (( USE_BUNDLED_TEST_FAUCET )); then
  "$MFN_CLI" --wallet "$FAUCET_WALLET" --force wallet restore "$TEST_FAUCET_SEED" --key-derivation payout_stealth_v1
elif [[ ! -f "$FAUCET_WALLET" ]]; then
  echo "participant-rehearsal-smoke: faucet wallet not found: $FAUCET_WALLET" >&2
  exit 1
fi
"$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$FAUCET_WALLET" wallet scan >/dev/null
FAUCET_BALANCE_OUT="$("$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$FAUCET_WALLET" wallet balance)"
FAUCET_BALANCE="$(awk '{
  for (i = 1; i <= NF; i++) {
    if ($i ~ /^balance=/) {
      sub(/^balance=/, "", $i)
      print $i
      exit
    }
  }
}' <<<"$FAUCET_BALANCE_OUT")"
if [[ -z "$FAUCET_BALANCE" || ! "$FAUCET_BALANCE" =~ ^[0-9]+$ ]]; then
  echo "participant-rehearsal-smoke: faucet wallet balance output missing balance=<value>" >&2
  printf '%s\n' "$FAUCET_BALANCE_OUT" >&2
  exit 1
fi
echo "participant-rehearsal-smoke: faucet_balance=$FAUCET_BALANCE"
if (( FAUCET_BALANCE == 0 )); then
  echo "participant-rehearsal-smoke: faucet wallet has zero spendable balance after scan; fund the faucet on this devnet or rerun with --faucet-wallet pointing at a funded operator wallet" >&2
  exit 1
fi

bash "$SCRIPT_DIR/participant-rehearsal.sh" \
  --rpc "$RPC_ADDR" \
  --faucet-wallet "$FAUCET_WALLET" \
  --rehearsal-dir "$REHEARSAL_DIR" \
  --wait-mined-seconds "$WAIT_MINED_SECONDS" \
  --wait-upload-seconds "$WAIT_UPLOAD_SECONDS" \
  --wait-proof-seconds "$WAIT_PROOF_SECONDS" \
  --no-build

echo "participant-rehearsal-smoke: PASS rpc=$RPC_ADDR rehearsal_dir=$REHEARSAL_DIR"
