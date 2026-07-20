#!/usr/bin/env bash
# Fund a participant wallet from an operator-controlled public-devnet faucet wallet.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
DEMO_ROOT="$SCRIPT_DIR/permanence-demo"
DEFAULT_RECIPIENT_WALLET="$DEMO_ROOT/uploader.json"

RPC=""
FAUCET_WALLET=""
RECIPIENT_WALLET=""
AMOUNT=1000000
FEE=10000
RING_SIZE=16
WAIT_MINED_SECONDS=180
MIN_OWNED_COUNT=2
NO_BUILD=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: fund-wallet.sh [options]

Options:
  --rpc HOST:PORT             mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --faucet-wallet FILE        funded operator wallet used as sender (required outside --plan-only)
  --recipient-wallet FILE     participant wallet to create/reuse (default: permanence-demo/uploader.json)
  --amount N                  amount to send in atomic units (default: 1000000)
  --fee N                     transfer fee in atomic units (default: 10000)
  --ring-size N               CLSAG ring size (default: 16)
  --wait-mined-seconds N      wait for recipient balance delta (default: 180; 0 disables wait)
  --min-owned-count N         F7 privacy floor: send until recipient owns >= N UTXOs (default: 2; 0 disables)
  --no-build                  use existing target/release/mfn-cli
  --plan-only                 print resolved flow without requiring binaries or faucet wallet
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)
      RPC="${2:-}"
      shift 2
      ;;
    --faucet-wallet)
      FAUCET_WALLET="${2:-}"
      shift 2
      ;;
    --recipient-wallet)
      RECIPIENT_WALLET="${2:-}"
      shift 2
      ;;
    --amount)
      AMOUNT="${2:-}"
      shift 2
      ;;
    --fee)
      FEE="${2:-}"
      shift 2
      ;;
    --ring-size)
      RING_SIZE="${2:-}"
      shift 2
      ;;
    --wait-mined-seconds)
      WAIT_MINED_SECONDS="${2:-}"
      shift 2
      ;;
    --min-owned-count)
      MIN_OWNED_COUNT="${2:-}"
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
      echo "fund-wallet: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_uint() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "fund-wallet: $name must be an integer >= $min" >&2
    exit 1
  fi
}

validate_uint amount "$AMOUNT" 1
validate_uint fee "$FEE" 0
validate_uint ring-size "$RING_SIZE" 16
validate_uint wait-mined-seconds "$WAIT_MINED_SECONDS" 0
validate_uint min-owned-count "$MIN_OWNED_COUNT" 0

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
  echo "fund-wallet: pass --rpc HOST:PORT or run start-all.sh first" >&2
  return 1
}

resolve_mfn_cli() {
  local bin="$REPO_ROOT/target/release/mfn-cli"
  if [[ ! -x "$bin" ]]; then
    bin="$REPO_ROOT/target/release/mfn-cli.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    echo "fund-wallet: missing target/release/mfn-cli; rerun without --no-build or build mfn-cli --release" >&2
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
    echo "fund-wallet: $label failed with exit=$code" >&2
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
  echo "fund-wallet: stdout missing $prefix" >&2
  echo "$text" >&2
  exit 1
}

json_field() {
  local text="$1" key="$2"
  if command -v node >/dev/null 2>&1; then
    printf '%s\n' "$text" | node -e 'const fs=require("fs"); const key=process.argv[1]; const value=JSON.parse(fs.readFileSync(0,"utf8"))[key]; if (value === undefined || value === null) process.exit(2); console.log(value);' "$key"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "$text" | python3 -c 'import json,sys; value=json.load(sys.stdin).get(sys.argv[1]); sys.exit(2) if value is None else print(value)' "$key"
    return
  fi
  echo "fund-wallet: wallet send --json requires node or python3 to parse tx_id; install one or run mfn-cli wallet send manually" >&2
  exit 1
}

# B-29: Nightly participant-rehearsal hits WS `trusted N vs checkpoint 0` when a
# pinned trusted summary outlives a rebuilt light checkpoint. Clear the pin and
# light-scan before balance waits so recovery does not depend on JOIN/HTTP paths.
refresh_wallet_light() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" label="${4:-wallet}"
  if "$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet light-scan \
    --reset-trusted-summary >/dev/null 2>&1; then
    echo "fund-wallet: ${label}_light_scan reset_trusted_summary=ok"
    return 0
  fi
  echo "fund-wallet: ${label}_light_scan reset_trusted_summary=retry_soft_fail"
  return 0
}

is_ws_tip_mismatch() {
  local text="$1"
  [[ "$text" == *"weak-subjectivity"* || "$text" == *"tip_height mismatch"* ]]
}

get_wallet_balance() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" label="$4"
  local out code
  set +e
  out="$("$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance 2>&1)"
  code=$?
  set -e
  if (( code != 0 )); then
    if is_ws_tip_mismatch "$out"; then
      echo "fund-wallet: $label wallet balance hit WS tip mismatch; resetting trusted summary"
      refresh_wallet_light "$mfn_cli" "$rpc_addr" "$wallet_path" "$label"
      out="$(run_checked "$label wallet balance (after WS reset)" "$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance)"
    else
      echo "fund-wallet: $label wallet balance failed with exit=$code" >&2
      echo "$out" >&2
      exit "$code"
    fi
  fi
  parse_field "$out" balance
}

get_wallet_owned_count() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" label="$4"
  local out code
  set +e
  out="$("$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance 2>&1)"
  code=$?
  set -e
  if (( code != 0 )); then
    if is_ws_tip_mismatch "$out"; then
      echo "fund-wallet: $label wallet balance hit WS tip mismatch; resetting trusted summary"
      refresh_wallet_light "$mfn_cli" "$rpc_addr" "$wallet_path" "$label"
      out="$(run_checked "$label wallet balance (after WS reset)" "$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance)"
    else
      echo "fund-wallet: $label wallet balance failed with exit=$code" >&2
      echo "$out" >&2
      exit "$code"
    fi
  fi
  parse_field "$out" owned_count
}

ensure_wallet() {
  local mfn_cli="$1" wallet_path="$2" label="$3"
  if [[ -f "$wallet_path" ]]; then
    echo "fund-wallet: using existing $label wallet at $wallet_path"
    return
  fi
  mkdir -p "$(dirname "$wallet_path")"
  run_checked "$label wallet new" "$mfn_cli" --wallet "$wallet_path" wallet new >/dev/null
  echo "fund-wallet: created $label wallet at $wallet_path"
}

wait_recipient_balance() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" starting_balance="$4" target_balance="$5" timeout_seconds="$6"
  if (( timeout_seconds <= 0 )); then
    return
  fi
  local deadline=$(( $(date +%s) + timeout_seconds ))
  local last_error=""
  local last_scan=0
  refresh_wallet_light "$mfn_cli" "$rpc_addr" "$wallet_path" recipient
  while (( $(date +%s) <= deadline )); do
    local balance balance_out tip_height now
    now=$(date +%s)
    # Periodic light-scan keeps resume height / trusted pin coherent while tip advances.
    if (( now - last_scan >= 30 )); then
      refresh_wallet_light "$mfn_cli" "$rpc_addr" "$wallet_path" recipient
      last_scan=$now
    fi
    tip_height="$(tip_height_text "$mfn_cli" "$rpc_addr")"
    if ! balance_out="$("$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance 2>&1)"; then
      last_error="recipient wallet balance failed: $balance_out"
      if [[ "$last_error" == *"Connection refused"* || "$last_error" == *"actively refused"* ]]; then
        echo "fund-wallet: hub RPC unreachable during mining wait; mesh may have stopped ($last_error)" >&2
        exit 1
      fi
      if is_ws_tip_mismatch "$last_error"; then
        echo "fund-wallet: recipient_balance_wait WS tip mismatch; light-scan --reset-trusted-summary"
        refresh_wallet_light "$mfn_cli" "$rpc_addr" "$wallet_path" recipient
        last_scan=$(date +%s)
      fi
      echo "fund-wallet: recipient_balance_wait retry_after_error=${last_error//$'\n'/ }"
      sleep 5
      continue
    fi
    balance="$(parse_field "$balance_out" balance)"
    echo "fund-wallet: recipient_balance_wait hub_tip_height=$tip_height balance=$balance target=$target_balance"
    if (( balance >= target_balance )); then
      echo "fund-wallet: recipient_balance=$balance"
      return
    fi
    last_error=""
    sleep 5
  done
  local suffix="" tip_height
  if [[ -n "$last_error" ]]; then
    suffix="; last_error=$last_error"
  fi
  tip_height="$(tip_height_text "$mfn_cli" "$rpc_addr")"
  echo "fund-wallet: recipient balance did not increase from $starting_balance to at least $target_balance within ${timeout_seconds}s (hub_tip_height=$tip_height); mine or wait for a producer block, then run wallet balance or wallet light-scan$suffix" >&2
  exit 1
}

tip_height_text() {
  local mfn_cli="$1" rpc_addr="$2"
  query_tip_height "$rpc_addr" "$REPO_ROOT"
}

# Track tip across faucet sends so F7 top-ups wait for a block + rescan (same
# failure mode as faucet-http: back-to-back spends reuse stale UTXOs).
TIP_AFTER_FAUCET_SEND=""

wait_tip_advance() {
  local mfn_cli="$1" rpc_addr="$2" from_height="$3" timeout_seconds="${4:-90}"
  local deadline=$(( $(date +%s) + timeout_seconds ))
  while (( $(date +%s) < deadline )); do
    local h
    h="$(tip_height_text "$mfn_cli" "$rpc_addr")"
    if [[ "$h" =~ ^[0-9]+$ ]] && (( h > from_height )); then
      echo "fund-wallet: tip_advanced from=$from_height to=$h"
      return 0
    fi
    sleep 2
  done
  echo "fund-wallet: WARN tip did not advance from $from_height within ${timeout_seconds}s" >&2
  return 1
}

refresh_faucet_wallet() {
  local mfn_cli="$1" rpc_addr="$2"
  refresh_wallet_light "$mfn_cli" "$rpc_addr" "$FAUCET_WALLET" faucet
  run_checked "faucet wallet scan" "$mfn_cli" --rpc "$rpc_addr" --wallet "$FAUCET_WALLET" wallet scan >/dev/null
}

prepare_before_faucet_send() {
  if [[ -n "$TIP_AFTER_FAUCET_SEND" ]]; then
    wait_tip_advance "$MFN_CLI" "$RPC_ADDR" "$TIP_AFTER_FAUCET_SEND" 90 || true
    refresh_faucet_wallet "$MFN_CLI" "$RPC_ADDR"
  fi
}

record_after_faucet_send() {
  TIP_AFTER_FAUCET_SEND="$(tip_height_text "$MFN_CLI" "$RPC_ADDR")"
}

RECIPIENT="${RECIPIENT_WALLET:-$DEFAULT_RECIPIENT_WALLET}"

if (( PLAN_ONLY )); then
  PLAN_RPC="$(resolve_rpc 2>/dev/null || printf '<pass --rpc HOST:PORT or run start-all.sh>')"
  PLAN_FAUCET="${FAUCET_WALLET:-<required --faucet-wallet FILE>}"
  echo "fund-wallet: plan"
  echo "  rpc=$PLAN_RPC"
  echo "  faucet_wallet=$PLAN_FAUCET"
  echo "  recipient_wallet=$RECIPIENT"
  echo "  amount=$AMOUNT fee=$FEE ring_size=$RING_SIZE wait_mined_seconds=$WAIT_MINED_SECONDS min_owned_count=$MIN_OWNED_COUNT"
  echo "  flow=create/reuse recipient wallet -> record starting balance -> refresh faucet light-scan/scan/balance -> wallet address -> faucet wallet send --json -> recipient light-scan --reset-trusted-summary -> wait for balance delta -> optional F7 top-up sends until owned_count >= min_owned_count"
  echo "  note=B-29: balance waits recover from WS trusted-vs-checkpoint tip mismatch via light-scan --reset-trusted-summary (Nightly path; not JOIN/fund-wallet-http)"
  echo "  warning=use only public-devnet/test funds; never store real faucet seeds in this repo"
  exit 0
fi

if [[ -z "$FAUCET_WALLET" ]]; then
  echo "fund-wallet: --faucet-wallet FILE is required outside --plan-only" >&2
  exit 1
fi
if [[ ! -f "$FAUCET_WALLET" ]]; then
  echo "fund-wallet: faucet wallet not found: $FAUCET_WALLET" >&2
  exit 1
fi

RPC_ADDR="$(resolve_rpc)"
if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
fi
MFN_CLI="$(resolve_mfn_cli)"

ensure_wallet "$MFN_CLI" "$RECIPIENT" recipient
STARTING_BALANCE="$(get_wallet_balance "$MFN_CLI" "$RPC_ADDR" "$RECIPIENT" recipient)"
TARGET_BALANCE=$(( STARTING_BALANCE + AMOUNT ))
if (( TARGET_BALANCE < STARTING_BALANCE )); then
  echo "fund-wallet: recipient balance target overflow" >&2
  exit 1
fi
echo "fund-wallet: recipient_starting_balance=$STARTING_BALANCE target_balance=$TARGET_BALANCE"

FAUCET_BALANCE="$(get_wallet_balance "$MFN_CLI" "$RPC_ADDR" "$FAUCET_WALLET" faucet)"
echo "fund-wallet: faucet_balance=$FAUCET_BALANCE"
if (( FAUCET_BALANCE < AMOUNT + FEE )); then
  echo "fund-wallet: faucet balance $FAUCET_BALANCE is below required $(( AMOUNT + FEE )); mine/scan the faucet wallet or choose a funded faucet" >&2
  exit 1
fi

ADDR_OUT="$(run_checked "recipient wallet address" "$MFN_CLI" --wallet "$RECIPIENT" wallet address)"
VIEW_HEX="$(parse_field "$ADDR_OUT" view_pub_hex)"
SPEND_HEX="$(parse_field "$ADDR_OUT" spend_pub_hex)"

send_fund_transfer() {
  local balance_before="$1"
  local balance_target="$2"
  prepare_before_faucet_send
  FAUCET_BALANCE="$(get_wallet_balance "$MFN_CLI" "$RPC_ADDR" "$FAUCET_WALLET" faucet)"
  if (( FAUCET_BALANCE < AMOUNT + FEE )); then
    echo "fund-wallet: faucet balance $FAUCET_BALANCE is below required $(( AMOUNT + FEE )); mine/scan the faucet wallet or choose a funded faucet" >&2
    exit 1
  fi
  local send_out tx_id mempool_len outcome
  send_out="$(run_checked "faucet wallet send" "$MFN_CLI" --rpc "$RPC_ADDR" --wallet "$FAUCET_WALLET" wallet send "$VIEW_HEX" "$SPEND_HEX" "$AMOUNT" --fee "$FEE" --ring-size "$RING_SIZE" --json)"
  tx_id="$(json_field "$send_out" tx_id)"
  mempool_len="$(json_field "$send_out" mempool_len)"
  outcome="$(json_field "$send_out" outcome)"
  echo "fund-wallet: submitted tx_id=$tx_id mempool_len=$mempool_len outcome=$outcome recipient_wallet=$RECIPIENT"
  echo "fund-wallet: wait_for_mining=$WAIT_MINED_SECONDS"
  wait_recipient_balance "$MFN_CLI" "$RPC_ADDR" "$RECIPIENT" "$balance_before" "$balance_target" "$WAIT_MINED_SECONDS"
  record_after_faucet_send
  printf '%s\n' "$tx_id"
}

TX_ID="$(send_fund_transfer "$STARTING_BALANCE" "$TARGET_BALANCE")"

if (( MIN_OWNED_COUNT > 0 )); then
  while true; do
    OWNED_COUNT="$(get_wallet_owned_count "$MFN_CLI" "$RPC_ADDR" "$RECIPIENT" recipient)"
    echo "fund-wallet: recipient_owned_count=$OWNED_COUNT min_owned_count=$MIN_OWNED_COUNT"
    if (( OWNED_COUNT >= MIN_OWNED_COUNT )); then
      break
    fi
    BALANCE_BEFORE="$(get_wallet_balance "$MFN_CLI" "$RPC_ADDR" "$RECIPIENT" recipient)"
    BALANCE_TARGET=$(( BALANCE_BEFORE + AMOUNT ))
    if (( BALANCE_TARGET < BALANCE_BEFORE )); then
      echo "fund-wallet: recipient balance target overflow during F7 top-up" >&2
      exit 1
    fi
    echo "fund-wallet: F7 top-up send (owned_count=$OWNED_COUNT < $MIN_OWNED_COUNT)"
    send_fund_transfer "$BALANCE_BEFORE" "$BALANCE_TARGET" >/dev/null
  done
fi

echo "fund-wallet: PASS tx_id=$TX_ID recipient_wallet=$RECIPIENT amount=$AMOUNT"
