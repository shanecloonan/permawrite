#!/usr/bin/env bash
# Real-run local smoke for participant-rehearsal against the public-devnet helper mesh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"

RPC=""
SMOKE_ROOT="$SCRIPT_DIR/participant-rehearsal-smoke"
FAUCET_WALLET=""
EVIDENCE_DIR=""
WAIT_AFTER_START_SECONDS=-1
WAIT_FAUCET_SECONDS=240
WAIT_MINED_SECONDS=240
WAIT_UPLOAD_SECONDS=360
WAIT_PROOF_SECONDS=240
NO_START=0
NO_STOP=0
NO_BUILD=0
PLAN_ONLY=0
ARCHIVE_EVIDENCE=0
WITH_OBSERVER=0
MIN_HUB_HEIGHT=0
WAIT_MIN_HUB_HEIGHT_SECONDS=180
WAIT_OBSERVER_CATCHUP_SECONDS=180
TEST_FAUCET_SEED="6565656565656565656565656565656565656565656565656565656565656565"
USE_BUNDLED_TEST_FAUCET=1

usage() {
  cat <<'EOF'
usage: participant-rehearsal-smoke.sh [options]

Options:
  --rpc HOST:PORT             existing mfnd JSON-RPC address (default: HUB_RPC from devnet-ports.env)
  --faucet-wallet FILE        faucet wallet to restore/use (default: participant-rehearsal-smoke/validator0-faucet.json)
  --smoke-dir DIR             smoke directory (default: participant-rehearsal-smoke/)
  --evidence-dir DIR          evidence directory (default: <smoke-dir>/evidence)
  --wait-after-start-seconds N wait after start-all before rehearsal (default: 30)
  --wait-faucet-seconds N     wait for faucet wallet to scan spendable rewards (default: 240; 0 checks once)
  --wait-mined-seconds N      wait for funding balance delta (default: 240)
  --wait-upload-seconds N     wait for upload discovery (default: 240)
  --wait-proof-seconds N      proof-list wait window (default: 240; 0 disables)
  --with-observer             start full mesh including non-validator observer (default: skip observer)
  --min-hub-height N          fail unless hub tip_height >= N after rehearsal (default: 0)
  --wait-min-hub-height-seconds N poll for min hub height after rehearsal (default: 180; 0 checks once)
  --wait-observer-catchup-seconds N poll for observer tip >= hub after rehearsal (default: 180)
  --no-start                  use an already-started mesh
  --no-stop                   leave mesh running after this script started it
  --no-build                  use existing release binaries
  --archive-evidence          write PASS transcript to scripts/public-devnet-v1/evidence/
  --plan-only                 print the local smoke flow without starting processes
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-wallet) FAUCET_WALLET="${2:-}"; USE_BUNDLED_TEST_FAUCET=0; shift 2 ;;
    --smoke-dir) SMOKE_ROOT="${2:-}"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --wait-after-start-seconds) WAIT_AFTER_START_SECONDS="${2:-}"; shift 2 ;;
    --wait-faucet-seconds) WAIT_FAUCET_SECONDS="${2:-}"; shift 2 ;;
    --wait-mined-seconds) WAIT_MINED_SECONDS="${2:-}"; shift 2 ;;
    --wait-upload-seconds) WAIT_UPLOAD_SECONDS="${2:-}"; shift 2 ;;
    --wait-proof-seconds) WAIT_PROOF_SECONDS="${2:-}"; shift 2 ;;
    --with-observer) WITH_OBSERVER=1; shift ;;
    --min-hub-height) MIN_HUB_HEIGHT="${2:-}"; shift 2 ;;
    --wait-min-hub-height-seconds) WAIT_MIN_HUB_HEIGHT_SECONDS="${2:-}"; shift 2 ;;
    --wait-observer-catchup-seconds) WAIT_OBSERVER_CATCHUP_SECONDS="${2:-}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --no-stop) NO_STOP=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --archive-evidence) ARCHIVE_EVIDENCE=1; shift ;;
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
  if [[ ! "$value" =~ ^-?[0-9]+$ ]] || (( value < min )); then
    echo "participant-rehearsal-smoke: $name must be an integer >= $min" >&2
    exit 1
  fi
}

if (( WAIT_AFTER_START_SECONDS < 0 )); then
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    # start-all already waits for hub tip + voter dials; short settle only.
    WAIT_AFTER_START_SECONDS=30
  elif (( WITH_OBSERVER )); then
    WAIT_AFTER_START_SECONDS=45
  else
    WAIT_AFTER_START_SECONDS=30
  fi
fi

validate_uint wait-after-start-seconds "$WAIT_AFTER_START_SECONDS" 0
validate_uint wait-faucet-seconds "$WAIT_FAUCET_SECONDS" 0
validate_uint wait-mined-seconds "$WAIT_MINED_SECONDS" 0
validate_uint wait-upload-seconds "$WAIT_UPLOAD_SECONDS" 1
validate_uint wait-proof-seconds "$WAIT_PROOF_SECONDS" 0
validate_uint min-hub-height "$MIN_HUB_HEIGHT" 0
validate_uint wait-min-hub-height-seconds "$WAIT_MIN_HUB_HEIGHT_SECONDS" 0
validate_uint wait-observer-catchup-seconds "$WAIT_OBSERVER_CATCHUP_SECONDS" 0

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  if (( WAIT_FAUCET_SECONDS == 240 )); then
    WAIT_FAUCET_SECONDS=600
  fi
  if (( WAIT_MINED_SECONDS == 240 )); then
    WAIT_MINED_SECONDS=480
  fi
  if (( WAIT_UPLOAD_SECONDS == 360 )); then
    WAIT_UPLOAD_SECONDS=480
  fi
  if (( WAIT_PROOF_SECONDS == 240 )); then
    WAIT_PROOF_SECONDS=480
  fi
  if (( WITH_OBSERVER )) && (( WAIT_OBSERVER_CATCHUP_SECONDS == 180 )); then
    WAIT_OBSERVER_CATCHUP_SECONDS=420
  fi
fi

if [[ -z "$FAUCET_WALLET" ]]; then
  FAUCET_WALLET="$SMOKE_ROOT/validator0-faucet.json"
fi
REHEARSAL_DIR="$SMOKE_ROOT/run"
if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$SMOKE_ROOT/evidence"
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

wallet_balance() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" balance_out balance
  "$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet scan >/dev/null
  balance_out="$("$mfn_cli" --rpc "$rpc_addr" --wallet "$wallet_path" wallet balance)"
  balance="$(awk '{
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^balance=/) {
        sub(/^balance=/, "", $i)
        print $i
        exit
      }
    }
  }' <<<"$balance_out")"
  if [[ -z "$balance" || ! "$balance" =~ ^[0-9]+$ ]]; then
    echo "participant-rehearsal-smoke: faucet wallet balance output missing balance=<value>" >&2
    printf '%s\n' "$balance_out" >&2
    exit 1
  fi
  printf '%s\n' "$balance"
}

tip_height_text() {
  local mfn_cli="$1" rpc_addr="$2"
  query_tip_height "$rpc_addr" "$REPO_ROOT"
}

wait_mesh_health_check() {
  local timeout_seconds="$1"
  local deadline
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    # start-all already gates on hub tip_height >= 1; single-sample liveness only.
    if MFN_HEALTH_REQUIRE_ALL_ROLES=0 \
      MFN_HEALTH_MIN_P2P_SESSIONS=0 \
      MFN_HEALTH_STALL_SAMPLES=1 \
      MFN_HEALTH_STALL_INTERVAL_SECONDS=0 \
      MFN_HEALTH_MIN_HEIGHT_DELTA=0 \
      bash "$SCRIPT_DIR/health-check.sh"; then
      echo "participant-rehearsal-smoke: STAGE=health_check PASS"
      return
    fi
    if (( $(date +%s) >= deadline )); then
      echo "participant-rehearsal-smoke: STAGE=health_check FAIL after ${timeout_seconds}s (hub RPC + genesis)" >&2
      exit 1
    fi
    echo "participant-rehearsal-smoke: health-check retry (waiting for hub RPC)..."
    sleep 10
  done
}

wait_hub_min_height() {
  local mfn_cli="$1" rpc_addr="$2" min_height="$3" timeout_seconds="$4"
  local deadline tip_height
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    tip_height="$(tip_height_text "$mfn_cli" "$rpc_addr")"
    echo "participant-rehearsal-smoke: hub_liveness_wait tip_height=$tip_height min_height=$min_height"
    if [[ "$tip_height" =~ ^[0-9]+$ ]] && (( tip_height >= min_height )); then
      return
    fi
    if (( timeout_seconds <= 0 || $(date +%s) >= deadline )); then
      echo "participant-rehearsal-smoke: STAGE=hub_liveness_fail tip_height=$tip_height min_height=$min_height after ${timeout_seconds}s" >&2
      echo "participant-rehearsal-smoke: hub tip_height=$tip_height below min_height=$min_height after ${timeout_seconds}s; diagnose hub --produce and committee voter quorum before faucet funding" >&2
      exit 1
    fi
    sleep 5
  done
}

wait_faucet_balance() {
  local mfn_cli="$1" rpc_addr="$2" wallet_path="$3" timeout_seconds="$4"
  local deadline balance tip_height
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    balance="$(wallet_balance "$mfn_cli" "$rpc_addr" "$wallet_path")"
    tip_height="$(tip_height_text "$mfn_cli" "$rpc_addr")"
    echo "participant-rehearsal-smoke: faucet_balance=$balance hub_tip_height=$tip_height"
    if (( balance > 0 )); then
      return
    fi
    if (( timeout_seconds <= 0 || $(date +%s) >= deadline )); then
      tip_height="$(tip_height_text "$mfn_cli" "$rpc_addr")"
      echo "participant-rehearsal-smoke: faucet wallet has zero spendable balance after ${timeout_seconds}s (hub_tip_height=$tip_height); wait for producer rewards, fund the faucet on this devnet, or rerun with --faucet-wallet pointing at a funded operator wallet" >&2
      exit 1
    fi
    sleep 5
  done
}

latest_observer_rpc() {
  local observer_rpc="" obs_log="$SCRIPT_DIR/logs/observer.log"
  if [[ -f "$PORTS_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$PORTS_FILE"
    observer_rpc="${OBSERVER_RPC:-}"
  fi
  if [[ -f "$obs_log" ]]; then
    local log_rpc
    log_rpc="$(grep -E 'mfnd_serve_listening=' "$obs_log" | tail -n1 | sed 's/.*=//')"
    if [[ -n "$log_rpc" ]]; then
      printf '%s\n' "$log_rpc"
      return
    fi
  fi
  if [[ -n "$observer_rpc" ]]; then
    printf '%s\n' "$observer_rpc"
    return
  fi
  return 1
}

assert_mesh_heights() {
  local mfn_cli="$1" hub_rpc="$2"
  local hub_height observer_height observer_rpc deadline
  hub_height="$(tip_height_text "$mfn_cli" "$hub_rpc")"
  if [[ ! "$hub_height" =~ ^[0-9]+$ ]]; then
    echo "participant-rehearsal-smoke: hub tip_height unreadable after rehearsal: $hub_height" >&2
    exit 1
  fi
  echo "participant-rehearsal-smoke: post_rehearsal hub_tip_height=$hub_height"
  if (( MIN_HUB_HEIGHT > 0 && hub_height < MIN_HUB_HEIGHT )); then
    echo "participant-rehearsal-smoke: hub tip_height=$hub_height below required min_hub_height=$MIN_HUB_HEIGHT" >&2
    exit 1
  fi
  if (( WITH_OBSERVER == 0 )); then
    return
  fi
  deadline=$(( $(date +%s) + WAIT_OBSERVER_CATCHUP_SECONDS ))
  while :; do
    hub_height="$(tip_height_text "$mfn_cli" "$hub_rpc")"
    observer_rpc="$(latest_observer_rpc || true)"
    if [[ -z "$observer_rpc" ]]; then
      echo "participant-rehearsal-smoke: WITH_OBSERVER but OBSERVER_RPC missing from $PORTS_FILE and logs" >&2
      exit 1
    fi
    observer_height="$(tip_height_text "$mfn_cli" "$observer_rpc")"
    if [[ ! "$observer_height" =~ ^[0-9]+$ ]]; then
      echo "participant-rehearsal-smoke: observer tip_height unreadable: $observer_height" >&2
      exit 1
    fi
    if (( observer_height >= hub_height )); then
      echo "participant-rehearsal-smoke: post_rehearsal observer_tip_height=$observer_height observer_rpc=$observer_rpc"
      return
    fi
    echo "participant-rehearsal-smoke: observer_catchup_wait hub_tip_height=$hub_height observer_tip_height=$observer_height observer_rpc=$observer_rpc"
    if (( $(date +%s) >= deadline )); then
      echo "participant-rehearsal-smoke: observer tip_height=$observer_height lagged hub tip_height=$hub_height after ${WAIT_OBSERVER_CATCHUP_SECONDS}s" >&2
      exit 1
    fi
    sleep 5
  done
}

archive_rehearsal_smoke_evidence() {
  local rpc_addr="$1" hub_height="$2" observer_rpc="${3:-}" observer_height="${4:-unknown}"
  local evidence_dir="$SCRIPT_DIR/evidence"
  local observer_label stamp path commit cmd platform
  mkdir -p "$evidence_dir"
  if (( WITH_OBSERVER == 1 )); then
    observer_label="observer"
  else
    observer_label="no-observer"
  fi
  platform="linux"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) platform="windows" ;;
  esac
  stamp="$(date -u +"%Y%m%dTHHmmssZ")"
  path="$evidence_dir/participant-rehearsal-${observer_label}-${platform}-${stamp}.txt"
  commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
  cmd="participant-rehearsal-smoke.sh"
  if (( WITH_OBSERVER == 1 )); then cmd+=" --with-observer"; fi
  if (( MIN_HUB_HEIGHT > 0 )); then cmd+=" --min-hub-height $MIN_HUB_HEIGHT"; fi
  {
    echo "# Participant rehearsal smoke - $observer_label ($platform)"
    echo "# Generated: $stamp"
    echo "# Command: $cmd"
    if [[ -n "$commit" ]]; then echo "# Commit: $commit"; fi
    echo ""
    echo "SUMMARY: PASS"
    echo ""
    echo "Hub RPC=$rpc_addr"
    if (( WITH_OBSERVER == 1 )) && [[ -n "$observer_rpc" ]]; then
      echo "Observer RPC=$observer_rpc"
    fi
    echo ""
    echo "participant-rehearsal-smoke: PASS with_observer=$WITH_OBSERVER hub_tip_height=$hub_height min_hub_height=$MIN_HUB_HEIGHT"
    if (( WITH_OBSERVER == 1 )) && [[ "$observer_height" != "unknown" ]]; then
      echo "participant-rehearsal-smoke: post_rehearsal observer_tip_height=$observer_height observer_rpc=$observer_rpc"
    fi
  } >"$path"
  echo "participant-rehearsal-smoke: EVIDENCE archived=$path"
}

wait_for_min_hub_height() {
  local mfn_cli="$1" hub_rpc="$2" target="$3" timeout_seconds="$4"
  local deadline height
  if (( target <= 0 )); then
    return
  fi
  height="$(tip_height_text "$mfn_cli" "$hub_rpc")"
  if [[ "$height" =~ ^[0-9]+$ ]] && (( height >= target )); then
    echo "participant-rehearsal-smoke: min_hub_height already satisfied hub_tip_height=$height target=$target"
    return
  fi
  if (( timeout_seconds <= 0 )); then
    return
  fi
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    height="$(tip_height_text "$mfn_cli" "$hub_rpc")"
    echo "participant-rehearsal-smoke: min_hub_height_wait hub_tip_height=$height target=$target"
    if [[ "$height" =~ ^[0-9]+$ ]] && (( height >= target )); then
      return
    fi
    if (( $(date +%s) >= deadline )); then
      echo "participant-rehearsal-smoke: hub tip_height=$height below min_hub_height=$target after ${timeout_seconds}s" >&2
      exit 1
    fi
    sleep 5
  done
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
  echo "  evidence_dir=$EVIDENCE_DIR"
  echo "  wait_faucet_seconds=$WAIT_FAUCET_SECONDS"
  echo "  wait_after_start_seconds=$WAIT_AFTER_START_SECONDS"
  echo "  with_observer=$WITH_OBSERVER"
  echo "  min_hub_height=$MIN_HUB_HEIGHT"
  echo "  wait_min_hub_height_seconds=$WAIT_MIN_HUB_HEIGHT_SECONDS"
  echo "  wait_observer_catchup_seconds=$WAIT_OBSERVER_CATCHUP_SECONDS"
  echo "  flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh"
  echo "  warning=default wallet uses public validator-0 test payout seed only for local/public devnet rehearsal; custom faucet wallets are never overwritten"
  exit 0
fi

cd "$REPO_ROOT"
mkdir -p "$SMOKE_ROOT"
STARTED_MESH=0
cleanup() {
  if (( STARTED_MESH == 1 && NO_STOP == 0 )); then
    bash "$SCRIPT_DIR/stop-all.sh" --all-mfnd --remove-ports-file || true
  fi
}
trap cleanup EXIT

if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
  cargo build -p mfn-storage-operator --release --bin mfn-storage-operator --manifest-path "$REPO_ROOT/Cargo.toml"
fi

if (( NO_START == 0 )); then
  if [[ -z "${SLOT_MS:-}" ]]; then
    export SLOT_MS=10000
  fi
  if (( WITH_OBSERVER == 0 )); then
    export MFN_DEVNET_NO_OBSERVER=1
  else
    unset MFN_DEVNET_NO_OBSERVER
  fi
  bash "$SCRIPT_DIR/stop-all.sh" --all-mfnd --remove-ports-file
  echo "participant-rehearsal-smoke: STAGE=start_mesh"
  if (( NO_BUILD )); then
    bash "$SCRIPT_DIR/start-all.sh" --no-build || {
      echo "participant-rehearsal-smoke: STAGE=start_mesh_fail" >&2
      exit 1
    }
  else
    bash "$SCRIPT_DIR/start-all.sh" || {
      echo "participant-rehearsal-smoke: STAGE=start_mesh_fail" >&2
      exit 1
    }
  fi
  echo "participant-rehearsal-smoke: STAGE=start_mesh_done"
  STARTED_MESH=1
  if (( WAIT_AFTER_START_SECONDS > 0 )); then
    sleep "$WAIT_AFTER_START_SECONDS"
  fi
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    wait_mesh_health_check 900
  fi
fi
RPC_ADDR="$(resolve_rpc)"

MFN_CLI="$(resolve_mfn_cli)"
if (( USE_BUNDLED_TEST_FAUCET )); then
  "$MFN_CLI" --wallet "$FAUCET_WALLET" --force wallet restore "$TEST_FAUCET_SEED" --key-derivation payout_stealth_v1
elif [[ ! -f "$FAUCET_WALLET" ]]; then
  echo "participant-rehearsal-smoke: faucet wallet not found: $FAUCET_WALLET" >&2
  exit 1
fi
HUB_LIVENESS_WAIT=120
HUB_LIVENESS_MIN=1
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  HUB_LIVENESS_MIN=2
  HUB_LIVENESS_WAIT=900
fi
echo "participant-rehearsal-smoke: STAGE=hub_liveness"
wait_hub_min_height "$MFN_CLI" "$RPC_ADDR" "$HUB_LIVENESS_MIN" "$HUB_LIVENESS_WAIT"
echo "participant-rehearsal-smoke: STAGE=faucet_balance"
wait_faucet_balance "$MFN_CLI" "$RPC_ADDR" "$FAUCET_WALLET" "$WAIT_FAUCET_SECONDS"
echo "participant-rehearsal-smoke: STAGE=participant_rehearsal"
if [[ -d "$REHEARSAL_DIR" ]]; then
  rm -rf "$REHEARSAL_DIR"
  echo "participant-rehearsal-smoke: cleared rehearsal_dir=$REHEARSAL_DIR"
fi

bash "$SCRIPT_DIR/participant-rehearsal.sh" \
  --rpc "$RPC_ADDR" \
  --faucet-wallet "$FAUCET_WALLET" \
  --rehearsal-dir "$REHEARSAL_DIR" \
  --evidence-dir "$EVIDENCE_DIR" \
  --wait-mined-seconds "$WAIT_MINED_SECONDS" \
  --wait-upload-seconds "$WAIT_UPLOAD_SECONDS" \
  --wait-proof-seconds "$WAIT_PROOF_SECONDS" \
  --no-build

wait_for_min_hub_height "$MFN_CLI" "$RPC_ADDR" "$MIN_HUB_HEIGHT" "$WAIT_MIN_HUB_HEIGHT_SECONDS"
assert_mesh_heights "$MFN_CLI" "$RPC_ADDR"

FINAL_HUB_HEIGHT="$(tip_height_text "$MFN_CLI" "$RPC_ADDR")"
OBSERVER_RPC=""
OBSERVER_HEIGHT="unknown"
if (( WITH_OBSERVER == 1 )); then
  OBSERVER_RPC="$(latest_observer_rpc || true)"
  if [[ -n "$OBSERVER_RPC" ]]; then
    OBSERVER_HEIGHT="$(tip_height_text "$MFN_CLI" "$OBSERVER_RPC")"
  fi
fi

echo "participant-rehearsal-smoke: PASS rpc=$RPC_ADDR rehearsal_dir=$REHEARSAL_DIR evidence_dir=$EVIDENCE_DIR with_observer=$WITH_OBSERVER hub_tip_height=$FINAL_HUB_HEIGHT min_hub_height=$MIN_HUB_HEIGHT"
if (( ARCHIVE_EVIDENCE == 1 )); then
  archive_rehearsal_smoke_evidence "$RPC_ADDR" "$FINAL_HUB_HEIGHT" "$OBSERVER_RPC" "$OBSERVER_HEIGHT"
fi
