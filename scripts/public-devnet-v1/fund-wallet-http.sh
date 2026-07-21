#!/usr/bin/env bash
# Fund a participant wallet via the public testnet HTTP faucet (async job API).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"

RPC=""
FAUCET_URL="http://127.0.0.1:8788"
RECIPIENT_WALLET=""
CHECKPOINT_LOG=""
WAIT_MINED_SECONDS=300
MIN_OWNED_COUNT=2
NO_BUILD=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: fund-wallet-http.sh [options]

Options:
  --rpc HOST:PORT             mfnd JSON-RPC for recipient balance polling (required outside --plan-only)
  --faucet-url URL            HTTP faucet base URL (default: http://127.0.0.1:8788)
  --recipient-wallet FILE     participant wallet with address to fund (required outside --plan-only)
  --checkpoint-log FILE       signed checkpoint log for wallet light-scan (recommended on tall tips)
  --wait-mined-seconds N      wait for balance + owned_count floor (default: 300; 0 checks once)
  --min-owned-count N         F7 privacy floor (default: 2; 0 disables)
  --no-build                  use existing target/release/mfn-cli
  --plan-only                 print resolved flow without network I/O
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-url) FAUCET_URL="${2:-}"; shift 2 ;;
    --recipient-wallet) RECIPIENT_WALLET="${2:-}"; shift 2 ;;
    --checkpoint-log) CHECKPOINT_LOG="${2:-}"; shift 2 ;;
    --wait-mined-seconds) WAIT_MINED_SECONDS="${2:-}"; shift 2 ;;
    --min-owned-count) MIN_OWNED_COUNT="${2:-}"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "fund-wallet-http: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if (( PLAN_ONLY )); then
  plan_rpc="${RPC:-<required --rpc HOST:PORT>}"
  plan_wallet="${RECIPIENT_WALLET:-<required --recipient-wallet FILE>}"
  echo "fund-wallet-http: plan"
  echo "  rpc=$plan_rpc"
  echo "  faucet_url=$FAUCET_URL"
  echo "  recipient_wallet=$plan_wallet"
  echo "  checkpoint_log=${CHECKPOINT_LOG:-<none>}"
  echo "  wait_mined_seconds=$WAIT_MINED_SECONDS"
  echo "  min_owned_count=$MIN_OWNED_COUNT"
  echo "  flow=F67 pin-then-fund: bootstrap-wallet-from-checkpoint-log (if --checkpoint-log) -> wallet address -> POST /faucet -> poll GET /faucet/job -> wallet light-scan -> wait balance + owned_count"
  echo "  f67=pin BEFORE fund so faucet UTXOs are not skipped by scan_height"
  echo "  warning=test-only HTTP faucet; never commit wallet seeds"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  echo "fund-wallet-http: --rpc HOST:PORT is required outside --plan-only" >&2
  exit 1
fi
if [[ -z "$RECIPIENT_WALLET" ]]; then
  echo "fund-wallet-http: --recipient-wallet FILE is required outside --plan-only" >&2
  exit 1
fi
if [[ ! -f "$RECIPIENT_WALLET" ]]; then
  echo "fund-wallet-http: recipient wallet not found: $RECIPIENT_WALLET" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "fund-wallet-http: curl is required" >&2
  exit 1
fi

MFN_CLI="$REPO_ROOT/target/release/mfn-cli"
if (( ! NO_BUILD )); then
  cargo build -p mfn-cli --release --bin mfn-cli --manifest-path "$REPO_ROOT/Cargo.toml"
fi
if [[ ! -x "$MFN_CLI" ]]; then
  echo "fund-wallet-http: mfn-cli missing at $MFN_CLI" >&2
  exit 1
fi

parse_kv() {
  local key="$1" text="$2"
  printf '%s\n' "$text" | tr -d '\r' | sed -n "s/^${key}=//p" | head -1
}

wallet_light_scan() {
  # B-146 / F101b: after faucet mine, use plain light-scan. Hard --checkpoint-log F45-fails
  # when live tip > Path A max and can abort the entire scan (owned_count stuck at 0).
  "$MFN_CLI" --rpc "$RPC" --wallet "$RECIPIENT_WALLET" wallet light-scan >/dev/null 2>&1 || true
}

# F67 / B-54: pin scan_height to the signed checkpoint *before* faucet sends.
# Pinning after fund skips any UTXO at height <= pin tip (partial owned_count).
if [[ -n "$CHECKPOINT_LOG" && -f "$CHECKPOINT_LOG" ]]; then
  echo "fund-wallet-http: F67 pin-then-fund via bootstrap-wallet-from-checkpoint-log"
  bash "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" --apply \
    --wallet "$RECIPIENT_WALLET" \
    --rpc "$RPC" \
    --log "$CHECKPOINT_LOG" || {
    echo "fund-wallet-http: checkpoint pin failed (snapshot EAGAIN?). Retry when tip is quiet." >&2
    exit 2
  }
fi

health="$(curl -fsS "${FAUCET_URL%/}/health" 2>&1)" || {
  echo "fund-wallet-http: faucet health failed at $FAUCET_URL" >&2
  echo "$health" >&2
  exit 1
}
echo "fund-wallet-http: faucet_health=$health"

addr_out="$("$MFN_CLI" --wallet "$RECIPIENT_WALLET" wallet address 2>&1)"
address="$(parse_kv address "$addr_out")"
if [[ -z "$address" || "$address" != mf* ]]; then
  echo "fund-wallet-http: could not read mf address from wallet" >&2
  echo "$addr_out" >&2
  exit 1
fi
echo "fund-wallet-http: recipient_address=$address"

start_bal_out="$("$MFN_CLI" --rpc "$RPC" --wallet "$RECIPIENT_WALLET" wallet status 2>&1 || true)"
start_bal="$(parse_kv balance_cached "$start_bal_out")"
[[ -z "$start_bal" ]] && start_bal="$(parse_kv balance "$start_bal_out")"
start_bal="${start_bal:-0}"
echo "fund-wallet-http: starting_balance=$start_bal"

claim_body="$(printf '{"address":"%s"}' "$address")"
claim_resp="$(curl -fsS -X POST "${FAUCET_URL%/}/faucet" \
  -H "Content-Type: application/json" \
  --data-binary "$claim_body" 2>&1)" || {
  if printf '%s' "$claim_resp" | grep -qE '503|faucet busy'; then
    echo "fund-wallet-http: POST /faucet busy — retry in 15s" >&2
    sleep 15
    claim_resp="$(curl -fsS -X POST "${FAUCET_URL%/}/faucet" \
      -H "Content-Type: application/json" \
      --data-binary "$claim_body" 2>&1)" || {
      echo "fund-wallet-http: POST /faucet failed after retry" >&2
      echo "$claim_resp" >&2
      exit 1
    }
  else
    echo "fund-wallet-http: POST /faucet failed" >&2
    echo "$claim_resp" >&2
    exit 1
  fi
}
echo "fund-wallet-http: claim_response=$claim_resp"

job_id="$(printf '%s' "$claim_resp" | sed -n 's/.*"job_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
if [[ -z "$job_id" ]]; then
  echo "fund-wallet-http: POST /faucet returned no job_id" >&2
  exit 1
fi
echo "fund-wallet-http: job_id=$job_id"

deadline=$(( $(date +%s) + 900 ))
job_status="pending"
reclaim_attempts=0
while :; do
  job_resp="$(curl -sS -w $'\n%{http_code}' "${FAUCET_URL%/}/faucet/job?id=${job_id}" 2>&1)" || {
    echo "fund-wallet-http: GET /faucet/job failed" >&2
    echo "$job_resp" >&2
    exit 1
  }
  http_code="$(printf '%s' "$job_resp" | tail -1)"
  job_body="$(printf '%s' "$job_resp" | sed '$d')"
  if [[ "$http_code" == "404" ]]; then
    if (( reclaim_attempts >= 1 )); then
      echo "fund-wallet-http: job $job_id lost after re-claim; faucet may still be funding — check balance manually" >&2
      exit 1
    fi
    reclaim_attempts=$((reclaim_attempts + 1))
    echo "fund-wallet-http: job $job_id unknown (faucet restart?); re-claiming (attempt $reclaim_attempts)"
    claim_resp="$(curl -fsS -X POST "${FAUCET_URL%/}/faucet" \
      -H "Content-Type: application/json" \
      --data-binary "$claim_body" 2>&1)" || {
      echo "fund-wallet-http: POST /faucet re-claim failed" >&2
      echo "$claim_resp" >&2
      exit 1
    }
    echo "fund-wallet-http: reclaim_response=$claim_resp"
    job_id="$(printf '%s' "$claim_resp" | sed -n 's/.*"job_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    if [[ -z "$job_id" ]]; then
      echo "fund-wallet-http: re-claim returned no job_id" >&2
      exit 1
    fi
    echo "fund-wallet-http: job_id=$job_id"
    sleep 3
    continue
  fi
  if [[ "$http_code" != "200" ]]; then
    echo "fund-wallet-http: GET /faucet/job HTTP $http_code" >&2
    echo "$job_body" >&2
    exit 1
  fi
  job_status="$(printf '%s' "$job_body" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  echo "fund-wallet-http: job_poll status=$job_status"
  if [[ "$job_status" == "done" ]]; then
    echo "fund-wallet-http: job_result=$job_body"
    break
  fi
  if [[ "$job_status" == "error" ]]; then
    echo "fund-wallet-http: faucet job failed: $job_body" >&2
    exit 1
  fi
  if (( $(date +%s) >= deadline )); then
    echo "fund-wallet-http: timed out waiting for faucet job $job_id" >&2
    exit 1
  fi
  sleep 3
done

echo "fund-wallet-http: post-fund light-scan (plain; F45-safe)"
wallet_light_scan

if (( WAIT_MINED_SECONDS <= 0 )); then
  echo "fund-wallet-http: PASS (wait disabled)"
  exit 0
fi

wait_deadline=$(( $(date +%s) + WAIT_MINED_SECONDS ))
last_scan=0
while :; do
  now=$(date +%s)
  if (( now - last_scan >= 45 )); then
    wallet_light_scan
    last_scan=$now
  fi
  st_out="$("$MFN_CLI" --rpc "$RPC" --wallet "$RECIPIENT_WALLET" wallet status 2>&1 || true)"
  bal="$(parse_kv balance_cached "$st_out")"
  [[ -z "$bal" ]] && bal="$(parse_kv balance "$st_out")"
  owned="$(parse_kv owned_count_cached "$st_out")"
  [[ -z "$owned" ]] && owned="$(parse_kv owned_count "$st_out")"
  bal="${bal:-0}"
  owned="${owned:-0}"
  echo "fund-wallet-http: wait balance=$bal owned_count=$owned (start=$start_bal min_owned=$MIN_OWNED_COUNT)"
  ok_bal=0
  ok_owned=0
  if (( bal > start_bal )); then ok_bal=1; fi
  if (( MIN_OWNED_COUNT <= 0 || owned >= MIN_OWNED_COUNT )); then ok_owned=1; fi
  if (( ok_bal && ok_owned )); then
    echo "fund-wallet-http: PASS balance=$bal owned_count=$owned"
    exit 0
  fi
  if (( $(date +%s) >= wait_deadline )); then
    echo "fund-wallet-http: timed out balance=$bal owned_count=$owned" >&2
    exit 1
  fi
  sleep 10
done
