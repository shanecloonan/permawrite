#!/usr/bin/env bash
# Lane 7 / TL-8: sign and append a maintainer checkpoint log entry (F12 phase 4).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DEFAULT_LOG="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
RPC=""
LOG_PATH="$DEFAULT_LOG"
SIGNER_ID="${MFN_CHECKPOINT_LOG_SIGNER_ID:-permawrite-maintainer-1}"
APPLY=0
PLAN_ONLY=0
TMPDIR=""

usage() {
  cat <<'EOF'
usage: publish-checkpoint-log.sh [--rpc HOST:PORT] [--log PATH] [--signer-id ID] [--apply|--plan-only]

Fetches the chain tip trusted summary from JSON-RPC, signs with
MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX, and appends to the community JSONL log.

Default is dry-run (prints planned paths). --apply writes the log entry.
--plan-only is CI-safe (no RPC or maintainer seed required).

Requires release mfn-cli on PATH or ./target/release/mfn-cli.
EOF
}

cleanup() {
  if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:?}"; shift 2 ;;
    --log) LOG_PATH="${2:?}"; shift 2 ;;
    --signer-id) SIGNER_ID="${2:?}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "publish-checkpoint-log: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "publish-checkpoint-log: plan"
  echo "  flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"
  echo "  default_log=$DEFAULT_LOG"
  echo "  docs=docs/CHECKPOINT_LOG.md"
  echo "publish-checkpoint-log: PASS plan-only"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  BIND="$SCRIPT_DIR/vps-bind.env"
  if [[ -f "$BIND" ]]; then
    # shellcheck source=/dev/null
    source "$BIND"
    if [[ -n "${MFND_RPC_LISTEN_HUB:-}" ]]; then
      RPC="$MFND_RPC_LISTEN_HUB"
    fi
  fi
fi
if [[ -z "$RPC" ]]; then
  PORTS="$SCRIPT_DIR/devnet-ports.env"
  if [[ -f "$PORTS" ]]; then
    # shellcheck source=/dev/null
    source "$PORTS"
    RPC="${HUB_RPC:-}"
  fi
fi
if [[ -z "$RPC" ]]; then
  echo "publish-checkpoint-log: set --rpc or run from a host with vps-bind.env / devnet-ports.env" >&2
  exit 1
fi

MCLI="${MCLI:-$REPO_ROOT/target/release/mfn-cli}"
if [[ ! -x "$MCLI" ]]; then
  if command -v mfn-cli >/dev/null 2>&1; then
    MCLI="$(command -v mfn-cli)"
  else
    echo "publish-checkpoint-log: build mfn-cli release first or set MCLI=" >&2
    exit 1
  fi
fi

if [[ -z "${MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX:-}" ]]; then
  echo "publish-checkpoint-log: set MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX (32-byte hex maintainer seed)" >&2
  exit 1
fi

echo "publish-checkpoint-log: TL-8 preview rpc=$RPC log=$LOG_PATH signer_id=$SIGNER_ID"
echo "publish-checkpoint-log: flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"

if (( APPLY == 0 )); then
  echo ""
  echo "publish-checkpoint-log: dry-run only; re-run with --apply after TL-7 sign-off"
  exit 0
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/mfn-checkpoint-log.XXXXXX")"
SUMMARY="$TMPDIR/trusted-summary.json"
WALLET="$TMPDIR/publish-wallet.json"

cd "$REPO_ROOT"
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet new >/dev/null
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet export-trusted-summary --out "$SUMMARY"

SIGN_ARGS=(
  checkpoint-log sign
  --summary "$SUMMARY"
  --signer-id "$SIGNER_ID"
  --signer-seed-hex "$MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX"
  --append "$LOG_PATH"
)
"$MCLI" "${SIGN_ARGS[@]}" >/dev/null
"$MCLI" checkpoint-log verify "$LOG_PATH"
"$MCLI" checkpoint-log cross-check --summary "$SUMMARY" --log "$LOG_PATH"

echo "publish-checkpoint-log: OK appended to $LOG_PATH"
echo "publish-checkpoint-log: commit log + link from docs/TESTNET_INVITE.md (TL-8)"
