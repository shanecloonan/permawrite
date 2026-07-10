#!/usr/bin/env bash
# F12 phase 1–4: signed checkpoint log rehearsal (plan-only default; --live uses local devnet).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/CHECKPOINT_LOG.md"
PUBLISH="$SCRIPT_DIR/publish-checkpoint-log.sh"

# Test-only maintainer seed for local rehearsal (NOT for production testnet maintainers).
REHEARSAL_SEED_HEX="${MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
REHEARSAL_SIGNER_ID="${MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID:-permawrite-rehearsal-maintainer}"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only|--live] [--no-start] [--no-stop]

Validates F12 checkpoint log docs + (optional) live sign/verify/cross-check on local devnet.
EOF
}

PLAN_ONLY=1
NO_START=0
NO_STOP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --live) PLAN_ONLY=0; shift ;;
    --no-start) NO_START=1; shift ;;
    --no-stop) NO_STOP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

if [[ ! -f "$DOC" ]]; then
  echo "checkpoint-log-rehearsal-smoke: missing $DOC" >&2
  exit 1
fi
if [[ ! -x "$PUBLISH" ]] && [[ ! -f "$PUBLISH" ]]; then
  echo "checkpoint-log-rehearsal-smoke: missing $PUBLISH" >&2
  exit 1
fi

for needle in \
  "checkpoint-log sign" \
  "checkpoint-log verify" \
  "checkpoint-log cross-check" \
  "publish-checkpoint-log" \
  "MFN:checkpoint-log-signer:v1" \
  "MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX" \
  "MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX" \
  "--checkpoint-log" \
  "checkpoint_log=matched" \
  "checkpointLogVerify" \
  "checkpointLogCrossCheck" \
  ; do
  if ! grep -qF "$needle" "$DOC"; then
    echo "checkpoint-log-rehearsal-smoke: CHECKPOINT_LOG.md missing: $needle" >&2
    exit 1
  fi
done

echo "checkpoint-log-rehearsal-smoke: plan"
echo "  flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"
echo "  tl8=publish-checkpoint-log.sh --apply (production maintainer seed)"
echo "  light_scan=wallet light-scan --checkpoint-log FILE"
echo "  docs=docs/CHECKPOINT_LOG.md"
echo "  cli=mfn-cli checkpoint-log sign|verify|cross-check"
echo "  wasm=checkpointLogVerify; checkpointLogCrossCheck (mfn-wasm wasm-full)"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "checkpoint-log-rehearsal-smoke: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
MFND="${MFND:-$REPO_ROOT/target/release/mfnd}"
MCLI="${MCLI:-$REPO_ROOT/target/release/mfn-cli}"
if [[ ! -x "$MFND" ]] || [[ ! -x "$MCLI" ]]; then
  echo "checkpoint-log-rehearsal-smoke: build mfnd + mfn-cli release first" >&2
  exit 1
fi

if (( NO_START == 0 )); then
  bash "$SCRIPT_DIR/start-all.sh" --no-build
fi

PORTS="$SCRIPT_DIR/devnet-ports.env"
if [[ ! -f "$PORTS" ]]; then
  echo "checkpoint-log-rehearsal-smoke: missing $PORTS (start-all or pass --no-start with running mesh)" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$PORTS"
RPC="${HUB_RPC:-}"
if [[ -z "$RPC" ]]; then
  echo "checkpoint-log-rehearsal-smoke: HUB_RPC missing from $PORTS" >&2
  exit 1
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/mfn-checkpoint-rehearsal.XXXXXX")"
cleanup() {
  rm -rf "$TMPDIR"
  if (( NO_STOP == 0 && NO_START == 0 )); then
    bash "$SCRIPT_DIR/stop-all.sh" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

SUMMARY="$TMPDIR/trusted-summary.json"
LOG="$TMPDIR/checkpoints.jsonl"
WALLET="$TMPDIR/wallet.json"

"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet new >/dev/null
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet export-trusted-summary --out "$SUMMARY"
"$MCLI" checkpoint-log sign \
  --summary "$SUMMARY" \
  --signer-id "$REHEARSAL_SIGNER_ID" \
  --signer-seed-hex "$REHEARSAL_SEED_HEX" \
  --append "$LOG" >/dev/null
"$MCLI" checkpoint-log verify "$LOG"
"$MCLI" checkpoint-log cross-check --summary "$SUMMARY" --log "$LOG"

echo "checkpoint-log-rehearsal-smoke: PASS live rpc=$RPC signer_id=$REHEARSAL_SIGNER_ID"
