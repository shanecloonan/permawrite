#!/usr/bin/env bash
# Lane 5 / F12 phase 5: demo web checkpoint-log WASM wiring + live crypto smoke.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INDEX="$REPO_ROOT/demo/web/index.html"
MAIN="$REPO_ROOT/demo/web/main.js"
DOC="$REPO_ROOT/docs/M4_WASM.md"

REHEARSAL_SEED_HEX="${MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
REHEARSAL_SIGNER_ID="${MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID:-permawrite-rehearsal-maintainer}"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only|--live]

Validates demo/web F12 checkpoint log UI + WASM import wiring.
--live signs a fixture and runs CLI + mfn-wasm unit verify/cross-check.
EOF
}

PLAN_ONLY=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --live) PLAN_ONLY=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

for f in "$INDEX" "$MAIN" "$DOC"; do
  if [[ ! -f "$f" ]]; then
    echo "demo-web-f12-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "checkpointLogVerify" \
  "checkpointLogCrossCheck" \
  "btn-checkpoint-log-verify" \
  "btn-checkpoint-log-cross-check" \
  ; do
  if ! grep -qF -- "$needle" "$INDEX" && ! grep -qF -- "$needle" "$MAIN"; then
    echo "demo-web-f12-rehearsal-smoke: demo/web missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "checkpointLogVerify" "$MAIN"; then
  echo "demo-web-f12-rehearsal-smoke: main.js must import checkpointLogVerify" >&2
  exit 1
fi
if ! grep -qF -- "checkpointLogCrossCheck" "$MAIN"; then
  echo "demo-web-f12-rehearsal-smoke: main.js must import checkpointLogCrossCheck" >&2
  exit 1
fi
if ! grep -qF -- "checkpointLogVerify" "$DOC"; then
  echo "demo-web-f12-rehearsal-smoke: M4_WASM.md missing checkpointLogVerify" >&2
  exit 1
fi

echo "demo-web-f12-rehearsal-smoke: plan"
echo "  ui=demo/web/index.html#checkpoint-log"
echo "  wasm=checkpointLogVerify checkpointLogCrossCheck"
echo "  docs=docs/M4_WASM.md"
echo "  live=sign fixture -> mfn-cli verify/cross-check -> cargo test mfn-wasm checkpoint_log"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "demo-web-f12-rehearsal-smoke: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
MCLI="${MCLI:-$REPO_ROOT/target/release/mfn-cli}"
if [[ ! -x "$MCLI" ]]; then
  echo "demo-web-f12-rehearsal-smoke: build mfn-cli release first (cargo build -p mfn-cli --release)" >&2
  exit 1
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/mfn-demo-f12.XXXXXX")"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

SUMMARY="$TMPDIR/trusted-summary.json"
LOG="$TMPDIR/checkpoints.jsonl"

python3 - <<PY
import json
summary = {
    "genesis_id": "aa" * 32,
    "tip_height": 42,
    "tip_block_id": "bb" * 32,
    "validator_count": 3,
    "validator_set_root": "cc" * 32,
    "checkpoint_digest": "dd" * 32,
}
with open("$SUMMARY", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
PY

"$MCLI" checkpoint-log sign \
  --summary "$SUMMARY" \
  --signer-id "$REHEARSAL_SIGNER_ID" \
  --signer-seed-hex "$REHEARSAL_SEED_HEX" \
  --append "$LOG" >/dev/null
"$MCLI" checkpoint-log verify "$LOG"
cross_out="$("$MCLI" checkpoint-log cross-check --summary "$SUMMARY" --log "$LOG")"
echo "$cross_out"
if [[ "$cross_out" != *"checkpoint_log=matched"* ]]; then
  echo "demo-web-f12-rehearsal-smoke: expected checkpoint_log=matched" >&2
  exit 1
fi

cargo test -p mfn-wasm --release --features wasm-full checkpoint_log_core -- --nocapture

echo "demo-web-f12-rehearsal-smoke: PASS live signer_id=$REHEARSAL_SIGNER_ID"
