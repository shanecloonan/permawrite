#!/usr/bin/env bash
# Lane 5 / F12 phase 5: plan-only demo web checkpoint-log WASM wiring gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INDEX="$REPO_ROOT/demo/web/index.html"
MAIN="$REPO_ROOT/demo/web/main.js"
DOC="$REPO_ROOT/docs/M4_WASM.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates demo/web F12 checkpoint log UI + WASM import wiring (no browser).
EOF
}

PLAN_ONLY=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
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

echo "demo-web-f12-rehearsal-smoke: plan"
echo "  ui=demo/web/index.html#checkpoint-log"
echo "  wasm=checkpointLogVerify checkpointLogCrossCheck"
echo "  docs=docs/M4_WASM.md"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "demo-web-f12-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "demo-web-f12-rehearsal-smoke: live mode not implemented" >&2
exit 1
