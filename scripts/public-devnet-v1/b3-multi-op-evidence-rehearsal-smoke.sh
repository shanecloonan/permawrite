#!/usr/bin/env bash
# B-32: plan-only multi-op evidence assert + ROADMAP wiring gate (no live mesh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROADMAP="$REPO_ROOT/docs/ROADMAP.md"
PERMANENCE="$REPO_ROOT/docs/PERMANENCE_HARDENING.md"
ASSERT="$SCRIPT_DIR/assert-b3-multi-op-evidence.sh"
FIXTURE="$SCRIPT_DIR/fixtures/b3-multi-op-evidence-v1/b3-multi-op-linux-20260720T000000Z.txt"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates assert-b3-multi-op-evidence + B-32 doc wiring (no live operators).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

for f in "$ROADMAP" "$ASSERT" "$FIXTURE"; do
  if [[ ! -f "$f" ]]; then
    echo "b3-multi-op-evidence-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "B-32" \
  "b3-multi-op" \
  "assert-b3-multi-op-evidence" \
  ; do
  if ! grep -qF -- "$needle" "$ROADMAP"; then
    echo "b3-multi-op-evidence-rehearsal-smoke: ROADMAP.md missing: $needle" >&2
    exit 1
  fi
done

if [[ -f "$PERMANENCE" ]] && ! grep -qF -- "B-32" "$PERMANENCE"; then
  echo "b3-multi-op-evidence-rehearsal-smoke: WARN PERMANENCE_HARDENING.md missing B-32 (non-fatal)"
fi

bash "$ASSERT" "$FIXTURE"

echo "b3-multi-op-evidence-rehearsal-smoke: plan"
echo "  assert=assert-b3-multi-op-evidence.sh|.ps1"
echo "  fixture=fixtures/b3-multi-op-evidence-v1/"
echo "  live=archive b3-multi-op-<date>.txt after >=2 operators prove SPoRA (arm day-of L4)"
echo "b3-multi-op-evidence-rehearsal-smoke: PASS plan-only"
exit 0