#!/usr/bin/env bash
# Fail unless participant-rehearsal-smoke staged audit-ready evidence exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${1:-$SCRIPT_DIR/participant-rehearsal-smoke/evidence}"
LOG="$EVIDENCE_DIR/participant-rehearsal.log"
BUNDLE="$EVIDENCE_DIR/support-bundle"
MANIFEST="$BUNDLE/manifest.json"

if [[ ! -f "$LOG" ]]; then
  echo "assert-participant-smoke-evidence: missing $LOG" >&2
  exit 1
fi
if [[ ! -d "$BUNDLE" ]]; then
  echo "assert-participant-smoke-evidence: missing support bundle directory $BUNDLE" >&2
  exit 1
fi
if ! grep -qE 'participant-rehearsal: PASS commitment_hash=[0-9a-fA-F]+ restored_sha256=[0-9a-fA-F]{64} restored_path=\S+ support_bundle=' "$LOG"; then
  echo "assert-participant-smoke-evidence: $LOG missing final PASS line" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "assert-participant-smoke-evidence: missing $MANIFEST" >&2
  exit 1
fi
echo "assert-participant-smoke-evidence: OK evidence_dir=$EVIDENCE_DIR"