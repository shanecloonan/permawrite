#!/usr/bin/env bash
# Fail unless a TL-5 VPS internet soak evidence transcript is audit-ready.
set -euo pipefail

EVIDENCE_FILE="${1:?assert-vps-internet-soak-evidence: pass path to vps-internet-soak-linux-*.txt}"

if [[ ! -f "$EVIDENCE_FILE" ]]; then
  echo "assert-vps-internet-soak-evidence: missing $EVIDENCE_FILE" >&2
  exit 1
fi

base="$(basename "$EVIDENCE_FILE")"
if [[ "$base" != vps-internet-soak-linux-* ]]; then
  echo "assert-vps-internet-soak-evidence: expected vps-internet-soak-linux-*.txt got $base" >&2
  exit 1
fi

if ! grep -qF -- "# TL-5 internet-facing VPS soak" "$EVIDENCE_FILE"; then
  echo "assert-vps-internet-soak-evidence: $EVIDENCE_FILE missing TL-5 VPS header" >&2
  exit 1
fi
if ! grep -qE 'soak: SUMMARY status=PASS' "$EVIDENCE_FILE"; then
  echo "assert-vps-internet-soak-evidence: $EVIDENCE_FILE missing soak: SUMMARY status=PASS" >&2
  exit 1
fi
if ! grep -qE 'soak: SAMPLE ' "$EVIDENCE_FILE"; then
  echo "assert-vps-internet-soak-evidence: $EVIDENCE_FILE missing soak: SAMPLE lines" >&2
  exit 1
fi
expected_genesis="454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
if ! grep -qF -- "genesis_id=$expected_genesis" "$EVIDENCE_FILE"; then
  echo "assert-vps-internet-soak-evidence: $EVIDENCE_FILE missing genesis_id=$expected_genesis" >&2
  exit 1
fi

echo "assert-vps-internet-soak-evidence: OK evidence_file=$EVIDENCE_FILE"
