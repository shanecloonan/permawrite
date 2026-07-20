#!/usr/bin/env bash
# Fail unless a B-32 B3 multi-op SPoRA evidence transcript is audit-ready.
set -euo pipefail

EVIDENCE_FILE="${1:?assert-b3-multi-op-evidence: pass path to b3-multi-op-*.txt}"

if [[ ! -f "$EVIDENCE_FILE" ]]; then
  echo "assert-b3-multi-op-evidence: missing $EVIDENCE_FILE" >&2
  exit 1
fi

base="$(basename "$EVIDENCE_FILE")"
if [[ "$base" != b3-multi-op-* ]]; then
  echo "assert-b3-multi-op-evidence: expected b3-multi-op-*.txt got $base" >&2
  exit 1
fi

if ! grep -qF -- "# B-32 B3 multi-op SPoRA evidence" "$EVIDENCE_FILE"; then
  echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing B-32 header" >&2
  exit 1
fi
if ! grep -qE '^SUMMARY: PASS$' "$EVIDENCE_FILE"; then
  echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing SUMMARY: PASS" >&2
  exit 1
fi
if ! grep -qE '^operator_count=[0-9]+$' "$EVIDENCE_FILE"; then
  echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing operator_count" >&2
  exit 1
fi
op_count="$(grep -Eo '^operator_count=[0-9]+$' "$EVIDENCE_FILE" | head -1 | cut -d= -f2)"
if [[ -z "$op_count" ]] || (( op_count < 2 )); then
  echo "assert-b3-multi-op-evidence: need operator_count>=2 got $op_count" >&2
  exit 1
fi
for key in distinct_hosts distinct_payouts spora_proofs_from_both; do
  if ! grep -qE "^${key}=true$" "$EVIDENCE_FILE"; then
    echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing ${key}=true" >&2
    exit 1
  fi
done
if ! grep -qE '^commitment_hash=[0-9a-fA-F]{64}$' "$EVIDENCE_FILE"; then
  echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing commitment_hash=64hex" >&2
  exit 1
fi
if ! grep -qE '^tip_height=[0-9]+$' "$EVIDENCE_FILE"; then
  echo "assert-b3-multi-op-evidence: $EVIDENCE_FILE missing tip_height" >&2
  exit 1
fi
tip_height="$(grep -Eo '^tip_height=[0-9]+$' "$EVIDENCE_FILE" | head -1 | cut -d= -f2)"
if [[ -z "$tip_height" ]] || (( tip_height <= 0 )); then
  echo "assert-b3-multi-op-evidence: invalid tip_height=$tip_height" >&2
  exit 1
fi

echo "assert-b3-multi-op-evidence: OK evidence_file=$EVIDENCE_FILE operator_count=$op_count tip_height=$tip_height"