#!/usr/bin/env bash
# Fail unless a B-15 JOIN_TESTNET live rehearsal evidence transcript is audit-ready.
set -euo pipefail

EVIDENCE_FILE="${1:?assert-join-testnet-rehearsal-evidence: pass path to join-testnet-rehearsal-*.txt}"

if [[ ! -f "$EVIDENCE_FILE" ]]; then
  echo "assert-join-testnet-rehearsal-evidence: missing $EVIDENCE_FILE" >&2
  exit 1
fi

base="$(basename "$EVIDENCE_FILE")"
if [[ "$base" != join-testnet-rehearsal-* ]]; then
  echo "assert-join-testnet-rehearsal-evidence: expected join-testnet-rehearsal-*.txt got $base" >&2
  exit 1
fi

if ! grep -qF -- "# B-15 live testnet JOIN_TESTNET participant rehearsal" "$EVIDENCE_FILE"; then
  echo "assert-join-testnet-rehearsal-evidence: $EVIDENCE_FILE missing B-15 header" >&2
  exit 1
fi
if ! grep -qE '^SUMMARY: PASS$' "$EVIDENCE_FILE"; then
  echo "assert-join-testnet-rehearsal-evidence: $EVIDENCE_FILE missing SUMMARY: PASS" >&2
  exit 1
fi
if ! grep -qE 'join-testnet-rehearsal-smoke: PASS faucet_http=true light_scan_checkpoint=true observer_proxy=true' "$EVIDENCE_FILE"; then
  echo "assert-join-testnet-rehearsal-evidence: $EVIDENCE_FILE missing smoke PASS line" >&2
  exit 1
fi
if ! grep -qE 'join-testnet-rehearsal: PASS .*faucet_http=true light_scan_checkpoint=true' "$EVIDENCE_FILE"; then
  echo "assert-join-testnet-rehearsal-evidence: $EVIDENCE_FILE missing rehearsal PASS line" >&2
  exit 1
fi
if ! grep -qE '^tip_height=[0-9]+$' "$EVIDENCE_FILE"; then
  echo "assert-join-testnet-rehearsal-evidence: $EVIDENCE_FILE missing tip_height" >&2
  exit 1
fi

tip_height="$(grep -Eo '^tip_height=[0-9]+$' "$EVIDENCE_FILE" | head -1 | cut -d= -f2)"
if [[ -z "$tip_height" ]] || (( tip_height <= 0 )); then
  echo "assert-join-testnet-rehearsal-evidence: invalid tip_height=$tip_height" >&2
  exit 1
fi

echo "assert-join-testnet-rehearsal-evidence: OK evidence_file=$EVIDENCE_FILE tip_height=$tip_height"
