#!/usr/bin/env bash
# Fail unless a TL-6 VPS participant rehearsal evidence transcript is audit-ready.
set -euo pipefail

EVIDENCE_FILE="${1:?assert-vps-participant-rehearsal-evidence: pass path to vps-participant-rehearsal-*.txt}"

if [[ ! -f "$EVIDENCE_FILE" ]]; then
  echo "assert-vps-participant-rehearsal-evidence: missing $EVIDENCE_FILE" >&2
  exit 1
fi

base="$(basename "$EVIDENCE_FILE")"
if [[ "$base" != vps-participant-rehearsal-* ]]; then
  echo "assert-vps-participant-rehearsal-evidence: expected vps-participant-rehearsal-*.txt got $base" >&2
  exit 1
fi

if ! grep -qF -- "# TL-6 internet-facing VPS participant rehearsal" "$EVIDENCE_FILE"; then
  echo "assert-vps-participant-rehearsal-evidence: $EVIDENCE_FILE missing TL-6 VPS header" >&2
  exit 1
fi
if ! grep -qE '^SUMMARY: PASS$' "$EVIDENCE_FILE"; then
  echo "assert-vps-participant-rehearsal-evidence: $EVIDENCE_FILE missing SUMMARY: PASS" >&2
  exit 1
fi
if ! grep -qE 'participant-rehearsal-smoke: PASS with_observer=true' "$EVIDENCE_FILE"; then
  echo "assert-vps-participant-rehearsal-evidence: $EVIDENCE_FILE missing observer PASS line" >&2
  exit 1
fi
if ! grep -qE 'hub_tip_height=[0-9]+ min_hub_height=[0-9]+' "$EVIDENCE_FILE"; then
  echo "assert-vps-participant-rehearsal-evidence: $EVIDENCE_FILE missing hub height summary" >&2
  exit 1
fi

min_height="$(grep -Eo 'min_hub_height=[0-9]+' "$EVIDENCE_FILE" | head -1 | cut -d= -f2)"
hub_height="$(grep -Eo 'hub_tip_height=[0-9]+' "$EVIDENCE_FILE" | head -1 | cut -d= -f2)"
if [[ -z "$min_height" || -z "$hub_height" ]]; then
  echo "assert-vps-participant-rehearsal-evidence: $EVIDENCE_FILE missing parseable hub heights" >&2
  exit 1
fi
if (( hub_height < min_height )); then
  echo "assert-vps-participant-rehearsal-evidence: hub_tip_height=$hub_height < min_hub_height=$min_height" >&2
  exit 1
fi

echo "assert-vps-participant-rehearsal-evidence: OK evidence_file=$EVIDENCE_FILE hub_tip_height=$hub_height"
