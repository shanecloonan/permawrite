#!/usr/bin/env bash
# Fail unless a B-27 outside-in invite-head soak evidence transcript is audit-ready.
set -euo pipefail

EVIDENCE_FILE="${1:?assert-outside-in-invite-soak-evidence: pass path to outside-in-invite-soak-*.txt}"
EXPECTED_GENESIS="${MFN_EXPECTED_GENESIS_ID:-454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005}"

if [[ ! -f "$EVIDENCE_FILE" ]]; then
  echo "assert-outside-in-invite-soak-evidence: missing $EVIDENCE_FILE" >&2
  exit 1
fi

base="$(basename "$EVIDENCE_FILE")"
if [[ "$base" != outside-in-invite-soak-* ]]; then
  echo "assert-outside-in-invite-soak-evidence: expected outside-in-invite-soak-*.txt got $base" >&2
  exit 1
fi

if ! grep -qF -- "# B-27 outside-in invite-head soak" "$EVIDENCE_FILE"; then
  echo "assert-outside-in-invite-soak-evidence: missing B-27 header" >&2
  exit 1
fi
if ! grep -qF -- "never=faucet-http mfnd restart join-testnet-rehearsal" "$EVIDENCE_FILE"; then
  echo "assert-outside-in-invite-soak-evidence: missing never= conflict guard" >&2
  exit 1
fi
if ! grep -qE 'soak: SUMMARY status=PASS' "$EVIDENCE_FILE"; then
  echo "assert-outside-in-invite-soak-evidence: missing soak: SUMMARY status=PASS" >&2
  exit 1
fi
if ! grep -qE 'soak: SAMPLE ' "$EVIDENCE_FILE"; then
  echo "assert-outside-in-invite-soak-evidence: missing soak: SAMPLE lines" >&2
  exit 1
fi
if ! grep -qF -- "genesis_id=$EXPECTED_GENESIS" "$EVIDENCE_FILE"; then
  echo "assert-outside-in-invite-soak-evidence: missing genesis_id=$EXPECTED_GENESIS" >&2
  exit 1
fi

echo "assert-outside-in-invite-soak-evidence: OK evidence_file=$EVIDENCE_FILE"
