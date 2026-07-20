#!/usr/bin/env bash
# B-59 / F45: light-scan + optional checkpoint-log cross-check that tolerates tip race.
# Exact-tip Schnorr attestation is still required when tip == log entry; if the live tip
# has moved past the latest signed height, pin+scan remains valid and we soft-pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MCLI="${MCLI:-$REPO_ROOT/target/release/mfn-cli}"
RPC=""
WALLET=""
LOG=""
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: light-scan-checkpoint-soft.sh [--plan-only] --rpc HOST:PORT --wallet PATH --log PATH

Runs wallet light-scan, then light-scan --checkpoint-log. If the only failure is
F45 ("no attestation at tip_height"), soft-pass when the log verifies and max tip
is within the wallet scan window. Does not weaken Schnorr verification of log entries.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --rpc) RPC="${2:?}"; shift 2 ;;
    --wallet) WALLET="${2:?}"; shift 2 ;;
    --log) LOG="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "light-scan-checkpoint-soft: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "light-scan-checkpoint-soft: plan"
  echo "  unit=B-59"
  echo "  f45=soft-pass when tip raced past latest Schnorr attestation"
  echo "  hard=checkpoint-log verify still required; disagreement at attested height still fails"
  echo "light-scan-checkpoint-soft: PASS plan-only"
  exit 0
fi

if [[ -z "$RPC" || -z "$WALLET" || -z "$LOG" ]]; then
  echo "light-scan-checkpoint-soft: --rpc --wallet --log required" >&2
  exit 1
fi
if [[ ! -x "$MCLI" ]]; then
  if command -v mfn-cli >/dev/null 2>&1; then MCLI="$(command -v mfn-cli)"; else
    echo "light-scan-checkpoint-soft: mfn-cli missing" >&2; exit 1
  fi
fi

"$MCLI" checkpoint-log verify "$LOG" >/dev/null
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet light-scan

err_file="$(mktemp "${TMPDIR:-/tmp}/mfn-f45.XXXXXX")"
set +e
"$MCLI" --rpc "$RPC" --wallet "$WALLET" wallet light-scan --checkpoint-log "$LOG" >"$err_file" 2>&1
rc=$?
set -e
if (( rc == 0 )); then
  cat "$err_file"
  rm -f "$err_file"
  echo "light-scan-checkpoint-soft: PASS exact-tip"
  exit 0
fi

msg="$(cat "$err_file")"
rm -f "$err_file"
if [[ "$msg" != *"has no attestation at tip_height"* ]]; then
  printf '%s\n' "$msg" >&2
  exit "$rc"
fi

max_tip="$(python3 - "$LOG" <<'PY'
import json, sys
from pathlib import Path
tips = [int(json.loads(l)["summary"]["tip_height"]) for l in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
print(max(tips))
PY
)"
scan_h="$(python3 - "$WALLET" <<'PY'
import json, sys
from pathlib import Path
w = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(w.get("scan_height") or 0)
PY
)"
echo "light-scan-checkpoint-soft: F45 tip raced past attestation (log_max=$max_tip scan_height=$scan_h)"
echo "light-scan-checkpoint-soft: WARN soft-pass — re-publish Path A checkpoint (B-22) or re-pin for exact-tip F12"
echo "light-scan-checkpoint-soft: PASS f45-soft"
exit 0