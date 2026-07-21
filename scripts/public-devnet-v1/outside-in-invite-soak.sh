#!/usr/bin/env bash
# B-27 / lane 1: outside-in invite-head soak via public observer proxy.
# Read-only: never restarts faucet/mfnd, never runs JOIN. Safe during B-15 capture.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PROXY_URL="${MFN_OUTSIDE_IN_PROXY_URL:-http://5.161.201.73:8787/rpc}"
EXPECTED_GENESIS="${MFN_EXPECTED_GENESIS_ID:-454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005}"
SAMPLES="${MFN_OUTSIDE_IN_SOAK_SAMPLES:-6}"
INTERVAL_S="${MFN_OUTSIDE_IN_SOAK_INTERVAL_S:-45}"
MIN_DELTA="${MFN_OUTSIDE_IN_SOAK_MIN_DELTA:-1}"
PLAN_ONLY=0
ARCHIVE=1
EVIDENCE_DIR="$SCRIPT_DIR/evidence"

usage() {
  cat <<'EOF'
usage: outside-in-invite-soak.sh [--plan-only] [--no-archive]

Samples get_tip on the public observer proxy over several intervals and
requires tip_height to advance. Archives evidence under evidence/.
Never restarts faucet/mfnd; never runs JOIN (B-15-safe).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --no-archive) ARCHIVE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "outside-in-invite-soak: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "outside-in-invite-soak: plan"
  echo "  unit=B-27"
  echo "  proxy=$PROXY_URL"
  echo "  samples=$SAMPLES interval_s=$INTERVAL_S min_delta=$MIN_DELTA"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "  assert=assert-outside-in-invite-soak-evidence.sh"
  echo "outside-in-invite-soak: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
head_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
  echo "# B-27 outside-in invite-head soak (public observer proxy)"
  echo "# head_sha=$head_sha"
  echo "# proxy=$PROXY_URL"
  echo "# samples=$SAMPLES interval_s=$INTERVAL_S min_delta=$MIN_DELTA"
  echo "# never=faucet-http mfnd restart join-testnet-rehearsal"
  nightly_run="${MFN_B27_NIGHTLY_RUN:-}"
  ci_run="${MFN_B27_CI_RUN:-}"
  if [[ -z "$nightly_run" ]] && command -v gh >/dev/null 2>&1; then
    nightly_run="$(gh run list --workflow Nightly --limit 12 --json databaseId,conclusion --jq '.[] | select(.conclusion=="success") | .databaseId' 2>/dev/null | head -n1 || true)"
  fi
  if [[ -z "$ci_run" ]] && command -v gh >/dev/null 2>&1; then
    ci_run="$(gh run list --workflow CI --branch main --limit 12 --json databaseId,conclusion --jq '.[] | select(.conclusion=="success") | .databaseId' 2>/dev/null | head -n1 || true)"
  fi
  # B-123: single numeric pin only (reject multi-line/junk gh output; Win parity).
  if [[ -n "$nightly_run" && ! "$nightly_run" =~ ^[0-9]+$ ]]; then
    echo "outside-in-invite-soak: WARN ignoring non-numeric nightly_run=$nightly_run" >&2
    nightly_run=""
  fi
  if [[ -n "$ci_run" && ! "$ci_run" =~ ^[0-9]+$ ]]; then
    echo "outside-in-invite-soak: WARN ignoring non-numeric ci_run=$ci_run" >&2
    ci_run=""
  fi
  if [[ -n "$nightly_run" ]]; then
    echo "# nightly_run=$nightly_run"
  fi
  if [[ -n "$ci_run" ]]; then
    echo "# ci_run=$ci_run"
  fi
  # B-96 fail-closed: soak evidence without Nightly+CI pins is not archiveable.
  if [[ -z "$nightly_run" || -z "$ci_run" ]]; then
    if [[ "${MFN_B27_ALLOW_UNPINNED:-0}" != "1" ]]; then
      echo "outside-in-invite-soak: FAIL missing nightly_run/ci_run pins (set MFN_B27_ALLOW_UNPINNED=1 to override)" >&2
      exit 1
    fi
  fi
} >"$tmp"

get_tip() {
  python3 - "$PROXY_URL" <<'PY'
import json, sys, urllib.request
url = sys.argv[1]
req = urllib.request.Request(
    url,
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get_tip", "params": []}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as resp:
    body = json.loads(resp.read().decode())
if "error" in body:
    raise SystemExit(f"rpc error: {body['error']}")
r = body["result"]
print(f"{r['tip_height']}\t{r['tip_id']}\t{r['genesis_id']}\t{r.get('validator_count', '?')}")
PY
}

first_h=""
last_h=""
ok_samples=0
for i in $(seq 1 "$SAMPLES"); do
  line="$(get_tip)"
  h="$(echo "$line" | cut -f1)"
  tip_id="$(echo "$line" | cut -f2)"
  genesis="$(echo "$line" | cut -f3)"
  validators="$(echo "$line" | cut -f4)"
  if [[ "$genesis" != "$EXPECTED_GENESIS" ]]; then
    echo "outside-in-invite-soak: FAIL genesis_id mismatch got=$genesis want=$EXPECTED_GENESIS" >&2
    echo "soak: SUMMARY status=FAIL reason=genesis_mismatch" >>"$tmp"
    if (( ARCHIVE )); then
      mkdir -p "$EVIDENCE_DIR"
      out="$EVIDENCE_DIR/outside-in-invite-soak-${ts}.txt"
      cp "$tmp" "$out"
      echo "soak: EVIDENCE archived=$out status=FAIL" >&2
    fi
    exit 1
  fi
  echo "soak: SAMPLE i=$i tip_height=$h tip_id=$tip_id genesis_id=$genesis validator_count=$validators" | tee -a "$tmp"
  if [[ -z "$first_h" ]]; then first_h="$h"; fi
  last_h="$h"
  ok_samples=$((ok_samples + 1))
  if (( i < SAMPLES )); then sleep "$INTERVAL_S"; fi
done

delta=$((last_h - first_h))
status="PASS"
reason="ok"
if (( ok_samples < SAMPLES )); then
  status="FAIL"
  reason="sample_count"
elif (( delta < MIN_DELTA )); then
  status="FAIL"
  reason="tip_stall first=$first_h last=$last_h delta=$delta min_delta=$MIN_DELTA"
fi

echo "soak: SUMMARY status=$status first_tip_height=$first_h last_tip_height=$last_h delta=$delta samples=$ok_samples genesis_id=$EXPECTED_GENESIS head_sha=$head_sha reason=$reason" | tee -a "$tmp"

if (( ARCHIVE )); then
  mkdir -p "$EVIDENCE_DIR"
  out="$EVIDENCE_DIR/outside-in-invite-soak-${ts}.txt"
  cp "$tmp" "$out"
  echo "soak: EVIDENCE archived=$out status=$status"
fi

if [[ "$status" != "PASS" ]]; then
  echo "outside-in-invite-soak: FAIL $reason" >&2
  exit 1
fi
echo "outside-in-invite-soak: PASS delta=$delta last_tip_height=$last_h"
