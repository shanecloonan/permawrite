#!/usr/bin/env bash
# Lane 7 / TL-9: automatable launch gate summary (human sign-off still required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MANIFEST="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
JSON=0
FAIL=0

[[ "${1:-}" == "--json" ]] && JSON=1

pass() { echo "launch-go-no-go: PASS $1"; }
fail() { echo "launch-go-no-go: FAIL $1" >&2; FAIL=1; }
warn() { echo "launch-go-no-go: WARN $1" >&2; }

local_mfer_evidence_passes() {
  local pattern="$1" f
  shopt -s nullglob
  for f in $EVIDENCE_DIR/$pattern; do
    if grep -q "SUMMARY: PASS" "$f" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

head_sha="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
genesis_id=""
seed_count=0
if [[ -f "$MANIFEST" ]]; then
  genesis_id="$(python3 -c "import json; print(json.load(open('$MANIFEST'))['genesis_id'])" 2>/dev/null || true)"
  seed_count="$(python3 -c "import json; print(len(json.load(open('$MANIFEST')).get('seed_nodes',[])))" 2>/dev/null || echo 0)"
fi

expected_genesis="454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
if [[ "$genesis_id" == "$expected_genesis" ]]; then
  pass "genesis_id matches public_devnet_v1 ($genesis_id)"
else
  fail "genesis_id=$genesis_id expected $expected_genesis (Path B? document TL-7 sign-off)"
fi

if (( seed_count >= 3 )); then
  pass "seed_nodes count=$seed_count"
else
  fail "seed_nodes count=$seed_count (need >= 3 for TL-8)"
fi

soak_evidence=""
if soak_evidence="$(compgen -G "$EVIDENCE_DIR/vps-internet-soak-linux-*.txt" | head -1)"; then
  if grep -q "status=PASS" "$soak_evidence" 2>/dev/null; then
    pass "TL-5 evidence $(basename "$soak_evidence")"
  else
    fail "TL-5 evidence missing PASS summary in $(basename "$soak_evidence")"
  fi
else
  if local_mfer_evidence_passes "participant-rehearsal-no-observer-*.txt" \
    && local_mfer_evidence_passes "participant-rehearsal-observer-*.txt"; then
    warn "TL-5 not run; local MFER rehearsals PASS — ready for VPS provision (docs/VPS_PROVISION.md)"
  else
    warn "TL-5 not run; complete local participant-rehearsal-smoke on MFER devnet before VPS"
  fi
  fail "TL-5 evidence missing (vps-internet-soak-linux-*.txt)"
fi

rehearsal_evidence=""
if rehearsal_evidence="$(compgen -G "$EVIDENCE_DIR/vps-participant-rehearsal-*.txt" | head -1)"; then
  if grep -q "SUMMARY: PASS" "$rehearsal_evidence" 2>/dev/null; then
    pass "TL-6 evidence $(basename "$rehearsal_evidence")"
  else
    fail "TL-6 evidence missing PASS in $(basename "$rehearsal_evidence")"
  fi
else
  if [[ -n "$soak_evidence" ]]; then
    warn "TL-6 not run; VPS soak evidence present — run vps-participant-rehearsal.sh"
  fi
  fail "TL-6 evidence missing (vps-participant-rehearsal-*.txt)"
fi

release_evidence=""
if release_evidence="$(compgen -G "$EVIDENCE_DIR/release-evidence-*.json" | head -1)"; then
  pass "release evidence $(basename "$release_evidence")"
else
  warn "release-evidence-*.json not archived under evidence/ (refresh on green CI head)"
fi

tl7_note="$REPO_ROOT/docs/TESTNET_GENESIS_CEREMONY.md"
if [[ -f "$tl7_note" ]]; then
  pass "TL-7 ceremony doc present (human sign-off still required)"
else
  fail "missing docs/TESTNET_GENESIS_CEREMONY.md"
fi

if [[ -f "$REPO_ROOT/docs/PUBLIC_DEVNET_THREAT_MODEL.md" ]]; then
  pass "threat model doc present"
else
  fail "missing docs/PUBLIC_DEVNET_THREAT_MODEL.md"
fi

if command -v gh >/dev/null 2>&1; then
  ci_line="$(cd "$REPO_ROOT" && gh run list --workflow CI --limit 1 --json status,conclusion,headSha 2>/dev/null || true)"
  if [[ -n "$ci_line" ]]; then
    ci_status="$(echo "$ci_line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r['status'])")"
    ci_conclusion="$(echo "$ci_line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r.get('conclusion') or '')")"
    if [[ "$ci_status" == "completed" && "$ci_conclusion" == "success" ]]; then
      pass "GitHub CI green (latest run)"
    elif [[ "$ci_status" == "in_progress" ]]; then
      warn "GitHub CI in progress on latest push"
    else
      fail "GitHub CI status=$ci_status conclusion=$ci_conclusion"
    fi
  else
    warn "gh run list unavailable"
  fi
else
  warn "gh not on PATH — skip CI lookup"
fi

echo ""
echo "launch-go-no-go: manual gates (see OPERATORS.md § Launch go/no-go):"
echo "  - TL-7 named human sign-off (toy keys Path A or fresh genesis Path B)"
echo "  - TL-9 named launch-day watchers + halt authority"
echo "  - RPC loopback-only verified on VPS"
echo "  - Backups + rollback plan documented"
echo ""
echo "launch-go-no-go: head=$head_sha playbook=docs/TESTNET_LAUNCH.md"

if [[ "$JSON" -eq 1 ]]; then
  automatable_pass=0
  if (( FAIL == 0 )); then automatable_pass=1; fi
  export REPO_ROOT head_sha genesis_id seed_count automatable_pass
  export soak_base="${soak_evidence##*/}"
  export rehearsal_base="${rehearsal_evidence##*/}"
  python3 - <<'PY'
import json, os
print(json.dumps({
    "schema_version": "launch-go-no-go.v1",
    "head_sha": os.environ.get("head_sha", ""),
    "genesis_id": os.environ.get("genesis_id", ""),
    "seed_nodes_count": int(os.environ.get("seed_count", "0")),
    "automatable_pass": os.environ.get("automatable_pass") == "1",
    "tl5_evidence": os.environ.get("soak_base", ""),
    "tl6_evidence": os.environ.get("rehearsal_base", ""),
}, indent=2))
PY
fi

if (( FAIL != 0 )); then
  exit 1
fi
echo "launch-go-no-go: automatable gates PASS (human TL-7/TL-9 sign-off still required before invite)"
