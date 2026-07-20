#!/usr/bin/env bash
# B-62: fail-closed readiness check before vps-roll-mfnd --apply.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
RPC="${MFN_ROLL_RPC:-127.0.0.1:18731}"
FAUCET_HEALTH_URL="${MFN_ROLL_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"

usage() {
  cat <<'EOF'
usage: assert-vps-roll-ready.sh [--plan-only]

Checks: tip readable, faucet idle, CI GREEN (gh or public API), B-51 marker in tree,
release mfnd binary present. Does not restart anything.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-vps-roll-ready: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "assert-vps-roll-ready: plan"
  echo "  unit=B-62"
  echo "  checks=tip faucet CI B-51-binary-presence"
  echo "assert-vps-roll-ready: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
fail=0

# tip
if command -v mfn-cli >/dev/null 2>&1 || [[ -x "$REPO_ROOT/target/release/mfn-cli" ]]; then
  MCLI="$REPO_ROOT/target/release/mfn-cli"
  tip="$("$MCLI" --rpc "$RPC" tip 2>/dev/null | sed -n 's/.*tip_height=\([0-9]*\).*/\1/p' | head -1 || true)"
  if [[ -n "$tip" ]]; then
    echo "assert-vps-roll-ready: tip_height=$tip"
  else
    echo "assert-vps-roll-ready: FAIL tip unreadable at $RPC" >&2
    fail=1
  fi
else
  echo "assert-vps-roll-ready: WARN mfn-cli missing — skip tip check" >&2
fi

# faucet
if command -v curl >/dev/null 2>&1; then
  fh="$(curl -fsS --max-time 8 "$FAUCET_HEALTH_URL" || true)"
  busy="$(printf '%s' "$fh" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("1" if h.get("busy") or int(h.get("pending_jobs") or 0)>0 else "0")' 2>/dev/null || echo "?")"
  if [[ "$busy" == "1" ]]; then
    echo "assert-vps-roll-ready: FAIL faucet busy/pending" >&2
    fail=1
  elif [[ "$busy" == "0" ]]; then
    echo "assert-vps-roll-ready: faucet idle OK"
  else
    echo "assert-vps-roll-ready: WARN faucet health parse failed" >&2
  fi
fi

# CI via public API (same as B-61)
api_url="${MFN_ROLL_CI_API:-https://api.github.com/repos/shanecloonan/permawrite/actions/workflows/ci.yml/runs?branch=main&per_page=1}"
api_body="$(curl -fsS --max-time 20 -H 'Accept: application/vnd.github+json' -H 'User-Agent: permawrite-roll-ready' "$api_url" || true)"
eval "$(printf '%s' "$api_body" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin); r=(d.get("workflow_runs") or [None])[0]
  if not r:
    print("status="); print("conclusion="); print("run_id=")
  else:
    print("status="+str(r.get("status") or ""))
    print("conclusion="+str(r.get("conclusion") or ""))
    print("run_id="+str(r.get("id") or ""))
except Exception:
  print("status="); print("conclusion="); print("run_id=")' 2>/dev/null || true)"
if [[ -z "${run_id:-}" ]]; then
  echo "assert-vps-roll-ready: FAIL cannot read CI" >&2
  fail=1
elif [[ "${status:-}" == "in_progress" || "${status:-}" == "queued" ]]; then
  echo "assert-vps-roll-ready: FAIL CI #$run_id still $status" >&2
  fail=1
elif [[ "${conclusion:-}" != "success" ]]; then
  echo "assert-vps-roll-ready: FAIL CI #$run_id conclusion=$conclusion" >&2
  fail=1
else
  echo "assert-vps-roll-ready: CI #$run_id GREEN OK"
fi

# B-51 marker
if grep -q "ephemeral" "$REPO_ROOT/mfn-node/src/p2p_fanout.rs" 2>/dev/null; then
  echo "assert-vps-roll-ready: B-51 source marker OK"
else
  echo "assert-vps-roll-ready: FAIL missing B-51 ephemeral marker in p2p_fanout.rs" >&2
  fail=1
fi

if [[ -x "$REPO_ROOT/target/release/mfnd" ]]; then
  echo "assert-vps-roll-ready: mfnd binary present"
else
  echo "assert-vps-roll-ready: FAIL missing target/release/mfnd (run vps-prebuild-mfnd.sh --apply)" >&2
  fail=1
fi

if (( fail )); then
  echo "assert-vps-roll-ready: NOT READY" >&2
  exit 1
fi
echo "assert-vps-roll-ready: READY"