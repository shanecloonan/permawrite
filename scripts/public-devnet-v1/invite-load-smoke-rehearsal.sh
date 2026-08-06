#!/usr/bin/env bash
# B-42 / B-248 invite-load smoke — plan gate + B-15-safe preflight (live JOIN only when explicitly armed).
# Privacy/permanence: never weaken ring/SPoRA floors; never thrash faucet/mfnd during B-15 capture.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
APPLY=0
LIVE=0
PROXY_HEALTH="${MFN_PROXY_HEALTH:-http://127.0.0.1:8787/health}"
FAUCET_HEALTH="${MFN_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"
PUBLIC_HOST="${MFN_INVITE_PUBLIC_HOST:-5.161.201.73}"
SEED_PORTS="${MFN_INVITE_SEED_PORTS:-19001,19002,19003}"
EVIDENCE_DIR="${MFN_INVITE_LOAD_EVIDENCE_DIR:-$SCRIPT_DIR/evidence}"

usage() {
  cat <<'EOF'
usage: invite-load-smoke-rehearsal.sh [--plan-only|--apply|--live]

  (no flags)    same as --plan-only (ci-check / backward compatible)
  --plan-only   CI plan gate
  --apply       B-15-safe preflight: proxy+faucet health, seed TCP, serialize-with-reason (no JOIN)
  --live        Requires MFN_INVITE_LOAD_ALLOW_LIVE=1 + idle faucet; JOIN remains operator-driven
Never restarts faucet/mfnd. Prefer --apply until lane3 B-15 clear.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --live) LIVE=1; APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "invite-load-smoke-rehearsal: unknown $1" >&2; exit 1 ;;
  esac
done

# Bare invoke => plan-only (preserves historical ci-check / smoke callers).
if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  PLAN_ONLY=1
fi

if (( PLAN_ONLY )); then
  echo "invite-load-smoke-rehearsal: plan"
  echo "  unit=B-42"
  echo "  flow=staggered join-testnet-rehearsal x2 against live faucet+observer after B-15 lock"
  echo "  checks=SUMMARY PASS or serialize-with-reason; R-4 cooldown; proxy healthy; light-scan-checkpoint-soft (F45)"
  echo "  evidence=invite-load-smoke-YYYYMMDD.txt under scripts/public-devnet-v1/evidence/"
  echo "  docs=docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9"
  echo "  conflict=do not run during B-15 faucet lock"
  echo "  preflight=--apply (B-248); live=--live + MFN_INVITE_LOAD_ALLOW_LIVE=1"
  echo "  never=faucet-http mfnd restart"
  echo "invite-load-smoke-rehearsal: PASS plan-only"
  exit 0
fi

fail=0
echo "invite-load-smoke-rehearsal: apply preflight"
echo "  unit=B-42/B-248"
echo "  proxy_health=$PROXY_HEALTH"
echo "  faucet_health=$FAUCET_HEALTH"
echo "  public_host=$PUBLIC_HOST"
echo "  never=faucet-http mfnd restart"

proxy_json="$(curl -fsS --max-time 10 "$PROXY_HEALTH" || true)"
if [[ -z "$proxy_json" ]]; then
  echo "invite-load-smoke-rehearsal: FAIL proxy health unreachable" >&2
  fail=1
else
  python3 - "$proxy_json" <<'PY' || fail=1
import json, sys
d = json.loads(sys.argv[1])
if d.get("ok") is not True:
    print("invite-load-smoke-rehearsal: FAIL proxy ok!=true", file=sys.stderr)
    sys.exit(1)
idx = d.get("index") or {}
print(
    "invite-load-smoke-rehearsal: proxy ok tip=%s hub_tip_rpc=%s"
    % (idx.get("tip_height"), d.get("hub_tip_rpc"))
)
PY
fi

faucet_busy="unknown"
faucet_pending="unknown"
faucet_json="$(curl -fsS --max-time 10 "$FAUCET_HEALTH" || true)"
if [[ -z "$faucet_json" ]]; then
  echo "invite-load-smoke-rehearsal: FAIL faucet health unreachable" >&2
  fail=1
else
  faucet_meta="$(python3 - "$faucet_json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
if d.get("ok") is not True:
    print("FAIL", file=sys.stderr)
    sys.exit(1)
busy = d.get("busy")
pending = d.get("pending_jobs")
print("%s\t%s" % (busy, pending))
PY
)" || fail=1
  if [[ -n "${faucet_meta:-}" ]]; then
    faucet_busy="${faucet_meta%%$'\t'*}"
    faucet_pending="${faucet_meta#*$'\t'}"
    echo "invite-load-smoke-rehearsal: faucet ok busy=${faucet_busy} pending_jobs=${faucet_pending}"
  fi
fi

python3 - "$PUBLIC_HOST" "$SEED_PORTS" <<'PY' || fail=1
import socket, sys
host = sys.argv[1]
ports = [int(p.strip()) for p in sys.argv[2].split(",") if p.strip()]
bad = []
for port in ports:
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
    except OSError as e:
        bad.append("%s:%s" % (port, e))
    finally:
        s.close()
if bad:
    print("invite-load-smoke-rehearsal: FAIL seed ports " + "; ".join(bad), file=sys.stderr)
    sys.exit(1)
print(
    "invite-load-smoke-rehearsal: seeds ok host=%s ports=%s"
    % (host, ",".join(str(p) for p in ports))
)
PY

if (( fail != 0 )); then
  echo "invite-load-smoke-rehearsal: FAIL preflight" >&2
  exit 1
fi

allow="${MFN_INVITE_LOAD_ALLOW_LIVE:-0}"
busy_l="$(printf '%s' "$faucet_busy" | tr '[:upper:]' '[:lower:]')"

if (( LIVE == 1 )) && [[ "$allow" == "1" ]]; then
  if [[ "$busy_l" == "true" ]]; then
    echo "invite-load-smoke-rehearsal: FAIL refuse --live while faucet busy" >&2
    exit 1
  fi
  if [[ "$faucet_pending" != "0" && "$faucet_pending" != "None" && "$faucet_pending" != "null" && -n "$faucet_pending" ]]; then
    echo "invite-load-smoke-rehearsal: FAIL refuse --live while pending_jobs=$faucet_pending" >&2
    exit 1
  fi
  echo "invite-load-smoke-rehearsal: LIVE armed — staggered JOIN not auto-started from this script yet"
  echo "  next=operator runs two join-testnet-rehearsal with stagger + archive invite-load-smoke-*.txt"
  echo "  docs=docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9"
  echo "invite-load-smoke-rehearsal: PASS live-armed-preflight (JOIN operator-driven)"
  exit 0
fi

reason="MFN_INVITE_LOAD_ALLOW_LIVE_unset"
if (( LIVE == 1 )) && [[ "$allow" != "1" ]]; then
  reason="MFN_INVITE_LOAD_ALLOW_LIVE_unset"
elif (( LIVE == 0 )); then
  reason="need_--live_flag"
fi
if [[ "$busy_l" == "true" ]]; then
  reason="faucet_busy"
fi

mkdir -p "$EVIDENCE_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
ev="$EVIDENCE_DIR/invite-load-preflight-${stamp}.txt"
{
  echo "invite-load-smoke-rehearsal: preflight"
  echo "unit=B-248"
  echo "status=PASS"
  echo "serialize_with_reason=$reason"
  echo "proxy_health=$PROXY_HEALTH"
  echo "faucet_health=$FAUCET_HEALTH"
  echo "faucet_busy=$faucet_busy"
  echo "faucet_pending=$faucet_pending"
  echo "public_host=$PUBLIC_HOST"
  echo "seed_ports=$SEED_PORTS"
  echo "live_armed=$allow"
  echo "never=join-testnet-rehearsal_without_ALLOW_LIVE"
} | tee "$ev"
echo "invite-load-smoke-rehearsal: PASS preflight serialize-with-reason=$reason evidence=$ev"
exit 0
