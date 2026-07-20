#!/usr/bin/env bash
# B-89 / lane 7: assert Path A near-tip lag timer (B-88) is healthy on the VPS.
# B-15-safe: never touches faucet/mfnd.
set -euo pipefail
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: assert-path-a-near-tip-timer.sh [--plan-only|--apply]

On --apply (run on VPS): timer active, unit files present, last oneshot
not failed, signer env present. Never restarts faucet/mfnd.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-path-a-near-tip-timer: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "assert-path-a-near-tip-timer: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "assert-path-a-near-tip-timer: plan"
  echo "  unit=B-89"
  echo "  checks=timer-active unit-files signer-env last-result"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "assert-path-a-near-tip-timer: PASS plan-only"
  exit 0
fi

fail=0
for u in path-a-near-tip-ckpt.timer path-a-near-tip-ckpt.service; do
  if [[ ! -f "/etc/systemd/system/$u" ]]; then
    echo "assert-path-a-near-tip-timer: FAIL missing /etc/systemd/system/$u" >&2
    fail=1
  fi
done
if [[ ! -f /root/.mfn/checkpoint-signer.env ]]; then
  echo "assert-path-a-near-tip-timer: FAIL missing /root/.mfn/checkpoint-signer.env" >&2
  fail=1
fi
if ! systemctl is-active --quiet path-a-near-tip-ckpt.timer; then
  echo "assert-path-a-near-tip-timer: FAIL timer not active" >&2
  fail=1
fi
# OnesHot may be inactive (dead) — only fail if last result is failed
res="$(systemctl show -p Result --value path-a-near-tip-ckpt.service 2>/dev/null || echo unknown)"
if [[ "$res" == "failed" ]]; then
  echo "assert-path-a-near-tip-timer: FAIL last oneshot Result=failed" >&2
  systemctl status path-a-near-tip-ckpt.service --no-pager -l | tail -30 >&2 || true
  fail=1
fi
if (( fail )); then
  exit 1
fi
echo "assert-path-a-near-tip-timer: OK timer=active last_result=$res"
systemctl list-timers path-a-near-tip-ckpt.timer --no-pager || true