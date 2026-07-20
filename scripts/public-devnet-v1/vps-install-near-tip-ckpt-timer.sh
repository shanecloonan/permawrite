#!/usr/bin/env bash
# B-88 / lane 7: install systemd timer for B-85 near-tip Path A lag republish.
# Safe during B-15: never touches faucet/mfnd. Requires ~/.mfn/checkpoint-signer.env on VPS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: vps-install-near-tip-ckpt-timer.sh [--plan-only|--apply]

Installs path-a-near-tip-ckpt.service + .timer (every 30m).
Never restarts faucet/mfnd. After a publish, commit the updated
mfn-node/testdata/public_devnet_v1.checkpoints.jsonl from an agent host.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-install-near-tip-ckpt-timer: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-install-near-tip-ckpt-timer: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-install-near-tip-ckpt-timer: plan"
  echo "  unit=B-88"
  echo "  installs=path-a-near-tip-ckpt.service path-a-near-tip-ckpt.timer"
  echo "  interval=OnUnitActiveSec=30min"
  echo "  runs=publish-near-tip-checkpoint-if-lag.sh --apply"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "vps-install-near-tip-ckpt-timer: PASS plan-only"
  exit 0
fi

if [[ ! -f /root/.mfn/checkpoint-signer.env ]]; then
  echo "vps-install-near-tip-ckpt-timer: FAIL missing /root/.mfn/checkpoint-signer.env" >&2
  exit 1
fi

install -m 644 "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.service" /etc/systemd/system/path-a-near-tip-ckpt.service
install -m 644 "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.timer" /etc/systemd/system/path-a-near-tip-ckpt.timer
systemctl daemon-reload
systemctl enable --now path-a-near-tip-ckpt.timer
systemctl is-active path-a-near-tip-ckpt.timer
systemctl list-timers path-a-near-tip-ckpt.timer --no-pager || true
# Smoke oneshot once (may SKIP if lag below threshold)
systemctl start path-a-near-tip-ckpt.service || true
systemctl is-active faucet-http.service observer-rpc-proxy.service >/dev/null
echo "vps-install-near-tip-ckpt-timer: OK timer active (commit jsonl when lag publish dirties working tree)"