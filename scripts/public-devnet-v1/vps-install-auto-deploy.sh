#!/usr/bin/env bash
# Install the public-devnet auto-deploy timer on the VPS.
# Does not build, does not restart mfnd, and does not delete chain data.
#
#   bash scripts/public-devnet-v1/vps-install-auto-deploy.sh --plan-only
#   bash /root/permawrite/scripts/public-devnet-v1/vps-install-auto-deploy.sh --apply
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: vps-install-auto-deploy.sh [--plan-only|--apply]

Installs pfpchain-auto-deploy.service and pfpchain-auto-deploy.timer.
The timer fires every 15 minutes (OnCalendar=*-*-* *:00/15:00) and runs
vps-auto-deploy.sh --apply. Enabling the timer does not start a deploy.
To deploy once by hand:

  systemctl start pfpchain-auto-deploy.service

Run --apply as root from the checkout at /root/permawrite.
Never deletes chain data.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-install-auto-deploy: unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-install-auto-deploy: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-install-auto-deploy: plan"
  echo "  installs=pfpchain-auto-deploy.service pfpchain-auto-deploy.timer"
  echo "  interval=OnCalendar=*-*-* *:00/15:00"
  echo "  runs=vps-auto-deploy.sh --apply"
  echo "  state=/var/lib/pfpchain-deploy/status.json"
  echo "  enable=systemctl enable --now pfpchain-auto-deploy.timer"
  echo "  does_not_start=the deploy service (next quarter-hour, or systemctl start)"
  echo "  never=delete chain data"
  echo "vps-install-auto-deploy: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-install-auto-deploy: --apply must run as root on the VPS" >&2
  exit 1
fi

install -d -m 755 /var/lib/pfpchain-deploy
install -m 644 "$SCRIPT_DIR/systemd/pfpchain-auto-deploy.service" /etc/systemd/system/pfpchain-auto-deploy.service
install -m 644 "$SCRIPT_DIR/systemd/pfpchain-auto-deploy.timer" /etc/systemd/system/pfpchain-auto-deploy.timer
systemctl daemon-reload
systemctl enable --now pfpchain-auto-deploy.timer
systemctl is-active pfpchain-auto-deploy.timer
systemctl list-timers pfpchain-auto-deploy.timer --no-pager || true
echo "vps-install-auto-deploy: OK timer active (deploy starts on the next 15-minute mark)"
echo "vps-install-auto-deploy: status will be /var/lib/pfpchain-deploy/status.json"
echo "vps-install-auto-deploy: journalctl -u pfpchain-auto-deploy.service"
