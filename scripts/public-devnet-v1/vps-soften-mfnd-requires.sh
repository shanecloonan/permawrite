#!/usr/bin/env bash
# Soften mfnd-v* / mfnd-observer systemd deps: Requires=mfnd-hub -> Wants=mfnd-hub.
#
# Why: systemctl restart mfnd-hub previously tore down voters/observer via
# Requires=, which caused tip stalls (vote fanout quarantine + multi-minute
# pre-RPC bind storms) during B-15 / tip-4031 recovery. Wants= keeps followers
# alive across hub restart.
#
# Safe to re-run. Does not touch faucet-http. Does not restart any unit.
set -euo pipefail

UNITS=(mfnd-v1.service mfnd-v2.service mfnd-observer.service)
changed=0
for u in "${UNITS[@]}"; do
  f="/etc/systemd/system/${u}"
  if [[ ! -f "$f" ]]; then
    echo "skip missing $f"
    continue
  fi
  if grep -q '^Requires=mfnd-hub.service' "$f"; then
    sed -i 's/^Requires=mfnd-hub.service/Wants=mfnd-hub.service/' "$f"
    echo "softened $u"
    changed=1
  else
    echo "ok $u (no Requires=mfnd-hub)"
  fi
done

hub=/etc/systemd/system/mfnd-hub.service
if [[ -f "$hub" ]]; then
  sed -i '/MFN_P2P_DIAL_EXTRA=/d' "$hub"
  sed -i '/Environment=MFN_P2P_LISTEN=/a Environment="MFN_P2P_DIAL_EXTRA=127.0.0.1:19102 127.0.0.1:19103 127.0.0.1:19104"' "$hub"
  echo "quoted MFN_P2P_DIAL_EXTRA on mfnd-hub.service"
  changed=1
fi

if [[ "$changed" -eq 1 ]]; then
  systemctl daemon-reload
  echo "daemon-reload done (no unit restarts)"
else
  echo "no changes"
fi
