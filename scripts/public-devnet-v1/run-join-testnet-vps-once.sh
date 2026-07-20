#!/usr/bin/env bash
# One-shot VPS runner for B-15 evidence (operator use only).
set -euo pipefail
cd /root/permawrite
git pull --ff-only origin main
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart faucet-http 2>/dev/null || true
  sleep 3
fi
for i in $(seq 1 24); do
  h="$(curl -fsS http://127.0.0.1:8788/health)"
  echo "$h"
  if echo "$h" | grep -q '"busy":false'; then
    break
  fi
  sleep 15
done
SM="/tmp/join-b15-$(date +%s)"
bash scripts/public-devnet-v1/join-testnet-rehearsal-smoke.sh \
  --no-build --no-start --rpc 127.0.0.1:18734 \
  --smoke-dir "$SM" --archive-evidence
ls -t scripts/public-devnet-v1/evidence/join-testnet-rehearsal-linux-*.txt | head -1
