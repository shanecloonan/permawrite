# B-54 — F67 pin-then-fund (2026-07-20)

**Lane:** 7
**Claim base:** `f295625`
**Closes:** F67 (B-50 pin after faucet misses pre-checkpoint UTXOs)

## Root cause

Pinning `scan_height` to checkpoint tip skips all heights <= pin. Faucet dual-sends mined at or below that tip are invisible until a lower pin or genesis scan — wave10 dave saw owned_count=1 / 500000 instead of 2 / 1000000.

## Fix

1. JOIN_TESTNET Step 5: **pin -> fund -> light-scan**
2. `fund-wallet-http.sh`: when `--checkpoint-log` is set, run `bootstrap-wallet-from-checkpoint-log.sh --apply` before POST /faucet
3. join-testnet-rehearsal(+smoke) plan strings updated
4. Bootstrap plan/smoke needles mention F67

## Deploy

Docs/scripts only. Hetzner `git pull` — no mfnd/faucet restart required.
Lane 3 wave11 pin-then-fund path is now the documented default.