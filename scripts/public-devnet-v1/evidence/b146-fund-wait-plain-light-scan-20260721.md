# B-146 — fund-wallet-http wait uses plain light-scan (F101b)

Date: 2026-07-21
Lane: 3
Unit: B-146

## Bug

B-15 JOIN: faucet job `done` (2 txs) but wait loop timed out `balance=0 owned_count=0`.
Manual `wallet light-scan` afterward showed `balance=1000000 owned_count=2`.

Cause: wait-loop `wallet_light_scan` used `light-scan --checkpoint-log`, which F45-fails when
tip > Path A max and aborted scanning (`|| true` hid the failure).

## Fix

Post-fund wait uses plain `wallet light-scan` only. Immediate scan after job `done`.
