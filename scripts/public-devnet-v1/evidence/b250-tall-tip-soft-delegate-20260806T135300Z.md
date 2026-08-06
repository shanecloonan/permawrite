# B-250 — tall-tip soft-scan auto-delegates unpinned wallets (2026-08-06)

## Goal

Stop cold `light-scan-checkpoint-soft` from hanging at tip ~16k (genesis→tip walk). Unpinned wallets must pin via `bootstrap-wallet-from-checkpoint-log` first.

## Change

- `light-scan-checkpoint-soft.sh` / `.ps1`: if `scan_height <= 1` or missing `light_checkpoint_hex`, print B-250 needle and exec bootstrap helper.
- Rehearsal smoke needles for B-250 + bootstrap delegate.
- JOIN_TESTNET + OPERATORS honesty.

## Prove (Hetzner `moneyfund` / `5.161.201.73`)

```
light-scan-checkpoint-soft-rehearsal-smoke: PASS plan-only
cold_wallet_unpinned scan_height=0
light-scan-checkpoint-soft: B-250 wallet unpinned — delegating to bootstrap-wallet-from-checkpoint-log
bootstrap-wallet-from-checkpoint-log: log_max_tip=16309
bootstrap-wallet-from-checkpoint-log: pinned scan_height=16309
light-scan-checkpoint-soft: PASS f45-soft
bootstrap-wallet-from-checkpoint-log: OK
b250_prove: PASS rc=0
```

Live tip after prove ≈ **16311** (F45 soft: log_max=16309). No mfnd/faucet restart. Duration ~203s (snapshot + 2-block delta).

## Honesty

Soft-pass ≠ exact-tip attestation. Schnorr log verify still required. Prefer explicit B-50 bootstrap for JOIN F67 pin-before-fund.
