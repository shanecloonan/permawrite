# B-59 / F45 soft + B-22 tip-4166 (2026-07-20)

## Why

JOIN `wallet light-scan --checkpoint-log` fails with F45 whenever the live tip advances past the latest Schnorr attestation (tip race). That blocks B-15 SUMMARY even after a valid B-50 pin.

## Actions

1. Published Path A checkpoint tip **4166** (entries=9); seed offline on VPS.
2. Added `light-scan-checkpoint-soft.sh`: verify log, scan, then `--checkpoint-log`; soft-pass only on `no attestation at tip_height`.
3. Wired bootstrap `.sh` / `.ps1` through the soft path.
4. Schnorr disagreement at an attested height still fails hard.

## Ask lane 3

Point `join-testnet-rehearsal.sh` light-scan at `light-scan-checkpoint-soft.sh` for F45-tolerant SUMMARY (or re-run within 0-1 of tip after B-22 publish).

## Note

B-51 Rust WIP was staged locally but **not** on `origin/main` at land time - left unstaged for lane 4.