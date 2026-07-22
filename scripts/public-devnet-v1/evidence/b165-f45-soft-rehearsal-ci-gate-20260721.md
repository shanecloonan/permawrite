# B-165 — F45 soft rehearsal CI gate + live prove (2026-07-21)

## Unit
Fail-closed CI gate for `light-scan-checkpoint-soft.ps1` twin + B-161 needles (`MFN_HEAVY_RPC_TIMEOUT_MS`, `checkpoint_log_f45_soft_pass`, B-50 auto-bootstrap).

## Scripts
- `light-scan-checkpoint-soft-rehearsal-smoke.sh` / `.ps1`
- Extended `bootstrap-wallet-from-checkpoint-log-rehearsal-smoke.sh`
- Wired into `scripts/ci-check.sh` + `ci-check.ps1`

## Local smoke
```
light-scan-checkpoint-soft-rehearsal-smoke: PASS plan-only
bootstrap-wallet-from-checkpoint-log-rehearsal-smoke: PASS plan-only
```

## Live prove (Hetzner hub via SSH tunnel :18731)
- `checkpoint_log_auto_bootstrap tip=5523`
- `checkpoint_log_f45_soft_pass` → wallet pin/scan_height at tip~5524
- Schnorr checkpoint-log verify still hard; F45 tip-race soft only

## Lane boundaries
Lane 5 only. Did not stage lane-4 `apply_block_proposals.rs` or lane-3 JOIN smoke WIP.