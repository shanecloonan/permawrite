# B-60 — mfnd roll preflight + JOIN F45 wire (2026-07-20)

## Why

`vps-roll-mfnd.sh --apply` could thrash hub while CI is red/in-progress or while B-15 holds the faucet lock. JOIN rehearsal still used hard `--checkpoint-log` (F45 tip race).

## Changes

1. **B-60 preflight** on `--apply`: refuse if faucet `busy`/`pending_jobs`; refuse if latest CI not GREEN / still in progress (`gh`). Overrides: `MFN_ROLL_ALLOW_FAUCET_BUSY=1`, `MFN_ROLL_ALLOW_RED_CI=1`.
2. Wired `join-testnet-rehearsal.sh` through `light-scan-checkpoint-soft.sh` (closes lane-7→3 B-59 ask).
3. Did **not** `--apply` roll — CI `#29717107514` still in flight; faucet was busy at SYNC.

## Smoke

- `vps-roll-mfnd.sh --plan-only` / rehearsal smoke
- join plan strings mention F45 soft
