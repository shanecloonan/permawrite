# B-144 — Windows/MSYS JOIN python3 + mfn-cli.exe resolve

Date: 2026-07-21
Lane: 3 (seat C) / tooling for B-15
Unit: B-144

## Why

Formal B-15 `join-testnet-rehearsal` on Windows/MSYS failed early:
1. `python3: command not found` (host has `python` 3.12 only)
2. Local observer `chain.blocks` hung on replay after hard kill — quarantined; fresh sync in `live-testnet-data/b15-fresh`
3. `get_light_snapshot` against wedged RPC timed out (connection 10060)

## What landed

- `scripts/public-devnet-v1/lib-python3.sh` — `mfn_require_python3` + `mfn_resolve_release_bin`
- Sourced from `bootstrap-wallet-from-checkpoint-log.sh`, `light-scan-checkpoint-soft.sh`, `join-testnet-rehearsal.sh`

## B-15 status

Local observer catching up tip~771→~5306 (public). JOIN re-run after tip_id match + Path A lag check.
