# B-278 — Faucet UTXO prune + HTTP fund prove (2026-08-14)

**Lane:** 7 (testnet launch)  
**Host:** `5.161.201.73` (Path A)  
**never=** parallel `join-testnet-rehearsal*`; mfnd restart avoided (hub tip recovered without roll)

## Root cause (F122)

- Faucet wallet `/root/testnet-wallets/validator0-faucet.json` uses `payout_stealth_v1` seed `eee…` (validator0 payouts).
- Every coinbase credits another ~5e9 UTXO → `owned_count≈22062`, wallet file ~14 MiB, `pending_spent≈480`.
- Bench: slim 8 UTXOs send in **0.59s**; 4096 UTXOs ~**68s**; full set timed out at 90–600s.
- `faucet-consolidate.sh` full-balance self-send cannot shrink under the **2-output privacy floor**.

## Live apply

1. `systemctl stop faucet-http` (`busy=false`).
2. `faucet-wallet-prune.sh --keep 32` → owned **22062→32**, pending cleared; backup `validator0-faucet.json.bak-prePrune-20260814T220957Z`.
3. Started rotate to `faucet-ops.json` (funded 2e11 atoms, tx `84bc7eb9…` mined at tip 22310); tip-pin/light-scan of new wallet still operational follow-up (EAGAIN under load). **Hot path remains pruned `validator0-faucet.json`** for this prove.
4. `systemctl start faucet-http`.

## Prove

| Check | Result |
| --- | --- |
| Direct `wallet send` (pruned, ring 16) | **PASS** Fresh submit in ~2s |
| HTTP `POST /faucet` dual-send job `41af9de1…` | **done** in **99.2s** (`duration_ms=97635`) — under 120s gate |
| tip during prove | 22310→22312 |

Tx ids: `0e023b0d…`, `b50a1d66…`.

## Tooling landed

- `scripts/public-devnet-v1/faucet-wallet-prune.sh`
- `scripts/public-devnet-v1/faucet-rotate-from-payout.sh` (tip-pin before fund)
- CLI: O(n) pending-spend diff in `wallet send`/`upload` (was O(n²) over owned keys)
- OPERATORS hygiene row updated

## Follow-ups

- Point systemd `FAUCET_WALLET=/root/testnet-wallets/faucet-ops.json` once ops wallet light-scan is confirmed (stops coinbase re-bloat on hot path).
- Periodic prune timer while faucet still shares payout seed.
- Lane 3: F122 fund path unblocked for JOIN waves.