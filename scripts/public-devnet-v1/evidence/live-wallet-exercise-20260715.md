# Live testnet wallet exercise — findings (2026-07-15)

Mesh at exercise time: tip ≈ 1910–1950, genesis `454fa5d4…`, validators=3,
faucet `/root/testnet-wallets/validator0-faucet.json` (payout stealth).

## What worked

| Step | Result |
| --- | --- |
| Create carol+dave (`wallet new`) | PASS — distinct `mf…` addresses / view pubs |
| Fund carol 2×500_000 from faucet (`wallet send`, ring=16) | PASS — outcomes `Fresh` |
| Carol receives both UTXOs (F7 floor) | PASS — `balance=1000000` `owned_count=2` |
| Carol → dave 100_000 CLSAG transfer | PASS — `ring_size=16` `outcome=Fresh` tx `f90a4eee…` |
| View pubs not in tip block JSON | PASS (privacy-check.mjs when run) |
| No public `get_balance` method | PASS |

Evidence run dir on VPS: `/root/testnet-wallets/exercise-20260715T022938Z/`.

## Errors / issues found

### E1. Faucet UTXO explosion + full `get_block` catch-up is ops-hostile

After ~2k tip heights the operator faucet held **~1883 owned outputs**. A full
`wallet scan`/`wallet send` path walks every missing height via `get_block`
and only persisted at the end (fixed in this commit with 32-block
checkpoints). Catch-up from height ~889 → ~1900 took **many minutes** and
blocked faucet HTTP as well.

**Mitigation:** consolidate faucet periodically; prefer light-scan for
participants; mid-scan persist (shipped).

### E2. New-wallet full scan from genesis is unusable at tip ~2k

`wallet balance` / `wallet send` call `sync_wallet_from_node` (`get_block`).
Fresh wallets start at height 1 — tens of minutes. Exercise switched to
`wallet light-scan` for receive verification.

### E3. Light-scan hard-fails after spend empties temporary UTXO cache (bug)

After carol’s transfer, wallet file had:

- `scan_height=1943`
- `owned_outputs=[]` (inputs spent; change not yet re-scanned)
- `light_checkpoint_hex` still at tip 1943

`wallet light-scan` treated empty owned as “no cache” → `start_height=1`, then
rejected checkpoint tip 1943 vs resume 1:

```text
light checkpoint tip_height 1943 does not match wallet scan resume at 1
```

Dave receive verification stalled on a full light sync from genesis.

**Fix (this commit):** resume from `scan_height` even when owned is empty;
on checkpoint mismatch, drop stale checkpoint and re-bootstrap from snapshot.

### E4. HTTP faucet shares the same slow faucet wallet

`POST :8788/faucet` runs `wallet scan` on validator0-faucet before send — same
E1 latency. Cooldown/rate-limit OK; ops need kept-caught-up faucet process.

## Privacy observations

- Reference transfers enforce ring size 16 (CLI refuse <16).
- Recipient stealth addresses differ; funding addresses are one-time on chain.
- Transparent account balance API is not exposed publicly (expected).

## Follow-ups

1. Prefer light-follow inside `wallet send` / `wallet balance` when a light
   checkpoint exists (avoid surprise full `get_block` sync).
2. Operator job: faucet self-consolidate to ≤ a few UTXOs weekly.
3. Frontend wallet should document first-sync cost at high tip / prefer
   light catch-up.
