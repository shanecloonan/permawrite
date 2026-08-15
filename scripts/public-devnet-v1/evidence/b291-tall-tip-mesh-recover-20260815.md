# B-291 - Tall-tip mesh recover + hairpin elimination (2026-08-15)

## Goal (claimed)

Dual-payment live storm + `faucet-ops` systemd rotate after B-278.

## What blocked the storm

1. **Public seed hairpins** (`5.161.201.73:1900x` in boot dials / peers) caused 10-23s handshakes, inbound cap storms, and tip stalls while proposals could not gather votes.
2. **Tall-tip cold start** (~22.3k blocks): `mfnd` block-log replay before bind takes **~10-15 min** with no RPC. Restarting hub+voters together means the producer proposes while voters are still replaying - `vote_fanout` Connection refused - tip stall.
3. **`peers.json` shape**: must be `{version, max_outbound_peers, peers:[...]}` - a bare string list aborts load (`expected u8`).
4. **`wallet light-scan` EAGAIN** (os error 11) under any hub/observer load - even after tip ticks - blocked alice/bob UTXO discovery for the storm binary. Dual-fund *submits* mined (observer `total_user_tx_count` 384-391) but wallets could not reliably rescan.
5. **`mfnd save` without an existing checkpoint** also requires a full replay; stopping hub for save without voters-hot restart order left hub inactive until restored.

## Fixes applied on Hetzner (`5.161.201.73`)

| Item | State |
|------|--------|
| `Environment=MFN_SKIP_MANIFEST_SEEDS=1` | hub + v1 + v2 + observer systemd units |
| Boot dials | loopback committee only (`127.0.0.1:19102-19104` / hub `19101`) |
| `peers.json` | loopback-only `19101-19104` (correct object shape); public hairpins removed |
| Restart order | **voters hot first**, then hub-only restart; wait RPC after ~14m replay |
| Faucet hot path | `FAUCET_WALLET=/root/testnet-wallets/validator0-faucet.json` (pruned B-278); `faucet-ops.json` remains funded on-chain for a later rotate when light-scan is reliable |
| Tip after recover | **22350** advancing; mesh hub/v1/v2/observer/faucet **active** |

## Prove numbers

| Metric | Value |
|--------|--------|
| Tip (proxy) | 22350 |
| `total_user_tx_count` | 391 (was 384 at B-291 start; dual-fund txs landed) |
| B-278 CI | `#31848492528` GREEN |
| Dual-payment storm (`onchain-tx-storm` count-12) | **Deferred** - **B-296** (blocked on light-scan EAGAIN + need calm window) |

## Operator doctrine (tall tip)

1. Prefer **never** restart hub casually at tip-15k without a `chain.checkpoint`.
2. If restart is required: set `MFN_SKIP_MANIFEST_SEEDS=1`, scrub peers to loopback committee (object shape), restart **voters**, wait until `:19102/:19103` listen, then restart **hub only**, wait RPC (~15m), confirm tip advances -2.
3. Do **not** thrash `wallet light-scan` / faucet keepalive during tip recovery.
4. Do **not** run `mfnd save` expecting a fast checkpoint unless a prior checkpoint exists - save replays the block log too.

## Next

- **B-296**: dual-payment storm + faucet-ops rotate prove (observer user-tx delta - storm count) once light-scan is calm or checkpointed cold-starts land.
- Optional: persist `chain.checkpoint` on a planned maintenance window (voters hot, hub stop-save-start) to cut replay from ~15m to seconds.