# B-296 — Faucet-ops systemd rotate + dual-payment storm (2026-08-15)

**Lane:** 7 (testnet launch) / Seat C
**Host:** 5.161.201.73 (Path A)
**never=** parallel join-testnet-rehearsal*; no mfnd restart; faucet stopped only while idle for rotate

## Goal

1. Point systemd aucet-http at a dedicated aucet-ops.json (stop coinbase re-bloat on the hot path).
2. Prove HTTP dual-fund still lands under 120s.
3. Run a dual-payment live storm; observer 	otal_user_tx_count delta >= storm count.

## Live state (pre)

| Item | Value |
| --- | --- |
| Tip (hub=observer) | 22403, validators=3, mempool=0 |
| Faucet | idle, FAUCET_WALLET=validator0-faucet.json (owned=77, pending=47, 54 KiB) |
| aucet-ops.json | existed (pin 22328, owned=0) — B-278 fund at 22310 was skipped by a later tip-pin |
| Observer user-tx | **391** (B-291 end) |
| mfn-p2p-forward-hub | failed since 02:04 UTC (not touched; 19002-19004 active) |

## Rotate apply

1. systemctl stop faucet-http (usy=false).
2. aucet-rotate-from-payout.sh --fund-atoms 200000000000 — tip-pin ops at 22404; first fund tx 6dec75ac… (Fresh).
3. Second fund 52987a21… (2e11); first scan raced (owned=0 then 1).
4. Third fund 640ec7b… (3e10; payout could not afford another 2e11).
5. Rescan at tip 22408: **owned=3**, balance=430e9.
6. Drop-in /etc/systemd/system/faucet-http.service.d/wallet.conf:
   Environment=FAUCET_WALLET=/root/testnet-wallets/faucet-ops.json
7. daemon-reload + systemctl start faucet-http. Health: wallet=faucet-ops.json, synced.

## HTTP prove (ops wallet)

| Check | Result |
| --- | --- |
| Job | 759cc731775927640fdc22b |
| Status | **done** in **76s** (duration_ms=73763) — under 120s gate |
| Txs | 31a2e086…, e304d023… (F7 dual-send) |
| Alice pin | tip snapshot 22409 (not historical log max) |

## Storm

Light-scan was calm (1–4 blocks/hop after tip-pin). onchain-tx-storm default mount=50000 **deadlocks** after hop 1: dest holds 2×50k=100k < 110k (2×amount+fee); sender left with 1 change UTXO.

| Wave | Count / amount | Landed | Notes |
| --- | --- | --- | --- |
| 1 | 12 / 50000 | 1 | c6409079… then F7 deadlock; killed |
| 2 | 12 / 20000 | 6 | hops 1–6 then both sides owned=1 / 20k |
| 3 | 6 / 10000 | 6 | after payout refill 2×500k (HTTP 429 address cooldown) |
| **Total** | | **13** | |

Second HTTP faucet to the same alice address returned **429** (address cooldown; loopback does not skip address cooldown). Refill used payout wallet send instead.

## Observer visibility

| When | tip | 	otal_user_tx_count |
| --- | --- | --- |
| B-291 / session start | ~22402 | 391 |
| After rotate funds | 22408 | 394 |
| After storm | 22426 | **408** |

Delta **17 >= storm 13**. Gate PASS.

## Tooling follow-up (this commit)

- aucet-rotate-from-payout.sh sends a second fund when owned<2 (F7).
- onchain-tx-storm.ps1 defaults Count=12, AmountEach=10000.

## Not in this unit

- mfn-p2p-forward-hub still failed (19001). Do not restart mfnd to chase it.
- No chain.checkpoint save (B-291: save without checkpoint replays the full log).
- Live **B-32** still needs a second distinct host.
- **B-42** invite-load is Next.

## Next

**B-42** invite-load smoke; 2nd host B-32.
