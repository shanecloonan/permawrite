# faucet HTTP F7 prove (2026-08-15)

**Lane:** 7 / Seat C
**never=** parallel JOIN / 0.0.0.0 mfnd / Seat A CI scripts / Seat B consensus tests

## Before / after (skeptic)

| Surface | Before | After |
| --- | --- | --- |
| `POST http://5.161.201.73:8788/faucet` | F7 blocked (`faucet-ops` scan 22479 / owned=1) | job **`f77a4048f05e9d22c2b28d3c` `done` 73s** (gate <120s) |
| Dual-send tx ids | none | `eb4e89a3b9535af9…` + `ac8d77a41bec4cbf…` |
| Public tip | 22508 stuck | **22522** (produce restored) |
| `/health` | scan 22479 / 29 behind / lock | scan **22522** / behind **0** / `busy=false` |

Outsider verify: `curl -sS http://5.161.201.73:8788/health` shows `wallet=faucet-ops.json`, `wallet_blocks_behind` near 0, `busy=false`. Loopback `POST /faucet` + poll `/faucet/job?id=` until `status=done` (15 min IP cooldown for non-loopback).

## Apply

1. Stop idle `faucet-http`. B-50 `bootstrap-wallet-from-checkpoint-log --apply` on observer `:18734` (python snapshot 255s @ 22504; F45 soft). faucet-ops scan **22508** owned still **1**.
2. Payout two 2e6 via observer — parked in observer mempool while hub `:19101` sat at **48 CLOSE-WAIT** (B-300 binary live; leak returned). Forward-only restart did not clear hub slots.
3. `systemctl restart mfnd-hub` only (voters then later) — tall-tip replay ~10 min. Voters rejected new 22509 as `competing:height=22509` (stale pre-restart proposal). Restarted **voters only**; then hub again once voters were live.
4. Hub sealed **22509–22522**. Resubmitted refills via hub `:18731` (observer txs did not gossip). Scan owned **3**, then **5** after a first F7 attempt spent the pair and missed change (`job 100157d7` error owned=1).
5. `systemctl start faucet-http`. `POST /faucet` loopback → job **`f77a4048` done 73185ms** two txs.

No JOIN rehearsal. Faucet left **active**. Path A repo ckpt still **22504** (lag vs 22522 — next unit).

## Not closed

2nd distinct operator host (B-32). Concurrent JOIN x2. Human SUMMARY. Path A lag after tip recover.