# B-42 second staggered JOIN last_proven 22487 to 22492 (2026-08-15)

**Lane:** 7 / Seat C
**never=** mfnd restart / faucet-http restart / parallel join-testnet-rehearsal / get_light_snapshot

## Before / after (skeptic)

| Surface | Before | After |
| --- | --- | --- |
| Public newest last_proven | **22487** (24e62a5a, iris) | **22492** (ea7cba7c, b42-join-a) |
| Distinct JOIN commitments at tip | 1 (iris) | **2** (iris 22487 + join-a 22492) |
| Upload index total | 95 | **96** |
| Observer user_tx | 419 | **422** |
| Live tip | 22488 | **22492** |
| Path A repo ckpt_max | 22486 | 22486 (lag=6 OK) |

Outsider verify: POST http://5.161.201.73:8787/rpc method list_recent_uploads limit=2. Expect newest commitment_hash=ea7cba7c1f9da10a630465ea57fab82d1a3b95e7ff2af29fbada65637ef7f5ab last_proven_height=22492 and prior 24e62a5a last_proven_height=22487.

## Apply

Payout -> b42-join-a two 2e6 sends via observer (tx 287182d0 mined 22490; 9608acd7 mined 22491). Observer light-scan owned=2. Observer upload Fresh aeda3134. Hub already had the tx. Mined+proven in 22492. No mfnd/faucet restart. No snapshot. No parallel JOIN.

## Not closed

Concurrent join-testnet-rehearsal x2 SUMMARY still open. Live B-32 still distinct_hosts=1. Human SUMMARY still tip=5322 archive.