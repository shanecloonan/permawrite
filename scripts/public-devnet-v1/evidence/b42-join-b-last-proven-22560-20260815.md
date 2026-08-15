# B-42 third staggered JOIN last_proven 22492 to 22560 (2026-08-15)

**Lane:** 7 / Seat C
**never=** mfnd restart / faucet-http restart / parallel join-testnet-rehearsal / get_light_snapshot

## Before / after (skeptic)

| Surface | Before | After |
| --- | --- | --- |
| Public newest last_proven | **22492** (ea7cba7c, b42-join-a) | **22560** (6a1468fc, b42-join-b) |
| Distinct JOIN commitments at tip | 2 (iris + join-a) | **3** (iris 22487 + join-a 22492 + join-b 22560) |
| Upload index total | 96 | **97** |
| Live tip | 22545 | **22560** |
| Path A repo ckpt_max | 22535 | 22535 (lag ~25; Next) |

Outsider verify: POST http://5.161.201.73:8787/rpc method list_recent_uploads limit=1. Expect commitment_hash=6a1468fcc6b13c4a12d318dee67f29e95b67d6fe929af055044051ba79d51ffa last_proven_height=22560.

## Apply

Payout -> b42-join-b two 2e6 via hub (tx 0879c01a + 25587283). B-50 pin observer 18734 (log_max=22543; no CLI snapshot). Incremental light-scan owned=2. Observer upload Fresh 1a2028bb commitment 6a1468fc (hub+voter already had the tx). Mined+proven in 22560. No mfnd/faucet restart. No parallel JOIN.

## Not closed

Concurrent join-testnet-rehearsal x2 SUMMARY still open. Live B-32 still distinct_hosts=1. Human SUMMARY still tip=5322 archive. Path A lag (ckpt 22535 vs tip 22560).