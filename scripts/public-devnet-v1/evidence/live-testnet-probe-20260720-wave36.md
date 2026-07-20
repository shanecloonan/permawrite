# Live public testnet probe - wave 36 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~17:42Z 2nd wipe → ~18:05Z close (+ ~6 min extended poll)
**Prior:** wave35b F104 recur; wave34 zoe PASS
**Mode:** faucet post-2nd-wipe — **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| 2nd wipe + sync | **PASS** tip_id match @4559 (~4 min) |
| Ports / tip match at close | **PASS** |
| ckpt_max (B-84 tip-4554) | **4554**; F45 TIMEOUT lag=5 |
| Ben faucet | **PASS** |
| Pin@4554=4554 | owned=1 / 500k (F101) |
| Pin@4504 | **PASS** 1M / owned=2 |
| tip_id match before upload | **PASS** |
| Upload Fresh + bound | **PASS** `d9d6f90e` @ tip 4564 |
| last_proven / proxy_has | **FAIL** local_only; proxy False after >15 min |
| Local mempool during poll | **stuck at 1**; proxy mempool **0** |
| claims | stayed **14** |
| **permanence_public** | **FAIL** |

## Finding F107 - tip_id match + Fresh ≠ mempool inclusion

After a clean wipe, upload returned Fresh with tip_id matched, yet:

- local `mempool_len` remained **1** across many tip advances
- proxy `mempool_len` stayed **0**
- status never left `local_only`
- proxy never listed commitment `d9d6f90efca6afe84034be54d0a924cf1a851ae8e5a7e47c43bcacecf25c7b9c`
- tip_ids still matched periodically (local often +1 ahead)

**Interpretation:** CLI Fresh can mean accepted into the *local* mempool without successful gossip/inclusion on the public validator set. `peer_count=3` with `session_count=0` correlates with failed tx propagation (not proven causal).

**JOIN implication:** after upload, require either:

1. local mempool returns to 0 *and* tip_id still matches, then poll prove, or
2. proxy `list_recent_uploads` contains commitment within N minutes

Do not treat tip_id match alone as proof the Fresh tx left the machine. Extends F104/F88b.

## Wipe reliability matrix (same day)

| Wave | Wipe | Minutes after wipe | permanence_public |
| --- | --- | --- | --- |
| 34 zoe | 1st | ~0–20 | **PASS** @4533 |
| 35b amy | ~40m after 1st | — | **FAIL** F104 |
| 36 ben | 2nd (fresh) | ~0–20 | **FAIL** F107 |

Wipe is necessary after diverge but **not sufficient** for reliable permanence from a light observer with session_count=0.

## F45

Hard scan TIMEOUT; ckpt tip-4554 already lagging live tip by ~5 within minutes of Path A publish.

## JOIN scorecard

Still **seventeen** proxy-proven wallets (zoe). Ben/amy not counted. Proxy still shows zoe `4ded4c6d` + yara `fe091b02`.

## Artifacts

- `_wave36-results.json`, `_wave36-ben-upload.json`, `user-wallet/ben.json`
- quarantine `live-testnet-data-divergent-20260720-124203`
