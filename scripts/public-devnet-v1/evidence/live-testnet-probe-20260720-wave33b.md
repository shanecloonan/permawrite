# Live public testnet probe - wave 33b findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~16:07Z-16:30Z (+ extended prove poll)
**Prior:** wave33 fund FAIL; recovery after faucet cooldown
**Tip close:** matched intermittently; local often ±1 ahead (F88b)
**Mode:** faucet recovery — **upload Fresh but NOT publicly proven**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet yara | **PASS** dual-send → 1M / owned=2 @ pin **4446** |
| F45 hard scan | **TIMEOUT** 60s (rc=-1); lag~15 vs ckpt 4496 |
| Upload authorship bound | **PASS** Fresh `0d2b070b…` tip_height=4514 |
| Prove / last_proven | **FAIL** status stuck **local_only** >15 min |
| Proxy list_recent_uploads has yara | **FAIL** (total stayed 25; has=false) |
| Claims recent | **13** (unchanged — no new claim) |
| tip_id during prove poll | Flaps match/mismatch; local mempool_len=1 vs proxy 0 |

## Finding F104 - Fresh upload ≠ public permanence (local_only trap)

Yara faucet+upload returned `outcome=Fresh`, `authorship_claim=bound`, commitment `0d2b070b4e8bce26df2fb5ca1dfe2f875c5cf2e943d5a09456beab55096eb0f9`. Extended polling (~6 min in-runner + ~6 min follow-up) never produced `last_proven_height`. Proxy never listed the commitment. Local `uploads status` remained `local_only`.

Concurrent observations:

- `session_count=0` with `peer_count=3` (F88b)
- Local tip frequently one height ahead of proxy with **different tip_id**
- At poll end: local `mempool_len=1`, proxy `mempool_len=0`
- get_tx via public proxy **403** (expected surface limit)

**JOIN implication (hard):** do **not** treat CLI Fresh / bound authorship as permanence. Require:

1. tip_id match with proxy through settle, and
2. proxy `list_recent_uploads` contains commitment, and
3. `last_proven_height` set (and preferably `claims for <data_root>`).

If stuck local_only with tip_id flap + local mempool residue → wipe/resync observer (F74) before inviting users. Soft-fail the permanence loop rather than claiming success.

## Finding F45 timeout under load

Hard `--checkpoint-log` light-scan hit **TIMEOUT 60s** (and earlier 180s crash before soft-fail). Soft JOIN path must not block faucet on hard-scan.

## Recovery partial success

- Fund path after F95 cooldown: **works** (pin@4446 = ckpt_max-50).
- Permanence path: **blocked by F104** this session.

## JOIN scorecard

Still **sixteen** public last_proven wallets. Yara **not** counted until proxy-proven.

## Artifacts (local)

- `_wave33b-results.json`, `_wave33b-yara-upload.json`, `user-wallet/yara.json`
