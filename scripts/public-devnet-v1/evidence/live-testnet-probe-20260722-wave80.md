# Live public testnet probe - wave 80 findings (2026-07-22) — PROVE FAIL (F107)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T16:08Z` → close ~16:28Z (~21 min wall)
**Prior:** wave79 yukon permanence PASS last_proven=5947
**Tip open (proxy):** **5948**; **tip close (proxy):** **5958** (tip_id matched at close)
**Mode:** faucet-F101b + Fresh upload → stuck local_only; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** ~200s (poll idx 40; no 429) |
| F110 / F101b fund | **PASS** owned=1@5928 → owned=2@5933 |
| Pre-upload tip_id + mem=0 | **PASS** @5953 |
| Upload Fresh bound | **rc=0** tip=5953; commit `227ce538` tx `1725a80f3ba43441…` |
| Prove poll (~48×10s) | stuck **local_only**; last_proven=None; proxy_has=false |
| Local mempool during prove | **mem=1 sticky** entire window (even when tip_id matched) |
| Proxy mempool at close/diagnosis | **0** (public tip healthy / advancing) |
| tip_id vs proxy mid prove | frequent lag/diverge; occasional match with mem=1 still |
| Claims recent | 51 → 51 (no new public claim) |
| F45 lag | **658** (ckpt_max still 5290) |
| **permanence_public** | **FAIL** (prove / F107) |

## Findings

### F107 reconfirmed at tip~5953–5958 (third sticky prove fail class after wave73)

Wave80 repeated the wave73 pattern after a long PASS streak (waves 74–79, except tooling wave76):

1. Fund path healthy: faucet done → owned=1 early-exit (F110) → F101b re-pin → owned=2 (`faucet-F101b`).
2. Pre-upload gate clean: tip_id match + mempool_len=0.
3. Upload returned Fresh / authorship=bound / local mempool_len=1 in the upload JSON.
4. Prove poll never left `local_only`; `proxy_has_zara=false`; `zara_last_proven=None`.
5. Tip heights advanced on both local and proxy during the poll, but the commitment never appeared on the public tip.
6. Post-wave diagnosis (~16:29Z): local tip 5959 mem=1; proxy tip 5958 mem=0; tip_ids differ.

**Interpretation:** the Fresh upload stayed in the local observer mempool / fork view and did not gossip+seal into the public chain. Local tip_id can still *catch up* in height with the proxy while retaining a sticky mem=1 and a non-public commitment — matching F107/F108 lessons (restart-without-wipe insufficient).

### F111 — prove budget still too long once mem=1 is sticky

Prove loop logged `st local_only … mem 1` for the full poll (~8 min). Fail-fast after ~3–5 min of sticky mem=1 + no last_proven would save wall clock before wipe+resync (~6–10 min).

### F45 lag **658** — Path A still frozen at 5290

Hard checkpoint-log pin remains unusable for JOIN. Soft / near-tip pin ladder continues to be mandatory. Lag crossed 650.

### Session arc (waves 76–80)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 76 | troy | UPLOAD FAIL | F112 `--mestroy` tooling |
| 77 | vela | PASS @5923 | F112 fix + F95 retry |
| 78 | wynn | PASS @5932 | clean F110 |
| 79 | yukon | PASS @5947 | faucet-retry-F101b |
| 80 | zara | **PROVE FAIL** | F107 sticky mem=1 / local_only |

**JOIN scorecard:** fifty-four proxy-proven wallets unchanged (zara excluded).

## Ops follow-up (same commit session)

1. Quarantine `live-testnet-data/b15-fresh` → `live-testnet-data-divergent-<stamp>`.
2. Restart `mfnd` with empty `b15-fresh` + `--p2p-dial` seeds 19001–19003.
3. Wait tip_id match + mem=0 before wave81 (aster).
4. Do **not** densify on sticky local_only evidence.

## Artifacts

- this markdown
- `_wave80-results.json` / `_wave80-zara-upload.json` (gitignored)
- `user-wallet/zara.json` + upload artifacts (local only; not committed)

