# Live public testnet probe - wave 73 findings (2026-07-22) — PROVE FAIL (F107)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~13:20Z–13:42Z (~22 min)
**Prior:** wave72 nico permanence PASS
**Tip close (proxy):** **5874** tip_id matched at close, but local fork/mempool sticky
**Mode:** faucet-F101b + Fresh upload → stuck local_only; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** ~208s |
| F110 / F101b fund | **PASS** owned=2 |
| Pre-upload tip_id + mem=0 | **PASS** |
| Upload Fresh bound | **rc=0** tip=5869; commit `21e4dd81` |
| Prove poll (48×10s) | stuck **local_only**; last_proven=None; proxy_has=false |
| Local mempool during prove | **mem=1 sticky** entire window |
| Proxy mempool at diagnosis | **0** (public tip healthy) |
| tip_id vs proxy mid/late prove | often **diverged** (local ahead/wrong id) |
| Claims for data_root | claim_count=**0** |
| **permanence_public** | **FAIL** (prove / F107) |

## Findings

### F107 reconfirmed — Fresh upload can stick local_only with mempool=1

After a clean fund+upload gate (tip_id match + mempool=0), the Fresh upload returned success with authorship=bound, but the local observer never matched the commitment on the public tip. Prove poll logged `st local_only proxy_has False mem 1` for ~8 minutes. Post-wave diagnosis: local `mempool_len=1` while proxy `mempool_len=0` and tip_ids diverge.

**JOIN fix:**
1. Treat Fresh upload + sticky mem=1 + no last_proven within ~3–5 min as F107 — stop density.
2. Wipe/quarantine local observer data dir and resync from seeds (restart-without-wipe insufficient — F108).
3. Do not trust local_only uploads for permanence evidence.

### F111 (wave73) — prove budget exhausted without recovery

Prior F110 waves typically saw last_proven within ~2–4 min after upload. Wave73 exhausted the full 48×10s prove poll with zero progress (never left local_only). Density runners should fail-fast earlier on sticky mem=1 to avoid wasting ~8 min, then wipe.

### F45 lag **574** unrelated but still open

Path A ckpt still 5290.

## Artifacts

- `_wave73-results.json` (opal_funded=true; permanence_public=false)
- `user-wallet/opal.json` + upload artifacts (local only)
- Follow-up: quarantine `live-testnet-data/b15-fresh` → divergent stamp; fresh sync

## Follow-up

- Wipe local observer; resync; wave74+ only after tip_id match + mem=0.

