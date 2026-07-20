# Live public testnet probe - wave 44 findings (2026-07-20) — FAIL

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~20:21Z-20:42Z (~22 min wall)
**Prior:** wave43 iris last_proven=4636 (7-PASS streak)
**Tip close:** 4647 (eventually matched)
**Mode:** faucet 429 → peer-dual-donor (iris+hank); **permanence_public FAIL**

---

## Executive verdict

| Gate | Result |
| --- | --- |
| Fund | **PASS** peer after 429 |
| tip_id + mempool=0 before upload | **PASS** |
| Upload Fresh bound | **PASS** `985a944f` @4642 (CLI Fresh) |
| Prove leaves local_only | **FAIL** — stayed `local_only` all 48 polls (~8 min) |
| Local mempool during prove | **stuck =1** entire window (F107) |
| last_proven | **None** |
| proxy_has | **False** |
| Claims | 21 → 21 (no new claim) |
| **permanence_public** | **FAIL** |

---

## Failure mode (F104 + F107 recur)

Same pattern as waves 35b/36/yara/amy/ben:

1. Pre-upload gate satisfied (tip_id match + mempool=0).
2. CLI returns Fresh + bound authorship + local mempool_len=1.
3. Tip flaps ±1 (F88b); for a stretch local tip **stalled at 4642** while proxy advanced to 4643–4644, then local jumped ahead.
4. Upload status never left `local_only`; `last_proven` never set; proxy `list_recent_uploads` never showed the commitment.
5. Close tip_ids rematched, but sticky local mempool_len=**1** remained after the run.

**Interpretation:** the Fresh TX was accepted into the local observer mempool but never propagated / never included on the public tip. Local matched alone is insufficient (already JOIN policy). This breaks the 7-wave PASS streak and reconfirms wipe is required when mempool sticks at 1 with no proxy_has.

---

## Ops action (same session)

1. Quarantine `live-testnet-data` → `live-testnet-data-divergent-20260720-154243` (timestamp approx close).
2. Restart fresh `mfnd` dialing seeds 19001–19003.
3. Wait tip_id match + mempool=0 before wave45.
4. Do **not** restart-without-wipe (F108 — sticky mempool survives restart on same dir).

---

## Streak context

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 37–43 | cora…iris | **PASS** x7 | mempool gate held |
| **44** | **jade** | **FAIL** | F104/F107 after ~2h on same observer |

Matches wave35b lesson: wipe restores permanence for a while; F104 can return on a long-lived observer.

## Artifacts

- `_wave44-results.json` (permanence_public=false)
- commitment `985a944f…` — not on proxy
- `_wave44-jade-upload.json`, peer send JSONs

