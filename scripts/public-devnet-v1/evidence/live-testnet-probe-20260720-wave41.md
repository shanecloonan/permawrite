# Live public testnet probe - wave 41 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~19:33Z-19:48Z (~15 min wall)
**Prior:** wave40 frank last_proven=4611
**Tip close:** **4620** (matched)
**Mode:** **faucet**; mempool=0 gate; **permanence_public PASS**

---

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer preflight | tip rematch @4613; mempool=0; no wipe |
| Path A ckpt_max | **4606** (was 4584 in wave40) |
| F45 hard lag | **7** (was 19) — still TIMEOUT 60s |
| Faucet gina | **PASS** ~195s dual-send (job polls 0-39) |
| Pin@4606 | owned=1 / 500k (F101) |
| Pin@4556 | **PASS** 1M / owned=2 |
| tip_id + mempool=0 before upload | **PASS** |
| Upload bound Fresh | **PASS** `8aeb43ec` @ tip 4618 |
| Prove mempool→0 | **PASS** by poll ~10 |
| F100 local matched before tip_id | **observed** again (poll 10 vs 21) |
| F105 proxy list lag | **observed** (~110s) |
| last_proven + tip match + proxy_has | **PASS** **4620** |
| Claims | **18 → 19** |
| **permanence_public** | **PASS** |

---

## Timeline highlights

1. Open tip lag F88b (±1) cleared in ~48s; no sticky mempool.
2. Checkpoint log max advanced to **4606** (lane 7 Path A publish landed locally) — F45 lag shrunk to **7** but hard `--checkpoint-log` still TIMED OUT at 60s. Soft JOIN remains the safe path.
3. Faucet cooled enough after wave40 peer path — dual-send succeeded (~195s).
4. Pin ladder 4606→4556 closed F101 (owned 1→2).
5. Upload Fresh @4618; prove showed same F100/F105 pattern as wave40 (local matched@4620 while proxy tip lagged; proxy_has true only at tip rematch poll 21).
6. Close: tip match @4620; claims 18→19.

---

## Permanence scorecard (newest)

| Commitment | Wallet | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- |
| `8aeb43ec` | **gina** | **4620** | faucet | wave41 |
| `8f866ea2` | frank | 4611 | peer | wave40 |
| `8af641cd` | erin | 4602 | faucet | wave39 |
| `8d15b8e5` | dana | 4594 | peer | wave38 |

**JOIN scorecard:** twenty-two new-wallet public permanence loops (…frank + **gina**).

Fifth consecutive PASS on post-wipe observer (cora→dana→erin→frank→**gina**).

---

## Findings

| ID | Wave41 note |
| --- | --- |
| **F45** | Lag improved (19→7) after Path A tip-4606 land, but hard scan still TIMEOUT — near-tip attestation ≠ exact tip yet. |
| **F88b** | tip_id ±1 during open/prove; normal. |
| **F95** | Faucet available again after cooldown (contrast wave40 429). |
| **F100/F105** | Reproduced exactly: matched+last_proven before tip_id/proxy list. Triple gate still required. |
| **F101** | Pin ladder required after faucet. |
| **F107** | Not triggered. |

---

## Artifacts

- `_wave41-results.json`, `_wave41-gina-upload.json`, `user-wallet/gina.json`
- Runner: `_wave41_run.py`

