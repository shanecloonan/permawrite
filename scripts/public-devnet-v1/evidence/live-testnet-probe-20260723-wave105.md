# Live public testnet probe - wave 105 findings (2026-07-23) — permanence FAIL (F107)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T16:37Z` → close ~16:59Z (~21 min)
**Prior:** wave104 xan last_proven=6678 (post-wipe streak x3)
**Tip close:** proxy~6689 tip_close_match=True at DONE; **post-close tip_id diverge** (local mem=1)
**Mode:** faucet-F101b; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **PASS** (no 429) |
| F110 / F101b | **PASS** |
| Upload | Fresh `95a0d87a` |
| Prove | **FAIL** — sticky `local_only` + local `mempool_len=1` through budget; never `proxy_has` |
| Claims | **74 → 74** (no new claim) |
| F45 lag | **1389** (ckpt 5290) |
| **permanence_public** | **FAIL** |
| Recovery | **F107 wipe** before wave106 |

## Findings

### F107 recurrence after only 3 post-wipe PASSes

| Arc | Waves | Result |
| --- | --- | --- |
| Prior | 81–100 | x20 PASS then wave101 F107 |
| This | 102–104 | x3 PASS then **wave105 F107** |

F107 is not a rare once-per-day event under dense Fresh-upload loops. Wipe remains mandatory; restart-only (F108) insufficient. Tip can still report match at DONE while sticky mem=1 prevents proxy prove; tip_id diverge appears during/after prove budget.

### F45 lag **1389**

Continues climbing; Path A republish still open for lane 7.

## Permanence board note

| Commitment | Wallet | Result |
| --- | --- | --- |
| `95a0d87a` | **yara** | **FAIL F107** |
| 0bc9dd51… | xan | PASS @6678 |

**JOIN scorecard:** still seventy-seven (no increment).
