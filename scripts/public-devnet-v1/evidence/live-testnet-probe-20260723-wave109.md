# Live public testnet probe - wave 109 findings (2026-07-23) — permanence FAIL (F107)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T19:38Z` → close ~20:10Z (~32 min; F95 path)
**Prior:** wave108 blake last_proven=6768
**Tip close:** tip_close_match=True at DONE; **post-close tip_id diverge** + local mem=1
**Mode:** faucet-retry-F101b; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload | Fresh `c7c85f67` |
| Prove | **FAIL** — sticky `local_only` + mem=1; never `proxy_has` |
| Claims | **76 → 76** |
| F45 lag | **1479** |
| Recovery | **F107 wipe #3** today before wave110 |

## Findings

### Third F107 wipe in one density day

| Wipe | After streak | Wave |
| --- | --- | --- |
| #1 | x20 (81–100) | 101 |
| #2 | x3 (102–104) | 105 |
| #3 | x2 (107–108) | **109** |

Under dense Fresh-upload loops, sticky mem=1 is a recurring local-observer hazard. Wipe+resync remains the only recovery (F108 restart-only insufficient).

### F45 lag **1479**

Path A still 5290.

**JOIN scorecard:** still seventy-nine.
