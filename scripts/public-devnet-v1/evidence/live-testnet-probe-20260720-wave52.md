# Live public testnet probe - wave 52 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~23:26Z-23:40Z (~14 min)
**Prior:** wave51 rita last_proven=4728
**Tip close:** **4736** (matched)
**Mode:** **faucet** first try; F101b runner armed but unused; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer | tip match @4729; mem=0; no wipe |
| Faucet sara | **PASS** ~135s dual-send (no 429) |
| Pin@4679 owned=1 → @4629 owned=2 | **PASS** (classic F101) |
| F101b re-pin loop | not needed |
| Upload Fresh | **PASS** `a900c1d5` |
| Public prove | **PASS** last_proven=**4736** |
| Claims | **26 → 27** |
| F45 lag | **50** (ckpt still 4679) — TIMEOUT |
| **permanence_public** | **PASS** |

## Findings

### Clean faucet path after cooldown

Unlike waves 48/50/51, faucet accepted immediately (~15m after rita). Pin ladder closed F101 in one pass. Validates that spacing waves by cooldown restores the simplest JOIN path.

### F45 lag growing (ops signal for lane 7)

Path A max still **4679** while tip ~4730+ → lag **50**. Hard `--checkpoint-log` remains TIMEOUT. Soft JOIN unaffected; hard path increasingly far from usable without Path A republish.

### Runner note

Wave52 runner includes F101b re-pin + corrected peer fund_mode labeling (from wave51 lessons). Neither path fired this wave.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `a900c1d5` | **sara** | **4736** | faucet |
| `e5dd4c00` | rita | 4728 | faucet-retry/F101b |
| `ce817776` | quinn | 4709 | faucet-retry |

**JOIN scorecard:** thirty proxy-proven wallets.

## Artifacts

- `_wave52-results.json`, `_wave52-sara-upload.json`, `user-wallet/sara.json`
- Runner: `_wave52_run.py` (F101b-aware)

