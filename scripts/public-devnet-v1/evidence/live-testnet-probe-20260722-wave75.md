# Live public testnet probe - wave 75 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~14:06Z–14:35Z (~29 min; includes 600s F95)
**Prior:** wave74 reed last_proven=5886 (post-F107 wipe)
**Tip close:** **5901** (matched)
**Mode:** F95 429 → retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet first POST | **429** (post-reed cooldown) |
| F95 wait + retry | **done** ~222s |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**5901** `32e7ab2e` |
| Claims | **47 → 48** |
| F45 lag | **597** (ckpt 5290) — approaching 600 |
| **permanence_public** | **PASS** |

## Session arc (waves 71–75)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 71 | mira | PASS | 5853 | clean F110 |
| 72 | nico | PASS | (wave72) | clean F110 |
| 73 | opal | PROVE FAIL | — | F107 sticky mem=1 |
| 74 | reed | PASS | 5886 | post-wipe recovery |
| 75 | sage | PASS | 5901 | F95+retry |

## Findings

### F107 wipe + F95 density both exercised

Wave73→74 proved wipe recovery. Wave75 immediately re-hit F95 (expected after reed faucet). Recipe holds.

### F45 lag **597**

Soft JOIN only.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `32e7ab2e` | **sage** | **5901** | faucet-retry-F101b |
| `480340e7` | reed | 5886 | faucet-F101b |
| `4e9c8758` | mira | 5853 | faucet-F101b |

**JOIN scorecard:** fifty-one proxy-proven wallets.

## Artifacts

- this markdown

