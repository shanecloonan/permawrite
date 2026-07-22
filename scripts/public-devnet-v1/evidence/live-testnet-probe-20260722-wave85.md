# Live public testnet probe - wave 85 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T17:57Z` → close ~18:26Z (~30 min; includes F95 600s)
**Prior:** wave84 dante last_proven=6002
**Tip close:** **6017** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry done (~210s) — F95 |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**6017** `7cab6287` |
| Claims | **55 → 56** |
| F45 lag | **713** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Session arc (waves 80–85)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | — | F107 → wipe |
| 81 | aster | PASS | 5972 | post-wipe |
| 82 | brynn | PASS | 5982 | F110 |
| 83 | coral | PASS | 5993 | F95 |
| 84 | dante | PASS | 6002 | lag>700 |
| 85 | eden | PASS | 6017 | F95+F110 |

### F45 lag **713**

Path A still 5290; soft JOIN only.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `7cab6287` | **eden** | **6017** | faucet-retry-F101b |
| (dante) | dante | 6002 | faucet-F101b |
| `86de6d8f` | coral | 5993 | faucet-F101b |

**JOIN scorecard:** fifty-nine proxy-proven wallets.

## Artifacts

- this markdown
- see also `live-testnet-session-findings-20260722-waves80-83.md` (extend mentally through wave85)

