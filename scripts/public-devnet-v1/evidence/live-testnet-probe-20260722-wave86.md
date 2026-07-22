# Live public testnet probe - wave 86 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T18:27Z` → close ~18:44Z (~18 min)
**Prior:** wave85 eden last_proven=6017
**Tip close:** **6026** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**6026** `6c5e6c65` |
| Claims | **56 → 57** |
| F45 lag | **728** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x6 (waves 81–86)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | F107 → wipe |
| 81–85 | aster…eden | PASS | density + F95 x2 |
| 86 | felix | PASS @6026 | clean F110; lag=728 |

### F45 lag **728**

Path A still 5290; soft JOIN only.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `6c5e6c65` | **felix** | **6026** | faucet-F101b |
| `7cab6287` | eden | 6017 | faucet-retry-F101b |
| (dante) | dante | 6002 | faucet-F101b |

**JOIN scorecard:** sixty proxy-proven wallets.

## Artifacts

- this markdown
