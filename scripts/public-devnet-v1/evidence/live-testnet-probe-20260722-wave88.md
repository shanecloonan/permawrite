# Live public testnet probe - wave 88 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T19:15Z` → close ~19:34Z (~19 min)
**Prior:** wave87 gryph last_proven=6040
**Tip close:** **6050** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6050** `c6a012ca` |
| Claims | **58 → 59** |
| F45 lag | **751** (ckpt 5290; approaching 750+) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x8 (waves 81–88)

Eight consecutive permanence PASSes after wave80 F107 wipe. Tip advanced ~5972→6050; F45 lag 672→751.

### Session scorecard (waves 80–88)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | — | F107 → wipe |
| 81 | aster | PASS | 5972 | post-wipe |
| 82 | brynn | PASS | 5982 | F110 |
| 83 | coral | PASS | 5993 | F95 |
| 84 | dante | PASS | 6002 | lag>700 |
| 85 | eden | PASS | 6017 | F95 |
| 86 | felix | PASS | 6026 | F110 |
| 87 | gryph | PASS | 6040 | F95 |
| 88 | haven | PASS | 6050 | F110; lag=751 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `c6a012ca` | **haven** | **6050** | faucet-F101b |
| (gryph) | gryph | 6040 | faucet-retry |
| (felix) | felix | 6026 | faucet-F101b |

**JOIN scorecard:** sixty-two proxy-proven wallets.

## Artifacts

- this markdown
- `live-testnet-session-findings-20260722-waves80-87.md` (extend through 88)
