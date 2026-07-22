# Live public testnet probe - wave 96 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T22:10Z` → close ~22:36Z (~26 min; F95 path)
**Prior:** wave95 orin last_proven=6128
**Tip close:** **6141** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6141** `b2e0ef61` |
| Claims | **66 → 67** |
| F45 lag | **838** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Back-to-back F95 (waves 95–96)

Orin and pax both hit faucet HTTP 429. Dense permanence loops at tip~61xx now often need ~15m cooldown between funds. 600s retry continues to recover without peer-fund.

### Post-wipe streak x16 (waves 81–96)

Sixteen consecutive permanence PASSes after wave80 F107 wipe. Tip ~5972→6141. F45 lag **838**.

### Session arc (waves 93–96)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 93 | moss | PASS | 6104 | lag>800 |
| 94 | nash | PASS | 6113 | F110 |
| 95 | orin | PASS | 6128 | F95 |
| 96 | pax | PASS | 6141 | F95; lag=838 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `b2e0ef61` | **pax** | **6141** | faucet-retry-F101b |
| `063c60ee` | orin | 6128 | faucet-retry-F101b |
| `dae77944` | nash | 6113 | faucet-F101b |

**JOIN scorecard:** seventy proxy-proven wallets.

## Artifacts

- this markdown
