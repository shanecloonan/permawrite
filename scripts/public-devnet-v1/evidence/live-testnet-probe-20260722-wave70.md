# Live public testnet probe - wave 70 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~12:20Z–12:37Z (~17 min)
**Prior:** wave69 kira last_proven=5833
**Tip close:** **5842** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** ~196s |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5842** `55cee933` |
| Claims | **43 → 44** |
| F45 lag | **544** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Waves 66–70: five more PASSes at tip~5800+

hugo (F95 retry), ivy, joss, kira, lena — all permanence_public with F110 runner. Only density hiccup was wave66 F95 429.

### F45 lag **544** still the top honesty gap

Path A frozen at 5290. Soft JOIN mandatory. Lane 7 Path A republish would close operator pain.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `55cee933` | **lena** | **5842** | faucet-F101b |
| `7f6b2496` | kira | 5833 | faucet-F101b |
| `775fc539` | joss | 5819 | faucet-F101b |

**JOIN scorecard:** forty-seven proxy-proven wallets.

## Artifacts

- this markdown; `_wave70-results.json` gitignored

