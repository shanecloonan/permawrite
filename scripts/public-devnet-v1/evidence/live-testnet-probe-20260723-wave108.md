# Live public testnet probe - wave 108 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T19:11Z` → close ~19:38Z (~26 min; F95 path)
**Prior:** wave107 aria last_proven=6754
**Tip close:** **6768** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6768** `12c2f830` |
| Claims | **75 → 76** |
| F45 lag | **1465** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Session density continues post-F114

Waves 107–108 both permanence PASS after wave106 fund break. F95 still paces consecutive faucet calls.

### F45 lag **1465**

Path A frozen at 5290; lag ~1465 and rising.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `12c2f830` | **blake** | **6768** | faucet-retry-F101b |
| a865c9f9… | aria | 6754 | faucet-F101b |

**JOIN scorecard:** seventy-nine proxy-proven wallets.
