# Live public testnet probe - wave 112 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T21:03Z` → close ~21:32Z (~29 min; F95 path)
**Prior:** wave111 eden last_proven=6809
**Tip close:** **6824** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6824** `e788f78b` |
| Claims | **77 → 78** |
| F45 lag | **1520** (ckpt 5290) |
| **permanence_public** | **PASS** |
| Post-wipe streak | **x2** (111–112 after F115 wipe#4) |

## Findings

### Post-F115 streak holds

Second consecutive PASS after tip_id-diverge wipe. F95 still paces density.

### F45 lag **1520**

Path A frozen at 5290.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `e788f78b` | **finn** | **6824** | faucet-retry-F101b |
| dd7e4fc9… | eden | 6809 | faucet-F101b |

**JOIN scorecard:** eighty-one proxy-proven wallets.
