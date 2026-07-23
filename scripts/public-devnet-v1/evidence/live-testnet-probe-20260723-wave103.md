# Live public testnet probe - wave 103 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T15:46Z` → close ~16:05Z (~18 min)
**Prior:** wave102 vera last_proven=6652 (post-wipe)
**Tip close:** **6662** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **PASS** |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6662** `a27e8adf` |
| Claims | **72 → 73** |
| F45 lag | **1363** (ckpt 5290) |
| **permanence_public** | **PASS** |
| Post-wipe streak | **x2** (102–103) |

## Findings

### Post-wipe streak holds

Second consecutive PASS after wave101 F107 quarantine. Recipe unchanged at tip~66xx.

### F45 lag **1363**

Path A still 5290; soft JOIN mandatory. Overnight+day lag growth continues without republish.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `a27e8adf` | **wade** | **6662** | faucet-F101b |
| ec2aff4a… | vera | 6652 | faucet-F101b |

**JOIN scorecard:** seventy-six proxy-proven wallets.

## Artifacts

- this markdown
- session rollup `live-testnet-session-findings-20260723-waves100-103.md`
