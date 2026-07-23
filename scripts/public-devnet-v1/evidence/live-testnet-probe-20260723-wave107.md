# Live public testnet probe - wave 107 findings (2026-07-23) — permanence PASS (F114 recovery)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T18:55Z` → close ~19:11Z (~17 min)
**Prior:** wave106 zeke F114 UNFUNDED (hub 111); faucet health later OK
**Tip close:** **6754** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **PASS** (job done; ~340s) — F114 transient cleared without faucet restart |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6754** `a865c9f9` |
| Claims | **74 → 75** |
| F45 lag | **1456** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F114 was transient

Wave106 hub Connection refused (111) cleared by the next wave without lane-3 faucet restart (§6). Faucet `/health` showed busy=false before wave107; job completed normally.

### F45 lag **1456**

Path A still 5290; lag continues to climb (~1456). Soft JOIN mandatory.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `a865c9f9` | **aria** | **6754** | faucet-F101b |

**JOIN scorecard:** seventy-eight proxy-proven wallets.
