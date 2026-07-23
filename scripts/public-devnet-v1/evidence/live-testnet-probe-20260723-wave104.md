# Live public testnet probe - wave 104 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T16:05Z` → close ~16:37Z (~31 min; F95 path)
**Prior:** wave103 wade last_proven=6662
**Tip close:** **6678** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6678** `0bc9dd51` |
| Claims | **73 → 74** |
| F45 lag | **1373** (ckpt 5290) |
| **permanence_public** | **PASS** |
| Post-wipe streak | **x3** (102–104) |

## Findings

### F95 pacing continues under density

Wave104 hit 429 after consecutive clean faucets on 102–103. ~15m IP cooldown remains the dominant wall-clock cost when dense loops share an egress IP.

### Post-wipe streak x3

F107 wipe recovery holds; no sticky mem=1 this wave.

### F45 lag **1373**

Still climbing vs Path A 5290.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `0bc9dd51` | **xan** | **6678** | faucet-retry-F101b |
| a27e8adf… | wade | 6662 | faucet-F101b |

**JOIN scorecard:** seventy-seven proxy-proven wallets.
