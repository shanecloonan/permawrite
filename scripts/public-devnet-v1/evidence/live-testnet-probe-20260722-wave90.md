# Live public testnet probe - wave 90 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T19:55Z` → close ~20:14Z (~20 min)
**Prior:** wave89 iota last_proven=6060
**Tip close:** **6070** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6070** `f1ee38e1` |
| Claims | **60 → 61** |
| F45 lag | **771** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x10 (waves 81–90)

Ten consecutive permanence PASSes after wave80 F107 wipe. Tip advanced ~5972→6070. F45 lag **771** with Path A still frozen at 5290.

### Milestone: wave 90

Outside-in JOIN permanence density has now completed ninety probe waves on public-devnet-v1. Dominant success path remains faucet → F110 near-tip pins → F101b owned=2 → Fresh upload → public prove. Residual hazards: F107 sticky mem=1, F95 429 cooldown, F45 hard checkpoint lag.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `f1ee38e1` | **juno** | **6070** | faucet-F101b |
| `662d06b9` | iota | 6060 | faucet-F101b |
| `c6a012ca` | haven | 6050 | faucet-F101b |

**JOIN scorecard:** sixty-four proxy-proven wallets.

## Artifacts

- this markdown
