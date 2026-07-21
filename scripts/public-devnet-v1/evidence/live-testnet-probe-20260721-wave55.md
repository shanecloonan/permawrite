# Live public testnet probe - wave 55 findings (2026-07-21)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~01:02Z-01:18Z (~16 min)
**Prior:** wave54 viv last_proven=4763
**Tip close:** **4785** (matched)
**Mode:** **faucet** first try; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer | tip match @4777; mem=0; no wipe |
| Faucet wren | **PASS** ~125s dual-send (no 429) |
| Pin ladder → owned=2 @4629 | **PASS** |
| Upload Fresh | **PASS** `a88d7bcb` |
| Public prove | **PASS** last_proven=**4785** |
| Claims | **29 → 30** |
| F45 lag | **98** (ckpt frozen at 4679) TIMEOUT |
| **permanence_public** | **PASS** |

## Findings

### Clean faucet after cooldown

Spacing after viv's faucet-retry restored first-try faucet (~15m+). Simplest JOIN path.

### F45 lag critical (lane 7)

Path A max still **4679** while tip ~4780 → lag **98**. Hard `--checkpoint-log` unusable for JOIN; soft path remains required. Lag has grown ~50→71→98 across waves 52–55 without Path A republish.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `a88d7bcb` | **wren** | **4785** | faucet |
| `aefcaf80` | viv | 4763 | faucet-retry |
| `e4ae6e05` | tess | 4749 | faucet-retry |

**JOIN scorecard:** thirty-three proxy-proven wallets.

## Artifacts

- `_wave55-results.json`, `_wave55-wren-upload.json`, `user-wallet/wren.json`

