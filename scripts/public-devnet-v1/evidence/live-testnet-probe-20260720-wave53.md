# Live public testnet probe - wave 53 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~23:41Z-00:06Z (~25 min incl. faucet wait)
**Prior:** wave52 sara last_proven=4736
**Tip close:** **4749** (matched)
**Mode:** faucet 429 → 600s → **faucet-retry**; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet first | **429** (cooldown after sara) |
| Wait 600s + retry | **PASS** dual-send |
| Pin → owned=2 @4629 | **PASS** (1M; first pin@4679 owned=0 then ladder) |
| Upload Fresh | **PASS** `e4ae6e05` @4747 |
| F100/F105 | recur (matched poll 12; proxy_has later) |
| Public prove | **PASS** last_proven=**4749** |
| Claims | **27 → 28** |
| F45 lag | **58** (ckpt 4679 frozen) |
| **permanence_public** | **PASS** |

## Notes

- Reinforces wave50 faucet-retry JOIN path under donor-pool exhaustion.
- F45 lag continues to grow (50→58) with Path A stuck at 4679 — lane 7 Path A republish increasingly urgent for hard JOIN.
- F101b loop not needed; classic pin ladder after retry sufficed.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `e4ae6e05` | **tess** | **4749** | faucet-retry |
| `a900c1d5` | sara | 4736 | faucet |
| `e5dd4c00` | rita | 4728 | faucet-retry/F101b |

**JOIN scorecard:** thirty-one proxy-proven wallets.

## Artifacts

- `_wave53-results.json`, `_wave53-tess-upload.json`, `user-wallet/tess.json`

