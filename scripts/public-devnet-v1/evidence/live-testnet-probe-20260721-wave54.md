# Live public testnet probe - wave 54 findings (2026-07-21)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~00:07Z-00:30Z (incl. 600s faucet wait; shell monitor aborted mid-wait, process completed)
**Prior:** wave53 tess last_proven=4749
**Tip close:** **4763** (matched)
**Mode:** faucet 429 → 600s → **faucet-retry**; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet first | **429** |
| Wait 600s + retry | **PASS** dual-send (~190s) |
| Pin → owned=2 @4629 | **PASS** 1M |
| Upload Fresh | **PASS** `aefcaf80` @4761 |
| Public prove | **PASS** last_proven=**4763** + proxy_has |
| Claims | **28 → 29** |
| F45 lag at open | **71** (ckpt 4679) TIMEOUT |
| **permanence_public** | **PASS** |

## Notes

- Cursor shell task aborted during the 600s cooldown sleep; runner finished and wrote `_wave54-results.json` anyway.
- Another faucet-retry JOIN success under donor-pool exhaustion.
- F45 lag at open was **71** (Path A still frozen at 4679).

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `aefcaf80` | **viv** | **4763** | faucet-retry |
| `e4ae6e05` | tess | 4749 | faucet-retry |
| `a900c1d5` | sara | 4736 | faucet |

**JOIN scorecard:** thirty-two proxy-proven wallets.

## Artifacts

- `_wave54-results.json`, `_wave54-viv-upload.json`, `user-wallet/viv.json`

