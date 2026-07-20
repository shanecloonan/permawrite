# Live public testnet probe - wave 47 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~21:27Z-21:42Z (~15 min)
**Prior:** wave46 liam FUND FAIL (F106)
**Tip close:** **4677** (matched)
**Mode:** **faucet** (cooldown cleared); **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet nora | **PASS** dual-send |
| Pin → owned=2 | **PASS** |
| Upload Fresh | **PASS** `53bab1a0` |
| Public prove | **PASS** last_proven=**4677** |
| Claims | **22 → 23** |
| F45 lag | 8 (ckpt 4662) |
| **permanence_public** | **PASS** |

## Notes

- Waiting ~15m after wave45 faucet (through wave46 fund fail) restored faucet path — preferred over peer dual-fund under F106.
- Post-wipe observer still healthy (kate→nora PASSes).
- **JOIN scorecard:** twenty-six proxy-proven wallets.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `53bab1a0` | **nora** | **4677** | faucet |
| `8b491ece` | kate | 4661 | faucet |
| `39bffdd5` | iris | 4636 | faucet |

## Artifacts

- `_wave47-results.json`, `_wave47-nora-upload.json`, `user-wallet/nora.json`

