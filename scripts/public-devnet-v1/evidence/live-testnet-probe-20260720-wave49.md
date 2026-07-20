# Live public testnet probe - wave 49 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~22:04Z-22:16Z (~12 min)
**Prior:** wave48 owen FUND FAIL (F106; all donors owned=1)
**Tip close:** **4694** (matched)
**Mode:** **faucet** (first try; cooldown cleared); **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet paula | **PASS** ~190s dual-send (no 429) |
| Pin@4679 → owned=1; @4629 → owned=2 | **PASS** (F101) |
| tip_id + mempool=0 pre-upload | **PASS** immediately |
| Upload Fresh | **PASS** `c054d610` |
| Public prove | **PASS** last_proven=**4694** + proxy_has |
| Claims | **23 → 24** |
| Path A ckpt_max | **4679** (was 4662) |
| F45 lag | 9 — still TIMEOUT 60s |
| **permanence_public** | **PASS** |

## Key ops finding: donor pool exhausted

Pre-wave49 census of local permanence wallets (hank/gina/frank/iris/nora/kate/erin/dana): **all owned_count=1**. Under F75, owned=1 cannot send. Peer dual-fund is **impossible** until faucet creates a fresh owned=2 wallet (or change consolidation yields multiple UTXOs).

Wave48 failed for this reason. Wave49 succeeded by waiting for faucet cooldown instead of peer fallback.

**JOIN rule (updated):** if faucet returns 429 and a quick donor census shows no owned≥2 wallets, **wait for cooldown** — do not burn time on peer dual-fund.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `c054d610` | **paula** | **4694** | faucet |
| `53bab1a0` | nora | 4677 | faucet |
| `8b491ece` | kate | 4661 | faucet |

**JOIN scorecard:** twenty-seven proxy-proven wallets.

## Artifacts

- `_wave49-results.json`, `_wave49-paula-upload.json`, `user-wallet/paula.json`

