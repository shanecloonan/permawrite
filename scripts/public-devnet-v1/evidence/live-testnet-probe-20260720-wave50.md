# Live public testnet probe - wave 50 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~22:19Z-22:44Z (~25 min incl. 600s faucet wait)
**Prior:** wave49 paula last_proven=4694
**Tip close:** **4709** (matched)
**Mode:** faucet 429 → **600s wait → faucet-retry PASS**; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet first try | **HTTP 429** (cooldown after paula) |
| Peer dual-fund | skipped (donor pool owned=1; F106/F75) |
| Wait 600s + faucet retry | **PASS** dual-send (~175s) |
| Pin ladder → owned=2 | **PASS** @4629 |
| Upload Fresh | **PASS** `ce817776` |
| Public prove | **PASS** last_proven=**4709** |
| Claims | **24 → 25** |
| F45 lag | 18 (ckpt 4679) TIMEOUT |
| **permanence_public** | **PASS** |

## Finding: faucet-retry JOIN path proven

With the entire local permanence wallet pool at owned=1, peer dual-fund is dead. Waiting the full ~15m faucet cooldown and retrying is the working JOIN path under F95+F106.

Wave50 is the first explicit end-to-end proof of the **429 → sleep → faucet-retry → prove** loop (fund_mode=`faucet-retry`).

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `ce817776` | **quinn** | **4709** | faucet-retry |
| `c054d610` | paula | 4694 | faucet |
| `53bab1a0` | nora | 4677 | faucet |

**JOIN scorecard:** twenty-eight proxy-proven wallets.

## Artifacts

- `_wave50-results.json`, `_wave50-quinn-upload.json`, `user-wallet/quinn.json`

