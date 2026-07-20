# Live public testnet probe - wave 51 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~22:47Z-23:24Z (~37 min)
**Prior:** wave50 quinn last_proven=4709
**Tip close:** **4728** (matched)
**Mode:** faucet 429 → 600s → faucet-retry; delayed owned=2 visibility; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet first | **429** |
| Wait 600s + faucet retry | job **done** (~190s) |
| Immediate pin@4679/@4629 | owned=1 / 500k only (half of dual-send visible) |
| Deep pins 4400/4262 | TIMEOUT (F99) |
| Peer nora/kate | **SKIP** owned=1 (F106) — no sends |
| Re-pin@4679 after ~2 min tip advance | **PASS** 1M / owned=2 |
| Runner fund_mode label | **misreported** `peer-dual-donor` (no peer send occurred) |
| Upload + public prove | **PASS** last_proven=**4728** |
| Claims | **25 → 26** |
| F45 lag | 31 (ckpt stuck 4679) |
| **permanence_public** | **PASS** |

## Finding F101b — delayed second faucet UTXO

Faucet dual-send job reported `done`, but the first pin ladder only saw **one** 500k UTXO. After ~2 minutes of tip growth (and a no-op peer section), re-pin at the same ckpt height showed **owned=2 / 1e6**.

True fund source: **faucet-retry with delayed second-output visibility**, not peer dual-donor.

**JOIN implication:** after faucet `done`, if owned=1, wait for tip advance and **re-pin the same near-tip heights** before declaring fund failure. Do not trust runner `fund_mode` strings when peer donors were all skipped.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund (corrected) |
| --- | --- | --- | --- |
| `e5dd4c00` | **rita** | **4728** | faucet-retry (delayed F101) |
| `ce817776` | quinn | 4709 | faucet-retry |
| `c054d610` | paula | 4694 | faucet |

**JOIN scorecard:** twenty-nine proxy-proven wallets.

## Artifacts

- `_wave51-results.json` (note misleading fund_mode), `_wave51-rita-upload.json`

