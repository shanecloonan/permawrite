# Live public testnet probe - wave 39 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~18:57Z-19:12Z
**Prior:** wave38 dana last_proven=4594
**Tip close:** **4602** (matched)
**Mode:** faucet; mempool=0 gate; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer preflight | mempool=0; tip_id lag ±1 only (F88b) — **no wipe** |
| Faucet erin | **PASS** ~195s dual-send |
| Pin@4584 | owned=1 / 500k (F101) |
| Pin@4534 | **PASS** 1M / owned=2 |
| tip_id + mempool=0 before upload | **PASS** |
| Upload bound Fresh | **PASS** `8af641cd` |
| Prove mempool→0 | **PASS** |
| last_proven + proxy_has | **PASS** **4602** |
| Claims | **16 → 17** |
| F45 hard | TIMEOUT lag=11 (ckpt 4584) |
| **permanence_public** | **PASS** |

## Ops note

Third consecutive permanence PASS on the same post-wipe observer (cora→dana→erin) with the mempool=0 gate. Supports JOIN guidance: wipe when F107 sticky mempool appears; otherwise keep observer and enforce tip_id+mempool=0.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `8af641cd` | erin | **4602** | wave39 faucet |
| `8d15b8e5` | dana | 4594 | wave38 |
| `e8da3321` | cora | 4585 | wave37 |

## JOIN scorecard

Twenty new-wallet public permanence loops: … dana, **erin**.

## Artifacts

- `_wave39-results.json`, `_wave39-erin-upload.json`, `user-wallet/erin.json`
