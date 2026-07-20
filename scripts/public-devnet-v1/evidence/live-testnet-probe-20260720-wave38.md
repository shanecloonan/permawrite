# Live public testnet probe - wave 38 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~18:39Z-18:56Z
**Prior:** wave37 cora last_proven=4585
**Tip close:** **4594** (matched)
**Mode:** peer-dual-donor after faucet **429**; mempool=0 gate; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Same observer (no wipe; mem=0 after cora) | **PASS** |
| Faucet | **429** (F95) |
| Peer zoe+wendy dual-donor | **PASS** (fund_mode=peer-dual-donor) |
| Pin@4534 | owned≥2 |
| tip_id + mempool=0 before upload | **PASS** |
| Upload bound | **PASS** `8d15b8e5` |
| last_proven + proxy_has | **PASS** **4594** |
| Claims | **15 → 16** |
| F45 | TIMEOUT; ckpt_max=4584 lag=2 (near-miss) |
| **permanence_public** | **PASS** |

## Findings reconfirmed

- **F95**: faucet cooldown after wave37.
- **F105**: local matched before proxy_has briefly.
- **F107 mitigation**: mempool returned to 0 during prove; public settle succeeded without wipe.
- **F45**: Path A tip advancing (ckpt 4584) still lags live tip within minutes.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `8d15b8e5` | dana | **4594** | wave38 peer-dual |
| `e8da3321` | cora | 4585 | wave37 |
| `4ded4c6d` | zoe | 4533 | wave34 |

## JOIN scorecard

Nineteen new-wallet public permanence loops: … cora, **dana**.

## Artifacts

- `_wave38-results.json`, `_wave38-dana-upload.json`, `user-wallet/dana.json`
