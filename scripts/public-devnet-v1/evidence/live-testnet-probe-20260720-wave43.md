# Live public testnet probe - wave 43 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~20:05Z-20:20Z (~15 min wall)
**Prior:** wave42 hank last_proven=4628
**Tip close:** **4636** (matched)
**Mode:** **faucet**; mempool=0 gate; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Path A ckpt_max | **4624** (was 4606 in wave42) |
| F45 hard lag | **5** — still TIMEOUT 60s |
| Faucet iris | **PASS** dual-send |
| Pin ladder → owned=2 | **PASS** @4574 |
| Upload Fresh | **PASS** `39bffdd5` |
| F100/F105 | recur (proxy_has at tip rematch) |
| Public prove | **PASS** last_proven=**4636** |
| Claims | **20 → 21** |
| **permanence_public** | **PASS** |

## Key finding: Path A catch-up

Lane 7 advanced Path A to **4624**, cutting F45 lag to **5** (wave42 had lag 15 @ ckpt 4606). Hard `--checkpoint-log` still times out at 60s — near-tip is not exact-tip — but the trend confirms F45 is an ops lag problem, not a soft-JOIN failure.

Seventh consecutive PASS (cora…hank→**iris**).

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `39bffdd5` | **iris** | **4636** | faucet |
| `69b678f3` | hank | 4628 | peer |
| `8aeb43ec` | gina | 4620 | faucet |

**JOIN scorecard:** twenty-four proxy-proven wallets.

## Artifacts

- `_wave43-results.json`, `_wave43-iris-upload.json`, `user-wallet/iris.json`

