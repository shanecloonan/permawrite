# Live public testnet probe - wave 42 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~19:49Z-20:04Z (~15.5 min wall)
**Prior:** wave41 gina last_proven=4620
**Tip close:** **4628** (matched)
**Mode:** faucet 429 → **peer-dual-donor** (gina+frank); mempool=0 gate; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet hank | **HTTP 429** (cooldown after wave41) |
| Peer gina→hank + frank→hank | **PASS** |
| Pin ladder → owned=2 | **PASS** @4556 |
| Upload Fresh | **PASS** `69b678f3` @4626 |
| F100/F105 | recur (matched poll 13; proxy_has poll 22) |
| Public prove | **PASS** last_proven=**4628** |
| Claims | **19 → 20** |
| F45 lag | 15 (ckpt 4606; tip advanced past Path A again) |
| **permanence_public** | **PASS** |

## Notes

- Sixth consecutive PASS (cora…gina→**hank**).
- F45 lag **grew again** (7→15) as live tip moved beyond frozen Path A max 4606 — confirms F45 closes only when Path A tracks tip, not when lag briefly shrinks.
- Peer dual-donor from two immediately prior permanence wallets remains reliable under F95.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `69b678f3` | **hank** | **4628** | peer |
| `8aeb43ec` | gina | 4620 | faucet |
| `8f866ea2` | frank | 4611 | peer |

**JOIN scorecard:** twenty-three proxy-proven wallets.

## Artifacts

- `_wave42-results.json`, `_wave42-hank-upload.json`, peer send JSONs, `user-wallet/hank.json`

