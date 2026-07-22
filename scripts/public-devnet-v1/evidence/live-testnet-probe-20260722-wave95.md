# Live public testnet probe - wave 95 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T21:41Z` → close ~22:10Z (~30 min; F95 path)
**Prior:** wave94 nash last_proven=6113
**Tip close:** **6128** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**6128** `063c60ee` |
| Claims | **65 → 66** |
| F45 lag | **824** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F95 returned after a clean streak

Waves 88–94 avoided HTTP 429; wave95 hit cooldown again (`faucet-retry-F101b`). Dense faucet loops still need the 600s retry. Post-wipe permanence streak continues (x15).

### F45 lag **824**

Path A still 5290; soft JOIN only. Lag climbing past 820.

### Session arc (waves 89–95)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 89–94 | iota…nash | PASS | 6060–6113 | clean F110 streak |
| 95 | orin | PASS | 6128 | F95 + F110; lag=824 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `063c60ee` | **orin** | **6128** | faucet-retry-F101b |
| `dae77944` | nash | 6113 | faucet-F101b |
| (moss) | moss | 6104 | faucet-F101b |

**JOIN scorecard:** sixty-nine proxy-proven wallets.

## Artifacts

- this markdown
