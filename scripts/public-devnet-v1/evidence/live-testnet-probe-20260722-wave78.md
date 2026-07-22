# Live public testnet probe - wave 78 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~15:20Z–15:37Z (~17 min)
**Prior:** wave77 vela last_proven=5923 (F112 fix)
**Tip close:** **5932** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** first try ~201s |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**5932** `7134e91b` |
| Claims | **49 → 50** |
| F45 lag | **634** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-F112 density healthy

vela→wynn consecutive PASSes with intact `--message`. F95 avoided (~20 min after vela faucet-retry done).

### F45 lag **634** — still climbing past 600

Soft JOIN only.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `7134e91b` | **wynn** | **5932** | faucet-F101b |
| `ef6cc45c` | vela | 5923 | faucet-retry-F101b |
| `32e7ab2e` | sage | 5901 | faucet-retry-F101b |

**JOIN scorecard:** fifty-three proxy-proven wallets.

## Artifacts

- this markdown

