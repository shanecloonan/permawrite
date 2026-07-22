# Live public testnet probe - wave 84 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T17:39Z` → close ~17:56Z (~17 min)
**Prior:** wave83 coral last_proven=5993
**Tip close:** **6002** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429 — F95 cooldown cleared after wave83 wait) |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**6002** `1cfa851f` |
| Prove path | local_only→matched@6002; proxy_has True |
| Claims | **54 → 55** |
| F45 lag | **704** (**>700**; ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F45 lag crossed **700**

Hard `--checkpoint-log` remains unusable (lag=704). Soft JOIN / near-tip pins only. Path A republish urgency increases.

### Post-wipe streak x4 (waves 81–84)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | F107 → wipe |
| 81 | aster | PASS @5972 | post-wipe |
| 82 | brynn | PASS @5982 | F110 |
| 83 | coral | PASS @5993 | F95+F110 |
| 84 | dante | PASS @6002 | F110; lag>700 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `1cfa851f` | **dante** | **6002** | faucet-F101b |
| `86de6d8f` | coral | 5993 | faucet-F101b |
| `96804c75` | brynn | 5982 | faucet-F101b |

**JOIN scorecard:** fifty-eight proxy-proven wallets.

## Artifacts

- this markdown

