# Live public testnet probe - wave 89 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T19:35Z` → close ~19:54Z (~19 min)
**Prior:** wave88 haven last_proven=6050
**Tip close:** **6060** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**6060** `662d06b9` |
| Prove path | transient local_only → matched@6060; proxy_has True |
| Claims | **59 → 60** |
| F45 lag | **761** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x9 (waves 81–89)

Nine consecutive permanence PASSes after wave80 F107 wipe. Tip ~5972→6060; F45 lag continues climbing with frozen Path A ckpt=5290.

### F45 lag **761**

Hard `--checkpoint-log` still unusable. Soft JOIN / near-tip pin ladder mandatory. Lane 7 Path A republish remains the unblock.

### Session arc (waves 80–89)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | — | F107 → wipe |
| 81–88 | aster…haven | PASS | 5972–6050 | post-wipe density |
| 89 | iota | PASS | 6060 | F110; lag=761 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `662d06b9` | **iota** | **6060** | faucet-F101b |
| `c6a012ca` | haven | 6050 | faucet-F101b |
| (gryph) | gryph | 6040 | faucet-retry |

**JOIN scorecard:** sixty-three proxy-proven wallets.

## Artifacts

- this markdown
