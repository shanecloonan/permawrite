# Live public testnet probe - wave 82 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T16:57Z` → close ~17:16Z (~20 min)
**Prior:** wave81 aster last_proven=5972
**Tip close:** **5982** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** ~195s (no 429) |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**5982** `96804c75` |
| Prove path | local_only→matched@5982; proxy_has True by idx 22 |
| Claims | **52 → 53** |
| F45 lag | **683** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe density streak holds (waves 81–82)

Two consecutive F110 permanence PASSes after the wave80 F107 wipe. Transient `local_only` + mem=1 after Fresh upload cleared within ~2 min — healthy path, not F107.

### F45 lag **683**

Path A still frozen at 5290; soft JOIN only. Lag approaching 700.

### Session arc (waves 80–82)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | F107 → wipe |
| 81 | aster | PASS @5972 | post-wipe recovery |
| 82 | brynn | PASS @5982 | clean F110 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `96804c75` | **brynn** | **5982** | faucet-F101b |
| `851f4f0a` | aster | 5972 | faucet-F101b |
| `f27142c1` | yukon | 5947 | faucet-retry-F101b |

**JOIN scorecard:** fifty-six proxy-proven wallets.

## Artifacts

- this markdown

