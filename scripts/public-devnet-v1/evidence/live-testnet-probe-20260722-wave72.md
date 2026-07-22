# Live public testnet probe - wave 72 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~13:00Z–13:19Z (~19 min)
**Prior:** wave71 mira last_proven=5853
**Tip close:** **5863** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | done first try ~218s |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5863** `8fc38085` |
| Claims | **45 → 46** |
| F45 lag | **564** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F110 density continues

mira→nico consecutive PASSes at tip~5860. Tall-tip recipe unchanged.

### F45 lag **564**

Soft JOIN only; Path A 5290 stale.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `8fc38085` | **nico** | **5863** | faucet-F101b |
| `4e9c8758` | mira | 5853 | faucet-F101b |
| `55cee933` | lena | 5842 | faucet-F101b |

**JOIN scorecard:** forty-nine proxy-proven wallets.

## Artifacts

- this markdown; `_wave72-results.json` gitignored

