# Live public testnet probe - wave 98 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T13:30Z` → close ~13:55Z (~25 min)
**Prior:** wave97 quill last_proven=6586
**Tip close:** **6599** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6599** `4a3d48f6` |
| Claims | **68 → 69** |
| F45 lag | **1297** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-resume streak holds (waves 97–98)

Two clean permanence PASSes after F113 recovery. F45 lag **1297** still climbing with Path A frozen at 5290.

### Session arc (waves 95–98)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 95 | orin | PASS | 6128 | F95 |
| 96 | pax | PASS | 6141 | F95 |
| 97 | quill | PASS | 6586 | F113 resume; lag>1200 |
| 98 | riven | PASS | 6599 | F110; lag=1297 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `4a3d48f6` | **riven** | **6599** | faucet-F101b |
| `ecc0d3f2` | quill | 6586 | faucet-F101b |
| `b2e0ef61` | pax | 6141 | faucet-retry-F101b |

**JOIN scorecard:** seventy-two proxy-proven wallets.

## Artifacts

- this markdown
