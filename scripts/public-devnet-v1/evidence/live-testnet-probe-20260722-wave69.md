# Live public testnet probe - wave 69 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~11:52Z–12:19Z (~27 min; faucet ~280s)
**Prior:** wave68 joss last_proven=5819
**Tip close:** **5833** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** first try ~280s (slow end of F109 band) |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5833** `7f6b2496` |
| Claims | **42 → 43** |
| F45 lag | **530** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Ten-wave tall-tip arc (59–69)

1 FUND FAIL (aria) + 10 PASSes after harden. F110 near-tip recipe remains the JOIN default at tip~5800+.

### F45 lag **530** — Path A 5290 increasingly stale

Lag now >500 for three consecutive waves (67–69). Soft JOIN only.

### Faucet duration variance

Kira faucet ~280s matches finn (~280s). Poll budget 100x5s still required.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `7f6b2496` | **kira** | **5833** | faucet-F101b |
| `775fc539` | joss | 5819 | faucet-F101b |
| `f1e786b4` | ivy | 5810 | faucet-F101b |
| `a9ae8fec` | hugo | 5800 | faucet-retry-F101b |

**JOIN scorecard:** forty-six proxy-proven wallets.

## Artifacts

- this markdown; `_wave69-results.json` gitignored

