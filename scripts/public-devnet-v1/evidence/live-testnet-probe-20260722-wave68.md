# Live public testnet probe - wave 68 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~11:34Z–11:52Z (~18 min wall)
**Prior:** wave67 ivy last_proven=5810; F45 lag>500
**Tip close:** **5819** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** first try ~224s (no 429) |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5819** `775fc539` |
| Claims | **41 → 42** |
| F45 lag | **521** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Density without F95 when spaced ~20 min

Wave68 started immediately after wave67 docs push (~20 min after ivy faucet done) and did **not** hit 429. Suggests effective cooldown window can be shorter than wall-clock 15m when prior faucet finished mid-wave, OR cooldown is measured from job completion and our inter-wave gap cleared it. Still treat F95 as possible under tighter packing.

### F45 lag **521** continues climbing

Soft JOIN only. Path A republish still the operator fix.

### Session arc update (waves 59–68)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 59 | aria | FAIL | — | F109/F99 |
| 60 | blake | PASS | 5729 | F110 control (slow) |
| 61–65 | cleo→gwen | PASS | 5741–5784 | F110 streak |
| 66 | hugo | PASS | 5800 | F95+retry |
| 67 | ivy | PASS | 5810 | lag>500 |
| 68 | joss | PASS | 5819 | clean F110 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `775fc539` | **joss** | **5819** | faucet-F101b |
| `f1e786b4` | ivy | 5810 | faucet-F101b |
| `a9ae8fec` | hugo | 5800 | faucet-retry-F101b |

**JOIN scorecard:** forty-five proxy-proven wallets.

## Artifacts

- this markdown; `_wave68-results.json` gitignored

