# Live public testnet probe - wave 100 findings (2026-07-23) — permanence PASS (milestone)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T14:12Z` → close ~14:39Z (~27 min; F95 path)
**Prior:** wave99 soren last_proven=6607
**Tip close:** **6621** (matched)
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6621** `d12dff55` |
| Claims | **70 → 71** |
| F45 lag | **1318** (ckpt 5290) |
| **permanence_public** | **PASS** |
| **Wave 100 milestone** | **REACHED** |

## Findings

### Wave 100 milestone on public-devnet-v1

One hundred outside-in permanence probe waves completed. Dominant success path remains faucet → F110 near-tip pins → F101b owned=2 → Fresh upload → public prove. Standing hazards: F107 sticky mem=1, F95 429, F45 Path A lag, F113 tall-tip snapshot timeout.

### F45 lag **1318**

Path A still 5290; lag more than doubled overnight (838→1286+) and continues climbing. Soft JOIN mandatory.

### Session arc (waves 97–100)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 97 | quill | PASS | 6586 | F113 resume |
| 98 | riven | PASS | 6599 | F110 |
| 99 | soren | PASS | 6607 | F110 |
| 100 | tessa | PASS | 6621 | F95; **milestone** |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `d12dff55` | **tessa** | **6621** | faucet-retry-F101b |
| (soren) | soren | 6607 | faucet-F101b |
| (riven) | riven | 6599 | faucet-F101b |

**JOIN scorecard:** seventy-four proxy-proven wallets.

## Artifacts

- this markdown
- session rollup `live-testnet-session-findings-20260723-waves97-100.md`
