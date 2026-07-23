# Live public testnet probe - wave 102 findings (2026-07-23) — permanence PASS (post-wipe)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T15:21Z` → close ~15:45Z (~23 min)
**Prior:** wave101 uma F107 FAIL → wipe + resync (~6 min to tip match)
**Tip close:** **6652** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer | Fresh `b15-fresh` after F107 quarantine; tip_id match before run |
| Faucet | **PASS** (no 429 this wave) |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6652** `ec2aff4a` (brief local_only→matched→proxy_has) |
| Claims | **71 → 72** |
| F45 lag | **1353** (ckpt 5290) |
| **permanence_public** | **PASS** |
| Post-wipe streak | **x1** (wave102) |

## Findings

### F107 wipe recovers density (F108 contrast)

Full data-dir quarantine + resync restored permanence on the next wave. Restart-without-wipe would not have cleared sticky mem=1 (F108). Healthy prove path showed short local_only with mem=1 then cleared to matched + proxy_has within ~2 min — not sticky through budget.

### Wave101→102 arc

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 100 | tessa | PASS | milestone; streak x20 |
| 101 | uma | FAIL F107 | wipe |
| 102 | vera | PASS | post-wipe first |

### F45 lag **1353**

Still climbing; Path A republish remains the JOIN UX unblock.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `ec2aff4a` | **vera** | **6652** | faucet-F101b |
| ad22ec72… | uma | FAIL | faucet-retry-F101b |
| d12dff55… | tessa | 6621 | faucet-retry-F101b |

**JOIN scorecard:** seventy-five proxy-proven wallets.

## Artifacts

- this markdown
- prior ops wipe note `live-testnet-ops-20260723-wave101-f107-wipe.md`
