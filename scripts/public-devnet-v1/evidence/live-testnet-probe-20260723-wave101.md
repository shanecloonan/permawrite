# Live public testnet probe - wave 101 findings (2026-07-23) — permanence FAIL (F107)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T14:40Z` → close ~15:13Z (~33 min incl. F95 600s wait)
**Prior:** wave100 tessa last_proven=6621 (milestone)
**Tip close:** proxy~6638 local~6638 **tip_id MISMATCH** (`tip_close_match=False`)
**Mode:** faucet-retry-F101b; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **429** then retry (F95) → funded |
| F110 / F101b | **PASS** (owned=1→2) |
| Upload | Fresh `ad22ec72` @ tip 6633 |
| Prove | **FAIL** — sticky `local_only` + local `mempool_len=1` through full prove budget; never `proxy_has` |
| Claims | **71 → 71** (no new claim) |
| F45 lag | **1332** (ckpt 5290) |
| **permanence_public** | **FAIL** |
| Recovery | **F107 wipe** of `live-testnet-data/b15-fresh` before wave102 |

## Findings

### F107 returns after 20-wave post-wipe streak (81–100)

Post-wipe streak from wave80 quarantine broke on wave101. Pattern identical to waves 44/73/80:

1. Upload at tip_id match + proxy mem=0 → Fresh
2. Local status stuck `local_only` with `mem=1`
3. Proxy never sees commitment (`proxy_has=False`)
4. Local tip eventually advances on a forked tip_id while sticky mempool entry remains
5. Prove budget expires; `last_proven=None`

Operator rule confirmed again: sticky mem=1 through prove budget ⇒ **quarantine wipe + resync**, not restart-only (F108). Distinct from F113 (RPC hang; data-dir keep OK).

### F95 still gates density

Wave101 hit HTTP 429 immediately after wave100's faucet-retry path; 600s cooldown then job succeeded (47 poll ticks). Dense loops remain paced by faucet IP cooldown.

### F45 lag **1332**

Path A still frozen at 5290; lag climbed from wave100's 1318 → 1332. Soft JOIN remains mandatory.

## Permanence board note

| Commitment | Wallet | Result | last_proven |
| --- | --- | --- | --- |
| `ad22ec72` | **uma** | **FAIL F107** | None |
| d12dff55… | tessa | PASS wave100 | 6621 |

**JOIN scorecard:** still seventy-four (no increment).

## Artifacts

- this markdown
- ops note `live-testnet-ops-20260723-wave101-f107-wipe.md`
- gitignored `_wave101-results.json` / runner
- wipe quarantine `live-testnet-data-divergent-wave101-*` (local only; not committed)
