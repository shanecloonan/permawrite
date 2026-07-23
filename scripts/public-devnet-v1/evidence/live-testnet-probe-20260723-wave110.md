# Live public testnet probe - wave 110 findings (2026-07-23) — UPLOAD ABORT (F115)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T20:18Z` → close ~20:38Z (~27 min after wipe#3 resync)
**Prior:** wave109 cyra F107 → wipe #3 → resync SYNC_OK
**Tip close:** tip_close_match=True at DONE (heights aligned late); during pre_upload local tip stayed **ahead** of proxy with **tip_id mismatch**
**Mode:** faucet-F101b; funded **True**; **permanence_public FAIL** (never uploaded)

## Executive verdict

| Gate | Result |
| --- | --- |
| Wipe#3 resync | **PASS** (SYNC_OK tip~679x) |
| Faucet / F101b | **PASS** (funded) |
| Pre-upload tip_id match | **FAIL** — ~40 attempts; local tip_height consistently 1+ ahead of proxy with different tip_id; mem=0 both sides |
| Upload | **ABORT** `no tip_id+mempool0 before upload` |
| Prove | n/a |
| F45 lag | **1498** (ckpt 5290) |
| Recovery | **wipe #4** (divergent tip quarantine) before wave111 |

## Findings

### F115 — Post-wipe tip_id diverge blocks upload (mem=0)

Distinct from F107 (sticky local mem=1 after Fresh upload):

1. Observer resynced to tip match after wipe#3
2. Faucet + F101b funded successfully
3. Before upload, local tip advanced on a **different tip_id** than proxy while heights were local=proxy+1
4. `wait_match` budget exhausted with mempool empty on both sides
5. Runner aborted: `no tip_id+mempool0 before upload`

Operator rule: tip_id mismatch with local tip ahead ⇒ treat like diverge — **quarantine wipe**, do not Fresh-upload on forked tip (F74/F88 family).

### Density day wipe count

| Wipe | Wave | Trigger |
| --- | --- | --- |
| #1 | 101 | F107 sticky mem=1 |
| #2 | 105 | F107 |
| #3 | 109 | F107 |
| #4 | 110 | **F115** tip_id diverge pre-upload |

### F45 lag **1498**

Path A still 5290.

**JOIN scorecard:** still seventy-nine (no increment).
