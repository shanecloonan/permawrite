# Live public testnet probe - wave 81 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T16:36Z` → close ~16:56Z (~20 min)
**Prior:** wave80 zara PROVE FAIL (F107) → wipe+resync READY tip=5962
**Tip close:** **5972** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Post-F107 wipe+resync | **PASS** (~6.5 min tip 0→5962 match mem=0) |
| Faucet | **done** (no 429) |
| F110 / F101b | **PASS** owned=1→2 |
| Pre-upload tip_id + mem=0 | **PASS** (after brief lag catch-up) |
| Upload + prove | **PASS** last_proven=**5972** `851f4f0a` |
| Prove path | local_only mem=1 briefly → matched@5972; proxy_has True |
| Claims | **51 → 52** |
| F45 lag | **672** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F108 wipe+resync validated again

After wave80 sticky mem=1, quarantining `b15-fresh` and cold-syncing from seeds restored a healthy observer. Wave81 then completed a full fund→upload→public prove path. Confirms restart-without-wipe is insufficient (F108); full data-dir quarantine is the recovery.

### Prove recovered after short local_only window (not F107)

Unlike wave80 (full poll stuck), wave81 left `local_only` by prove-poll idx 13 (`proven 5972 st matched mem 0`) and reached `proxy_has True` by idx 22. Transient local mem=1 after Fresh upload is normal; sticky-through-full-budget is the F107 failure mode.

### F45 lag **672**

Path A still 5290; soft JOIN mandatory. Lag continues climbing with tip.

### Session arc (waves 79–81)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 79 | yukon | PASS @5947 | faucet-retry-F101b |
| 80 | zara | PROVE FAIL | F107 → wipe |
| 81 | aster | PASS @5972 | post-wipe recovery |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `851f4f0a` | **aster** | **5972** | faucet-F101b |
| `f27142c1` | yukon | 5947 | faucet-retry-F101b |
| `7134e91b` | wynn | 5932 | faucet-F101b |

**JOIN scorecard:** fifty-five proxy-proven wallets.

## Artifacts

- this markdown

