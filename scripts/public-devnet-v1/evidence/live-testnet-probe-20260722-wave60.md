# Live public testnet probe - wave 60 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~08:07Z–08:50Z (~43 min wall; ~2560s runner)
**Prior:** wave59 aria FUND FAIL (F109/F99); tip~5700 ckpt=5290
**Tip close:** **5729** (tip_id matched; mempool=0)
**Mode:** tall-tip harden → faucet-F101b → upload → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer tip match (open) | **PASS** @5708; mem=0; peer_count=3; session_count=0 (F88b) |
| Public ports 19001–19003 / 8787 / 8788 / 3000 | **OPEN** |
| Faucet /health | ok; busy=false; wallet tip=5708 |
| Path A ckpt_max | **5290** (valid_entries=48) |
| F45 hard `--checkpoint-log` | **TIMEOUT 60s**; lag **418** |
| Faucet POST + poll (100×5s budget) | **done** in 181465ms (~181s) — closes F109 for this tip |
| Initial pin@5290 + balance | **TIMEOUT 400s** (empty wallet; waste) |
| Post-faucet pin@5688 | owned=0 (too near tip; UTXOs not yet in window) |
| Post-faucet pin@5628 | owned=1 / balance=500000 (F101 first UTXO) |
| Post-faucet pin@5290/@5240 | **TIMEOUT 400s** ×2 (deep scan waste) |
| F101b re-pin round 0 @5688 | **PASS** owned=2 / balance=1e6 (pin_height=5688) |
| Upload Fresh + bound authorship | **PASS** tip=5727; commit `e40023df` |
| Prove + proxy list | **PASS** last_proven=**5729**; proxy_has=true; status=matched |
| Claims recent | **33 → 34** |
| **permanence_public** | **PASS** |

## Timeline (selected)

| t (approx) | Event |
| --- | --- |
| 08:07 | tip match @5708 after ±1 lag settle |
| 08:07 | F45 hard TIMEOUT; lag=418 |
| +wallet | blake created; pin@5290 bal TIMEOUT 400s |
| faucet | job `662c1c7e2cba…` accepted |
| ~+181s | faucet status=done; txs `c75bd5b3e763…`, `eee1f05da75c…` |
| post_faucet | tip match @5714 |
| pin ladder | 5688→0; 5628→owned=1; 5290/5240 TIMEOUT |
| F101b_0 | after tip catch-up @5726 → owned=2 |
| upload | Fresh @5727; mempool=1 briefly |
| prove poll | local last_proven=5729 before proxy_has; then both @5729 |
| close | tip_id match @**5729**; permanence_public=true |

## Findings

### F109 closed (this tip window)

Wave59 assumed faucet needed >250s at tip~5700. Wave60 faucet completed in **181465ms (~3 min)** with poll budget 100×5s. F109 remains a real risk under hub load, but the extended poll is sufficient when the faucet is healthy. Do not treat 250s as a hard fail at tall tip.

### F99 / F110 — deep Path A pins still timeout; near-tip ladder is mandatory

Even with balance timeout **400s**:
1. Empty-wallet pin@ckpt_max=5290 timed out before faucet (pure waste).
2. After faucet, pin@5290 and @5240 each timed out at 400s while pin@5628 already showed owned=1.

**JOIN fix (wave61):**
- Pin new wallets near live tip (tip−20), not ckpt_max, before faucet.
- First try_pins ladder = tip−20 / tip−80 / tip−150 / tip−250 only when lag≫0.
- If any pin returns owned=1, skip deeper pins and enter F101b wait+re-pin immediately.
- Soft JOIN remains mandatory while F45 lag ≫ 0.

### F101 / F101b reconfirmed at tip~5720

Classic sequence: faucet done → pin near tip owned=0 → mid pin owned=1 → wait tip + re-pin near tip owned=2. Fund mode labeled `faucet-F101b`. Third consecutive F101b success after yuki/zion (aria failed before fund).

### F45 still open — lag 418

Path A frozen at **5290** while tip **5729** → lag **418**. Hard light-scan `--checkpoint-log` TIMEOUT 60s. Soft bootstrap / near-tip pin remains the only JOIN-safe path. Lane 7 Path A republish would close operator pain; protocol tests continue regardless.

### F88b / F100 / F105 still hold

- `session_count=0` with `peer_count=3` at open.
- Tip_id ±1 lag common (local ahead of proxy).
- Prove poll: `last_proven=5729` appeared while `proxy_has=false` and tip_id mismatch; full gate waited for tip match + proxy list (correct).
- Upload gate: tip_id match **and** mempool_len=0 before Fresh upload.

### Tall-tip cost model (operator expectation)

| Phase | Wall time this wave |
| --- | --- |
| Faucet dual-send | ~3.0 min |
| Wasted deep bal TIMEOUTs | ~20 min (3×400s) |
| F101b + tip match | ~2–4 min |
| Upload + prove + proxy | ~4 min |
| **Total** | **~43 min** (should be ~15–20 with wave61 pin harden) |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `e40023df` | **blake** | **5729** | faucet-F101b |
| (zion) | zion | 4823 | faucet-F101b |
| (yuki) | yuki | 4808 | faucet-F101b |

**JOIN scorecard:** thirty-seven proxy-proven wallets (blake adds one after wave59 fail).

## Artifacts

- `_wave60-results.json`
- `_wave60-blake-upload.json`
- `_wave60_run.py` (hardened runner; do not commit wallets)
- `user-wallet/blake.json` (local only)

## Follow-up

- Wave61 (cleo): near-tip-only pin ladder; skip empty deep bal; early F101b on owned=1.
- Continue permanence density; honor §6 (no faucet restart / no parallel Hetzner JOIN).
- Path A republish (lane 7) when lag allows — F45 honesty.

