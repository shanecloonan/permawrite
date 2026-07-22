# Live testnet permanence density — session findings waves 80–96 (2026-07-22)

**Lane:** 3 (B-15 outside-in)
**Network:** public-devnet-v1 · seeds `5.161.201.73:19001–19003` · proxy `:8787/rpc` · faucet `:8788`
**Observer:** wiped once after wave80 (`live-testnet-data-divergent-20260722-112926`)

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 → wipe |
| 81–94 | aster…nash | **PASS** x14 | 5972–6113 | mostly faucet-F101b | F95 earlier 83/85/87 |
| 95 | orin | **PASS** | 6128 | faucet-retry-F101b | F95 returns |
| 96 | pax | **PASS** | 6141 | faucet-retry-F101b | F95 again; lag=838 |

**JOIN scorecard:** 54 → **70** proxy-proven (zara excluded).
**Tip / Path A:** tip~6141 · ckpt=**5290** · F45 lag=**838** · post-wipe streak **x16**.

## Detailed findings

### 1. F107/F108 — wipe still the only density breaker this arc

Wave80 sticky local_only+mem=1 forced quarantine wipe. Waves 81–96 then completed **16/16** permanence PASSes with only healthy transient local_only (~2 min). Operator rule unchanged: sticky mem=1 through prove budget ⇒ wipe, do not densify.

### 2. F95 pacing intensified at tip~61xx

HTTP 429 hit waves 83/85/87 earlier, then quiet 88–94, then **back-to-back on 95–96**. Expect ~15m IP cooldown under dense faucet use; keep 600s retry.

### 3. F45 lag critical (**838**)

Hard `--checkpoint-log` unusable every wave (`f45_hard_rc=-1`, ckpt_max=5290). Lag climbed **658 → 838**. Soft JOIN / near-tip pins mandatory. Lane 7 Path A republish is the JOIN UX unblock.

### 4. F110/F101b remains the standing tall-tip fund recipe

Near-tip pin ladder, owned=1 early exit, F101b to owned=2, upload only on tip_id match + mem=0. Zero bal TIMEOUTs post-wipe.

### Ops hygiene held

- No Hetzner parallel JOIN / no faucet-http restart (§6).
- No F112 `--message` corruption.
- Docs pushed to main `[skip ci]` after each wave.

## Next

wave97+ density; lane7 Path A republish urgently; human SUMMARY when invite window opens.
