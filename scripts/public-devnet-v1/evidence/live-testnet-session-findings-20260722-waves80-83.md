# Live testnet permanence density — session findings waves 80–83 (2026-07-22)

**Lane:** 3 (B-15 outside-in)
**Network:** public-devnet-v1 · seeds `5.161.201.73:19001–19003` · proxy `:8787/rpc` · faucet `:8788`
**Observer:** local `mfnd` `127.0.0.1:18734` data dir `live-testnet-data/b15-fresh`
**Commits on main (docs):** `96111f61` (w80 fail) · `9a118a77` (w81) · `2a2c00a2` (w82) · this commit (w83)

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes | Docs |
| --- | --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 sticky mem=1 / local_only; tip~5958 | `96111f61` |
| 81 | aster | **PASS** | 5972 | faucet-F101b | F108 wipe+resync ~6.5 min then PASS | `9a118a77` |
| 82 | brynn | **PASS** | 5982 | faucet-F101b | clean F110; transient local_only OK | `2a2c00a2` |
| 83 | coral | **PASS** | 5993 | faucet-F101b | F95 429+600s then F110 | this |

**JOIN scorecard delta:** 54 → **57** proxy-proven (zara excluded).
**Tip / Path A:** tip~5993 · ckpt_max=**5290** · F45 lag=**693**.

## Detailed findings

### F107 / F108 — sticky local_only is still a real JOIN hazard

Wave80 funded and uploaded Fresh (`227ce538…`) with a clean pre-upload tip_id+mem=0 gate, then spent the entire prove budget at `st local_only … mem 1` while the proxy tip advanced with mempool=0. Post-mortem: local tip 5959 mem=1 vs proxy 5958 mem=0 and divergent tip_ids.

**Recovery that worked:** stop density → quarantine `b15-fresh` → `live-testnet-data-divergent-20260722-112926` → restart mfnd with empty data dir + three seed dials → wait tip_id match + mem=0 (~6.5 min from tip 0→5962). Wave81 immediately recovered permanence.

**Operator rule:** Fresh upload + sticky mem=1 + no `last_proven` for ~3–5 min ⇒ wipe, do not keep densifying. Restart-without-wipe is insufficient (F108).

### Healthy prove vs F107

Waves 81–83 all showed a short `local_only`/`mem=1` window after Fresh upload, then `st matched` and `proxy_has` within ~2–4 minutes. That transient state is normal. F107 is only when it never clears through the full poll.

### F95 faucet cooldown

Wave83 hit HTTP 429 after consecutive fund successes (waves 81–82). The standing runner wait (600s)+retry recovered without peer-fund. Density pacing should assume occasional 15-minute gaps.

### F45 hard checkpoint-log still broken for JOIN

Every wave this session: `f45_hard_rc=-1`, ckpt_max=5290, lag climbed 658→693. Soft / near-tip pin ladder + F101b remain mandatory. Path A republish (lane 7) is the unblock.

### F110 / F101b remain the dominant fund path

All three PASSes used near-tip pin ladder, early exit on owned=1, then F101b re-pin to owned=2. Deep Path A pins were skipped.

### What we did *not* break

- No Hetzner parallel JOIN / no faucet-http restart (honored §6).
- No F112 `--message` corruption (runners cloned via explicit token map from `_wave74_run.py`).
- Wallets / `live-testnet-data*` / other-lane dirty files not committed.

## Recommended next steps

1. Continue wave84+ density while observer stays tip_id-matched.
2. On next F107: wipe immediately; do not burn prove budget.
3. Lane 7: Path A republish near tip to collapse F45 lag.
4. Human SUMMARY sign-off when invite window opens; do not fake TL completion.

