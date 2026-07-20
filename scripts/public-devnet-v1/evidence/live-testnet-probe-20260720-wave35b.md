# Live public testnet probe - wave 35b findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~17:13Z-17:33Z (+ extended prove poll ~6 min)
**Prior:** wave35 fund FAIL; wave34 wipe+zoe PASS
**Mode:** faucet recovery — **upload Fresh but permanence_public FAIL (F104 recur)**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet amy (after cooldown) | **PASS** |
| Pin ladder | **PASS** owned≥2 @ **4482** |
| ckpt_max | **4532** (Path A tip-4532; lag at F45=11) |
| F45 hard | **TIMEOUT** rc=-1 |
| tip_id match before upload | **PASS** |
| Upload Fresh + bound | **PASS** `807b5a5a` |
| last_proven / proxy_has | **FAIL** stuck **local_only**; proxy_has=False |
| Local mempool after poll | **1** (proxy tip advancing; tip_id often local+1) |
| claims | stayed **14** |
| **permanence_public** | **FAIL** |

## Finding F104 recur post-wipe

Wave34 proved wipe restores permanence. Wave35b shows F104 can **return on the same fresh observer** within ~40 minutes: CLI Fresh + bound authorship, tip_id matched at upload, then prove never leaves `local_only` while local `mempool_len=1` and tip flaps ±1 with `session_count=0`.

**JOIN implication:** wipe is necessary but not sufficient. Treat any Fresh without proxy_has within ~5–10 min as failed permanence; do not invite on local matched alone. Consider another wipe if mempool residue + tip_id flap persist (wave35b).

## Finding F45 near-miss with tip-4532

ckpt_max=4532 but live tip already ahead (f45_lag=11 at scan). Exact-tip Path A windows remain short.

## Contrast with wave34

| Wave | Wipe age | permanence_public |
| --- | --- | --- |
| 34 zoe | minutes after wipe | **PASS** @4533 |
| 35b amy | ~40 min after wipe | **FAIL** F104 |

## JOIN scorecard

Still **seventeen** proxy-proven wallets (zoe latest). Amy **not** counted.

## Artifacts

- `_wave35b-results.json`, `_wave35b-amy-upload.json`, `user-wallet/amy.json`
