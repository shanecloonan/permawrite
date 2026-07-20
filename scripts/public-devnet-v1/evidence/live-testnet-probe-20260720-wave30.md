# Live public testnet probe - wave 30 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~14:50Z-15:06Z
**Prior:** wave29 / uma last_proven=4466
**Tip close:** **4479** (matched)
**Mode:** faucet (pin@4443)

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match (open/close) | **PASS** (open after ~12 tip polls; close matched) |
| Ports 19001-03 / 8787 / 8788 / 3000 | **OPEN** |
| FE `/` `/testnet` | **200** |
| FE `/join` | **404** (unchanged) |
| Uma retrieve (wave29 commitment) | **PASS** rc=0, 64 bytes |
| Uma bal @ckpt_max=4443 | **PASS** ~999k / owned=2 |
| F45 hard `--checkpoint-log` | **FAIL** rc=1; lag=29 (ckpt_max=4443 vs tip~4473) |
| Headers object form vs proxy tip | **PASS** |
| Proxy uploads / has uma | **22** / True |
| Claims recent open → close | **10 → 11** |
| Vera faucet F7 dual-send | **PASS** done ~130s |
| Vera pin@4443 | **PASS** 1M / owned=2 (first ladder height) |
| Vera upload bound | **PASS** `b90c135c` |
| Vera last_proven | **PASS** **4479** status=matched |
| Proxy has vera + claims for | **PASS** |

## Permanence loop (new wallet vera)

1. Soft tip_id wait (local often +1 ahead of proxy — F88b) until match.
2. `wallet new` → pin@4443 → faucet `POST /faucet` → poll job → **done**.
3. Post-faucet tip wait exhausted without match (local 4476 vs proxy 4475) — continued anyway.
4. Pin ladder first height **4443** (ckpt_max) showed **1000000 / owned=2** — no F97 timeouts this wave.
5. Upload `--message wave30-vera-authorship` → authorship **bound**, outcome Fresh, commitment `b90c135c972fd4602345f12e6500508147cfcdde079f0790a7304341bab60f38`.
6. Prove lag ~3–4 min: status stayed `local_only` until tip~4479; `last_proven` appeared while tip_id still mismatched (local ahead), then matched.
7. Proxy `list_recent_uploads` includes vera; `claims for <data_root>` returns 1 claim at height 4479; recent claims **11**.

## Finding F45 reconfirmed (post B-79 tip-4443)

Hard light-scan still fails when live tip advances past Path A attestation:

```
checkpoints.jsonl has no attestation at tip_height 4473
```

ckpt_max=4443, f45_lag=29. Soft JOIN bootstrap remains correct default. Exact-tip Path A (wave28 PASS) is the only hard-path green mode.

## Finding F100 - last_proven can precede tip_id match

During prove poll, `uploads status` showed `last_proven_height=4479` / `matched` while local tip_id still disagreed with proxy (local 4479 vs proxy 4478). Operator challenge / JOIN automation should treat tip_id match as the settle gate for *public* visibility, but local prove completion is not blocked by F88b lag. Do not abort prove polling solely because tip_id mismatches by ±1.

## Finding F88b reconfirmed

`session_count=0` with `peer_count=3`; local tip frequently one height ahead of proxy during waits. Upload/prove still succeeded after waiting for match before upload.

## Finding F99 note (wave30 contrast)

Unlike wave29 (low pins TIMEOUT, @4400 PASS), wave30 funded on **first** pin@4443. Ladder still required — order near-tip/ckpt-max first remains best practice.

## P2P / surface

- p2p: peer_count=3, session_count=0 (F88b)
- faucet health ok at open; busy=false before job
- No Hetzner JOIN; no faucet-http restart (§6)

## Permanence board (newest first)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `b90c135c` | vera | **4479** | wave30 faucet pin@4443 |
| `0916e1d6` | uma | 4466 | wave29; retrieve reconfirmed |
| `bce3dd28` | tina | 4452 | wave28 |
| `518e69ba` | sam | 4430 | wave27 |

## JOIN scorecard

Fourteen new-wallet public permanence loops: … tina, uma, **vera**.

## Artifacts (local; not committed)

- `_wave30-results.json`, `_wave30-vera-upload.json`, `_wave30_run.py`
- `user-wallet/vera.json`, `live-testnet-data/`
