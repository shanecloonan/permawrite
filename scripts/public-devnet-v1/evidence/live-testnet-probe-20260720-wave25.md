# Live public testnet probe - wave 25 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~11:28Z-12:06Z
**Prior:** wave24 / patricia last_proven=4362
**Tip close:** **4390** (local tip_id matched proxy)
**Mode:** peer-fund fallback after faucet **HTTP 429**

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match open/close | **PASS** (F88b waits; stuck-ahead periods observed) |
| Seeds + 8787/8788/3000 | **OPEN** |
| FE `/` `/testnet` | **200**; `/join` **404** |
| Checkpoint-log verify | **PASS** max_tip=**4323** entries=12 |
| F45 HARD / pin@ckpt_max | **FAIL** (tip ~4375; same as wave24) |
| `get_block_headers` object | **PASS** (F92) |
| Patricia permanence recheck | **PASS** last_proven 4362; retrieve **64B**; proxy listed |
| Quinn faucet | **FAIL** HTTP **429** Too Many Requests (F95) |
| patricia->quinn peer dual-send | **PASS** 2x150000 with tip-wait (F91 avoided) |
| Quinn funded | **PASS** owned>=2 after pin-retry |
| Quinn upload `--message` | **PASS** bound `750e2d52` |
| Quinn last_proven | **PASS** **4390**; proxy listed; claims for PASS |
| `claims recent` | **5 -> 6** |
| wave25-open tip stuck-ahead | documented earlier (F88b / F94) |

## Finding F95 - faucet HTTP 429 rate limit

After patricia faucet (~99s at wave24) and a second wave25 attempt within the cooldown window, `POST /faucet` returned:

```
HTTP Error 429: Too Many Requests
```

Faucet health still reported `ok:true`, `busy:false`, `cooldown_ms:900000` (15 min). **JOIN implication:** scripts must handle 429 with backoff equal to `cooldown_ms`, and offer **peer-fund fallback** (this wave: patricia->quinn 2x150k with tip-wait between sends).

## Finding F91 reconfirmed (positive)

Two peer sends of 150000 with tip_id match + ~35s settle between them both returned **Fresh**. No RBF decline when tip-wait is honored.

## Finding F45 / F92 / F93 / F94 unchanged

- Hard checkpoint-log still fails at live tip even after pin@4323.
- Headers object schema still PASS.
- Did not re-exercise early challenge (F93); waited for natural prove.
- Headers should use proxy tip when local is ahead (F94; wave25-open).

## Permanence board (wave25 close)

| Commitment | Wallet | last_proven | Proxy | Claims |
| --- | --- | --- | --- | --- |
| `750e2d52` | quinn | **4390** | yes | yes (bound) |
| `9bcf2b56` | patricia | 4362 | yes | yes |
| `b0ce8cdb` | oscar | 4337 | yes | yes |
| `016d205f` | nina | 4318 | yes | yes |

## JOIN scorecard

Nine new-wallet public permanence loops: heidi, ivan, judy, karl, mike, nina, oscar, patricia, **quinn**.

## Artifacts (local only)

- `user-wallet/quinn.json` + upload-artifacts
- `_wave25-results.json`, `_wave25-quinn-upload.json`, `_wave25-patricia-to-quinn-150000.json`
- `_wave25-open-results.json`, `live-testnet-probe-20260720-wave25-open.md`
