# Live public testnet probe - wave 29 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~14:24Z-14:40Z (restart after first attempt F97 crash)
**Prior:** wave28 / tina last_proven=4452
**Tip close:** **4466** (matched)
**Mode:** faucet (pin@4400)

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match | **PASS** |
| Ports | **OPEN** |
| Tina proxy recheck | **PASS**; claims=9 at open |
| Uma faucet | **PASS** done ~3min; dual-send |
| Uma bal @4173 | **TIMEOUT 120s** (F97) |
| Uma bal @4262 | **TIMEOUT 120s** (F97) |
| Uma bal @4400 | **PASS** 1M/owned=2 (**F99**) |
| Uma upload bound | **PASS** `0916e1d6` |
| Uma last_proven | **PASS** **4466** |
| Proxy + claims | **PASS** claims=10 |

## Finding F99 - higher pin can succeed when lower pins timeout

After faucet `done`, balance at pin@4173 and @4262 each hit **120s timeout**. Pin@**4400** completed quickly with **1000000 / owned=2** (scan only ~63 blocks vs hundreds from 4173).

**JOIN implication:** pin-retry must include **near-tip / ckpt-max** heights, not only old bootstrap pins. Timeouts on low pins are not underfunding — try a higher pin before peer-fund / declaring failure. Extends F96/F97.

First wave29 attempt crashed the whole runner on an uncaught 240s timeout at pin@4173 (before faucet). Restart used catch+continue.

## Finding F97 reconfirmed

`wallet balance` timeouts remain intermittent under load after faucet. Soft-fail and continue pin ladder.

## Permanence board

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `0916e1d6` | uma | **4466** | wave29 |
| `bce3dd28` | tina | 4452 | wave28 |
| `518e69ba` | sam | 4430 | wave27 |

## JOIN scorecard

Thirteen new-wallet public permanence loops: … sam, tina, **uma**.

## Artifacts (local)

- `_wave29-results.json`, `_wave29-uma-upload.json`, `user-wallet/uma.json`
