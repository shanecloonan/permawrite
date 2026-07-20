# Live public testnet probe - wave 26 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~12:31Z-12:52Z
**Prior:** wave25 / quinn last_proven=4390 / tip-4400 Path A ckpt on main (`b1ce264`)
**Tip close:** **4412** (local tip_id matched proxy)
**Runner wall time:** ~21 min

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match open/close | **PASS** (F88b waits) |
| Seeds + 8787/8788/3000 | **OPEN** |
| FE `/` `/testnet` | **200**; `/join` **404** |
| Checkpoint-log verify | **PASS** entries=**13** max_tip=**4400** |
| F45 HARD @ tip ~4404 | **FAIL** - no attestation at tip (lag ~4 vs ckpt max) |
| F45 HARD after pin@4400 | **FAIL** - still demands live-tip attestation |
| F45 exact tip==ckpt_max | *not exercised* (proxy tip was 4404, not 4400) |
| `get_block_headers` proxy tip | **PASS** (F92/F94) |
| Quinn permanence recheck | **PASS** last_proven 4390; retrieve **64B**; proxy listed |
| `claims recent` | **6 -> 7** after rose |
| Rose faucet F7 dual-send | **PASS** ~114s; total 1_000_000 |
| Rose fund visibility | pin@4173 -> 0; pin@4262 -> 1M/owned=2 (retry required) |
| Rose upload `--message` | **PASS** bound `b3debb6a` |
| Rose last_proven | **PASS** **4412**; proxy listed; claims for PASS |

## Finding F45 update - tip-4400 checkpoint still insufficient at tip+N

Lane 7 landed Path A checkpoint max_tip=**4400** (valid_entries=13). Hard `light-scan --checkpoint-log` at live tip **4404** still fails:

```
checkpoints.jsonl has no attestation at tip_height 4404
```

Pinning wallet at 4400 does not change the error. Soft bootstrap remains JOIN-safe. Exact-tip PASS still unproven in the field (would need tip to equal ckpt max at scan time).

## Finding F96 - post-faucet pin-retry still mandatory (not only pin-too-high)

After faucet `done` (~114s), first pin@4173 showed **balance=0 / owned=0**; pin@4262 then showed **1000000 / owned=2**. This is the inverse height order of some earlier waves (where lower pins found more). Likely confirmation/tip-settle lag (F90) interacting with pin height. **JOIN scripts must retry multiple pin heights and not declare faucet failure on the first zero balance.**

Also observed: `wallet balance` after pin@4262 took a long time (tens of seconds to minutes) while tip advanced - serialize RPC (F85).

## Permanence board (wave26 close)

| Commitment | Wallet | last_proven | Proxy | Claims |
| --- | --- | --- | --- | --- |
| `b3debb6a` | rose | **4412** | yes | yes (bound) |
| `750e2d52` | quinn | 4390 | yes | yes |
| `9bcf2b56` | patricia | 4362 | yes | yes |
| `b0ce8cdb` | oscar | 4337 | yes | yes |

## JOIN scorecard

Ten new-wallet public permanence loops: heidi, ivan, judy, karl, mike, nina, oscar, patricia, quinn, **rose**.

## Ops notes

- Honored §6 (no faucet-http restart; no VPS JOIN).
- Faucet health at open: sync_needed=false; cooldown_ms=900000.
- F95 (429) not hit this wave - faucet accepted rose after prior cooldown.

## Artifacts (local only)

- `user-wallet/rose.json` + upload-artifacts
- `_wave26-results.json`, `_wave26-rose-upload.json`, `_wave26-quinn-retrieve.bin`
