# Live public testnet probe - wave 24 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~10:54Z-11:15Z
**Prior:** wave23 / oscar last_proven=4337 / ckpt max=4323
**Tip close:** **4364** (local tip_id matched proxy)
**Runner wall time:** ~20.5 min

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match open/close | **PASS** (F88b waits; local often +1 ahead) |
| Seeds + 8787/8788/3000 | **OPEN** |
| FE `/` `/testnet` | **200**; `/join` **404** |
| Checkpoint-log verify | **PASS** entries=**12** max_tip=**4323** |
| F45 HARD (live tip ~4355) | **FAIL** - no attestation at exact tip |
| F45 HARD after pin@ckpt_max 4323 | **FAIL** - still demands tip attestation (not pin height) |
| `get_block_headers` `{from_height,to_height}` | **PASS** (F92 confirmed correct) |
| Oscar permanence recheck | **PASS** last_proven 4337; retrieve **64B**; proxy listed |
| `claims recent` | **4 -> 5** after patricia |
| Patricia faucet F7 dual-send | **PASS** ~99s; total 1_000_000 / 2 txs |
| Patricia fund visibility | pin@4323 -> 0; @4262 -> 500k/1; @4173 -> 1M/2 |
| Patricia upload `--message` | **PASS** bound `9bcf2b56` |
| Patricia last_proven | **PASS** **4362**; proxy listed; claims for PASS |
| Early operator challenge (tip lag) | **FAIL** unknown commitment (F93) |
| oscar->patricia peer 50k | **PASS** Fresh |
| Patricia post-recv balance @pin 4323 | **998997 / owned=2** (change + peer; F90 delay after upload) |

## Finding F45 - pin@ckpt_max does **not** satisfy hard checkpoint-log

Hard `wallet light-scan --checkpoint-log` fails when live tip is ahead of the log max, **even if the wallet is pinned at `max_tip_height`**:

```
checkpoints.jsonl has no attestation at tip_height 4355
```

Observed both before and after `pin @ 4323`. Hard path validates the **current tip**, not the wallet pin. Soft bootstrap / pin@ckpt remains JOIN-safe; hard path still needs exact-tip attestation or auto-bootstrap from log max (B-50).

## Finding F92 confirmed - headers object schema works

Proxy `get_block_headers` with JSON object `{from_height, to_height}` returned **result** (headers for 4352..4354). Prior wave23 wrong shapes (`start_height`/`count`, array) remain invalid. Invite/FE tooling must use the object form.

## Finding F93 - challenge before chain visibility fails

While patricia upload was still `local_only` and tip_id lagged (local 4361 vs proxy 4360), `operator challenge` returned:

```
rpc error -32602: unknown storage commitment 9bcf2b56...
```

After tip matched and status became `matched` with `last_proven_height=4362`, proxy listed the upload and `claims for` returned the bound claim. **JOIN implication:** do not challenge/prove until tip_id match and upload is visible on-chain (or wait for natural prove). Early challenge is a false negative, not a gate failure.

## Finding F90 / pin-retry - post-faucet and post-upload visibility

After faucet `done` (~99s, two tx_ids), successive pins:

| Pin height | Balance | owned_count |
| --- | --- | --- |
| 4323 (ckpt max) | 0 | 0 |
| 4262 | 500000 | 1 |
| 4173 | 1000000 | 2 |

Likely mix of (a) dual-send confirmation lag and (b) pin/trusted-summary interaction. JOIN scripts must **retry multiple pin heights** and wait tip_id match before declaring underfunded.

After upload, CLI reported `balance_after_upload=0` / `owned_count_after=0`. Later pin@4323 after oscar peer-send showed **998997 / owned=2** (~1M - fee change + 50k receive). Treat immediate post-upload zero as provisional (F90 extended to change outputs).

## Finding F88b reconfirmed

`peer_count=3` with `session_count=0` / `ipv4_session_count=0` throughout. tip_id match required explicit waits (often local tip = proxy tip + 1 for several polls).

## Permanence board (wave24 close)

| Commitment | Wallet | last_proven | Proxy | Claims |
| --- | --- | --- | --- | --- |
| `9bcf2b56` | patricia | **4362** | yes | yes (bound; message `wave24-patricia-authorship`) |
| `b0ce8cdb` | oscar | 4337 | yes | yes |
| `016d205f` | nina | 4318 | yes | yes |
| `61731fb9` | mike | 4304 | yes | yes |

## JOIN scorecard

Eight new-wallet public permanence loops: heidi, ivan, judy, karl, mike, nina, oscar, **patricia**.

## Ops notes (this wave)

- Did **not** restart `faucet-http` or run VPS JOIN (honored §6).
- Local observer RPC `127.0.0.1:18734`; genesis `454fa5d4…a005`.
- Faucet health at open: wallet tip 4354, sync_needed=false, busy=false.
- Challenge at i=6 was expected-fail under tip lag (documented as F93).

## Artifacts (local only - do not commit wallets)

- `user-wallet/patricia.json` + `patricia.upload-artifacts/`
- `_wave24-results.json`, `_wave24-patricia-upload.json`, `_wave24-oscar-to-patricia.json`
- `_wave24-oscar-retrieve.bin` (64B)
- `_wave24_run.py` (runner; optional to keep for replay)
