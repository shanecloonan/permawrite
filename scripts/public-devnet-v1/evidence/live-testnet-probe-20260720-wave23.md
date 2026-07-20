# Live public testnet probe - wave 23 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~09:55Z-10:21Z
**Prior:** wave22 / tip-4323 ckpt on main
**Tip close:** **4337** (local tip_id matched proxy)

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match open/close | **PASS** (F88b waits) |
| Seeds + 8787/8788/3000 | **OPEN** |
| FE `/` `/testnet` | **200**; `/join` **404** |
| Checkpoint-log verify | **PASS** entries=**12** max_tip=**4323** (near-tip!) |
| F45 HARD @ tip 4325 | **FAIL** - no attestation at exact tip (lag ~2) |
| Nina permanence recheck | **PASS** last_proven 4318; retrieve **64B**; proxy listed |
| `claims recent` | **3 -> 4** after oscar |
| `get_block_headers` start_height/count | **FAIL** needs from_height/to_height (F92) |
| nina->oscar peer send #1 | **PASS** Fresh 120000 |
| nina->oscar peer send #2 | **FAIL** RBF same-fee declined (F91) |
| Oscar after F90 re-scan | owned=1 (120k) then faucet -> **620000/owned=2** |
| Oscar faucet | **PASS** ~185s dual-send |
| Oscar upload `--message` | **PASS** bound `b0ce8cdb` |
| Oscar last_proven | **PASS** **4337**; proxy listed; claims for PASS |

## Finding F45 update - near-tip checkpoint landed (max 4323)

Checkpoint log now verifies with **max_tip_height=4323**, **valid_entries=12** (was 4262/11). Hard `light-scan --checkpoint-log` still fails when live tip is even **2** blocks ahead:

```
checkpoints.jsonl has no attestation at tip_height 4325
```

Soft bootstrap remains JOIN-safe. Hard path needs attestation at the **exact** tip or auto-bootstrap from log max (B-50 follow-up).

## Finding F91 - second peer-send hits replace-by-fee decline

After nina->oscar 120k Fresh (still in mempool / same fee class), second 120k send failed:

```
rpc error -32001: mempool admit: replace-by-fee declined: existing fee 10000 >= proposed fee 10000
```

**JOIN implication:** for peer dual-fund (F7 style), wait until first send leaves the mempool / confirms, or bump fee. Faucet dual-send already tip-waits between sends - peer-fund scripts must do the same.

## Finding F92 - get_block_headers param schema

Proxy rejects:
- `{start_height, count}` -> `missing params.from_height`
- `[from, count]` array -> `params must be a JSON object with from_height and to_height`

Correct shape is a JSON **object** with **`from_height`** and **`to_height`**. Document for invite tooling / FE.

## Finding F90 reconfirmed

Immediate oscar balance after first peer send was **0**; after tip settle + re-pin -> **120000/owned=1**. Do not treat first zero as underfunded.

## Permanence board

| Commitment | Wallet | last_proven | Proxy | Claims |
| --- | --- | --- | --- | --- |
| `b0ce8cdb` | oscar | **4337** | yes | yes (bound) |
| `016d205f` | nina | 4318 | yes | yes |
| `61731fb9` | mike | 4304 | yes | yes |

## JOIN scorecard

Seven new-wallet public permanence loops: heidi, ivan, judy, karl, mike, nina, **oscar**.

## Artifacts (local only)

- `user-wallet/oscar.json` + upload-artifacts
- `_wave23-results.json`, `_wave23-oscar-upload.json`, `_wave23-nina-to-oscar-*.json`
- `_wave23-nina-retrieve.bin`
