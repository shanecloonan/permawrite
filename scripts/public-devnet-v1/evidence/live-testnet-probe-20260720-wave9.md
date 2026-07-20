# Live public testnet probe - wave 9 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~03:39Z-03:40Z
**Prior:** wave8 `387b6ae`
**Tip:** 4090 -> **4095** during soak

## Executive verdict

| Gate | Result |
| --- | --- |
| SPoRA `operator prove` (wave7 upload) | **PASS** - outcome Fresh; pool_len=1 |
| Proof pool | **PASS** - commit `a20fcb43...` present |
| Alice balance after transfer | **PASS** - 888995 / owned=1 / tip-synced |
| Tip soak | **PASS** - 4094->4095 |
| Seeds | all OPEN |
| Faucet | ok; tip-synced; busy=false |
| UTXO set (proxy list_utxos) | total **4255** |

## Finding F59 (SPoRA prove SUCCESS on live chain)

Outside-in operator prove against local synced observer for commitment from wave7 upload:

| Field | Value |
| --- | --- |
| commitment_hash | a20fcb43a5aec973e5621aa0db5b303380a41a4a4b0d76cd4700412117e2bee9 |
| outcome | Fresh |
| next_height / next_slot | 4091 |
| payload_source | wallet_artifact |
| payload_bytes | 128 |
| pool_len after prove | 1 |

`operator pool` returned the same commit hash. Permanence challenge/prove path is live (contrast empty pool during tip-stall waves).

## Finding F60 (chain activity)

Proxy tip advancing; faucet wallet tip=4094; utxo total 4255 (was ~4174 at tip 4031 / ~4181 at 4036). Growth consistent with faucet dual-sends + transfers + uploads.

## B-15 status

Permanence loop now exercised end-to-end outside-in: **fund -> receive -> upload -> retrieve -> challenge -> prove -> pool**. Remaining: formal JOIN rehearsal archive + near-tip checkpoint so documented `light-scan --checkpoint-log` exits 0.
