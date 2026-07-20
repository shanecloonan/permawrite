# Live public testnet probe - wave 8 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~03:25Z-03:34Z
**Prior:** wave7 `21ab99c` / wave8 open `01b390a`
**Tip range:** 4074 -> **4090+** (healthy production)

## Executive verdict

| Gate | Result |
| --- | --- |
| Tip soak (60s+) | **PASS** - 4077->4078 during soak; peers=3 sess=1-2 on proxy |
| Permanence retrieve | **PASS** - local artifact -> 128B payload matches wave7 sample text |
| Alice -> bob transfer | **PASS** - tx `2d1a591c...` Fresh; bob **1_100_000** / owned=3; alice **888_995** / owned=1 |
| Carol faucet | **PASS** - job `0e1bf0a1...` done 123274 ms; 2 txs |
| Carol receive verify (B-50 pin + balance) | **PASS** - owned_count=2, balance=1_000_000, sync_needed=false |
| `light-scan --checkpoint-log` after B-50 pin | **FAIL exit 1** - no attestation at tip 4089 (log max **4057**) - F45 reproduced |
| Faucet address cooldown | **PASS** - re-fund carol -> **429** address cooldown, retry_after_ms~390729 |
| SPoRA challenge (alice upload) | **PASS** - next_height=4091 for commitment `a20fcb43...` |
| Public proxy `get_light_snapshot` / `get_block_headers` | **TIMEOUT** (>=15-30s) - not usable for outside-in bootstrap |
| Windows `bash` for B-50 script | **MISSING** on PATH - Python-equivalent used |

## Finding F51 (retrieve permanence SUCCESS)

```
uploads retrieve a20fcb43... -> evidence/_wave8-retrieve.bin
payload_bytes=128
retrieve=ok
tx_id=12d714056c3b8a69e99d8bb8b236fc22350e60c7ea74314069bcf4eef7a68957
```

Payload text matches wave7 sample (`permawrite B-15 wave7 permanence probe...`).

## Finding F52 (peer transfer SUCCESS)

Alice sent **100000** to bob at tip ~4076:

| Wallet | After settle | owned | Notes |
| --- | --- | --- | --- |
| alice | 888995 | 1 | 998995 - 100000 - 10000 fee |
| bob | 1100000 | 3 | prior 2 faucet UTXOs + 1 transfer |

tx_id=`2d1a591c4d22b1ecfa5a361c9f84376e7822b5815d8d25137386f7dc02e27503`, ring_size=16, outcome=Fresh.

## Finding F53 (Carol end-to-end faucet->receive)

1. New wallet `carol.json`
2. Faucet job `0e1bf0a1fb4f6a767efd903d` **done** (123s); txs `4fbe5e60...`, `78795c16...`
3. B-50 flow (Python stand-in - see F56): `get_light_snapshot(4057)` -> pin wallet -> `light-scan --checkpoint-log` **exit 1** (F45) -> `wallet balance` scanned **33** blocks -> **owned_count=2**

Confirms B-50 honesty docs: snapshot pin is the skip-ahead; checkpoint-log flag still fails until tip matches a published attestation.

## Finding F54 (proxy allowlist / timeouts)

| Method | Public proxy |
| --- | --- |
| get_tip / get_status / get_block_header / list_methods / get_mempool | OK |
| submit_tx junk | -32602 codec (allowlisted, validates) |
| get_network_info / get_checkpoint_log | **403** method not allowed |
| get_light_snapshot / get_block_headers | **TIMEOUT** (not practical outside-in) |

**JOIN implication:** light-wallet bootstrap **requires a synced local observer** (or hub TCP RPC). Browser/proxy-only participants cannot `get_light_snapshot`.

## Finding F55 (tip soak healthy; local observer thin mesh)

Proxy soak: tip advanced; peers=3. Local mfnd can show peer_count=1 session_count=0 while tip-matched - single-seed sync is enough for wallet ops.

## Finding F56 (Windows host: no bash for B-50 script)

`bash` not on PATH; Git bash not found in default Program Files paths. Lane-3 Windows evidence used a Python reimplementation of `bootstrap-wallet-from-checkpoint-log.sh --apply`. Ops note: document `Git\bin` PATH or ship a `.ps1` twin.

## Finding F57 (SPoRA challenge live)

`operator challenge` on wave7 commitment returned `next_height=4091`, chunk_index=0, replication=3. Challenge path alive on advancing tip.

## Finding F58 (faucet cooldown still enforced)

Immediate carol re-fund -> HTTP **429** address cooldown (~6.5 min remaining at sample). Confirms R-4 rate limit after successful fund.

## Checkpoint lag

`checkpoint_log_verify_ok entries=5 max_tip_height=4057` while live tip **4090** (delta~33). Cross-check will keep failing JOIN-documented `light-scan --checkpoint-log` until Path A republish (lane 7) or cross-check policy relaxes to <= tip.

## B-15 status after wave8

| Item | Status |
| --- | --- |
| Outside tip + seeds | PASS |
| Faucet multi-wallet | PASS (alice/bob/carol) |
| Receive verify x3 | PASS |
| Transfer | PASS |
| Permanence upload + retrieve | PASS |
| SPoRA challenge | PASS |
| Formal `join-testnet-rehearsal` SUMMARY archive | PENDING (Windows bash gap; F45 tip lag) |
| Front-end ports | still closed (prior waves) |

**Next:** when bash/WSL available or `.ps1` exists, archive JOIN smoke; ask lane 7 for checkpoint republish near tip 4090+.
