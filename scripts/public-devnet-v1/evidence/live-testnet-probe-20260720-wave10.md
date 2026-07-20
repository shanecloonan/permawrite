# Live public testnet probe - wave 10 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~04:03Z-04:10Z (+ observer resync)
**Prior:** wave9 `d3213a5` / wave10 open `a550ad4`
**Public tip:** 4131 -> **4137+**

## Executive verdict

| Gate | Result |
| --- | --- |
| Public tip / seeds / faucet | **PASS** - tip advancing; seeds OPEN; dave fund done 94577 ms |
| Tip soak (proxy) | **PASS** - 4134->4135; peers=3 sess=1-2 |
| Checkpoint log | **IMPROVED** - entries=6 max_tip_height=**4133** (was 4057) |
| Dave faucet | **PASS** - job `0f3d5762...` 2 txs; total 1_000_000 |
| Dave receive verify | **BLOCKED** - local observer store corrupt then resyncing |
| Alice/bob/carol wallets | **GONE** from `user-wallet/` (only dave.json left) |
| Local get_block / get_light_snapshot | **FAIL -32002** until resync completes |
| SPoRA challenge (RPC) | **PASS** - next_height=4136 for wave7 commitment |
| Proof pool | still holds `a20fcb43...` (pool_len=1); last_proven_height stuck **4071** |
| Front-end 80/443 | still FAIL |

## Finding F61 (local evidence wallets deleted)

At wave10 open, `scripts/public-devnet-v1/user-wallet/` contained only `dave.json`. `alice.json` / `bob.json` / `carol.json` missing (`io: The system cannot find the file specified`). Seeds not in repo (correct); **local continuity lost** for prior funded wallets. On-chain UTXOs remain but are unspendable without seed backup. Ops: treat probe wallets as ephemeral; copy seeds to an ignored backup path before long sessions.

## Finding F62 (CRITICAL - local observer tip/block-log split-brain)

Local `mfnd` reported `tip_height=4136` while `get_block` / `get_block_txs` / `get_light_snapshot` failed:

```
rpc error -32002: read_block_log_validated: block log has 46 record(s) but chain tip_height is 4136
```

`live-testnet-data/chain.blocks` had shrunk to **~79 KiB** (was ~6 MiB in wave7). P2P still applied tips (`mfnd_p2p_sync_end ... final_height=4136`) so **header/tip state raced ahead of durable block log**. Wallet light-scan and B-50 snapshot bootstrap impossible.

**Mitigation taken (laptop only, not Hetzner):** stopped pid 13696; renamed data dir to `live-testnet-data-corrupt-*`; restarted `mfnd` with `--p2p-dial` 19001-19003. Fresh sync progressing (~250 height / 10s early samples).

## Finding F63 (Path A checkpoint catch-up)

Repo checkpoint log now:

```
checkpoint_log_verify_ok entries=6
max_tip_height=4133
```

Delta tip-live vs log shrinks to ~4 when public tip ~4137. **F45 may clear** once local observer is healthy enough to pin snapshot@4133 and light-scan the small remainder. Lane 7 republish during this session is load-bearing for JOIN.

## Finding F64 (Dave fund SUCCESS; receive deferred)

| Field | Value |
| --- | --- |
| address | mf02968f25f981ef54d77480f5eb0ba0ada17e8a292b6f94513f1841b145d0da34498cca210f80b0d9d242753617c57f0be37ae8dbea897a2634620f500f273a44c41ba585 |
| job_id | 0f3d57629d28219e87134fd2 |
| duration_ms | 94577 |
| tx_ids | 292bc357..., a54ee79e... |

Receive verify pending observer resync (wave10 addendum).

## Finding F65 (SPoRA prove not advancing last_proven)

Wave7 upload still shows `last_proven_height=4071` at tip 4131+ while proof pool retains the commit. Challenge still returns advancing `next_height`. Either proofs are not being included in blocks (operator committee / salted path / B-45 roll pending) or index lags. Track for lane 4/7 — permanence **challenge** works; **on-chain prove settlement** looks stale.

## Finding F66 (proxy tip soak still healthy)

| Sample UTC | tip | tip_id prefix | peers | sess |
| --- | --- | --- | --- | --- |
| 04:06:13 | 4134 | 1db370e3b868 | 3 | 1 |
| 04:06:34 | 4135 | 5bda6cf13c52 | 3 | 2 |
| 04:06:54 | 4135 | 5bda6cf13c52 | 3 | 1 |
| 04:07:14 | 4135 | 5bda6cf13c52 | 3 | 2 |

## B-15 status

Public chain + faucet remain green. JOIN archive blocked this wave by **local observer corruption** (fixed via wipe+resync) and **lost probe wallets**. After resync: dave B-50 receive verify; optionally recreate alice/bob/carol.

**Ask lane 7:** confirm VPS observer block-log health (same -32002 class); keep checkpoint within ~10 of tip.
**Ask lane 4/7:** why `last_proven_height` stuck at 4071 with pool_len=1.

## Addendum A — observer resync + dave receive (04:12Z)

### F62 resolution (laptop)

Fresh `live-testnet-data` + dial 19001-19003: local tip caught public tip (**4139**), `get_block` OK. Corrupt dir preserved as `live-testnet-data-corrupt-*` (not committed).

### Dave receive verify

| Step | Result |
| --- | --- |
| get_light_snapshot(4133) | OK |
| light-scan --checkpoint-log | exit **1** — `mfn-node\testdata\public_devnet_v1.checkpoints.jsonl has no attestation at tip_height 4139` |
| wallet balance | see below |

```
tip_height=4139
blocks_scanned=6
utxo_cache=false
scan_height=4139
balance=500000
owned_count=1
wallet_path=scripts\public-devnet-v1\user-wallet\dave.json
```

```json
{
  "balance_cached": 500000,
  "blocks_behind": 1,
  "light_checkpoint_present": true,
  "owned_count_cached": 1,
  "pending_spent_count": 0,
  "scan_height": 4139,
  "sync_needed": true,
  "tip_height": 4140,
  "trusted_light_summary_present": true,
  "utxo_cache": true,
  "wallet_path": "scripts\\public-devnet-v1\\user-wallet\\dave.json",
  "wallet_version": 2
}
```

