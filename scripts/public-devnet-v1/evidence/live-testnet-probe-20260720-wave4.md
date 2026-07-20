# Live public testnet probe - wave 4 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15 full JOIN)
**UTC start:** ~2026-07-20T02:36Z
**Claim base:** f94bed6 / board B-15 full JOIN
**Local observer:** tip_height=4031 at start (synced after B-41)

## Executive snapshot (partial - tests still running)

| Check | Result |
| --- | --- |
| Local tip | 4031; peers=1 sessions=0 |
| Proxy get_tip | Recovered to 200 (was 502 at session open); tip 4031 matches local tip_id |
| Proxy /health | ok=true but index_errors=3385 (elevated after repair churn) |
| P2P 19001 | FAIL |
| P2P 19002 / 19003 | OPEN |
| Faucet health | near tip (scan=tip=4031, behind=0) |
| Alice re-fund after cooldown | **202** job 0547352894fb4c988e2ae818 accepted |
| Bob concurrent fund | **503** faucet busy (expected) |
| light-scan alice | IN FLIGHT (pid started; progress TBD) |

## Finding F19 (PARTIAL SUCCESS)

After ~15 min address/IP cooldown from wave1, the same outside IP can fund again. Concurrent second address correctly gets busy 503 while job runs.

## Finding F20 (OPS)

Seed 19001 flapped FAIL while 19002/19003 stayed OPEN. Outside sync can still hold tip via remaining peers, but published three-seed diversity is degraded. Hub/socat forward for 19001 may need a re-check after B-41/B-45 rolls.

## Finding F21 (OPS)

Observer proxy /health reports ok=true with large index_errors after repair windows. Treat get_tip success (not /health alone) as RPC liveness.

## Addendum A - critical results (~02:37-02:43Z)

### F22. Faucet job ERROR (EAGAIN) - HIGH

Alice re-fund job `0547352894fb4c988e2ae818` failed after ~54s:

```text
status=error
error=/root/permawrite/target/release/mfn-cli exited 1: io: Resource temporarily unavailable (os error 11)
```

Bob job `71fcf2ec670e6d400b2cb6e2` also failed the same way after ~80s. API accepts 202 then VPS faucet CLI hits EAGAIN. Wave1 job succeeded; this is a regression under load/churn (B-45 roll / observer 502 window).

### F23. Chain tip STALL at 4031 - HIGH

Local tip and faucet health tip stayed at **4031** / tip_id `cdb54fa85473...` across 90s soak and 4x35s samples (~2+ min) with peers=1 sessions=0. At 30s slots this is **production stall**, not observer lag. Correlates with B-41/B-45 restarts and 19001 down.

### F24. Checkpoint log improved (B-22 progress)

```text
checkpoint_log_verify_ok entries=2
max_tip_height=4028
signer_ids=permawrite-maintainer-1,permawrite-maintainer-path-a-2
```

Near-tip (4028 vs live 4031). Useful for JOIN once light-scan consumes it.

### F25. light-scan rate / no mid-persist

mfnd log shows continuous `get_block_txs` ~535-715ms each. At tip 4031 that is roughly **35-45 minutes** for a genesis light-scan. Wallet file still `scan_height=null` after several minutes - **no mid-scan persist** (reinforces F17).

### F26. Proxy flapping

`get_tip` alternated 200 vs 502; `/health` index_errors elevated (3385+).

## B-15 impact

| Gate | Status |
| --- | --- |
| Sync outside-in | Was green; tip stall now blocks new blocks |
| Faucet HTTP | Accepts jobs; **completion can ERROR** (F22) |
| Receive verify | light-scan slow in progress; not PASS |
| Full JOIN archive | Still blocked |

## Recommended ops (lane 7)

1. Restore tip production (hub/voters after B-45; fix 19001)
2. Investigate faucet EAGAIN (fd/ulimit / CLI concurrency)
3. Keep publishing checkpoint log near tip (F24)

