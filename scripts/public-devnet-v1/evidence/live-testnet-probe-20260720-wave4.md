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

## In flight

- Faucet job 0547352894fb4c988e2ae818 poll to done
- wallet light-scan on alice against local RPC 127.0.0.1:18734
- tip soak samples
- receive balance / owned_count verify

