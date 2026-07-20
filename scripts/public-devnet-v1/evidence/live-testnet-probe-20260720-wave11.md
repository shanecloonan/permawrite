# Live public testnet probe - wave 11 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** 2026-07-20T04:13Z
**Prior:** wave10 `2506594`
**Goal:** F67-aware receive — **pin then fund** using B-52 `.ps1` twin

## Snapshot

| Check | Result |
| --- | --- |
| Local tip | 4140; get_block height 1 OK |
| Checkpoint | entries=6 max_tip=4133 |
| Proxy /health | tip 4140; index_errors=**3** (was 4674) — B-52 effect? |
| Proxy get_tip | timed out once at open (flaky) |
| Seeds / faucet | OPEN / ok |
| Tooling | `bootstrap-wallet-from-checkpoint-log.ps1` present (B-52) |

## In flight

1. `-PlanOnly` smoke on ps1 twin
2. New `eve.json`: `-Apply` pin @4133 then faucet then balance
3. Tip soak + proxy method matrix post-B-52
4. Dave status; SPoRA pool/last_proven recheck
