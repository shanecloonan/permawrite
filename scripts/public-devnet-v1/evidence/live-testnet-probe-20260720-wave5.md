# Live public testnet probe - wave 5 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC start:** 2026-07-20T02:45:09Z
**Prior:** wave4 `ed296d4` / board escalate `73e40d4`
**Local observer:** tip still **4031** at open (same tip_id as wave4 stall)

## Executive snapshot (opening)

| Check | Result |
| --- | --- |
| Local tip | **4031** `cdb54fa85473...` — **still stalled** since wave4 (~02:36Z+) |
| peers / sessions | peers=1 sessions=0 |
| Proxy get_tip | **502** Bad Gateway |
| Proxy /health | ok=true, tip frozen 4031, index_errors=**4129** (was 3385 in wave4) |
| Faucet /health | ok=true but wallet_* fields **null** (hub RPC degraded) |
| P2P 19001 | FAIL |
| P2P 19002 / 19003 | OPEN |
| Checkpoint log | entries=2 max_tip_height=**4028** (unchanged) |
| alice light-scan | process still alive; wallet `scan_height=null`; get_block_txs count slow |

**Finding F27 (CONFIRMED STALL):** Tip production has been stuck at height **4031** for **~15+ minutes** wall-clock (wave4 first stall sample through wave5 open). This is not a transient single-slot miss. Outside observers cannot see new blocks; faucet tip height also frozen when reported.

**Finding F28 (OBS):** Proxy `/health` `index_errors` keeps climbing (3385 -> 4129) while tip is frozen — indexer is retrying a dead observer backend. Reinforces: do not treat `/health ok` as chain liveness.

## Local RPC battery (against synced tip-4031 node)

All via TCP JSON-RPC to `127.0.0.1:18734` (local mfnd):

| Method | Result |
| --- | --- |
| get_chain_params | OK — emission/treasury params readable; tip in params path |
| list_recent_uploads | OK — still **2** uploads; last_proven_height **1915** / **1909** |
| get_proof_pool | OK — empty |
| list_fraud_contests | OK — 0 |
| get_mempool | OK — empty |
| get_status | OK — peers=1 sessions=0 |

**Finding F29 (SUCCESS / read path):** Even during production stall + public proxy 502, a synced local observer serves full public-safe reads. Permanence index is stale (proofs not advancing) consistent with F7.

## In flight (this wave)

- Tip soak 4x40s (~160s) to extend stall evidence
- Fresh wallet `probe-carol` faucet fund attempt + job poll
- Continue monitoring alice light-scan mid-persist behavior

## B-15 status

Full JOIN still blocked on: tip production, faucet job completion without EAGAIN, and practical light-scan/receive verify.
