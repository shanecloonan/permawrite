# Live public testnet ops note — wave97 resume (2026-07-23)

**Lane:** 3 (onboarding / B-15)
**Context:** overnight interrupt of prior wave97 attempt; resume at tip~6575

## What happened overnight

1. Wave96 **pax@6141** landed on main (`e88e4e00`).
2. Wave97 (quill) started ~22:37Z Jul 22, reached faucet→owned=1→F101b at tip~6151, then the agent session was interrupted — **no results JSON**, no permanence evidence.
3. Local observer kept running overnight and advanced to tip~**6571** (proxy ~6570–6575).
4. Path A checkpoint log still max tip **5290** → F45 lag jumped to **~1281** (was 838 at wave96).

## Errors on resume (2026-07-23 morning)

| ID | Observation | Impact |
| --- | --- | --- |
| **F45** | lag **~1281** (tip~6575 vs ckpt 5290) | Hard `--checkpoint-log` still JOIN-blocked; soft/near-tip only |
| **F113** | `get_light_snapshot` **TimeoutError** at tip−20 with rpc timeout 180s | Wave97 recreate aborted mid-pin |
| **F113b** | After hung snapshot, tip/RPC became unresponsive (~20s tip timeout) | Required **mfnd restart** (same data dir; not F107 wipe) |
| **F113c** | Tip stuck 6571 while seeds at 6573; many `sync_abort … rejected:stale` | Cleared by restart; tip catch-up OK |

## Recovery performed

1. Restart `mfnd` with existing `live-testnet-data/b15-fresh` + seed dials (no quarantine).
2. Wait tip_id match + mem=0 (proxy tip 6575).
3. Probe `get_light_snapshot` @ tip−20 → **PASS in 53.8s** (needs ≥180–300s budget at tall tip).
4. Harden `_wave97`–`_wave100` runners: rpc_tcp default **300s** + pin_clean **3× retry**.
5. Restart wave97 permanence probe (fresh quill wallet).

## Findings

### Overnight tip advance without Path A republish is a JOIN cliff

Leaving density idle overnight while the chain seals ~400+ blocks with Path A frozen at 5290 more than doubles F45 lag. Soft JOIN remains mandatory; lane 7 Path A republish urgency is higher than at wave93 (lag>800).

### F113 — tall-tip light snapshot needs long RPC budget

At tip~657x, `get_light_snapshot` can take ~50s healthy and can hang/timeout at 180s when the node is under sync pressure. Density runners must use ≥300s + retries. A hung snapshot can wedge the local RPC until mfnd restart.

### Interrupted mid-wave is not permanence evidence

Partial faucet/owned=1 state for quill from the overnight attempt is discarded; only proxy-proven permanence counts.

## Next

- Complete wave97+ with hardened runners.
- Document permanence results as they land.
- Continue urging Path A republish (lane 7).
