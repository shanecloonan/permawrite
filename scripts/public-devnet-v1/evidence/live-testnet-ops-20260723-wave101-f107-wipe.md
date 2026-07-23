# Ops note — wave101 F107 wipe (2026-07-23)

**Trigger:** uma Fresh upload `ad22ec72` stuck `local_only` + local mem=1; tip_close_match=False; permanence_public=False.

**Action:**
1. Stop mfnd
2. Move `live-testnet-data/b15-fresh` → `live-testnet-data-divergent-wave101-<stamp>` (repo-root sibling quarantine)
3. Recreate empty `live-testnet-data/b15-fresh`
4. Restart mfnd with same genesis + seed dials (19001–19003), RPC `127.0.0.1:18734`
5. Wait tip_id match + mempool_len=0 before wave102

**Not done:** faucet restart; Hetzner JOIN; Path A republish (still lane-7).

**Post-wipe streak reset:** waves 81–100 = x20 PASS → wave101 FAIL → streak restarts at wave102.
