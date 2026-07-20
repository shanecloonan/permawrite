# Wave44 wipe open (2026-07-20)

After wave44 jade F104/F107 FAIL (sticky mempool=1, no proxy_has):

1. Stopped mfnd pid 3104
2. Quarantined `live-testnet-data` → `live-testnet-data-divergent-20260720-154342` (not committed)
3. Fresh mfnd dialing seeds 19001-19003 on new `live-testnet-data`
4. Waiting tip_id match + mempool=0 before wave45
