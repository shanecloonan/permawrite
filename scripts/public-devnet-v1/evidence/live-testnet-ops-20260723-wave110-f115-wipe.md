# Ops note — wave110 F115 tip_id diverge wipe #4 (2026-07-23)

**Trigger:** dax funded but pre-upload tip_id never matched; local tip ahead of proxy with mem=0; abort `no tip_id+mempool0 before upload`.

**Action:** quarantine `b15-fresh` → `live-testnet-data-divergent-wave110-<stamp>`; recreate; restart mfnd + seeds; wait tip_id match before wave111.

**Contrast:** F107 = sticky mem=1 after Fresh; F115 = diverge before upload (mem=0).
