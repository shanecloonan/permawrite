# Ops note — wave105 F107 wipe (2026-07-23)

**Trigger:** yara Fresh `95a0d87a` sticky local_only+mem=1; permanence_public=False after only 3 post-wipe PASSes (102–104).

**Action:** quarantine `b15-fresh` → `live-testnet-data-divergent-wave105-<stamp>`; recreate; restart mfnd + seed dials; wait tip_id match + mem=0 before wave106.

**Finding:** F107 recurrence interval under density can be as short as ~3 waves (not only ~20).
