# Ops note — wave115 resume after interrupt (2026-07-28)

**Lane:** 3 (B-15 permanence density)

## Prior state

- Wave114 **hugo** PASS last_proven=6848 on main (`c1f3a26b` / board `f748b2cf`)
- Wave115 **iris** started 2026-07-23 ~22:22Z then **session aborted** mid-run (no `_wave115-results.json`)
- Abort logs: faucet progressed; near-tip pins hit **bal TIMEOUT 400s**; tip had advanced ~7022

## Resume day (2026-07-28)

| Check | Result |
| --- | --- |
| Public tip | **~10465** (proxy); faucet health ok, busy=false |
| Path A ckpt | still **5290** → F45 lag **~5175** (soft JOIN mandatory) |
| Local observer | tip_id **diverged** (local ahead of proxy, mem=0) — F115-class |
| Action | quarantine `b15-fresh` → `live-testnet-data-divergent-wave115resume-*`; recreate; restart mfnd + seed dials |
| Next | wait tip_id match + mem=0; re-run wave115 (fresh iris wallet ok) |

**§6:** no faucet-http restart; no parallel Hetzner JOIN.

## Findings to carry

1. Multi-day idle leaves Path A lag in the **5000+** range — hard checkpoint-log JOIN is not viable.
2. Stale local observer after interrupt can fork tip_id without sticky mem=1 (F115) — wipe before densifying.
3. Tall-tip light-scan/bal after deep lag may need longer timeouts (F99/F110/F113 family).
