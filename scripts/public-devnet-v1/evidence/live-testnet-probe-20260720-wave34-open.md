# Live public testnet probe - wave 34 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** ~16:32Z wipe; battery after tip_id match @4525
**Prior:** wave33b F104 — yara Fresh stuck local_only on divergent observer

## Wipe / resync (F74 / F104 remediation)

1. Stopped divergent `mfnd` (tip 4522 local vs 4521 proxy; local mempool=1; tip_ids differed).
2. Quarantined `live-testnet-data` → `live-testnet-data-divergent-20260720-113211` (not committed).
3. Fresh `mfnd` dialing seeds 19001–19003; catch-up ~537→4525 in ~5 min.
4. tip_id **match** at height **4525**; peer_count=3, session_count=0 (F88b still present).

## Wave34 gate change

Permanence success now requires **all** of:

- tip_id match immediately before upload
- `last_proven_height` set
- tip_id match at prove
- proxy `list_recent_uploads` contains commitment

CLI Fresh alone is insufficient (F104).

## In progress

New wallet **zoe** — faucet + pin ladder + gated upload/prove.