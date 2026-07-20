# Live public testnet probe - wave 36 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** ~17:42Z wipe
**Prior:** wave35b F104 recur on post-wave34 observer (amy Fresh local_only; mempool=1)

## Second wipe (F104 ops)

1. Pre-wipe: local tip **4557** `f5398a0f…` vs proxy **4556** `6da7a3f6…`; match=False; local mempool=1; session_count=0.
2. Quarantined `live-testnet-data` → `live-testnet-data-divergent-20260720-124203` (not committed).
3. Fresh `mfnd` dialing seeds 19001–19003; catch-up in progress.
4. Wave36 gate: tip_id match before upload + last_proven + proxy `list_recent_uploads` (same as wave34).

## Intent

New wallet **ben** — faucet (busy=false at open) + pin ladder + gated permanence. Document F45 vs ckpt tip-4554.