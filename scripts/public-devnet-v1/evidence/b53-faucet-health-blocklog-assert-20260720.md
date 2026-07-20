# B-53 — non-blocking faucet /health + VPS block-log assert (2026-07-20)

**Lane:** 7
**Claim base:** `b3c3eab` / `6416ebe`
**Closes:** faucet /health 5s TIMEOUT during keepalive; answers wave10 F62 ask for VPS

## Live findings (pre-fix)

| Check | Result |
| --- | --- |
| Hetzner hub/observer `chain.blocks` | **6.3 MiB** each — healthy (not F62) |
| Hub `get_block(tip)` | **PASS** |
| Hub/observer `get_light_snapshot(4133)` | **EAGAIN** under faucet keepalive CLI load |
| Faucet `/health` with `--max-time 5` | **TIMEOUT** while keepalive held wallet lock; OK at 60s |
| Proof pool | empty; uploads still show `last_proven_height=4071` (B-45 roll pending) |

F62 in wave10 was **laptop local observer** corruption, not Hetzner.

## Changes

1. `faucet-http.mjs`: `/health` never awaits wallet lock; serves cache; background refresh; exposes `wallet_lock_held`.
2. `assert-vps-block-log-health.sh`: tip + `get_block(tip)` (+ optional `chain.blocks` size) for F62 class detection.

## Deploy

- Restart `faucet-http` only when `busy=false` / `pending_jobs=0` (after pull).
- Do not roll mfnd (still gated on CI + B-51).