# B-56 — tip-first faucet keepalive (2026-07-20)

**Lane:** 7
**Claim base:** `2ce427e`
**Why:** Keepalive held the wallet lock every 45s for `wallet status`/`scan`, colliding with tall-tip `get_light_snapshot` (EAGAIN) during B-15 JOIN.

## Change

`faucet-http.mjs` `keepaliveTick`:
1. Poll chain tip **without** wallet lock.
2. If faucet wallet is within `SYNC_BEHIND` of tip, refresh cached status fields only.
3. Full `ensureWalletReady` under the lock only when catch-up is needed.

## Privacy / permanence

- No protocol change; reduces RPC contention so light-client bootstrap remains usable.
- Deploy: restart `faucet-http` only when `busy=false` / `pending_jobs=0`.

## Verify

```
journalctl -u faucet-http -n 20 --no-pager
# expect fewer "faucet wallet sync (keepalive" lines when tip-matched
curl -sS http://127.0.0.1:8788/health   # still fast; wallet_lock_held usually false
```