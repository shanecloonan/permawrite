# B-47 — Faucet EAGAIN harden (2026-07-20)

## Root cause

/health called wallet status via mfn-cli **without** withWalletLock. JOIN / probe scripts poll /health during a fund job; concurrent CLI against hub RPC produced io: Resource temporarily unavailable (os error 11) and failed async faucet jobs (B-15 wave4/5, 3/3 fails).

Tip stall (B-46) amplified the window; the race remains after tip recovery.

## Fix (faucet-http.mjs)

1. /health serves lastWalletStatus while usy (no CLI spawn).
2. Idle /health takes withWalletLock before status (same queue as claim/keepalive).
3. 
unRetry for transient EAGAIN / Connection refused on status, scan, tip, send.

## Deploy / verify

- Restart aucet-http only when usy=false and pending_jobs=0 (does not drop in-flight B-15 jobs).
- Loopback fund probe after restart; tip must keep advancing.

## Lane notes

- Lane 3: resume B-15 full JOIN; faucet lock remains for parallel JOIN only.
- Lane 2: B-26 still after B-15 window (this is a targeted EAGAIN fix, not R-4 deploy).
## Related

- repair-vps-p2p-binds.sh now applies vps-soften-mfnd-requires.sh (quoted MFN_P2P_DIAL_EXTRA) so B-46 dial env survives remaps.
