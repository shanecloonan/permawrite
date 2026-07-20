# B-52 — proxy heavy RPC timeout + Windows bootstrap twin (2026-07-20)

**Lane:** 7 (testnet launch / observer proxy + JOIN UX)
**Claim base:** `90c9c5c`
**Closes findings:** F54 (proxy get_light_snapshot TIMEOUT), F56 (Windows no bash for B-50)

## Changes

1. observer-rpc-proxy.mjs: per-method timeout for heavy methods
   (get_light_snapshot, get_block_headers, get_light_follow, get_block)
   via PROXY_HEAVY_RPC_TIMEOUT_MS (default 180000). Default methods stay at 30s.
2. observer-rpc-proxy.service: sets PROXY_HEAVY_RPC_TIMEOUT_MS=180000.
3. bootstrap-wallet-from-checkpoint-log.ps1: Windows twin of the B-50 helper.
4. JOIN_TESTNET + rehearsal smoke needles updated.

## Privacy / permanence

- No new public methods; allowlist unchanged.
- Longer timeout only for already-public light-client reads.
- Wallet keys still must not go through the proxy.

## Deploy

- Restart only observer-rpc-proxy after git pull (never faucet-http / never mfnd roll here).
- mfnd binary roll remains gated on CI GREEN + B-51 (vps-roll-mfnd.sh --apply).