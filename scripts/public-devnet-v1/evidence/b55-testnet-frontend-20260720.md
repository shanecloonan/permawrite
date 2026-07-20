# B-55 — public testnet frontend on Hetzner :3000 (2026-07-20)

**Lane:** 7
**Claim base:** `8c97d4e`
**Closes:** wave1/wave10 finding — ports 80/443/3000 closed; docs claimed front-end on VPS

## Actions

1. `testnet-frontend.service` + `vps-start-testnet-frontend.sh`
2. Build Next.js app; bind `0.0.0.0:3000`
3. UFW allow `3000/tcp`
4. Upstream bridges: loopback observer proxy `:8787` + faucet `:8788` (no new public RPC)

## Privacy

- Browser wallet keys stay client-side; server only proxies public-safe RPC + faucet.
- Does not weaken ring/SPoRA; does not expose hub private RPC.

## Verify

```
curl -fsS http://5.161.201.73:3000/testnet | head
ufw status | grep 3000
systemctl is-active testnet-frontend
```

## Note

HTTPS/TLS (443) remains a follow-up (B-31 / B-26 lane). HTTP :3000 unblocks JOIN UX demos.