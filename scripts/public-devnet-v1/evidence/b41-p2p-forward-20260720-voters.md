# B-41 fix-forward — all seeds 19001-19003 (2026-07-20)

After hub-only socat, voter forwards failed: Linux cannot bind `0.0.0.0:19002` while `mfnd` holds `127.0.0.1:19002`.

## Fix (live on 5.161.201.73)

Remap mfnd P2P to `127.0.0.1:19101-19104` and socat `0.0.0.0:1900x -> 1910x` (units `mfn-p2p-forward-hub`, `mfn-p2p-forward-19002/03/04`).

## Verify (post-replay)

- EXT 19001/19002/19003 OPEN
- Hub + voters + observer RPC UP; tip aligned (~4030)
- RPC remains loopback-only (privacy)
- Faucet not restarted (B-15 lock)

Tooling: `scripts/public-devnet-v1/repair-vps-p2p-binds.sh`
