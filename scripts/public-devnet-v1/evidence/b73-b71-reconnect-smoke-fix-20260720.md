# B-73 — B-71 reconnect smoke fix (2026-07-20)

## Symptom

CI `#29734331038` (`f81d654`) **test (ubuntu-latest)** FAILED:

`mfnd_p2p_reconnects_saved_peers_on_restart` -> `read peers.json: NotFound`

## Root cause

B-71 `is_persistable_peer_addr` correctly rejects ports >=32768. The smoke test bound peer A with `--p2p-listen 127.0.0.1:0` (OS ephemeral), so successful dials registered as ephemeral and never wrote `peers.json`.

## Fix

- `reserve_loopback_addr` picks a free port in `19000..MIN_EPHEMERAL_PEER_PORT`
- Reconnect smoke binds peer A on that persistable addr
- Export `mfn_store::MIN_EPHEMERAL_PEER_PORT`

## Proof

Local: `cargo test -p mfn-node --test mfnd_smoke mfnd_p2p_reconnects_saved_peers_on_restart --release` PASS.

## Ops next

After CI GREEN on this head: `assert-vps-roll-ready` -> `vps-roll-mfnd --apply --skip-build` (VPS already has B-71 binary). Do not thrash faucet during B-15.