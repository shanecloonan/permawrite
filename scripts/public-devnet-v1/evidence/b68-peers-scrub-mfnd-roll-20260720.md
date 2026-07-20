# B-68 — scrub ephemeral peers.json + mfnd roll (2026-07-20)

## Summary

After **CI `#29725270815` GREEN** (B-29/B-64 stack), lane 7 applied `vps-roll-mfnd.sh --apply --skip-build` on Hetzner (`PREBUILD_OK` on `938661a`, tree at `c36561d`). Tip advanced once (4281→4282) then **stalled**: vote fan-out dialed ~90 ephemeral source ports persisted in `peers.json` as durable peers (B-51 quarantine skip only applies when the addr is *not* in the durable set).

## Recovery

1. Scrubbed `v0/v1/v2/peers.json` to committee listens only (`127.0.0.1:1910x`, `5.161.201.73:1900x`); backups `peers.json.pre-b67-*.bak` on VPS (unit renumbered **B-68** on board — lane 4 owns B-67 slash settle).
2. Restarted `mfnd-v1`/`mfnd-v2` then `mfnd-hub` (faucet untouched).
3. Tip resumed: 4283→4284→4285+; `vote_fanout_abort=0`, `peer_quarantine=0` in the 5m window after scrub restart.

## Tooling landed

- `scripts/public-devnet-v1/scrub-vps-peers-json.sh` (`--plan-only` / `--apply`)
- Wired into `vps-roll-mfnd.sh` before voter/hub restart

## Follow-up (lane 4)

Filter ephemeral / `0.0.0.0` addresses on `peers.json` load so polluted durable sets cannot recur after Advertise.

## Verification

- CI gate for roll: `#29725270815` GREEN on `23204cb`
- Faucet idle throughout; `faucet-http` not restarted
- Services: mfnd-hub/v1/v2, faucet-http, observer-rpc-proxy, testnet-frontend active