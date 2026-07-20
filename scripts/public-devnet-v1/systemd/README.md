# public-devnet-v1 systemd services (Hetzner VPS)

Keeps the hub validator, two committee voters, the observer, and the faucet
HTTP API running persistently across VPS reboots/crashes. Previously these
were started by hand (`vps-start-all.sh` in a background shell) and did not
come back after a VPS reboot — the faucet and RPC proxy stayed up (they were
already systemd units) but silently pointed at a dead `mfnd` backend, so the
web faucet and wallet balance checks failed with no obvious error on the
frontend side.

## Install (one-time, or after editing a unit file)

```bash
# on the VPS, as root
cp scripts/public-devnet-v1/vps-bind.env.example scripts/public-devnet-v1/vps-bind.env
# edit vps-bind.env if needed, then:
bash scripts/public-devnet-v1/systemd/install-vps-services.sh
systemctl start mfnd-hub
sleep 5
systemctl start mfnd-v1 mfnd-v2 mfnd-observer faucet-http
```

`mfnd-hub` is started first and given a few seconds head start; the voter/
observer units also `Requires=` + sleep past it so they don't race the hub's
P2P listener on a cold boot.

## Known issue: stale peer store causes hub RPC to stall

`mfnd`'s P2P layer persists a peer address book to `<data-dir>/peers.json`
and redials every entry on startup. Under `MFN_VPS_MODE` with public P2P
binds, that file can accumulate dozens of **ephemeral inbound source ports**
(not real listening addresses) across restarts. On the next boot, `mfnd`
tries to redial all of them; combined with an actively-voting committee this
was observed to stall the hub's RPC listener indefinitely (requests hung or
returned `os error 11`, chain height stopped advancing) after a few minutes.

Workaround shipped with this change:

- **P2P binds are loopback-only** (`127.0.0.1`, see unit files above) instead
  of `0.0.0.0`. This mesh is single-box; nothing needs to dial in from the
  public internet today, and it removes the self-dial/duplicate-session
  churn that appeared to trigger the stall.
- If `peers.json` in any `.permawrite-devnet-v1/<role>/` directory grows
  large (dozens+ of entries) and a node becomes unresponsive after a
  restart, stop the service and delete that file before restarting — it
  will be rebuilt from just the live `--p2p-dial` targets.

Re-enabling public P2P binds (`0.0.0.0`) for a real multi-operator testnet
launch needs a fix upstream in `mfn-net` peer persistence (only ever persist
a peer's *advertised listen address*, never the ephemeral source port of an
inbound connection) before it's safe to leave unattended — track under Lane
4/1 protocol hardening.

## Operational reset performed 2026-07-18

The devnet had run continuously since 2026-07-14 and reached height ~7635.
Node startup replay from disk at that height took ~3.5 minutes per role and,
combined with the peer-store issue above, made the hub unresponsive once the
committee started voting again. The chain was reset to a fresh genesis
(`rm -rf .permawrite-devnet-v1`) and the faucet wallet was restored from its
existing deterministic seed (`mfn-cli wallet restore ... --key-derivation
payout_stealth_v1`) so it kept the same payout address and resumed earning
block subsidy immediately. This is acceptable for a pre-audit experimental
testnet with no external validators yet onboarded (see `AGENTS.md` Lane 7).

Use **Wants=mfnd-hub.service** (not Requires=) so systemctl restart mfnd-hub does not tear down voters/observer (tip-4031 stall / B-46).
