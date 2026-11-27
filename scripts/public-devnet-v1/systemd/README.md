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

## Automatic deploy of `main`

A systemd timer on the VPS builds `origin/main` and rolls the running
services when the new commit is safe to run on the live chain. The agent
that added the scripts does not install them. On the VPS, as root, from
the checkout at `/root/permawrite`:

```bash
bash /root/permawrite/scripts/public-devnet-v1/vps-install-auto-deploy.sh --apply
```

That copies `pfpchain-auto-deploy.service` and `.timer` into
`/etc/systemd/system`, enables the timer, and does not start a deploy.
The timer uses `OnCalendar=*-*-* *:00/15:00` (every 15 minutes) with
`Persistent=false`, so enabling it does not restart the chain. The first
run is the next quarter-hour. To deploy once immediately:

```bash
systemctl start pfpchain-auto-deploy.service
journalctl -u pfpchain-auto-deploy.service -f
```

`vps-auto-deploy.sh --apply` then:

1. Takes `flock` on `/var/lib/pfpchain-deploy/deploy.lock`. A second run
   exits 0 while the first is still building.
2. Refuses a dirty worktree (tracked or untracked files) and records
   `refused-dirty`. Ignored chain data under `.permawrite-devnet-v1/` is
   left alone. The script never deletes chain data.
3. `git fetch origin main`. If that SHA is already deployed, it records
   `unchanged`.
4. Classifies the commits since the deployed SHA.
   - Docs, the board, and checkpoint jsonl fast-forward `HEAD` and do not
     rebuild or restart (`skipped-no-runtime-change`).
   - `mfn-consensus/`, `mfn-crypto/`, `mfn-bls/`, and the Path A / F-A
     genesis or manifest JSON (`public_devnet_v1.json`,
     `public_devnet_fa.json`, and both manifests) are
     `skipped-consensus` unless `/var/lib/pfpchain-deploy/allow-consensus`
     contains that exact 40-character `origin/main` SHA. The file is
     removed when the deploy starts, so the next consensus commit needs a
     new marker. Allowing one restarts the chain onto that commit. A
     different `genesis_id` will not load the existing data directory;
     the script still does not delete it.
   - `mfnd` and the validator unit scripts roll voters, then hub, then
     observer, then the proxy, then the faucet.
   - `mfn-cli` / faucet changes restart `faucet-http` only.
   - Proxy script changes restart `observer-rpc-proxy` only.
5. Before `cargo`, requires `MemAvailable + SwapFree` of at least 1536 MiB
   (override with `MFN_DEPLOY_MIN_FREE_MIB`). A tight 4 GB box records
   `skipped-low-memory` and tries again next interval.
6. Builds `mfnd` and `mfn-cli` in `/var/lib/pfpchain-deploy/staging/target`
   with `CARGO_BUILD_JOBS=2`. The live binaries in `target/release` stay
   in place until the build and tests finish.
7. Runs `cargo test -p <crate> --lib --release` for each touched crate
   (the fast subset; integration tests are not part of the deploy).
   `MFN_DEPLOY_SKIP_TESTS=1` skips that subset and should stay off.
8. Atomically replaces `target/release/mfnd` and `mfn-cli`, keeping the
   previous bytes in `/var/lib/pfpchain-deploy/previous/`.
9. Rolls with the existing scripts, in order: `vps-roll-mfnd.sh --apply
   --skip-pull --skip-build` (voters, then hub), `systemctl restart
   mfnd-observer`, `vps-update-observer-rpc-proxy.sh --apply`, then
   `systemctl restart faucet-http`. Public `mfn-p2p-forward-*` units are
   started if they are installed. The hub tip must advance within 900
   seconds (`MFN_DEPLOY_TIP_WAIT_SEC`).
10. If the roll or the tip check fails, the previous binaries are put
    back, `git reset --hard` returns tracked sources to the pre-deploy
    commit (gitignored chain data is not touched), and the services
    restart. `status.json` result is `rolled-back`. That SHA is not
    tried again until `origin/main` moves, or
    `/var/lib/pfpchain-deploy/retry-failed` contains the same SHA.

Status is `/var/lib/pfpchain-deploy/status.json` (`last_deployed_sha`,
`last_attempt_sha`, `time`, `result`, `detail`). stdout is in the journal
under `pfpchain-auto-deploy.service`, and the script also logs to syslog
with tag `pfpchain-deploy`.

`vps-update-faucet.sh` is not used: it pulls and rebuilds on its own.
The faucet unit is restarted after the staged `mfn-cli` is already in
`target/release`.

Faucet `/health` must be idle (`busy` false and `pending_jobs` 0) before
a roll that restarts `faucet-http`. A busy faucet records
`skipped-faucet-busy`.
