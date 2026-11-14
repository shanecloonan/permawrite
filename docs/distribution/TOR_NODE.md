# Tor-only node setup

`mfn-node-setup` writes a systemd unit, a Tor config, a container file, and a `podman run` line. The default is Tor-only.

What the default does:

- `mfnd` listens on `127.0.0.1` for RPC and for P2P. It does not bind `0.0.0.0`.
- `MFND_P2P_TRANSPORT=tor` and `MFND_TOR_SOCKS5=127.0.0.1:9050`.
- `MFND_SKIP_MANIFEST_SEEDS=1`, so a genesis manifest that lists clearnet boot nodes is not dialed.
- systemd `IPAddressDeny=any` and `IPAddressAllow=localhost`, so the `mfnd` process cannot open a clearnet socket even if a flag is wrong.
- Tor uses `SafeLogging 1` and a SOCKS policy that accepts only loopback.
- The container file has no `EXPOSE`. The run script has no `--publish`.

```bash
bash scripts/distribution/setup-node.sh --plan-only
bash scripts/distribution/setup-node.sh --write ./node-layout
bash scripts/distribution/setup-node.sh --onion abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8333 --write ./node-layout
```

`--allow-clearnet HOST:PORT` is a different mode. The unit says `CLEARNET OPT-IN` and does not apply the localhost address lock. It is never the default.

Copy the unit and the torrc onto the machine yourself. This repository does not start them and does not contact a host.

The layout does not change consensus. Path A and F-A are unchanged.
