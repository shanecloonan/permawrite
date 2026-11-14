# Tor-only node

The default self-hosted observer does not dial the clearnet and does not
listen on a public address.

`mfn-node-setup` writes:

| File | What it locks |
| --- | --- |
| `observer.env` | `MFND_P2P_TRANSPORT=tor` and `MFND_P2P_OVERLAY_ONLY=1` |
| `permawrite-observer.service` | RPC and P2P on `127.0.0.1`, `IPAddressDeny=any`, `IPAddressAllow=localhost` |
| `torrc` | SOCKS and the hidden service stay on loopback |
| `Containerfile` | no `EXPOSE` line |
| `run-container.sh` | `--network=none`, and it exits if asked for host networking |

`MFND_P2P_OVERLAY_ONLY=1` is the node's own switch: a clearnet dial is refused
before a socket is opened. The systemd address rule is a second lock, so a
bug in the binary still cannot open a public connection.

Peers must be v3 onion addresses. `203.0.113.5:8333` is rejected. `0.0.0.0`
is rejected.

```bash
scripts/setup-node.sh --plan-only
mfn-node-setup --out ./observer --peer YOUR56CHARACTERONIONNAMEHERE________________.onion:8333
```

This does not change consensus, Path A, or F-A. It does not start a node.
