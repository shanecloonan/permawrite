# Boot checklist

Before a node process starts, read the env file and the systemd unit. Start
the node only when this check passes.

The check requires:

- `MFND_P2P_TRANSPORT=tor`
- `MFND_P2P_OVERLAY_ONLY=1`
- Tor SOCKS on `127.0.0.1`, `localhost`, or `::1`
- `--rpc-listen` and `--p2p-listen` on loopback
- `IPAddressDeny=any` and `IPAddressAllow=localhost`
- every `--p2p-dial` is a v3 onion

It refuses `0.0.0.0`, a clearnet peer, and a TCP transport. It does not start
the node and it does not open a socket.

```bash
mfn-boot-check --env observer.env --unit permawrite-observer.service
```

This does not change consensus, Path A, or F-A.
