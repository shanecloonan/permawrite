# Tor P2P transport (B8.0–B8.2)

Optional onion-routed P2P for **privacy at the network layer** (complements ring
privacy on-chain). Cleartext TCP remains the default; Tor is opt-in with no
consensus impact.

See [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md) § B8 for the phased plan.

---

## Outbound dials (B8.1 + B8.2)

Set on `mfnd serve`:

```bash
export MFND_P2P_TRANSPORT=tor
export MFND_TOR_SOCKS5=127.0.0.1:9050   # Tor daemon or arti SOCKS port
```

Boot peers may be cleartext `IP:PORT` (routed through SOCKS5) or v3 hidden
services:

```bash
mfnd … serve \
  --p2p-listen 127.0.0.1:8333 \
  --p2p-dial abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333
```

Harness lines:

- `mfnd_p2p_transport=tor tor_socks5=127.0.0.1:9050`
- `mfnd_p2p_listening=127.0.0.1:8333`

Cleartext TCP rejects `.onion` dials with a clear error; use `MFND_P2P_TRANSPORT=tor`.

---

## Inbound hidden service (B8.2)

**Recommended (VPS operators):** bind P2P loopback-only and forward with system Tor.

1. Run mfnd with a fixed local P2P port:

```bash
mfnd … serve --p2p-listen 127.0.0.1:8333
```

2. Configure Tor (`/etc/tor/torrc` or `torrc.d/`):

```tor
HiddenServiceDir /var/lib/tor/permawrite-p2p/
HiddenServicePort 8333 127.0.0.1:8333
```

3. After Tor creates the service, read the v3 hostname:

```bash
cat /var/lib/tor/permawrite-p2p/hostname
# abc…xyz.onion
```

4. Publish the dial string in `seed_nodes` / invite docs as `HOST.onion:8333`.

5. Optional harness advertisement for soak scripts:

```bash
export MFND_P2P_ONION=abc…xyz.onion:8333
```

`mfnd` prints `mfnd_p2p_onion=…` when set (validated `.onion` suffix).

Example torrc snippet: [`scripts/public-devnet-v1/tor-hidden-service-example.sh`](../scripts/public-devnet-v1/tor-hidden-service-example.sh).

**Future:** embedded `arti` listener (same env knobs; not required for testnet).

---

## Participant join over Tor

Observers dial onion seed nodes:

```bash
export MFND_P2P_TRANSPORT=tor
export MFND_TOR_SOCKS5=127.0.0.1:9050

mfnd --data-dir ./observer \
  --genesis mfn-node/testdata/public_devnet_v1.json \
  --rpc-listen 127.0.0.1:18734 \
  --p2p-listen 127.0.0.1:0 \
  --p2p-dial YOURSEED.onion:8333 \
  serve
```

Keep RPC on loopback; use SSH tunnel if remote wallet access is needed.

---

## Testnet invite

Onion boot peers are **optional** alongside cleartext `seed_nodes`. See
[`TESTNET_INVITE.md`](./TESTNET_INVITE.md).

Non-goals for testnet: mandatory Tor, consensus wire changes, or blocking cleartext P2P.
