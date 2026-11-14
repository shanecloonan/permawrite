# Peer exchange

After the handshake, a dialer with `MFND_P2P_GETADDR=1` sends tag `0x15`. The neighbor answers with tag `0x16`, up to 16 `host:port` values it has already registered. The dialer then `register_peer`s each of them, so the next dial does not depend on DNS or the manifest seed.

Asking stays off unless that variable is set. A peer that still rejects unknown tags would otherwise close the session. Answering is always on, so a node that does ask can learn addresses from any neighbor running this code.

The integration test has node A tell node B about a third listener. B connects to that listener and writes a byte.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
