# `mfn-net`

Blocking TCP P2P: length-prefixed frames, versioned handshakes, and post-goodbye gossip.

- **`frame`** — `HelloV1`, ping/pong, `ChainTipV1`, `GoodbyeV1`, **`TxV1`** / **`BlockV1`** / **`GossipEndV1`** (**M2.3.16**).
- **`handshake`** — symmetric hello + dial helpers.
- **`gossip`** — `recv_gossip_v1` / `send_tx_v1` with a pluggable `GossipHandler`.
- **`serve`** — `mfnd serve` accept/dial threads and stdout harness lines (`mfnd_p2p_*`).

Admission and chain apply live in `mfn-node::p2p_gossip`.
