# `mfn-net`

Blocking TCP P2P: length-prefixed frames, versioned handshakes, and post-goodbye gossip.

- **`frame`** — `HelloV1`, ping/pong, `ChainTipV1`, `GoodbyeV1`, **`TxV1`** / **`BlockV1`** / **`GossipEndV1`** (**M2.3.16**).
- **`block_sync`** — **`GetBlocksByHeightV1`** / **`BlocksV1`** request/response (**M2.3.18**) and **`pull_blocks_to_tip`** catch-up when the remote tip is ahead (**M2.3.19**). Catch-up now enforces exact next-height advancement for every applied response block, caps request and response block counts, and **`recv_blocks_v1`** skips interleaved proposal/vote/gossip frames while waiting for a **`BlocksV1`** reply (live **`--produce`** sessions).
- **`light_follow`** — **`GetLightFollowV1`** / **`LightFollowV1`** request/response for light-wallet header + validator-evolution batches, with capped response row counts on encode/decode.
- **`handshake`** — symmetric hello + dial helpers.
- **`gossip`** — `recv_gossip_v1` / `send_tx_v1` with a pluggable `GossipHandler`; [`FanoutPeerSet`] + [`push_tx_gossip_to_peer`] for outbound mempool fan-out (**M2.3.20**) plus local peer success/failure scoring hooks.
- **`serve`** — `mfnd serve` accept/dial threads and stdout harness lines (`mfnd_p2p_*`).

Admission and chain apply live in `mfn-node::p2p_gossip`. Block-log queries live in `mfn-node::p2p_block_sync`.
