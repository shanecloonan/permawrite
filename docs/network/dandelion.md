# Dandelion++ epoch stem

When `--dandelion` is on, a transaction the node created is forwarded to exactly
one peer for the current epoch. The successor is `dhash(node salt || epoch)`
over the current peer list, so every transaction in that epoch shares one stem
edge and the edge rotates when the epoch changes.

A relayed stem uses a per-node fluff coin. With the coin at zero the relay
forwards to one peer and does not bounce a broadcast to every neighbor. After
`stem_timeout` the same transaction fails safe into fluff so it is not stuck
on a dead stem.

A neighbor therefore sees a single stem arrival. That arrival looks the same
whether this node created the transaction or is relaying it. The three-node
test `three_node_epoch_stem_hides_the_origin_from_a_neighbor` checks the
origin, the first hop, and the embargo.

The flag stays off by default so existing meshes keep parallel fan-out. See
[`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
