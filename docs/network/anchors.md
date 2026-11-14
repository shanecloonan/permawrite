# Anchor connections

A peer that completes a session is written to `p2p_anchors.txt` in the node
data directory, newest first, at most eight addresses. `mfnd serve` loads that
file on startup and places addresses that are not already in `peers.json` at
the front of the outbound dial list, ahead of manifest seeds. Peers already
saved in `peers.json` stay on the reconnect path so they are not dialed twice.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
