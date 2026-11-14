# Anchor connections

A peer that completes a session is written to `p2p_anchors.txt` in the node
data directory, newest first, at most eight addresses. `mfnd serve` loads that
file on startup and places those addresses at the front of the outbound dial
list, ahead of manifest seeds. A restart therefore redials peers that already
worked instead of depending on a seed that may be blocked.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
