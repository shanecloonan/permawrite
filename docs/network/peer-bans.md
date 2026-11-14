# Peer bans

Five protocol failures against one remote IP start a one-hour ban. The table
is `peer_bans.txt` in the node data directory and is loaded on `mfnd serve`
startup, so a restart does not forget the ban.

`inbound_allowed` runs before the hello handshake. A banned IP is closed
without handshake bytes. Loopback addresses are never banned.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
