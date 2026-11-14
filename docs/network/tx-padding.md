# Transaction padding

`MFND_P2P_PAD=1` sends transaction gossip as tag `0x17`: a real length, the
body, and zeros out to the next 1024-byte bucket. A 10-byte body and a
400-byte body occupy the same frame. Sends also wait for the next 100ms grid
so two transactions that arrive in one window leave together.

Receivers accept tag `0x17` even when the flag is off, strip the padding, and
admit the original body. The cleartext tag `0x06` is unchanged when the flag
is unset. See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
