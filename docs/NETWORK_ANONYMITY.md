# Network anonymity

Lane for transport privacy and takedown resistance. Consensus rules are unchanged.
Path A and F-A stay on cleartext P2P until an operator sets the flags below.

Documents for later capabilities live in [`docs/network/`](network/).

## Encrypted sessions

`MFND_P2P_ENCRYPT=1` makes `mfnd serve` load or create `p2p_session.key` (32-byte
X25519 static key) and speak **Noise_XX_25519_ChaChaPoly_SHA256** before the
usual hello.

Wire:

1. The dialer writes the four bytes `MFNS`.
2. Noise XX runs: ephemeral exchange, then each static key inside the handshake
   hash. A peer without the static secret cannot finish, so it cannot
   impersonate that node.
3. Hello, ping, tip, goodbye, and the transaction frame are ChaCha20-Poly1305
   transport messages. A passive recorder does not see the transaction bytes.

A listener with encryption on rejects a socket that does not start with `MFNS`.
Leave the flag unset and the node stays on the cleartext hello path.

The two-node test `wired_dial_and_accept_deliver_the_transaction` dials a real
TCP socket, checks the transaction arrives, and
`two_nodes_hide_the_transaction_from_the_socket_log` checks the plaintext is
absent from both directions of the capture.
