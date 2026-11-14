# Overlay-only dials

`MFND_P2P_OVERLAY_ONLY=1` refuses every dial whose host is not `.onion` or
`.i2p`. The refusal happens before `TcpStream::connect` and before a SOCKS
handshake, so a clearnet address never becomes a socket.

Loopback devnets leave the flag unset. An onion dial still needs
`MFND_P2P_TRANSPORT=tor` (or `i2p` for `.i2p`); overlay-only does not by
itself speak those protocols. It only blocks clearnet destinations.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
