# Censorship-resistant bootstrap

A node learns its first peers from three independent paths:

- DNS seeds (`MFND_DNS_SEEDS`, port `MFND_DNS_SEED_PORT`, default 19101). A name that does not resolve is skipped.
- Hardcoded onion seeds in the binary, dialed when `MFND_P2P_HARDCODED_ONIONS=1`.
- Addresses already received from another peer (`MFND_P2P_EXCHANGED_SEEDS`).

`discover_peers` keeps every valid address. Blocking any one path, or any two, still leaves a dial target when another path returned something. The results are merged into the serve dial list before manifest seeds.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
