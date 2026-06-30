# Wallet Address Formats

Permawrite wallets have two public receive-key encodings:

- `mf...` address: a user-facing display address with the `mf` prefix, the compressed view/spend public keys, and a checksum.
- Raw address keys: the underlying `view_pub_hex` and `spend_pub_hex` values printed by the wallet CLI.

Both forms decode to the same wallet public keys. The prefix is not part of key generation and does not change stealth-address cryptography, scanning, signing, or spend authority.

## Current Network Policy

For testnet and public-devnet UX, use the `mf...` address. It is easier to copy, easier to validate, and makes test-wallet support less error-prone.

For mainnet, prefer raw address keys by default. Raw keys are less recognizable to generic address scrapers than a chain-specific prefix, so they are the max-privacy default against simple crawler and regex collection. This is not a cryptographic privacy boundary: once a raw key pair is posted in a public place, anyone can still copy it. It only avoids giving scrapers an obvious `mf` pattern to harvest.

## CLI Behavior

`mfn-cli wallet address` prints both forms:

```text
address=mf...
address_prefix=mf
view_pub_hex=...
spend_pub_hex=...
```

`wallet send` accepts either format:

```bash
mfn-cli wallet send mf... 1000000
mfn-cli wallet send <VIEW_PUB_HEX> <SPEND_PUB_HEX> 1000000
```

Use `mf...` when testing, sharing support records, or onboarding users. Use raw keys when publishing a mainnet receive address and you want less prefix-based scraping surface.
