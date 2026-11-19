# Browser wallet

The testnet page can create a wallet, or restore one from 24 English words, without sending those words anywhere.

Create makes 32 random bytes, shows the words once, and stores them only as a passphrase seal in this browser's local storage. The seal is PBKDF2-HMAC-SHA256 (210,000 rounds) and AES-GCM. The seed is not written in the clear.

Restore checks the word list and the checksum, then seals the same seed under the passphrase you type. Unlock opens that seal and shows the address derived on this device (`mfn_wallet_v1`, the same derivation the CLI uses). A wrong passphrase does not open the wallet.

The address is computed here. A server is not asked what the address is.
