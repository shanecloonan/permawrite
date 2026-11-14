# Wallet lock

`wallet lock` seals the 32-byte seed before it is written.

The passphrase comes from the environment variable `MFN_WALLET_PASSPHRASE`. It is not a command-line flag, so it does not land in shell history, and it is not stored in the wallet file.

## What is sealed

New locks use **Argon2id** (19 MiB, 2 passes, 1 lane) and **ChaCha20-Poly1305**. A wrong passphrase and a modified file both fail. The seed stays empty in the JSON.

Older files sealed with PBKDF2-HMAC-SHA256 still open. The next `wallet lock` or save rewrites them as Argon2id. Plaintext wallets (version 1 and 2) are unchanged until you lock them.

## Commands

```bash
export MFN_WALLET_PASSPHRASE='a phrase you can remember'
mfn-cli --wallet alice.json wallet lock
mfn-cli --wallet alice.json wallet address
mfn-cli --wallet alice.json wallet unlock
```

`wallet unlock` writes the seed in plaintext again and says so. Losing the passphrase loses the money. The passphrase does not restore files you uploaded.
