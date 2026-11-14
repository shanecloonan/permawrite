# Decoy-RNG entropy contract (B-19 / F9)

Production decoy selection, signer-slot choice, and output shuffling draw
from the operating system's CSPRNG. A wallet seed must not reproduce those
draws. Two wallets that share a seed and differ only in their RNG
implementation would otherwise form their own anonymity set.

## Rules

1. Production code calls [`production_tx_rng`](../mfn-wallet/src/lib.rs)
   (`crypto_random`). It takes no seed.
2. [`production_decoy_rng`](../mfn-crypto/src/decoy.rs) accepts a wallet seed
   and ignores it. The same seed on two runs does not repeat the stream.
3. [`seeded_rng`](../mfn-crypto/src/decoy.rs) is test mode. The same `u32`
   repeats decoy indices. Reference frontends (CLI, WASM transfer, WASM
   upload) must not name it. The conformance scan enforces that.
4. If the OS CSPRNG fails, `crypto_random` prints one warning and panics.
   It does not fall back to a seed. [`note_os_entropy_failure_once`](../mfn-crypto/src/decoy.rs)
   is the once-flag.
5. WASM builds enable `getrandom` with the `js` feature
   (`mfn-wasm/Cargo.toml`). That feature reads `crypto.getRandomValues`
   and no other entropy source.

Path A and F-A transaction validity are unchanged. This contract is about
how reference wallets sample decoys, not about consensus verification.
