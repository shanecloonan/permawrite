# Permawrite

> A privacy-preserving, permanent-storage blockchain.
> **Monero-grade financial privacy fused with greater-than-Arweave-grade data permanence — in a single chain.**

This repository is the **reference Rust implementation** of the Permawrite protocol (internally codenamed **MoneyFund Network**, MFBN-1 on the wire). It contains the cryptographic core, eventual consensus engine, storage prover, node daemon, and wallet — all the consensus-critical code.

The Next.js demo site, in-browser executable specification (TypeScript reference of every primitive), and product UIs live in a separate repository ([`cloonan-group`](https://github.com/shanecloonan/cloonan-group)). The TS reference is byte-for-byte compatible with the Rust code in this repo — they validate each other.

---

## Status

**Pre-network.** This is a foundational layer build-out, not a running chain. As of the latest commit:

| Layer                      | Crate           | Tests | State                                           |
| -------------------------- | --------------- | :---: | ----------------------------------------------- |
| ed25519 primitives + ZK    | `mfn-crypto`    |  145  | All Tier-1 primitives ported, plus binary Merkle. Clippy clean. |
| BLS12-381 sig aggregation  | `mfn-bls`       |   16  | BLS done; KZG pending.                          |
| Permanent-storage primitives | `mfn-storage` |   32  | SPoRA chunking + Merkle proofs, endowment math, PPB-precision yield accumulator. |
| Chain state machine        | `mfn-consensus` |   70  | Emission, RingCT-style tx, coinbase, finality + slashing, **storage-proof verification + endowment-burden enforcement + two-sided treasury settlement — live**. End-to-end tests: 2-block chain with stake-zeroing; storage upload anchored at genesis + SPoRA proof in block 1. |
| Canonical wire codec       | `mfn-wire`      |   —   | Planned.                                        |
| Node daemon (`mfnd`)       | `mfn-node`      |   —   | Planned.                                        |
| Wallet CLI (`mfn-cli`)     | `mfn-wallet`    |   —   | Planned.                                        |
| WASM bindings              | `mfn-wasm`      |   —   | Planned (consumed by the demo page).            |
| **Total**                  |                 | **263** | Zero `unsafe`. Zero clippy warnings.          |

Detailed module-level tracking lives in [`PORTING.md`](./PORTING.md).

---

## What's in the box

### `mfn-crypto` — discrete-log cryptography over ed25519

Every primitive a confidential-transaction chain needs, built on the audited [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek):

- **Canonical binary codec** (MFBN-1, deterministic + length-prefixed)
- **Domain-separated hashing** — every hash in the protocol is tagged
- **Schnorr signatures** + **Pedersen commitments** (additively homomorphic)
- **CryptoNote dual-key stealth addresses** (basic + indexed)
- **Encrypted amounts** (RingCT-style mask + value)
- **LSAG** and **CLSAG** ring signatures (CLSAG = Monero's production ring sig, RingCTv3)
- **Groth–Kohlweiss one-out-of-many** zero-knowledge proofs (log-size ring proof, Triptych-grade)
- **Bulletproofs** (Bünz et al. 2017; transparent, log-size range proofs)
- O(N) bit-decomposition **range proofs** (Maxwell-style, kept for comparison)
- **VRF** (RFC 9381 ECVRF over ed25519) for leader election / VDF-substitute / decoy selection / audit beacons
- **Gamma-distributed decoy selection** (Monero ≥ v0.13 heuristic-resistance)
- **UTXO accumulator** — Zcash-style sparse Merkle tree, depth 32 (4.29 × 10⁹ outputs of capacity), domain-separated, O(D) appends, O(log N) membership proofs. The substrate that log-size ring proofs ride on top of.

### `mfn-bls` — pairing-friendly aggregation

BLS12-381 via [`bls12_381_plus`](https://crates.io/crates/bls12_381_plus):

- **BLS aggregate signatures** — same-message and batch aggregation
- IETF-standard hash-to-curve (SSWU, `ExpandMsgXmd<Sha256>`)
- **Committee voting** helpers: validator-set + bitmap → single aggregate verification (the core primitive for the eventual consensus layer)

KZG polynomial commitments are next on this crate; they're the substrate for log-size UTXO Merkle witnesses (Verkle-style accumulator).

### `mfn-storage` — permanent-storage primitives

The permanence half of the chain — what makes Permawrite different from
Monero:

- **`commitment`** — `StorageCommitment` struct + canonical hash. The
  content-addressed binding a transaction output uses to anchor a
  permanent data payload. Hidden endowment amount (Pedersen-committed).
- **`spora`** — Succinct Proofs of Random Access. Chunk + Merkle-tree the
  upload, deterministically derive `chunk_index_for_challenge` per
  block, build/verify `StorageProof` against the commitment's
  `data_root`. Operators who can't respond fail their per-block
  audit; over enough misses the chain can evict / slash.
- **`endowment`** — the monetary policy of permanence:
  `E₀ = C₀·(1+i)/(r−i)` evaluated on-chain in PPB-precision integer
  math, plus a per-commitment **PPB-precision yield accumulator** so
  even tiny uploads whose per-slot yield is `<< 1 base unit`
  eventually pay out integer base units. Anti-hoarding cap on the
  per-proof reward window prevents farming yield by going dormant.

### `mfn-consensus` — the state transition function

The lego pieces become a chain here:

- **`emission`** — Bitcoin-like halving curve asymptoting to a permanent
  tail (Monero design), plus EIP-1559-style fee split routing most of the
  priority fee to a storage treasury.
- **`storage`** — thin re-export of `mfn-storage::commitment` so existing
  `use mfn_consensus::storage::*` patterns keep working while the
  canonical owner of the type lives downstream.
- **`transaction`** — RingCT-style confidential transaction: CLSAG-signed
  inputs over decoy rings, Pedersen-committed amounts, Bulletproof range
  proofs, stealth addresses derived from the tx-level pubkey, pseudo-output
  blindings that prove balance without revealing amounts. The complete
  `sign_transaction` / `verify_transaction` round-trip lives here.
- **`coinbase`** — synthetic block-reward transaction with a deterministic
  ephemeral key so any node can replay history byte-for-byte.
- **`consensus`** — slot-based PoS engine: stake-weighted VRF leader election
  (ed25519), BLS12-381 committee finality with bitmap-aggregated signatures,
  quorum verification in basis points (default 6667 = 2/3 + 1bp).
- **`slashing`** — on-chain equivocation evidence: two BLS-signed headers
  at the same slot from the same validator → stake slashed to zero, anyone
  can submit, deterministic verification.
- **`block`** — header, body, `ChainState`, deterministic `apply_block`
  that verifies the producer's finality proof, walks the tx list
  (coinbase at position 0 + regular RingCT spends), enforces cross-block
  key-image uniqueness, applies slashing evidence, **verifies SPoRA
  storage proofs against per-commitment chain state**, **enforces that
  new storage uploads cover the protocol's required endowment via the
  treasury-bound fee share**, and **performs a two-sided treasury
  settlement** that drains the treasury for storage rewards before
  minting an emission backstop, all before re-deriving the post-block
  UTXO accumulator root. The integration suite drives both a 2-block
  chain with stake-zeroing and a SPoRA proof flow.

---

## Build

```bash
# Install Rust if you haven't: https://rustup.rs
git clone https://github.com/shanecloonan/permawrite
cd permawrite
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Tested toolchains: `stable-x86_64-unknown-linux-gnu`, `stable-x86_64-apple-darwin`, `stable-x86_64-pc-windows-gnu`.

> **Windows note.** Use the `*-pc-windows-gnu` toolchain. The MSVC toolchain works but needs the Visual Studio Build Tools (`link.exe`) installed; the GNU toolchain ships its own linker.

---

## Design philosophy

1. **No `unsafe`.** Enforced at the workspace level via `#![forbid(unsafe_code)]`. If a primitive cannot be built safely, we don't ship it.
2. **Constant-time where it matters.** Secret-dependent comparisons use [`subtle`](https://crates.io/crates/subtle). Secret material implements [`zeroize::Zeroize`] on drop.
3. **Audited libraries only.** No hand-rolled curves, no toy SHA. We compose; we don't reinvent.
4. **Domain separation everywhere.** Every hash carries an MFBN-1 tag. Adding a new tag is a hard fork by design.
5. **Reference implementation parity.** The TypeScript reference in [`cloonan-group/lib/network`](https://github.com/shanecloonan/cloonan-group/tree/main/lib/network) and the Rust code in this repo are byte-for-byte compatible. When they diverge, the test suite catches it.
6. **Production-grade error handling.** No `panic!`/`unwrap` outside of test code. Every fallible operation returns `Result<_, CryptoError>` (or the crate-local equivalent).

---

## Audited dependencies

| Crate                | Purpose                                    | Used by                                    |
| -------------------- | ------------------------------------------ | ------------------------------------------ |
| `curve25519-dalek`   | ed25519 scalars / Edwards points           | Signal, Zcash, Monero (Salvium), Solana    |
| `bls12_381_plus`     | BLS12-381 pairings + hash-to-curve         | Active fork tracking `sha2 0.10`           |
| `sha2`               | SHA-2 family                               | RustCrypto, used everywhere                |
| `subtle`             | Constant-time equality                     | dalek ecosystem                            |
| `zeroize`            | Secure memory wipe on drop                 | RustCrypto                                 |
| `rand_core` + `getrandom` | OS CSPRNG                             | Standard                                   |

No FFI. No C dependencies. Pure Rust top to bottom.

---

## What this is NOT

- **Not audited.** The code is production-*grade* (constant-time, no `unsafe`, proper error handling, comprehensive tests). A real network deployment requires a third-party cryptographic review.
- **Not a re-implementation of an existing chain.** Permawrite's design — endowment-funded permanent storage rewards, OoM-based log-size ring signatures over the full UTXO set, hybrid emission + fee-treasury tokenomics — is novel. See [`cloonan-group`](https://github.com/shanecloonan/cloonan-group)'s `/blockchain` page for the protocol overview.
- **Not running yet.** This repository contains the primitive layer; the consensus engine, storage prover, and node daemon are in the porting queue.

---

## License

Dual-licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- **MIT License** ([LICENSE-MIT](./LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. This is the standard Rust ecosystem dual license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work shall be dual-licensed as above, without any additional terms or conditions.

---

## Security

Please see [SECURITY.md](./SECURITY.md) for the disclosure process. Do **not** open public issues for vulnerabilities.
