# Glossary

> Every acronym, every protocol-specific term, every "what does that mean exactly?" — in one place.
> Sorted alphabetically. Cross-referenced with the deep-dive docs.

---

## A

**accumulator** — A cryptographic data structure that proves "this element is part of this set" with a small (log-size or constant) witness, without revealing or transmitting the whole set. Permawrite uses a depth-32 sparse-Merkle accumulator for the UTXO set (`mfn_crypto::utxo_tree`). Future: KZG-based accumulators are on the roadmap but not active. → [`PRIVACY.md`](./PRIVACY.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md)

**`apply_block`** — The single function that mutates chain state. Takes the current `ChainState` plus a candidate `Block` and produces either a new state or a list of errors. Deterministic — same inputs always produce same outputs. → [`ARCHITECTURE.md § State-transition function`](./ARCHITECTURE.md#state-transition-function-apply_block)

**Arweave** — A blockchain focused on permanent data storage, launched 2018. Pioneered the endowment-based permanence model that Permawrite refines. → [`OVERVIEW.md`](./OVERVIEW.md)

**audit (cryptographic)** — In Permawrite contexts, two meanings: (1) an external third-party security review of the code; (2) the protocol-level per-block storage challenge enforced by SPoRA, which "audits" operators' continued possession of their data.

---

## B

**base unit** — The smallest indivisible unit of MFN. `1 MFN = 10⁸ base units`, mirroring Bitcoin satoshis. Most internal arithmetic uses base units; user-facing displays use MFN.

**Bitcoin halving** — The protocol-level event in Bitcoin where the block subsidy halves every ~4 years. Permawrite's emission curve uses Bitcoin-style halvings for the first ~24 years, then transitions to a Monero-style tail emission. → [`ECONOMICS.md`](./ECONOMICS.md)

**BLS12-381** — A pairing-friendly elliptic curve. Permawrite uses it for **committee finality** signatures (aggregate `N` validator signatures into one). Same curve Ethereum 2.0 and Filecoin use. → [`CONSENSUS.md`](./CONSENSUS.md)

**BLS signature** — A signature scheme on BLS12-381 with the unique property that `N` signatures over the same (or different) messages can be **aggregated** into a single signature, verifiable in one pairing equation. → `mfn-bls`

**block header** — The hash-committed metadata of a block: version, prev_hash, height, slot, timestamp, tx_root, storage_root, producer_proof, utxo_root. Hashed via `BLOCK_HEADER` domain tag. → `BlockHeader` in `mfn_consensus`

**block id** — `dhash(BLOCK_ID, block_header_bytes)`. The canonical identity of a block.

**bond / unbond** — Transactions that lock or release validator stake. Currently *not implemented* — validator set is frozen at genesis. → [`ROADMAP.md`](./ROADMAP.md)

**Bulletproofs** — Log-size, no-trusted-setup, zero-knowledge range proofs invented by Bünz et al. (2017). Permawrite uses them to prove every output's hidden amount is non-negative without revealing the amount. → [`PRIVACY.md § Range proofs`](./PRIVACY.md#range-proofs)

**Bulletproof+** — Optimized variant of Bulletproofs with smaller transcripts. Planned for Tier 2.

---

## C

**ChainState** — The mutable state of a Permawrite chain: UTXO set, spent key images, storage registry, validator set + stats, treasury, accumulator root, block-id chain, consensus + emission + endowment params. → `mfn_consensus::ChainState`

**chunk** — A 256 KiB slice of a stored file. Files are chunked, each chunk is hashed, and the hashes form a Merkle tree whose root is the `data_root`. → [`STORAGE.md`](./STORAGE.md)

**CLSAG** — **C**oncise **L**inkable **S**pontaneous **A**nonymous **G**roup signature. The modern compact ring signature scheme Permawrite uses for transaction inputs. Hides which of N ring members signed; reveals a deterministic key image that prevents double-spending. → [`PRIVACY.md § CLSAG ring signatures`](./PRIVACY.md#3-clsag-ring-signatures)

**coinbase** — A synthetic transaction at position 0 of a block that produces the block's reward output (subsidy + producer fee share). Structurally distinguishable from regular txs (zero inputs). Deterministic — anyone can replay byte-for-byte. → `mfn_consensus::coinbase`

**commitment** — Either (a) a **Pedersen commitment** to a hidden amount, or (b) a **StorageCommitment** binding a tx output to a permanent stored payload. Context disambiguates.

**committee** — The set of validators eligible to vote on block finality. In Permawrite v0.1, the committee is the **entire validator set** (no sub-committees).

**confidential transaction (CT)** — A transaction with hidden amounts. Permawrite's CT model is RingCT-style: Pedersen-committed amounts + range proofs + ring signatures. → [`PRIVACY.md`](./PRIVACY.md)

**consensus** — The mechanism by which the network agrees on the next block. Permawrite uses slot-based PoS with stake-weighted VRF leader election and BLS-aggregated committee finality. → [`CONSENSUS.md`](./CONSENSUS.md)

**counterfeit-input attack** — A historical vulnerability where `apply_block` accepted CLSAG ring members that didn't exist in the UTXO set, allowing attackers to mint money. **Fixed**: every ring member is now verified to exist with matching commitment. → [`PRIVACY.md § Counterfeit-input attack closed`](./PRIVACY.md#counterfeit-input-attack-closed)

**curve25519-dalek** — The audited Rust library providing ed25519 curve arithmetic. Used throughout `mfn-crypto`. Same library Signal uses.

---

## D

**`data_root`** — The Merkle root of a file's chunk hashes. The 32-byte content-addressed identity of a stored file. → [`STORAGE.md`](./STORAGE.md)

**Dandelion** — A peer-to-peer tx propagation protocol that hides the originating IP. Not part of the consensus protocol; lives at the wallet/network layer.

**decoy** — A ring member that isn't the real spender. Selected from chain history using gamma-distributed age sampling (in CLSAG mode). In Tier 3, "decoys" become "all unspent outputs." → [`PRIVACY.md`](./PRIVACY.md)

**dhash** — Domain-separated SHA-256: `dhash(DOMAIN, parts) = SHA-256(DOMAIN || part_0 || part_1 || …)`. Every consensus-significant hash uses this construction with an unambiguous purpose tag. → `mfn_crypto::hash::dhash`

**discrete log problem** — The computational hardness assumption underlying every elliptic-curve cryptosystem Permawrite uses. Given points `P` and `Q = x·P`, finding `x` is computationally infeasible. → [`PRIVACY.md § Threat model`](./PRIVACY.md#threat-model)

**domain separation** — The practice of prefixing every hash with a unique tag (e.g., `MFBN-1/tx-id`) so a hash computed for purpose A can never collide with one computed for purpose B. → [`ARCHITECTURE.md § Domain separation`](./ARCHITECTURE.md#domain-separation)

**double-spend** — Attempting to spend the same UTXO twice. Prevented by key-image uniqueness in `apply_block`.

---

## E

**ed25519** — An elliptic curve (Curve25519 in twisted Edwards form) used for Schnorr signatures, stealth addresses, Pedersen commitments, VRFs, and ring signatures in `mfn-crypto`. Same curve Monero and Signal use.

**emission** — Fresh MFN minted into a block's coinbase per the emission curve. `emission(h)` is a function of block height `h`. → [`ECONOMICS.md`](./ECONOMICS.md)

**emission backstop** — When the treasury can't cover the block's storage rewards, the chain mints the shortfall using `emission_params.storage_proof_reward`. The only sustained sink for fresh tokens beyond the subsidy curve.

**endowment** — The upfront MFN payment a user makes to permanently store a file. Sized via the `E₀ = C₀·(1+i)/(r−i)` formula. → [`STORAGE.md § Endowment math`](./STORAGE.md#4-endowment-math) / [`ECONOMICS.md`](./ECONOMICS.md)

**EndowmentParams** — Protocol-level monetary policy for permanence: `cost_per_byte_year_ppb`, `inflation_ppb`, `real_yield_ppb`, `min_replication`, `max_replication`, `slots_per_year`, `proof_reward_window_slots`.

**equivocation** — When a validator signs two different headers for the same height/slot. Proven via `SlashEvidence`; punished by **stake-zeroing**.

**EVM** — Ethereum Virtual Machine. **Not used.** Permawrite has no general-purpose VM by design.

---

## F

**fee_to_treasury_bps** — Configuration parameter: what fraction of every tx fee flows to the storage treasury vs. the block producer's tip. Default `9000` = 90% treasury / 10% producer. → [`ECONOMICS.md`](./ECONOMICS.md)

**Filecoin** — A storage-focused blockchain. Permawrite differs from Filecoin in (a) using endowment-based permanence (Arweave-style) rather than periodic payments, and (b) adding privacy on the financial layer.

**finality** — The property of a block being irreversible. Permawrite uses **BLS-aggregated committee finality** with a default 2/3+1bp quorum. → [`CONSENSUS.md`](./CONSENSUS.md)

**`FinalityProof`** — The data structure proving a block is finalized: a producer's VRF + Schnorr signature + the committee's aggregate BLS sig + bitmap. Packed into the block header's `producer_proof` field. → `mfn_consensus::FinalityProof`

**finality bitmap** — A byte string where bit `i` indicates whether validator `i` participated in finalizing the block. Drives liveness tracking.

**Fiat-Shamir** — A transformation that converts an interactive zero-knowledge proof into a non-interactive one by replacing the verifier's challenges with hashes of the transcript. Used in CLSAG, range proofs, OoM, VRF — basically every ZK primitive here.

**fork-choice rule** — How a node picks between competing chains. Permawrite has **no fork choice in steady state** because finality is deterministic (a finalized block can't be re-orged).

**`forbid(unsafe_code)`** — A crate-level Rust attribute that forbids `unsafe` blocks anywhere in the crate. Enabled on every first-party crate.

---

## G

**`G`** — The standard ed25519 generator point.

**gamma decoy selection** — Sampling decoys from a gamma distribution calibrated to match the empirical age distribution of real spending. Monero's mitigation against statistical de-anonymization. → `mfn_crypto::decoy`

**gateway** — An off-chain service that retrieves a stored payload from a SPoRA-anchored commitment. Not part of consensus; lives outside the chain. → [`STORAGE.md`](./STORAGE.md)

**genesis** — Block 0. The trusted-setup block at chain start. Subject to special rules in `apply_block` (no finality proof, no coinbase, no slashings).

**Groth–Kohlweiss** — The log-size one-out-of-many ZK proof scheme from [Groth–Kohlweiss 2015](https://eprint.iacr.org/2014/764). Implemented in `mfn_crypto::oom`. The basis for Triptych and Permawrite's planned Tier 3 ring proofs.

---

## H

**`H`** — A second ed25519 generator with **unknown discrete log relative to G**. Derived via `hash_to_point(G)`. Used in Pedersen commitments: `C = v·H + b·G`.

**halving** — A 50% reduction in the per-block subsidy. Permawrite has 8 halvings before the tail era. → [`ECONOMICS.md`](./ECONOMICS.md)

**hash-to-curve / hash-to-point** — Deterministic mapping from arbitrary bytes to a curve point. Used for the `H` generator, BLS signature hashing, and CLSAG key-image computation. Permawrite uses try-and-increment for ed25519 and IETF SSWU for BLS12-381.

**hash-to-scalar** — Deterministic mapping from arbitrary bytes to a scalar modulo the curve order. Used for Fiat-Shamir challenges and shared-secret derivations.

**hiding (commitment property)** — Given a Pedersen commitment `C(v, b)`, the value `v` is computationally hidden if `b` is uniformly random. → [`PRIVACY.md`](./PRIVACY.md)

---

## I

**indexed stealth address** — A sub-address derived from a master stealth address using an index `i`. Lets a wallet have many receiving addresses from one keypair. → `mfn_crypto::stealth::indexed_stealth_address`

**inflation_ppb** — Annual storage-cost inflation rate, in parts per billion. Default `20_000_000` = 2.0%. → [`ECONOMICS.md`](./ECONOMICS.md)

**initial_reward** — The per-block subsidy in the first halving era. Default `50 MFN`.

---

## K

**key image** — A deterministic point derived from a one-time spending key: `I = x · hash_to_point(P)`. Revealed by CLSAG signatures; tracked by the chain to prevent double-spending. Doesn't reveal `x`. → [`PRIVACY.md § Key image`](./PRIVACY.md#key-image)

**KZG** — A pairing-based polynomial commitment scheme. Reserved domain tags exist (`KZG_SETUP`, `KZG_TRANSCRIPT`) for a future log-size accumulator implementation. Not currently active.

---

## L

**Lelantus** — An alternative log-size ring signature scheme. Variation of Groth–Kohlweiss; Permawrite uses Groth–Kohlweiss base + Triptych extension instead.

**liveness slashing** — Multiplicative stake reduction for validators who miss too many consecutive finality votes. Default: 1% stake reduction per slash after 32 consecutive misses. → [`CONSENSUS.md § Slashing — liveness`](./CONSENSUS.md#5-slashing--liveness)

**LSAG** — Linkable Spontaneous Anonymous Group signature. The predecessor to CLSAG. Implemented in `mfn-crypto::lsag` for completeness; CLSAG is the production path.

---

## M

**Merkle tree** — A binary tree where each internal node is the hash of its two children. The root is a constant-size commitment to the whole leaf set. Permawrite uses Merkle trees for: tx root, storage root, chunk root (SPoRA `data_root`), and the UTXO accumulator (sparse Merkle). → `mfn_crypto::merkle`

**MFBN-1** — **M**oney**F**und **B**inary **N**etwork v1. The custom canonical wire codec. Big-endian, length-prefixed, deterministic. → [`ARCHITECTURE.md § Wire codec`](./ARCHITECTURE.md#wire-codec-mfbn-1)

**MFN** — The native currency of Permawrite. `1 MFN = 10⁸ base units`. Also: the MoneyFund Network — the internal codename for Permawrite.

**MoneyFund Network** — The internal protocol codename. The repository / brand name is **Permawrite**.

**Monero** — A privacy-focused blockchain. Permawrite's privacy half borrows extensively from Monero's primitive set (CLSAG, RingCT, stealth addresses, key images, gamma decoy selection).

---

## N

**non-degeneracy condition** — The constraint `r > i` (real yield must exceed storage-cost inflation) that makes the endowment formula's geometric series converge. Hard-coded into `validate_endowment_params`. → [`ECONOMICS.md`](./ECONOMICS.md)

---

## O

**one-out-of-many (OoM)** — A zero-knowledge proof that one of N committed values is the prover's secret, without revealing which. Log-size in N. Permawrite implements the Groth–Kohlweiss variant in `mfn_crypto::oom`. Basis for Tier 3 log-size ring sigs. → [`PRIVACY.md § Tier 3`](./PRIVACY.md#5-tier-3-log-size-rings-via-one-out-of-many)

**one-time address** — A stealth address used for exactly one transaction output. Looks indistinguishable from a fresh random point to outside observers. → [`PRIVACY.md § Stealth addresses`](./PRIVACY.md#2-stealth-addresses)

---

## P

**`P`** — In CLSAG context, a one-time address (output's public key). The `(P, C)` pair is the ring-member identity.

**parts per billion (PPB)** — A precision unit: `1_000_000_000 PPB = 1`. Used everywhere a sub-base-unit fractional rate is needed without floating point. `1% = 10_000_000 PPB`. → `mfn_storage::endowment::PPB`

**Pedersen commitment** — `C(v, b) = v·H + b·G`. Hiding (`v` is hidden) and binding (can't open to a different `v`). Homomorphic — sums of commitments are commitments to sums. → [`PRIVACY.md`](./PRIVACY.md)

**permanence** — Permawrite's guarantee that uploaded data is stored forever (under the `r > i` condition and honest operator majority). The chain-level analog of Arweave's permanence model. → [`STORAGE.md`](./STORAGE.md)

**Permawrite** — The repository name and brand for the MoneyFund Network blockchain.

**PoS (Proof of Stake)** — A consensus mechanism where the right to produce blocks is allocated by stake. Permawrite uses slot-based PoS with VRF leader election. → [`CONSENSUS.md`](./CONSENSUS.md)

**PoW (Proof of Work)** — A consensus mechanism using computational puzzles. **Not used** by Permawrite. (Considered and rejected; energy + bribery vulnerability.)

**ppm** — Parts per million. Less common in Permawrite; we mostly use **ppb** (1000× higher precision).

**producer** — A validator selected by VRF sortition to propose a block in a given slot. Earns the subsidy + producer fee share via the coinbase. → [`CONSENSUS.md`](./CONSENSUS.md)

**`producer_proof`** — The MFBN-encoded `FinalityProof` carried in the block header. Verifies that the block was proposed by an eligible producer and finalized by ≥ quorum stake of committee validators.

**proof_reward_window_slots** — Anti-hoarding cap on how many slots of accrued yield a single storage proof can claim. Default `7200` ≈ 1 day. → [`STORAGE.md § Anti-hoarding cap`](./STORAGE.md#anti-hoarding-cap-proof_reward_window_slots)

---

## Q

**quorum** — The minimum stake share required for committee finality. Default `quorum_stake_bps = 6667` (= 2/3 + 1bp). → [`CONSENSUS.md`](./CONSENSUS.md)

---

## R

**`r`** — In endowment math, the annual real yield rate (per year). Must exceed `i` for the model to be solvent.

**range proof** — A zero-knowledge proof that a hidden amount is in a non-negative range `[0, 2^N − 1]`. Permawrite uses Bulletproofs (N = 64). → [`PRIVACY.md § Range proofs`](./PRIVACY.md#range-proofs)

**rejection sampling** — A technique for sampling a uniform distribution mod N from a uniformly random source: keep re-drawing until the sample falls below the largest multiple of N that fits in the source's range. Used in `challenge_index_from_seed` to avoid modulo bias.

**replication** — The number of distinct storage operators required to independently hold a stored file. Enforced in `[min_replication, max_replication]`. Default min = 3, max = 32.

**ring signature** — A signature scheme that proves one of N keys signed without revealing which. Permawrite uses CLSAG (a linkable variant). → [`PRIVACY.md`](./PRIVACY.md)

**RingCT** — The combination of (ring signatures + stealth addresses + Pedersen commitments + range proofs) that Monero ships and Permawrite inherits. Stands for "Ring Confidential Transactions." → [`PRIVACY.md`](./PRIVACY.md)

**rotation (validator)** — The ability to add or remove validators from the active set after genesis. Not yet implemented; next major milestone. → [`ROADMAP.md`](./ROADMAP.md)

---

## S

**Schnorr signature** — A simple, efficient discrete-log signature scheme. Used in Permawrite to sign producer VRF proofs and as a building block in CLSAG. → `mfn_crypto::schnorr`

**SHA-256** — The cryptographic hash function underlying every `dhash` invocation. Standard, well-audited, no known weaknesses.

**SlashEvidence** — On-chain proof that a validator equivocated. Submitted as part of a block's `slashings` vector; verified by `verify_evidence`; results in the offending validator's stake being zeroed. → `mfn_consensus::slashing`

**slashing** — The protocol-level penalty for misbehaving validators. Two kinds: **equivocation slashing** (stake zeroed) and **liveness slashing** (multiplicative reduction). → [`CONSENSUS.md`](./CONSENSUS.md)

**slot** — A fixed time interval (~12 seconds) during which one or more validators may propose a block.

**slot seed** — `dhash(CONSENSUS_SLOT, [prev_block_id, slot])`. Input to validator VRFs for eligibility computation.

**SPoRA** — **S**uccinct **P**roofs of **R**andom **A**ccess. Storage operators prove they hold a file by responding to per-block deterministic chunk challenges. Borrowed in concept from Arweave. → [`STORAGE.md § SPoRA`](./STORAGE.md#3-spora--deterministic-challenges)

**stake** — The MFN bonded by a validator to participate in consensus. Determines (a) eligibility threshold for leader selection, (b) committee voting weight, (c) slashing exposure.

**stealth address** — A one-time output address derived from the recipient's published `(S, V)` keypair plus a sender-chosen ephemeral scalar. Looks random to observers; detectable only by the holder of the recipient's view key. → [`PRIVACY.md`](./PRIVACY.md)

**storage commitment** — The on-chain binding of a tx output to a permanent stored payload. Carries `data_root`, `size_bytes`, `chunk_size`, `num_chunks`, `replication`, and a Pedersen-committed `endowment`. → [`STORAGE.md`](./STORAGE.md)

**storage operator** — A node that holds stored payloads off-chain and earns MFN by responding to SPoRA challenges. Distinct from validators (though one entity can be both).

**storage_proof_reward** — The emission-backstop amount per proof, used when the treasury is insufficient. Default `0.1 MFN`. → [`ECONOMICS.md`](./ECONOMICS.md)

**`storage_proofs`** — A field of `Block` containing the SPoRA proofs answering this block's challenges. Each proof carries the commit hash + the challenged chunk + a Merkle authentication path.

**subsidy** — Synonymous with `emission`. The fresh MFN per block.

---

## T

**tail emission** — A permanent constant per-block emission that kicks in after the halving era ends. Default `≈ 0.195 MFN/block`. Mirrors Monero's tail. → [`ECONOMICS.md`](./ECONOMICS.md)

**threat model** — The set of attacker capabilities and assumed limitations the protocol is designed to resist. Each subsystem has its own threat model (privacy, consensus, storage). → respective doc

**Tier (1/2/3/4)** — Monotonic privacy-strength milestones in the roadmap. Tier 1 is live. → [`ROADMAP.md`](./ROADMAP.md)

**transcript** — In ZK proof contexts, the deterministic accumulator of public-side bytes used in Fiat-Shamir challenges. Domain-separated.

**treasury** — The on-chain pool of MFN funded by tx fee shares; drained to pay storage rewards. Stored as `ChainState::treasury: u128`. → [`ECONOMICS.md`](./ECONOMICS.md)

**Triptych** — An extension of Groth–Kohlweiss with linkability + multi-spender support. Monero is preparing to ship Triptych. Permawrite uses GK base + Triptych extension at Tier 3.

**try-and-increment** — A simple, deterministic, slightly-non-constant-time hash-to-curve technique. Used for `hash_to_point` on ed25519 where constant-time hash-to-curve isn't critical (we only hash to known-public points). → `mfn_crypto::hash::hash_to_point`

---

## U

**unbond** — A transaction (planned, not yet implemented) that initiates a validator's exit from the active set. Subject to an unbond delay so equivocation slashing can still apply.

**unsafe code** — Rust syntax (`unsafe { … }`) that disables some compiler safety checks. **Forbidden** at the crate level in every first-party crate via `#![forbid(unsafe_code)]`.

**UTXO** — **U**nspent **T**ransaction **O**utput. Permawrite's accounting model is UTXO-based (like Bitcoin and Monero), not account-based (like Ethereum). → `mfn_consensus::UtxoEntry`

**UTXO accumulator** — A cryptographic data structure that lets you prove "this output is in the UTXO set" with a small witness. Currently a depth-32 sparse-Merkle tree. → `mfn_crypto::utxo_tree`

**`utxo_root`** — The Merkle root of the UTXO accumulator after a block is applied. Carried in the block header.

**`utxo_tree`** — The sparse-Merkle accumulator that maintains a constant-size commitment to the entire UTXO set across history. Outputs are appended in deterministic order; never deleted.

---

## V

**validator** — A staked participant in consensus. Has three keypairs: VRF (leader election), BLS (finality voting), Schnorr (producer claim). → `mfn_consensus::Validator`

**`ValidatorStats`** — Per-validator participation metrics: `consecutive_missed`, `total_signed`, `total_missed`, `liveness_slashes`. Updated by `apply_block` after every finality verification. → `mfn_consensus::ValidatorStats`

**varint** — A variable-length unsigned integer encoding (LEB128, 1-10 bytes). Used by the MFBN-1 codec for length prefixes.

**view key** — Half of a Permawrite stealth keypair. Lets the holder *detect* incoming outputs but not spend them. → [`PRIVACY.md`](./PRIVACY.md)

**VRF (Verifiable Random Function)** — A cryptographic function that produces a pseudo-random output + a proof that the output was correctly computed. Used for stake-weighted leader election. → `mfn_crypto::vrf`

---

## W

**wallet** — Software that manages keypairs, scans for incoming outputs, constructs signed transactions, and (optionally) drives storage uploads. Reference Rust wallet planned in `mfn-wallet`. → [`ROADMAP.md`](./ROADMAP.md)

**WASM** — WebAssembly. Planned `mfn-wasm` bindings will let the same Rust primitives run in browsers. → [`ROADMAP.md`](./ROADMAP.md)

**weak subjectivity** — The PoS-specific concept that nodes joining the chain for the first time must trust a recent checkpoint (because they can't distinguish histories where a majority of validators have been since-slashed). Long-range attack mitigation in future versions.

**whitepaper** — The conceptual design document. The TypeScript reference + this Rust implementation + the docs in `/docs` are the *implementation* of the whitepaper.

**wire format** — The on-the-wire byte representation of protocol data. Permawrite's is MFBN-1.

---

## X

**XOR (in encrypted amounts)** — The mask construction `enc_v = value XOR mask_v`. The recipient derives the same mask from the shared secret and XORs to recover the value. → [`PRIVACY.md § Encrypted amount blobs`](./PRIVACY.md#4-encrypted-amount-blobs)

---

## Y

**yield** — In storage contexts, the per-slot payout to operators for holding a file. Calculated as `endowment × real_yield / slots_per_year`. → [`STORAGE.md`](./STORAGE.md)

---

## Z

**zero-knowledge proof (ZK)** — A proof that a statement is true without revealing why. CLSAG, range proofs, OoM proofs, VRF proofs — all zero-knowledge in different senses.

**zeroize** — The Rust crate (and the practice) of securely wiping memory holding secret material on drop. Permawrite uses `zeroize::Zeroize` for every scalar that holds a private key.

---

## Common error variants (alphabetical)

These come up in test output and CI logs. Glossed for grep-ability.

- `BadChunkSize` — SPoRA proof's chunk is the wrong length.
- `BadMerkleProof` — SPoRA proof's Merkle authentication path doesn't connect to `data_root`.
- `DuplicateStorageProof` — Same commit hash proven twice in one block.
- `EmissionBackstop` — Logic path indicator (not an error): treasury was insufficient, emission covered shortfall.
- `EndowmentMathFailed` — `required_endowment` overflowed or saw a degenerate parameter.
- `GenesisHeightNotZero` — Tried to apply a non-zero-height block as genesis.
- `RealYieldNotAboveInflation` — `r ≤ i` violation in endowment params.
- `RingMemberCommitMismatch` — Ring member's `(P, C)` exists with `P` but different `C`.
- `RingMemberNotInUtxoSet` — Ring member's `P` not found in the chain's UTXO set.
- `StorageProofInvalid` — Generic catchall — verify the inner `StorageProofCheck` for the specific reason.
- `StorageProofUnknownCommit` — Proof for a commitment the chain doesn't know about.
- `StorageReplicationTooHigh` / `StorageReplicationTooLow` — Out-of-bounds replication factor.
- `UnexpectedCoinbase` — Block has a coinbase but no producer with a payout address.
- `UploadUnderfunded` — Tx fee's treasury share is below the required endowment.
- `WrongChunkIndex` — SPoRA proof targeted the wrong chunk (didn't match the challenge derivation).

For the full list, see each `BlockError`, `CryptoError`, `EndowmentError`, `SporaError` enum's definition.
