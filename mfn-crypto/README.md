# `mfn-crypto`

Discrete-log cryptographic primitives for Permawrite, built on the ed25519 prime-order subgroup via the audited [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) crate.

**Tests:** 153 passing &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

This is where every "math thing" lives that *doesn't* touch BLS12-381 or chain state. Schnorr signatures, Pedersen commitments, ring signatures, stealth addresses, range proofs, VRFs, the UTXO accumulator, plus the MFBN-1 wire codec and domain-separation registry.

For the *what* and *why*, see [`docs/PRIVACY.md`](../docs/PRIVACY.md). For the system-level architecture, see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

---

## Modules

| Module | Responsibility |
|---|---|
| [`domain`](src/domain.rs) | Domain-separation tags (`MFBN-1/…`). Adding a tag is a hard fork. |
| [`codec`](src/codec.rs) | MFBN-1 `Writer`/`Reader`. Big-endian, length-prefixed, deterministic. |
| [`scalar`](src/scalar.rs) | Scalar helpers (little-endian mod-L conversions, random scalar). |
| [`point`](src/point.rs) | Point helpers, the two generators `G` and `H = hash_to_point(G)`. |
| [`hash`](src/hash.rs) | `dhash`, `hash_to_scalar`, `hash_to_point` (try-and-increment). |
| [`schnorr`](src/schnorr.rs) | Schnorr signatures (used in producer claims, CLSAG building blocks). |
| [`pedersen`](src/pedersen.rs) | Pedersen commitments + balance equation. |
| [`stealth`](src/stealth.rs) | Dual-key CryptoNote stealth addresses, plus indexed sub-addresses. |
| [`encrypted_amount`](src/encrypted_amount.rs) | RingCT-style encrypted `(value, blinding)` blobs. |
| [`lsag`](src/lsag.rs) | Linkable Spontaneous Anonymous Group ring signatures (legacy). |
| [`clsag`](src/clsag.rs) | **Concise LSAG — the production ring signature.** |
| [`vrf`](src/vrf.rs) | RFC 9381 ECVRF over ed25519. Drives leader election. |
| [`range`](src/range.rs) | O(N) bit-decomposition range proofs (testing / fallback). |
| [`bulletproofs`](src/bulletproofs.rs) | **Log-size range proofs (Bünz et al. 2017).** |
| [`oom`](src/oom.rs) | Groth–Kohlweiss one-out-of-many ZK (basis for Tier 3 log-size rings). |
| [`decoy`](src/decoy.rs) | Gamma-distributed decoy sampling (Monero v0.13 heuristic). |
| [`utxo_tree`](src/utxo_tree.rs) | Depth-32 sparse-Merkle UTXO accumulator. |
| [`merkle`](src/merkle.rs) | Binary Merkle tree over pre-hashed leaves (tx root, storage root, SPoRA chunk root). |

---

## Public API (selected highlights)

```rust
// === Schnorr signatures ===========================================
let keys = schnorr_keygen(&mut rng);
let sig  = schnorr_sign(&keys.secret, message);
let ok   = schnorr_verify(&keys.public, message, &sig);

// === Pedersen commitments =========================================
let blinding = random_scalar(&mut rng);
let c        = pedersen_commit(value, &blinding);    // v·H + b·G
let ok       = pedersen_verify(&c, value, &blinding);
let sum      = pedersen_sum(&[c1, c2]);              // homomorphic add
let balanced = pedersen_balance(&inputs, &outputs, fee);

// === Stealth addresses ============================================
let wallet            = stealth_gen(/* … */)?;
let address           = wallet.address();
let (output, R, secret) = stealth_send_to(&address, value, &mut rng)?;
let detected          = stealth_detect(&wallet, &output);
let spend_key         = stealth_spend_key(&wallet, &output);

// === CLSAG ring signatures ========================================
let sig = clsag_sign(&ring, &secret, secret_index, &message, &mut rng)?;
let ok  = clsag_verify(&ring, &sig, &message)?;
let same_key = clsag_linked(&sig_a, &sig_b);

// === Bulletproof range proofs =====================================
let (proof, commit) = bp_prove(value, &blinding, &mut rng)?;
let ok              = bp_verify(&commit, &proof)?;

// === VRF ==========================================================
let keys             = vrf_keygen(&mut rng);
let VrfProveResult { proof, output, .. } = vrf_prove(&keys.secret, input)?;
let res              = vrf_verify(&keys.public, input, &proof);
let idx_u64          = vrf_output_as_u64(&output);

// === UTXO accumulator =============================================
let mut tree = empty_utxo_tree();
let leaf     = utxo_leaf_hash(&one_time_addr, &commit, height);
tree         = append_utxo(&tree, leaf)?;
let root     = utxo_tree_root(&tree);
let proof    = utxo_membership_proof(&tree, leaf_index)?;
let ok       = verify_utxo_membership(&root, &leaf, &proof)?;

// === Decoy selection ==============================================
let decoys = select_gamma_decoys(
    &utxo_pool, current_height, n_decoys,
    &DEFAULT_GAMMA_PARAMS, &mut rng,
)?;
```

Full type signatures are in [`src/lib.rs`](src/lib.rs).

---

## Safety contract

- `#![forbid(unsafe_code)]` at the crate level.
- Every secret-bearing type implements [`zeroize::Zeroize`](https://crates.io/crates/zeroize) and zeroes on drop.
- Curve point and scalar equality goes through [`subtle::ConstantTimeEq`](https://crates.io/crates/subtle).
- Every hash is domain-separated; reusing a tag for a new purpose is a hard fork by construction.
- Every fallible operation returns `Result<T, CryptoError>`. No `panic!`/`unwrap` outside test code.

---

## Test categories

- Per-module unit tests proving correctness against the TypeScript reference (`cloonan-group/lib/network/primitives.ts`).
- Cross-module integration tests (`tests/integration.rs`) — Pedersen-balanced rings, full transaction flows.
- Property-style tests for codec round-trips and curve identities.
- Determinism tests (same input → same output across runs).

```bash
cargo test -p mfn-crypto --release
```

---

## Dependencies

```
curve25519-dalek = "4.1"     # ed25519 curve arithmetic
sha2             = "0.10"    # SHA-256
subtle           = "2.5"     # constant-time equality
zeroize          = "1.7"     # secure memory wiping
rand_core        = "0.6"     # CSPRNG
thiserror        = "1.0"     # error derivation
hex              = "0.4"     # debug encoding
```

All audited, all production-tested across major Rust crypto consumers.

---

## See also

- [`docs/PRIVACY.md`](../docs/PRIVACY.md) — the math of every primitive in this crate
- [`docs/ARCHITECTURE.md § Cryptographic primitives`](../docs/ARCHITECTURE.md#cryptographic-primitives) — the full primitive table
- [`docs/GLOSSARY.md`](../docs/GLOSSARY.md) — definitions for every term
- [`PORTING.md`](../PORTING.md) — TS → Rust porting status
