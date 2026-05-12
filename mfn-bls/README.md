# `mfn-bls`

BLS12-381 signatures and (future) KZG commitments for Permawrite. This is the crate that makes **stake-weighted committee finality** cheap: aggregate `N` validator signatures into one 96-byte point and verify in a single pairing equation.

**Tests:** 16 passing &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

For where this fits in the consensus pipeline, see [`docs/CONSENSUS.md`](../docs/CONSENSUS.md). For the system view, [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

---

## Why BLS

When `N` validators need to sign the same message (a block header), naïvely you'd carry `N` signatures and verify each. With BLS aggregation:

- All `N` signatures sum to a single 96-byte point.
- Verification is **one pairing equation**, regardless of `N`.
- A bitmap (1 bit per validator) tells observers who signed.

This is what makes Ethereum 2.0's beacon chain practical at thousands of validators. We use the same scheme for committee finality.

---

## Curve / variant

IETF "long signatures" variant (signature in G2, public key in G1):

- `sk` — 32-byte scalar mod `r` (the BLS12-381 group order).
- `pk` — G1 point, 48 bytes compressed.
- `sig` — G2 point, 96 bytes compressed.
- Hash-to-curve: IETF SSWU with DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`.

This matches **Ethereum 2.0 / Filecoin / Polkadot**. Bridges and light clients on those chains can verify Permawrite finality proofs using existing BLS libraries.

---

## Public API

```rust
// Keygen
let keys = bls_keygen(&mut rng);
let keys = bls_keygen_from_seed(seed_bytes);

// Sign / verify
let sig = bls_sign(&keys.secret, message);
let ok  = bls_verify(&keys.public, message, &sig)?;

// Aggregation
let agg_sig = aggregate_signatures(&[sig1, sig2, sig3])?;
let agg_pk  = aggregate_public_keys(&[pk1, pk2, pk3])?;
let ok      = verify_aggregate_same_message(&agg_pk, message, &agg_sig)?;
let ok      = verify_aggregate_batch(&pks, &messages, &agg_sig)?;

// Committee finality (the production path)
let vote     = CommitteeVote { validator_index, signature };
let aggregate: CommitteeAggregate =
    aggregate_committee_votes(&validators_pks, &votes)?;
let ok = verify_committee_aggregate(
    &validators_pks,
    &aggregate,
    &header_signing_hash,
)?;

// Wire encoding
let bytes = encode_public_key(&pk);
let pk    = decode_public_key(&bytes)?;
let bytes = encode_signature(&sig);
let sig   = decode_signature(&bytes)?;
```

Full type signatures in [`src/sig.rs`](src/sig.rs).

---

## Notable types

```rust
pub struct BlsSecretKey(/* Scalar mod r, zeroized on drop */);
pub struct BlsPublicKey(/* G1Affine, 48 bytes compressed */);
pub struct BlsSignature(/* G2Affine, 96 bytes compressed */);

pub struct CommitteeVote {
    pub validator_index: u32,
    pub signature:       BlsSignature,
}

pub struct CommitteeAggregate {
    pub agg_sig: BlsSignature,
    pub bitmap:  Vec<u8>,      // bit i set iff validator i signed
}
```

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- `BlsSecretKey` zeroizes on drop.
- All comparisons of secret-bearing material go through constant-time paths.
- Backed by the audited pure-Rust `bls12_381_plus` crate (Zcash-derived). No FFI.

---

## Dependencies

```
bls12_381_plus  = "0.8"   # BLS12-381 curve + hash-to-curve
elliptic-curve  = "0.13"  # ExpandMsgXmd for hash-to-curve
ff              = "0.13"  # field trait
group           = "0.13"  # group trait
pairing         = "0.23"  # pairing trait
sha2            = "0.10"  # SHA-256 for hash-to-curve
subtle          = "2.5"   # constant-time equality
zeroize         = "1.7"   # secure memory wiping
rand_core       = "0.6"   # CSPRNG
thiserror       = "1.0"
hex             = "0.4"
```

---

## Test categories

- Single-sig sign/verify round-trips.
- Aggregate sign/verify across `N = 2, 5, 100, 1000` signers.
- Bitmap correctness (sparse aggregates).
- Cross-implementation parity with the TypeScript reference.
- Wrong-message rejection.
- Wrong-signer rejection.

```bash
cargo test -p mfn-bls --release
```

---

## Roadmap notes

- **KZG commitments** (planned). Reserved domain tags `KZG_SETUP` and `KZG_TRANSCRIPT` exist. KZG would enable a log-size UTXO accumulator at Tier 4, but ranked as low-priority — the current sparse-Merkle accumulator is already sufficient for v0.x. See [`docs/ROADMAP.md`](../docs/ROADMAP.md).

---

## See also

- [`docs/CONSENSUS.md § Committee finality`](../docs/CONSENSUS.md#3-committee-finality-bls12-381) — how this crate is used at the consensus layer
- [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — the system view
