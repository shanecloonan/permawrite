# `mfn-storage`

Permanent-storage primitives for Permawrite — the half of the chain that makes data outlast its uploader.

**Tests:** 44 passing &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

This crate is the chain-level engine for **endowment-funded permanent storage**: how to anchor a file on-chain, how to *prove* you're still holding it block-by-block, and how to compute the upfront escrow that lets storage operators get paid forever.

For the *what* and *why*, see [`docs/STORAGE.md`](../docs/STORAGE.md). For the economic derivation, [`docs/ECONOMICS.md`](../docs/ECONOMICS.md).

---

## Modules

| Module | Responsibility |
|---|---|
| [`commitment`](src/commitment.rs) | `StorageCommitment` struct + canonical hash. M2.0.10 adds `encode_storage_commitment` / `decode_storage_commitment`, a lossless full-struct codec used by storage-bearing transaction outputs in the full-block wire codec. |
| [`spora`](src/spora.rs) | **SPoRA — Succinct Proofs of Random Access.** Chunking, the per-block deterministic challenge derivation, and the `StorageProof` build/verify pipeline. M2.0.2 — `storage_proof_leaf_hash` / `storage_proof_merkle_root` for the per-block `storage_proof_root` commitment under the new `STORAGE_PROOF_LEAF` domain. M2.0.10 tightens `decode_storage_proof`: trailing bytes reject, and Merkle side flags must be exactly `0` or `1`. |
| [`endowment`](src/endowment.rs) | The `E₀ = C₀·(1+i)/(r−i)` formula, per-slot payouts, and the PPB-precision yield accumulator. |

---

## The endowment formula in one place

```
E₀ = C₀ · (1 + i) / (r − i)

where  C₀ = cost_per_byte_year × size_bytes × replication      (first-year cost)
        i = inflation_ppb / PPB                                 (annual storage-cost inflation)
        r = real_yield_ppb / PPB                                (annual real yield)

Non-degeneracy:  r > i  (enforced by validate_endowment_params)
```

Full derivation in [`docs/ECONOMICS.md § The permanence equation`](../docs/ECONOMICS.md#1-the-permanence-equation-derived).

---

## Public API

```rust
// === Commitments ===================================================
let commit = StorageCommitment {
    data_root,
    size_bytes,
    chunk_size,
    num_chunks,
    replication,
    endowment: pedersen_commit(amount, &blinding),
};
let hash = storage_commitment_hash(&commit);
let bytes = encode_storage_commitment(&commit);
let decoded = decode_storage_commitment(&bytes)?;

// === Chunking + Merkle tree ========================================
let chunks: Vec<&[u8]> = chunk_data(data)?;
let leaves: Vec<[u8;32]> = chunks.iter().map(|c| chunk_hash(c)).collect();
let tree   = merkle_tree_from_chunks(&chunks)?;

// === Build a commitment + proof from raw data =====================
let built: BuiltCommitment = build_storage_commitment(
    data, replication, endowment_amount, &endowment_blinding,
)?;
let proof: StorageProof = build_storage_proof(
    &built.commit, &built.chunks, &built.tree,
    prev_block_id: &[u8;32], slot: u64,
)?;

// === Verify a proof against on-chain commitment ===================
let check: StorageProofCheck = verify_storage_proof(
    &commit, prev_block_id: &[u8;32], slot: u64, &proof,
);
// Variants: Ok | UnknownCommit | WrongChunkIndex { expected, got }
//          | BadMerkleProof | BadChunkSize

// === Challenge derivation (you usually never call these directly) ==
let seed = challenge_index_from_seed(/* … */);
let idx  = chunk_index_for_challenge(prev_id, slot, &commit_hash, num_chunks);

// === Endowment math ================================================
validate_endowment_params(&DEFAULT_ENDOWMENT_PARAMS)?;
let required: u128 = required_endowment(size_bytes, replication, &params)?;
let max_bytes: u64 = max_bytes_for_endowment(amount, replication, &params)?;
let per_slot_ppb: u128 = payout_per_slot(/* … */)?;

// === Per-proof yield accrual (driven by apply_block) ===============
let accrued: AccrueResult = accrue_proof_reward(AccrueArgs {
    slot_now, last_proven_slot, per_slot_payout_ppb,
    pending_yield_ppb, params: &endowment_params,
});
// accrued.payout_base_units → reward emitted to the proof submitter
// accrued.new_pending_yield_ppb → fractional remainder, carried to next proof
```

Full type signatures in [`src/lib.rs`](src/lib.rs).

---

## Wire format — `StorageProof`

```text
[commit_hash (32 B)]
[varint(chunk.len()) ‖ chunk_bytes]
[varint(proof.len()) ‖ proof[0] (32 B) ‖ proof[1] (32 B) ‖ …]
```

Encoded by [`encode_storage_proof`](src/spora.rs); decoded by [`decode_storage_proof`](src/spora.rs). M2.0.10 makes the decoder strict: any trailing bytes or non-boolean sibling-side flags reject.

## Wire format — `StorageCommitment` (M2.0.10)

```text
[data_root (32 B)]
[size_bytes (u64)]
[chunk_size (u32)]
[num_chunks (u32)]
[replication (u8)]
[endowment (compressed EdwardsPoint, 32 B)]
```

Total: **81 bytes**. Encoded by [`encode_storage_commitment`](src/commitment.rs); decoded by [`decode_storage_commitment`](src/commitment.rs). This is intentionally the same field order that [`storage_commitment_hash`](src/commitment.rs) hashes under `MFBN-1/storage-commit`, so storage-bearing transaction outputs can carry the full commitment while roots and IDs keep using the commitment hash.

---

## Default parameters

```rust
pub const DEFAULT_ENDOWMENT_PARAMS: EndowmentParams = EndowmentParams {
    cost_per_byte_year_ppb:    200_000,        // 2 × 10⁻⁴ base units / byte-year / replica
    inflation_ppb:             20_000_000,     // 2.0% / year
    real_yield_ppb:            40_000_000,     // 4.0% / year
    min_replication:           3,
    max_replication:           32,
    slots_per_year:            2_629_800,      // ~12-second slots
    proof_reward_window_slots: 7_200,          // ~1 day anti-hoarding cap
};

pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;   // 256 KiB
pub const PPB: u128 = 1_000_000_000;
```

Worked example: **1 GB at 3× replication** → `E₀ ≈ 0.306 MFN`. See [`docs/STORAGE.md`](../docs/STORAGE.md) for more.

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- All arithmetic in `endowment.rs` is `u128` with `checked_mul` — overflow surfaces as a typed error, never a panic.
- Final monetary values use **ceiling division** so the protocol never under-funds.
- No floating-point math anywhere in this crate (PPB integer math is determinism-safe).

---

## Errors

```rust
pub enum SporaError { ... }       // bad chunk, bad Merkle proof, wrong index, etc.
pub enum EndowmentError {
    RealYieldZero,
    RealYieldNotAboveInflation { real_yield_ppb, inflation_ppb },
    MinReplicationTooLow { min },
    MaxReplicationBelowMin { min, max },
    ZeroSlotsPerYear,
    Overflow,
    // ...
}
```

---

## Dependencies

```
mfn-crypto       = path     # Merkle trees, hashing, codec, point ops
curve25519-dalek = "4.1"    # for the Pedersen-committed endowment field
sha2             = "0.10"   # chunk hashing
thiserror        = "1.0"
hex              = "0.4"
```

---

## Test categories

- **`spora`**: chunking edge cases (empty, single, exact-multiple, ragged final chunk), Merkle proof correctness for every position, challenge determinism across reruns, wrong-index rejection, wrong-chunk rejection, encode/decode round-trips; **M2.0.2 storage-proof Merkle commitment** (empty → zero sentinel, leaf domain-separation, deterministic leaf hashing, content-sensitive leaves, addition moves the root, order-sensitive across proofs, TS-parity golden vector for 0-sibling + 2-sibling-with-mixed-`right_side` proofs).
- **`endowment`**: parameter validation (positive-yield, `r > i`, replication bounds), `required_endowment` matches the formula at multiple sizes, `payout_per_slot` matches in aggregate, PPB accumulator carries fractional yield correctly across proofs, anti-hoarding cap enforced, overflow paths return typed errors.
- **`commitment`**: canonical hash is deterministic, field-sensitive, and matches the TS reference.

```bash
cargo test -p mfn-storage --release
```

---

## See also

- [`docs/STORAGE.md`](../docs/STORAGE.md) — the engineering deep dive
- [`docs/ECONOMICS.md`](../docs/ECONOMICS.md) — the economic derivation
- [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — the system view
- [`mfn-consensus`](../mfn-consensus/README.md) — the chain that consumes this crate
