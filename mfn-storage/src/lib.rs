//! # `mfn-storage`
//!
//! Permanent-storage primitives for the Permawrite protocol.
//!
//! - [`commitment`] — `StorageCommitment` struct + canonical hash. The
//!   wire-format binding a transaction output uses to anchor a payload.
//! - [`spora`] — SPoRA (Succinct Proofs of Random Access): chunking, the
//!   chunk-Merkle tree, per-block challenge derivation, and
//!   build/verify of the [`spora::StorageProof`] that ships inside a
//!   block.
//! - [`endowment`] — monetary policy for permanence: the
//!   `E₀ = C₀·(1+i)/(r−i)` (r>0) or `E₀ = C₀·(1+i)/d` (r=0, deflation mode)
//!   formula, per-slot payouts (0 when r=0), and the PPB-precision accumulator.
//!
//! ## Layering
//!
//! `mfn-consensus` depends on this crate; `apply_block` calls into
//! [`spora::verify_storage_proof`] for per-block storage audits and
//! [`endowment::required_endowment`] / [`endowment::accrue_proof_reward`]
//! for the two-sided treasury settlement.
//!
//! ## Canonical bytes
//!
//! Encoders, hashes, and protocol vectors in this crate define the Rust storage
//! wire formats. Byte drift is treated as a consensus bug.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod commitment;
pub mod endowment;
pub mod spora;

pub use commitment::{
    decode_storage_commitment, encode_storage_commitment, expected_num_chunks,
    pad_to_storage_size_bucket, storage_commitment_hash, storage_size_bucket,
    validate_storage_commitment_shape, CommitmentShapeError, StorageCommitment,
};
pub use endowment::{
    accrue_proof_reward, cumulative_payout, max_bytes_for_endowment, payout_per_slot,
    required_endowment, validate_endowment_params, AccrueArgs, AccrueResult, EndowmentError,
    EndowmentParams, DEFAULT_ENDOWMENT_PARAMS, PPB,
};
pub use spora::{
    build_storage_commitment, build_storage_proof, build_storage_proof_operator_salted,
    build_test_storage_proof, challenge_index_from_seed, chunk_data, chunk_hash,
    chunk_index_for_challenge, chunk_index_for_operator_challenge, decode_merkle_proof_wire,
    decode_storage_proof, encode_merkle_proof_wire, encode_storage_proof, merkle_tree_from_chunks,
    operator_identity_from_payout, operator_payout_is_valid, storage_proof_leaf_hash,
    storage_proof_merkle_root, test_operator_payout_keys, verify_endowment_opening,
    verify_storage_proof, verify_storage_proof_operator_salted, BuiltCommitment, SporaError,
    StorageProof, StorageProofCheck, DEFAULT_CHUNK_SIZE,
};
