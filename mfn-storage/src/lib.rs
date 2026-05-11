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
//!   `E₀ = C₀·(1+i)/(r−i)` formula, per-slot payouts, and the
//!   PPB-precision accumulator that lets sub-base-unit per-slot yields
//!   eventually pay out as integer base units.
//!
//! ## Layering
//!
//! `mfn-consensus` depends on this crate; `apply_block` calls into
//! [`spora::verify_storage_proof`] for per-block storage audits and
//! [`endowment::required_endowment`] / [`endowment::accrue_proof_reward`]
//! for the two-sided treasury settlement.
//!
//! ## Byte-for-byte parity
//!
//! Every encoder and hash in this crate matches the TypeScript reference
//! in `cloonan-group/lib/network/{storage,endowment}.ts` exactly.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod commitment;
pub mod endowment;
pub mod spora;

pub use commitment::{storage_commitment_hash, StorageCommitment};
pub use endowment::{
    accrue_proof_reward, cumulative_payout, max_bytes_for_endowment, payout_per_slot,
    required_endowment, validate_endowment_params, AccrueArgs, AccrueResult, EndowmentError,
    EndowmentParams, DEFAULT_ENDOWMENT_PARAMS, PPB,
};
pub use spora::{
    build_storage_commitment, build_storage_proof, challenge_index_from_seed, chunk_data,
    chunk_hash, chunk_index_for_challenge, decode_storage_proof, encode_storage_proof,
    merkle_tree_from_chunks, verify_endowment_opening, verify_storage_proof, BuiltCommitment,
    SporaError, StorageProof, StorageProofCheck, DEFAULT_CHUNK_SIZE,
};
