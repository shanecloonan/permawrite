//! Storage commitments — re-exported from `mfn-storage`.
//!
//! Historically a minimal copy of `StorageCommitment` lived here while the
//! storage prover was unimplemented. Now that [`mfn-storage`] is the
//! canonical owner of the type + its hasher, this module is a thin
//! re-export to keep existing `use mfn_consensus::storage::*` patterns
//! working.
//!
//! New code should prefer `use mfn_storage::*` directly.

pub use mfn_storage::commitment::{storage_commitment_hash, StorageCommitment};
