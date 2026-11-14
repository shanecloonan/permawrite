//! Scale-lane measurement for verification and header-link throughput.
//!
//! This crate does not change consensus, header versions, ring policy, or
//! genesis parameters. Path A and F-A keep the rules they already have.
//! The numbers here are a regression pin for later speed work: batch
//! verification, headers-first sync, and the light-client path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod baseline;
pub mod batch;
pub mod header_sync;
pub mod workload;

pub use baseline::{
    BASELINE_BULLETPROOF_BITS, BASELINE_CLSAG_RING, BASELINE_HEADER_LINK_BLOCKS,
    BASELINE_HEADER_LINK_HEX, BASELINE_MERKLE_LEAVES, BASELINE_MERKLE_PROOFS, BASELINE_RANGE_BITS,
};
pub use batch::{chunk_ranges, proofs_from_workload, verify_batch, verify_one, BatchProof};
pub use header_sync::{
    synthetic_body, synthetic_body_matches, synthetic_chain, synthetic_header_id, HeaderFirstSync,
    HeaderSource, HeaderSyncConfig, MemorySource, SyncError, SyncHeader, SyncStats,
};
pub use workload::{
    header_link_digest, prepare_verify_workload, PreparedWorkload, VerifyReport, WorkloadError,
    CLSAG_WORKLOAD_MESSAGE,
};
