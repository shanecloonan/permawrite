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
pub mod workload;

pub use baseline::{
    BASELINE_BULLETPROOF_BITS, BASELINE_CLSAG_RING, BASELINE_HEADER_LINK_BLOCKS,
    BASELINE_HEADER_LINK_HEX, BASELINE_MERKLE_LEAVES, BASELINE_MERKLE_PROOFS, BASELINE_RANGE_BITS,
};
pub use workload::{
    header_link_digest, prepare_verify_workload, PreparedWorkload, VerifyReport, WorkloadError,
};
