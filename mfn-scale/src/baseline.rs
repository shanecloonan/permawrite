//! Committed size of the verification workload.
//!
//! Wall-clock times live in [`docs/SCALE_I1_VERIFY_BASELINE.md`] and move
//! when the machine changes. These constants do not: a later patch that
//! silently shrinks the bench (fewer leaves, a smaller ring) fails the
//! unit test that reads them.

/// Leaves in the Merkle workload. Power of two so the tree has no
/// duplicated odd-node padding on the last level.
pub const BASELINE_MERKLE_LEAVES: usize = 1024;

/// Inclusion proofs verified on every pass (evenly spaced leaves).
pub const BASELINE_MERKLE_PROOFS: usize = 32;

/// CLSAG ring size. Matches the production wallet floor of 16.
pub const BASELINE_CLSAG_RING: usize = 16;

/// Bit width of the Borromean range proof in the workload.
///
/// 16 bits is enough to exercise every limb of `range_verify` without
/// turning the unit test into a 64-bit proving run. The bench measures
/// verification, which is linear in this width.
pub const BASELINE_RANGE_BITS: u32 = 16;

/// Bit width of the Bulletproof in the workload. Must be a power of two.
pub const BASELINE_BULLETPROOF_BITS: u32 = 16;

/// Header-link steps in the sync-throughput pin.
pub const BASELINE_HEADER_LINK_BLOCKS: u32 = 4096;

/// SHA-256 chain digest of [`BASELINE_HEADER_LINK_BLOCKS`] links.
///
/// Domain string `MFN-1/scale-header-link/v1`, previous digest, then the
/// height as 4 big-endian bytes. This is a harness digest, not
/// `block_id`.
pub const BASELINE_HEADER_LINK_HEX: &str =
    "b2d3715d5e56c929e37683098e05087bd86bae08c792eeb72e8477a523047c3c";
