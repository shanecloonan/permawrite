//! Full-node byte projection for the scale section of the permanence
//! upgrade (**B-315**). Planning constants, not a measurement of a live
//! store and not a prune switch.
//!
//! Commitments and decoys are never deleted. PM8 drops only historical
//! block bodies. A curve-tree / sparse-Merkle leaf compresses the UTXO
//! working set. The shipped [`mfn_crypto::utxo_tree`] depth is 32, so
//! 2^32 outputs is a hard cap (~2.1e9 uploads at two outputs each).

use mfn_crypto::utxo_tree::UTXO_TREE_DEPTH;

/// Storage commitment wire (see `mfn-storage` commitment header comment).
pub const STORAGE_COMMITMENT_WIRE_BYTES: u64 = 32 + 8 + 4 + 4 + 1 + 32;

/// `StorageEntry` tail: height `u32` + slot `u64` + pending yield `u128`.
pub const STORAGE_ENTRY_TAIL_BYTES: u64 = 4 + 8 + 16;

/// Map key.
pub const MAP_KEY_BYTES: u64 = 32;

/// Planning overhead per map node. Not a Rust `HashMap` measurement.
pub const MAP_NODE_OVERHEAD_BYTES: u64 = 64;

/// Bytes of storage-map state per anchored upload (key + commitment + tail + overhead).
pub const PER_UPLOAD_STORAGE_STATE_BYTES: u64 = MAP_KEY_BYTES
    + STORAGE_COMMITMENT_WIRE_BYTES
    + STORAGE_ENTRY_TAIL_BYTES
    + MAP_NODE_OVERHEAD_BYTES;

/// Raw UTXO record: key + compressed point + height + overhead.
pub const PER_OUTPUT_UTXO_BYTES: u64 = MAP_KEY_BYTES + 32 + 4 + MAP_NODE_OVERHEAD_BYTES;

/// Curve-tree / sparse-Merkle leaf planning size (point-sized, small overhead).
pub const PER_OUTPUT_CURVE_LEAF_BYTES: u64 = 40;

/// Spent key image map entry.
pub const PER_KEY_IMAGE_BYTES: u64 = MAP_KEY_BYTES + MAP_NODE_OVERHEAD_BYTES;

/// Key-image accumulator leaf (compress, do not drop).
pub const PER_KEY_IMAGE_ACCUMULATOR_BYTES: u64 = 40;

/// Upper bound on one upload transaction inside `chain.blocks` (two ring-16
/// inputs, two outputs, range proofs). Planning ceiling, not a consensus limit.
pub const PER_UPLOAD_BLOCK_BODY_UPPER_BYTES: u64 = 8_192;

/// Uniform-tier upload mints at least two outputs, and spends at least two inputs.
pub const OUTPUTS_PER_UPLOAD: u64 = 2;

/// Matches [`OUTPUTS_PER_UPLOAD`] for the F7 floor used by reference wallets.
pub const INPUTS_PER_UPLOAD: u64 = 2;

/// Projected bytes at one upload count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateProjection {
    /// Upload count the other fields were computed from.
    pub uploads: u64,
    /// Storage map + raw UTXO map + key images + block bodies.
    pub raw_full_node_bytes: u64,
    /// Raw, without historical block bodies (PM8). Maps stay.
    pub pm8_bytes: u64,
    /// PM8 plus UTXO and key-image leaves compressed. Storage map stays full.
    pub curve_tree_bytes: u64,
    /// One-block witness: two sibling paths plus a header allowance.
    pub stateless_witness_bytes: u64,
    /// `true` when `uploads * outputs` exceeds the depth-32 UTXO tree.
    pub utxo_tree_overflows: bool,
}

/// Leaf cap of the shipped sparse Merkle tree (`2^UTXO_TREE_DEPTH`).
#[must_use]
pub fn utxo_tree_leaf_cap() -> u64 {
    1u64 << UTXO_TREE_DEPTH
}

/// `true` when two outputs per upload would not fit in the shipped tree.
#[must_use]
pub fn uploads_overflow_utxo_tree(uploads: u64) -> bool {
    uploads.saturating_mul(OUTPUTS_PER_UPLOAD) > utxo_tree_leaf_cap()
}

/// Project state bytes. Saturates on overflow instead of panicking.
#[must_use]
pub fn project_state_bytes(uploads: u64) -> StateProjection {
    let storage = uploads.saturating_mul(PER_UPLOAD_STORAGE_STATE_BYTES);
    let utxo = uploads
        .saturating_mul(OUTPUTS_PER_UPLOAD)
        .saturating_mul(PER_OUTPUT_UTXO_BYTES);
    let images = uploads
        .saturating_mul(INPUTS_PER_UPLOAD)
        .saturating_mul(PER_KEY_IMAGE_BYTES);
    let bodies = uploads.saturating_mul(PER_UPLOAD_BLOCK_BODY_UPPER_BYTES);
    let pm8 = storage.saturating_add(utxo).saturating_add(images);
    let curve_utxo = uploads
        .saturating_mul(OUTPUTS_PER_UPLOAD)
        .saturating_mul(PER_OUTPUT_CURVE_LEAF_BYTES);
    let curve_images = uploads
        .saturating_mul(INPUTS_PER_UPLOAD)
        .saturating_mul(PER_KEY_IMAGE_ACCUMULATOR_BYTES);
    let curve = storage
        .saturating_add(curve_utxo)
        .saturating_add(curve_images);
    StateProjection {
        uploads,
        raw_full_node_bytes: pm8.saturating_add(bodies),
        pm8_bytes: pm8,
        curve_tree_bytes: curve,
        stateless_witness_bytes: stateless_witness_bytes(uploads),
        utxo_tree_overflows: uploads_overflow_utxo_tree(uploads),
    }
}

/// Sibling paths for a UTXO leaf and a storage-commitment leaf, plus 256
/// bytes of header. Independent of holding the set.
#[must_use]
pub fn stateless_witness_bytes(uploads: u64) -> u64 {
    let n = uploads.max(2);
    let log = 64 - u64::from(n.leading_zeros());
    32 * log * 2 + 256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b315_projection_constants_match_the_wire_comment() {
        assert_eq!(STORAGE_COMMITMENT_WIRE_BYTES, 81);
        assert_eq!(PER_UPLOAD_STORAGE_STATE_BYTES, 205);
        assert_eq!(utxo_tree_leaf_cap(), 1u64 << 32);
    }

    #[test]
    fn b315_scale_points_shrink_only_by_compression() {
        let million = project_state_bytes(1_000_000);
        let hundred_m = project_state_bytes(100_000_000);
        let ten_b = project_state_bytes(10_000_000_000);
        assert!(!million.utxo_tree_overflows);
        assert!(!hundred_m.utxo_tree_overflows);
        assert!(ten_b.utxo_tree_overflows);
        assert!(million.pm8_bytes < million.raw_full_node_bytes);
        assert!(million.curve_tree_bytes < million.pm8_bytes);
        assert_eq!(million.pm8_bytes, 661_000_000);
        assert_eq!(million.curve_tree_bytes, 365_000_000);
        assert_eq!(hundred_m.pm8_bytes, 66_100_000_000);
        assert!(ten_b.raw_full_node_bytes > ten_b.pm8_bytes);
        assert!(ten_b.pm8_bytes > ten_b.curve_tree_bytes);
        // Stateless witness stays kilobytes at 10B uploads.
        assert!(ten_b.stateless_witness_bytes < 4_096);
        assert!(million.stateless_witness_bytes < ten_b.stateless_witness_bytes);
    }

    #[test]
    fn b315_zero_uploads_does_not_overflow_the_tree() {
        let z = project_state_bytes(0);
        assert_eq!(z.raw_full_node_bytes, 0);
        assert!(!z.utxo_tree_overflows);
        assert!(z.stateless_witness_bytes > 0);
    }
}
