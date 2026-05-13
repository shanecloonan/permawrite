//! UTXO accumulator — incremental sparse Merkle tree.
//!
//! Port of `lib/network/utxo-tree.ts`. The chain commits to every output ever
//! produced via a fixed-depth Merkle tree; the 32-byte root rides in each
//! block header. Light clients verify "this output existed at height h" with a
//! O(log N) sibling path, and log-size ring proofs (Triptych/OoM family) build
//! their anonymity set from the same structure — anonymity set = every output
//! ever, not 16 decoys.
//!
//! ## Design
//!
//! - **Zcash-style sparse Merkle tree** with depth [`UTXO_TREE_DEPTH`] = 32
//!   (≈ 4.29 × 10⁹ leaves of capacity). Unfilled positions hash to a
//!   pre-computed `EMPTY_LEAF`; the corresponding empty interior nodes are
//!   likewise pre-computed and cached as `zeros[d]`.
//! - **Append-only.** Spent outputs remain in the tree; the key-image set
//!   tracks unspendability. This is Monero's anonymity model and the reason
//!   ring signatures remain sound.
//! - **Domain-separated hashing.** The leaf, node, and empty-leaf hashes are
//!   tagged distinctly so the tree's pre-image space is disjoint from every
//!   other hash structure on the chain.
//!
//! ## Complexity
//!
//! | Op                       | Cost                |
//! | ------------------------ | ------------------- |
//! | [`append_utxo`]          | O(D) hashes         |
//! | [`utxo_tree_root`]       | O(1)                |
//! | [`utxo_membership_proof`]| O(D) sibling fetches|
//! | [`verify_utxo_membership`]| O(D) hashes        |
//!
//! ## Byte-for-byte compatibility
//!
//! The leaf hash, node hash, and empty-leaf precomputation match the TS
//! reference exactly: every input is wrapped in the MFBN-1 `Writer::blob`
//! framing via [`crate::hash::dhash`], with the same `UTXO_LEAF`,
//! `UTXO_NODE`, and `UTXO_EMPTY` domain tags.

use std::collections::HashMap;

use curve25519_dalek::edwards::EdwardsPoint;
use subtle::ConstantTimeEq;

use crate::codec::{Reader, Writer};
use crate::domain::{UTXO_EMPTY, UTXO_LEAF, UTXO_NODE};
use crate::hash::dhash;

/// Tree depth. 2³² leaves = ~4.29 × 10⁹ outputs of capacity. Hard-coded into
/// the protocol — a network reset is required to change it. Implementations
/// MUST use the same depth or the roots diverge.
pub const UTXO_TREE_DEPTH: u32 = 32;

/// A sparse-Merkle-tree node key: `(depth, index)`. `depth ∈ [0, D]` with
/// `depth = 0` at the leaves and `depth = D` at the root. `index ∈
/// [0, 2^(D - depth))`.
type NodeKey = (u32, u64);

/// Pre-derived empty-leaf hash. Domain-separated and constant. Computed lazily
/// on first access since `dhash` is not a const fn.
pub fn empty_leaf() -> [u8; 32] {
    dhash(UTXO_EMPTY, &[])
}

/// State of an append-only UTXO accumulator.
///
/// `nodes` stores only non-empty interior and leaf hashes; missing positions
/// fall back to `zeros[depth]`. `leaf_count` is the number of leaves appended
/// so far (so the next leaf goes to index `leaf_count`). `zeros` is the cached
/// chain of empty-subtree hashes, one per depth level, length `D + 1`.
#[derive(Clone, Debug)]
pub struct UtxoTreeState {
    nodes: HashMap<NodeKey, [u8; 32]>,
    leaf_count: u64,
    zeros: Vec<[u8; 32]>,
}

impl UtxoTreeState {
    /// Number of leaves appended so far.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Capacity: `2^UTXO_TREE_DEPTH`.
    pub const fn capacity() -> u64 {
        1u64 << UTXO_TREE_DEPTH
    }

    /// Number of non-empty nodes currently stored (a cheap proxy for memory
    /// footprint of the state).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// Compute the cached chain of zero hashes for all depths `[0..=depth]`.
fn compute_zeros(depth: u32) -> Vec<[u8; 32]> {
    let mut zs = Vec::with_capacity(depth as usize + 1);
    zs.push(empty_leaf());
    for d in 1..=depth as usize {
        let prev = zs[d - 1];
        zs.push(dhash(UTXO_NODE, &[&prev, &prev]));
    }
    zs
}

/// A fresh, empty UTXO tree. The root of an empty tree is `zeros[D]`.
pub fn empty_utxo_tree() -> UtxoTreeState {
    UtxoTreeState {
        nodes: HashMap::new(),
        leaf_count: 0,
        zeros: compute_zeros(UTXO_TREE_DEPTH),
    }
}

/// Domain-separated leaf hash for a UTXO.
///
/// Binds the one-time stealth address `P`, the amount commitment `C`, and the
/// block `height` at which the output was anchored. Including height ties the
/// leaf to a specific point in chain history — a wallet's membership witness
/// is therefore valid only against the tree state at-or-after that height.
///
/// The 4-byte height is encoded big-endian to match the TS reference's
/// `DataView.setUint32(0, height, false)`.
pub fn utxo_leaf_hash(
    one_time_addr: &EdwardsPoint,
    amount_commit: &EdwardsPoint,
    height: u32,
) -> [u8; 32] {
    let p_bytes = one_time_addr.compress().to_bytes();
    let c_bytes = amount_commit.compress().to_bytes();
    let h_bytes = height.to_be_bytes();
    dhash(UTXO_LEAF, &[&p_bytes, &c_bytes, &h_bytes])
}

/// Capacity-exhaustion error from [`append_utxo`].
#[derive(Debug, thiserror::Error)]
pub enum UtxoTreeError {
    /// More than `2^UTXO_TREE_DEPTH` leaves have been appended.
    #[error("utxo-tree: capacity exhausted at depth {0}")]
    CapacityExhausted(u32),
}

/// Append a new leaf and return the resulting tree state.
///
/// PURE: the input state is not mutated; the returned state shares no mutable
/// references with it. (`zeros` is cloned cheaply via `Vec::clone`; we could
/// move to an `Arc<[[u8; 32]]>` if that ever shows up in a profile.) This
/// matches the rest of the chain-state API where `applyBlock` builds `next`
/// immutably so a failed validation can cleanly discard.
pub fn append_utxo(state: &UtxoTreeState, leaf: [u8; 32]) -> Result<UtxoTreeState, UtxoTreeError> {
    let idx = state.leaf_count;
    if idx >= UtxoTreeState::capacity() {
        return Err(UtxoTreeError::CapacityExhausted(UTXO_TREE_DEPTH));
    }

    let mut next = UtxoTreeState {
        nodes: state.nodes.clone(),
        leaf_count: idx + 1,
        zeros: state.zeros.clone(),
    };

    let mut cur = leaf;
    next.nodes.insert((0, idx), cur);
    let mut pos = idx;
    for d in 0..UTXO_TREE_DEPTH {
        let sib_pos = pos ^ 1;
        let sib = next
            .nodes
            .get(&(d, sib_pos))
            .copied()
            .unwrap_or(state.zeros[d as usize]);
        let is_left = (pos & 1) == 0;
        cur = if is_left {
            dhash(UTXO_NODE, &[&cur, &sib])
        } else {
            dhash(UTXO_NODE, &[&sib, &cur])
        };
        pos >>= 1;
        next.nodes.insert((d + 1, pos), cur);
    }
    Ok(next)
}

/// The 32-byte Merkle root. O(1).
pub fn utxo_tree_root(state: &UtxoTreeState) -> [u8; 32] {
    state
        .nodes
        .get(&(UTXO_TREE_DEPTH, 0))
        .copied()
        .unwrap_or(state.zeros[UTXO_TREE_DEPTH as usize])
}

/// A membership proof for one leaf.
#[derive(Clone, Debug)]
pub struct UtxoMembershipProof {
    /// Index of the leaf being proved (0-based, left-to-right append order).
    pub leaf_idx: u64,
    /// `D` sibling hashes, from leaf level (depth 0) up to just under the
    /// root (depth `D - 1`).
    pub siblings: Vec<[u8; 32]>,
}

/// Error returned by [`utxo_membership_proof`] when the requested index is
/// out of range.
#[derive(Debug, thiserror::Error)]
pub enum UtxoProofError {
    /// `leaf_idx >= leaf_count`.
    #[error("utxo-tree: leaf_idx {leaf_idx} out of range [0, {leaf_count})")]
    OutOfRange {
        /// Requested index.
        leaf_idx: u64,
        /// Number of leaves appended so far.
        leaf_count: u64,
    },
}

/// Build a membership proof for the leaf at `leaf_idx`.
///
/// The returned proof verifies against the CURRENT root. If the tree grows
/// (more leaves appended), the proof remains valid for the leaf in question
/// but only against the root AT THE TIME of proof generation — callers must
/// pin the matching root (typically from a known block header).
pub fn utxo_membership_proof(
    state: &UtxoTreeState,
    leaf_idx: u64,
) -> Result<UtxoMembershipProof, UtxoProofError> {
    if leaf_idx >= state.leaf_count {
        return Err(UtxoProofError::OutOfRange {
            leaf_idx,
            leaf_count: state.leaf_count,
        });
    }
    let mut siblings = Vec::with_capacity(UTXO_TREE_DEPTH as usize);
    let mut pos = leaf_idx;
    for d in 0..UTXO_TREE_DEPTH {
        let sib_pos = pos ^ 1;
        let sib = state
            .nodes
            .get(&(d, sib_pos))
            .copied()
            .unwrap_or(state.zeros[d as usize]);
        siblings.push(sib);
        pos >>= 1;
    }
    Ok(UtxoMembershipProof { leaf_idx, siblings })
}

/// Verify a membership proof against an expected root.
///
/// Re-hashes leaf+siblings up the tree and compares to `expected_root`. Uses a
/// constant-time final comparison via [`subtle::ConstantTimeEq`]; the hash
/// loop itself is data-independent in shape (`D` hashes regardless of input),
/// matching the TS reference.
pub fn verify_utxo_membership(
    leaf: &[u8; 32],
    proof: &UtxoMembershipProof,
    expected_root: &[u8; 32],
) -> bool {
    if proof.siblings.len() != UTXO_TREE_DEPTH as usize {
        return false;
    }
    let mut cur = *leaf;
    let mut pos = proof.leaf_idx;
    for d in 0..UTXO_TREE_DEPTH as usize {
        let sib = proof.siblings[d];
        let is_left = (pos & 1) == 0;
        cur = if is_left {
            dhash(UTXO_NODE, &[&cur, &sib])
        } else {
            dhash(UTXO_NODE, &[&sib, &cur])
        };
        pos >>= 1;
    }
    cur.ct_eq(expected_root).into()
}

/// Pretty-print a root or sibling hash for logs.
pub fn short_root(b: &[u8; 32]) -> String {
    let hex = hex::encode(b);
    format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
}

/* ----------------------------------------------------------------------- *
 *  Persistence codec (M2.0.15)                                              *
 * ----------------------------------------------------------------------- */

/// Errors produced by [`decode_utxo_tree_state`].
///
/// The codec is **structural**: it does not re-verify Merkle consistency
/// (re-hashing every node would defeat the purpose of a checkpoint).
/// What it does verify:
///
/// - varints fit; lengths fit `usize`;
/// - every `(depth, index)` key has `depth ≤ UTXO_TREE_DEPTH`;
/// - the sequence of keys is **strictly ascending** lexicographically
///   on `(depth, index)`, which simultaneously guarantees deterministic
///   encoding and prohibits duplicate keys;
/// - the encoded `leaf_count` does not exceed [`UtxoTreeState::capacity`].
///
/// Callers wanting to verify that the restored tree actually anchors
/// the expected `utxo_root` should compute [`utxo_tree_root`] on the
/// decoded state and compare to a known good root from a block header.
#[derive(Debug, thiserror::Error)]
pub enum UtxoTreeDecodeError {
    /// The buffer ran out before the expected number of bytes were
    /// available at `field`.
    #[error("utxo-tree decode: truncated at `{field}`: needed {needed} more byte(s)")]
    Truncated {
        /// Symbolic name of the field that was being read when truncation hit.
        field: &'static str,
        /// Bytes still required.
        needed: usize,
    },
    /// A length-prefix varint overflowed `u64`.
    #[error("utxo-tree decode: varint overflow at `{field}`")]
    VarintOverflow {
        /// Field whose length was being read.
        field: &'static str,
    },
    /// A `u64` length did not fit `usize` on this platform.
    #[error("utxo-tree decode: length {got} at `{field}` exceeds usize")]
    LengthOverflow {
        /// The raw `u64` length read.
        got: u64,
        /// Field whose length was being read.
        field: &'static str,
    },
    /// `leaf_count > 2^UTXO_TREE_DEPTH` — implies the encoder produced
    /// an invalid tree.
    #[error("utxo-tree decode: leaf_count {got} exceeds capacity {capacity}")]
    LeafCountExceedsCapacity {
        /// Encoded leaf count.
        got: u64,
        /// `UtxoTreeState::capacity()`.
        capacity: u64,
    },
    /// A `(depth, index)` key had `depth > UTXO_TREE_DEPTH`.
    #[error("utxo-tree decode: node #{node} has depth {depth} > UTXO_TREE_DEPTH ({max_depth})")]
    DepthOutOfRange {
        /// Position of the offending entry in the encoded list.
        node: usize,
        /// Read depth.
        depth: u32,
        /// Configured maximum.
        max_depth: u32,
    },
    /// Two consecutive `(depth, index)` keys were not strictly ascending
    /// — either a duplicate or an encoder bug.
    #[error("utxo-tree decode: nodes not strictly ascending at #{node}")]
    NodesNotSorted {
        /// Position in the list where ordering broke.
        node: usize,
    },
    /// Trailing bytes after the encoded body.
    #[error("utxo-tree decode: {remaining} trailing byte(s)")]
    TrailingBytes {
        /// Number of unread bytes after a successful decode.
        remaining: usize,
    },
}

impl UtxoTreeState {
    /// Iterate every persisted `(depth, index, hash)` triple. Order is
    /// **unspecified** — sort by `(depth, index)` before relying on
    /// determinism (e.g. inside a codec). The accessor exists primarily
    /// so external persistence layers can serialise the sparse tree
    /// without having to mutate the private `nodes` map.
    pub fn nodes_iter(&self) -> impl Iterator<Item = (u32, u64, [u8; 32])> + '_ {
        self.nodes.iter().map(|((d, i), h)| (*d, *i, *h))
    }

    /// Rebuild a [`UtxoTreeState`] from raw `(depth, index, hash)`
    /// entries + a `leaf_count`. `zeros` is recomputed deterministically
    /// from [`UTXO_TREE_DEPTH`] — it is **not** part of the canonical
    /// state.
    ///
    /// Used by [`decode_utxo_tree_state`] and any external caller that
    /// stores the tree in its own format (e.g. RocksDB column families).
    /// The function does **not** re-verify Merkle consistency.
    ///
    /// # Errors
    ///
    /// - [`UtxoTreeDecodeError::LeafCountExceedsCapacity`] when
    ///   `leaf_count > 2^UTXO_TREE_DEPTH`.
    /// - [`UtxoTreeDecodeError::DepthOutOfRange`] when any entry has
    ///   `depth > UTXO_TREE_DEPTH`.
    pub fn from_parts(
        nodes: HashMap<(u32, u64), [u8; 32]>,
        leaf_count: u64,
    ) -> Result<Self, UtxoTreeDecodeError> {
        if leaf_count > Self::capacity() {
            return Err(UtxoTreeDecodeError::LeafCountExceedsCapacity {
                got: leaf_count,
                capacity: Self::capacity(),
            });
        }
        for (i, &(d, _)) in nodes.keys().enumerate() {
            if d > UTXO_TREE_DEPTH {
                return Err(UtxoTreeDecodeError::DepthOutOfRange {
                    node: i,
                    depth: d,
                    max_depth: UTXO_TREE_DEPTH,
                });
            }
        }
        Ok(Self {
            nodes,
            leaf_count,
            zeros: compute_zeros(UTXO_TREE_DEPTH),
        })
    }
}

/// Encode a [`UtxoTreeState`] to its canonical bytes.
///
/// Layout:
///
/// ```text
///   leaf_count               u64 BE
///   nodes.len()              varint
///   for each (depth, index)
///     sorted ascending by:
///        depth               u32 BE
///        index               u64 BE
///        hash                32 bytes
/// ```
///
/// `zeros` is **not** serialised — it is derived from
/// [`UTXO_TREE_DEPTH`] and reconstructed identically on decode.
#[must_use]
pub fn encode_utxo_tree_state(state: &UtxoTreeState) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(state.leaf_count);
    let mut entries: Vec<(u32, u64, [u8; 32])> = state.nodes_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    w.varint(entries.len() as u64);
    for (d, i, h) in &entries {
        w.u32(*d);
        w.u64(*i);
        w.push(h);
    }
    w.into_bytes()
}

/// Decode a [`UtxoTreeState`] from canonical bytes produced by
/// [`encode_utxo_tree_state`]. The decoder is **strict**:
///
/// - depth is bounded by [`UTXO_TREE_DEPTH`];
/// - `(depth, index)` pairs must be strictly ascending (enforces
///   determinism + no duplicates);
/// - any trailing bytes are rejected.
///
/// # Errors
///
/// See [`UtxoTreeDecodeError`].
pub fn decode_utxo_tree_state(bytes: &[u8]) -> Result<UtxoTreeState, UtxoTreeDecodeError> {
    let mut r = Reader::new(bytes);
    let leaf_count = r.u64().map_err(|_| UtxoTreeDecodeError::Truncated {
        field: "leaf_count",
        needed: 8,
    })?;
    if leaf_count > UtxoTreeState::capacity() {
        return Err(UtxoTreeDecodeError::LeafCountExceedsCapacity {
            got: leaf_count,
            capacity: UtxoTreeState::capacity(),
        });
    }
    let raw_n = r
        .varint()
        .map_err(|_| UtxoTreeDecodeError::VarintOverflow { field: "nodes.len" })?;
    let n = usize::try_from(raw_n).map_err(|_| UtxoTreeDecodeError::LengthOverflow {
        got: raw_n,
        field: "nodes.len",
    })?;
    let mut nodes: HashMap<(u32, u64), [u8; 32]> = HashMap::with_capacity(n);
    let mut prev: Option<(u32, u64)> = None;
    for i in 0..n {
        let depth = r.u32().map_err(|_| UtxoTreeDecodeError::Truncated {
            field: "nodes[i].depth",
            needed: 4,
        })?;
        if depth > UTXO_TREE_DEPTH {
            return Err(UtxoTreeDecodeError::DepthOutOfRange {
                node: i,
                depth,
                max_depth: UTXO_TREE_DEPTH,
            });
        }
        let index = r.u64().map_err(|_| UtxoTreeDecodeError::Truncated {
            field: "nodes[i].index",
            needed: 8,
        })?;
        let key = (depth, index);
        if let Some(p) = prev {
            if key <= p {
                return Err(UtxoTreeDecodeError::NodesNotSorted { node: i });
            }
        }
        prev = Some(key);
        let hash_slice = r.bytes(32).map_err(|_| UtxoTreeDecodeError::Truncated {
            field: "nodes[i].hash",
            needed: 32,
        })?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_slice);
        nodes.insert(key, hash);
    }
    if !r.end() {
        return Err(UtxoTreeDecodeError::TrailingBytes {
            remaining: r.remaining(),
        });
    }
    UtxoTreeState::from_parts(nodes, leaf_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::point::{generator_g, generator_h};
    use curve25519_dalek::scalar::Scalar;

    fn leaf_for(seed: u8) -> [u8; 32] {
        let s = Scalar::from(u64::from(seed) + 1);
        let p = generator_g() * s;
        let c = generator_h() * s;
        utxo_leaf_hash(&p, &c, u32::from(seed))
    }

    #[test]
    fn empty_root_matches_zeros_d() {
        let st = empty_utxo_tree();
        let root = utxo_tree_root(&st);
        assert_eq!(root, st.zeros[UTXO_TREE_DEPTH as usize]);
    }

    #[test]
    fn append_changes_root() {
        let st = empty_utxo_tree();
        let r0 = utxo_tree_root(&st);
        let st1 = append_utxo(&st, leaf_for(1)).unwrap();
        let r1 = utxo_tree_root(&st1);
        assert_ne!(r0, r1, "appending a leaf must change the root");
        assert_eq!(st1.leaf_count(), 1);
    }

    #[test]
    fn append_is_pure() {
        let st = empty_utxo_tree();
        let _st1 = append_utxo(&st, leaf_for(1)).unwrap();
        assert_eq!(st.leaf_count(), 0, "original state must not be mutated");
        assert_eq!(utxo_tree_root(&st), st.zeros[UTXO_TREE_DEPTH as usize]);
    }

    #[test]
    fn membership_proof_roundtrip_first_leaf() {
        let st0 = empty_utxo_tree();
        let leaf = leaf_for(7);
        let st1 = append_utxo(&st0, leaf).unwrap();
        let proof = utxo_membership_proof(&st1, 0).unwrap();
        let root = utxo_tree_root(&st1);
        assert!(verify_utxo_membership(&leaf, &proof, &root));
    }

    #[test]
    fn membership_proof_for_each_of_many_leaves() {
        let mut st = empty_utxo_tree();
        let mut leaves = Vec::new();
        for i in 0u8..16 {
            let l = leaf_for(i);
            leaves.push(l);
            st = append_utxo(&st, l).unwrap();
        }
        let root = utxo_tree_root(&st);
        for (i, l) in leaves.iter().enumerate() {
            let proof = utxo_membership_proof(&st, i as u64).unwrap();
            assert!(
                verify_utxo_membership(l, &proof, &root),
                "leaf {i} proof must verify against final root"
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let mut st = empty_utxo_tree();
        for i in 0u8..4 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let root = utxo_tree_root(&st);
        let proof = utxo_membership_proof(&st, 1).unwrap();

        let wrong = leaf_for(99);
        assert!(!verify_utxo_membership(&wrong, &proof, &root));
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let mut st = empty_utxo_tree();
        for i in 0u8..4 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let leaf = leaf_for(1);
        let proof = utxo_membership_proof(&st, 1).unwrap();

        let mut bad_root = utxo_tree_root(&st);
        bad_root[0] ^= 0xff;
        assert!(!verify_utxo_membership(&leaf, &proof, &bad_root));
    }

    #[test]
    fn proof_rejects_tampered_sibling() {
        let mut st = empty_utxo_tree();
        for i in 0u8..4 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let leaf = leaf_for(1);
        let root = utxo_tree_root(&st);
        let mut proof = utxo_membership_proof(&st, 1).unwrap();
        proof.siblings[0][0] ^= 0xff;
        assert!(!verify_utxo_membership(&leaf, &proof, &root));
    }

    #[test]
    fn proof_rejects_wrong_index() {
        let mut st = empty_utxo_tree();
        for i in 0u8..4 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let leaf = leaf_for(1);
        let root = utxo_tree_root(&st);
        let mut proof = utxo_membership_proof(&st, 1).unwrap();
        proof.leaf_idx = 2;
        assert!(!verify_utxo_membership(&leaf, &proof, &root));
    }

    #[test]
    fn out_of_range_proof_request_errors() {
        let st = empty_utxo_tree();
        let err = utxo_membership_proof(&st, 0).unwrap_err();
        match err {
            UtxoProofError::OutOfRange {
                leaf_idx,
                leaf_count,
            } => {
                assert_eq!(leaf_idx, 0);
                assert_eq!(leaf_count, 0);
            }
        }
    }

    #[test]
    fn sibling_count_equals_depth() {
        let mut st = empty_utxo_tree();
        st = append_utxo(&st, leaf_for(0)).unwrap();
        let proof = utxo_membership_proof(&st, 0).unwrap();
        assert_eq!(proof.siblings.len(), UTXO_TREE_DEPTH as usize);
    }

    #[test]
    fn zeros_chain_is_consistent() {
        let st = empty_utxo_tree();
        for d in 0..UTXO_TREE_DEPTH as usize {
            let expected = dhash(UTXO_NODE, &[&st.zeros[d], &st.zeros[d]]);
            assert_eq!(st.zeros[d + 1], expected, "zeros[{}] mismatch", d + 1);
        }
    }

    #[test]
    fn root_stable_for_same_appends() {
        let mut st_a = empty_utxo_tree();
        let mut st_b = empty_utxo_tree();
        for i in 0u8..8 {
            st_a = append_utxo(&st_a, leaf_for(i)).unwrap();
            st_b = append_utxo(&st_b, leaf_for(i)).unwrap();
        }
        assert_eq!(utxo_tree_root(&st_a), utxo_tree_root(&st_b));
    }

    #[test]
    fn different_append_orders_yield_different_roots() {
        let mut st_a = empty_utxo_tree();
        st_a = append_utxo(&st_a, leaf_for(1)).unwrap();
        st_a = append_utxo(&st_a, leaf_for(2)).unwrap();

        let mut st_b = empty_utxo_tree();
        st_b = append_utxo(&st_b, leaf_for(2)).unwrap();
        st_b = append_utxo(&st_b, leaf_for(1)).unwrap();

        assert_ne!(
            utxo_tree_root(&st_a),
            utxo_tree_root(&st_b),
            "tree is order-sensitive (append-only)"
        );
    }

    #[test]
    fn leaf_hash_distinguishes_height() {
        let s = Scalar::from(42u64);
        let p = generator_g() * s;
        let c = generator_h() * s;
        let h1 = utxo_leaf_hash(&p, &c, 10);
        let h2 = utxo_leaf_hash(&p, &c, 11);
        assert_ne!(h1, h2);
    }

    #[test]
    fn leaf_hash_distinguishes_address() {
        let s1 = Scalar::from(1u64);
        let s2 = Scalar::from(2u64);
        let c = generator_h() * Scalar::from(99u64);
        let h1 = utxo_leaf_hash(&(generator_g() * s1), &c, 100);
        let h2 = utxo_leaf_hash(&(generator_g() * s2), &c, 100);
        assert_ne!(h1, h2);
    }

    #[test]
    fn leaf_hash_distinguishes_commitment() {
        let s = Scalar::from(7u64);
        let p = generator_g() * s;
        let c1 = generator_h() * Scalar::from(1u64);
        let c2 = generator_h() * Scalar::from(2u64);
        let h1 = utxo_leaf_hash(&p, &c1, 0);
        let h2 = utxo_leaf_hash(&p, &c2, 0);
        assert_ne!(h1, h2);
    }

    /* ------------------------------------------------------------------- *
     *  Persistence codec (M2.0.15)                                          *
     * ------------------------------------------------------------------- */

    #[test]
    fn utxo_tree_codec_empty_round_trip() {
        let st = empty_utxo_tree();
        let bytes = encode_utxo_tree_state(&st);
        let st2 = decode_utxo_tree_state(&bytes).unwrap();
        assert_eq!(st.leaf_count(), st2.leaf_count());
        assert_eq!(utxo_tree_root(&st), utxo_tree_root(&st2));
        assert_eq!(encode_utxo_tree_state(&st2), bytes);
    }

    #[test]
    fn utxo_tree_codec_many_leaves_round_trip() {
        let mut st = empty_utxo_tree();
        for i in 0u8..16 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let bytes = encode_utxo_tree_state(&st);
        let st2 = decode_utxo_tree_state(&bytes).unwrap();
        assert_eq!(st.leaf_count(), st2.leaf_count());
        assert_eq!(utxo_tree_root(&st), utxo_tree_root(&st2));
        let bytes2 = encode_utxo_tree_state(&st2);
        assert_eq!(
            bytes, bytes2,
            "encoding must be deterministic on round-trip"
        );

        for i in 0u8..16 {
            let leaf = leaf_for(i);
            let p_orig = utxo_membership_proof(&st, u64::from(i)).unwrap();
            let p_res = utxo_membership_proof(&st2, u64::from(i)).unwrap();
            assert_eq!(
                p_orig.siblings, p_res.siblings,
                "siblings differ at leaf {i}"
            );
            let root = utxo_tree_root(&st2);
            assert!(verify_utxo_membership(&leaf, &p_res, &root));
        }
    }

    #[test]
    fn utxo_tree_codec_is_deterministic_independent_of_append_order() {
        let mut st_a = empty_utxo_tree();
        let mut st_b = empty_utxo_tree();
        for i in 0u8..8 {
            st_a = append_utxo(&st_a, leaf_for(i)).unwrap();
        }
        for i in 0u8..8 {
            st_b = append_utxo(&st_b, leaf_for(i)).unwrap();
        }
        let a = encode_utxo_tree_state(&st_a);
        let b = encode_utxo_tree_state(&st_b);
        assert_eq!(
            a, b,
            "two identical histories must encode to identical bytes"
        );
    }

    #[test]
    fn utxo_tree_codec_rejects_truncation() {
        let mut st = empty_utxo_tree();
        for i in 0u8..3 {
            st = append_utxo(&st, leaf_for(i)).unwrap();
        }
        let bytes = encode_utxo_tree_state(&st);
        for cut in 0..bytes.len() {
            assert!(
                decode_utxo_tree_state(&bytes[..cut]).is_err(),
                "decode must reject truncation at {cut}"
            );
        }
    }

    #[test]
    fn utxo_tree_codec_rejects_trailing_bytes() {
        let st = empty_utxo_tree();
        let mut bytes = encode_utxo_tree_state(&st);
        bytes.push(0u8);
        match decode_utxo_tree_state(&bytes) {
            Err(UtxoTreeDecodeError::TrailingBytes { remaining }) => assert_eq!(remaining, 1),
            other => panic!("expected TrailingBytes, got {other:?}"),
        }
    }

    #[test]
    fn utxo_tree_codec_rejects_unsorted_nodes() {
        let mut w = Writer::new();
        w.u64(2);
        w.varint(2);
        w.u32(0);
        w.u64(1);
        w.push(&[0u8; 32]);
        w.u32(0);
        w.u64(0);
        w.push(&[0u8; 32]);
        let bad = w.into_bytes();
        match decode_utxo_tree_state(&bad) {
            Err(UtxoTreeDecodeError::NodesNotSorted { node }) => assert_eq!(node, 1),
            other => panic!("expected NodesNotSorted, got {other:?}"),
        }
    }

    #[test]
    fn utxo_tree_codec_rejects_depth_out_of_range() {
        let mut w = Writer::new();
        w.u64(0);
        w.varint(1);
        w.u32(UTXO_TREE_DEPTH + 1);
        w.u64(0);
        w.push(&[0u8; 32]);
        let bad = w.into_bytes();
        match decode_utxo_tree_state(&bad) {
            Err(UtxoTreeDecodeError::DepthOutOfRange {
                node,
                depth,
                max_depth,
            }) => {
                assert_eq!(node, 0);
                assert_eq!(depth, UTXO_TREE_DEPTH + 1);
                assert_eq!(max_depth, UTXO_TREE_DEPTH);
            }
            other => panic!("expected DepthOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn utxo_tree_codec_rejects_leaf_count_above_capacity() {
        let mut w = Writer::new();
        w.u64(UtxoTreeState::capacity() + 1);
        w.varint(0);
        let bad = w.into_bytes();
        match decode_utxo_tree_state(&bad) {
            Err(UtxoTreeDecodeError::LeafCountExceedsCapacity { got, capacity }) => {
                assert_eq!(got, UtxoTreeState::capacity() + 1);
                assert_eq!(capacity, UtxoTreeState::capacity());
            }
            other => panic!("expected LeafCountExceedsCapacity, got {other:?}"),
        }
    }
}
