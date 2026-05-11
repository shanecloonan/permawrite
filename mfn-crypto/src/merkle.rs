//! Binary Merkle tree over pre-hashed leaves.
//!
//! Standard scheme:
//!
//! - Leaves are already-hashed 32-byte digests (e.g. `tx_id(tx)` or
//!   `chunk_hash(bytes)`). This module does NOT re-hash them.
//! - Interior nodes use `dhash(MERKLE_NODE, left || right)`.
//! - When a level has an odd number of nodes, the last node is duplicated
//!   (the same scheme Bitcoin uses) — simple and unambiguous.
//!
//! Port of the binary-Merkle subset of `lib/network/storage.ts`. The
//! data-side Merkle root (with `MERKLE_LEAF`-tagged leaf hashing) used by
//! the SPoRA storage prover will live in the future `mfn-storage` crate;
//! here we only need the consensus-side primitive that hashes already-
//! computed 32-byte ids into a single root.
//!
//! ## Empty input
//!
//! [`merkle_root_or_zero`] returns the all-zero 32-byte sentinel for an
//! empty input (matching the TS reference's `txMerkleRoot([])`). Callers
//! that want to forbid empty inputs use [`merkle_tree_from_leaves`], which
//! returns `Err(MerkleError::Empty)`.

use crate::domain::MERKLE_NODE;
use crate::hash::dhash;

/// A fully-materialized Merkle tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `levels[0]` = leaves; `levels[depth]` = single-element root array.
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// The Merkle root. Equal to `levels[depth][0]`.
    pub fn root(&self) -> [u8; 32] {
        *self
            .levels
            .last()
            .expect("non-empty tree")
            .first()
            .expect("at least one node")
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }
}

/// A Merkle inclusion proof for one leaf.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Sibling hashes from leaf level upward (excluding the root).
    pub siblings: Vec<[u8; 32]>,
    /// For each step: `false` ⇒ sibling on the right, `true` ⇒ sibling on
    /// the left. Bool flips when the current node is itself on the right
    /// side of its pair.
    pub right_side: Vec<bool>,
    /// The leaf index this proof targets.
    pub index: usize,
}

/// Errors raised by Merkle builders/verifiers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    /// Caller supplied zero leaves.
    #[error("empty input")]
    Empty,
    /// Leaf index out of range.
    #[error("leaf index {idx} out of range [0, {count})")]
    IndexOutOfRange {
        /// Requested index.
        idx: usize,
        /// Number of leaves in the tree.
        count: usize,
    },
}

/// Build a Merkle tree from already-hashed 32-byte leaves.
pub fn merkle_tree_from_leaves(leaves: &[[u8; 32]]) -> Result<MerkleTree, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    levels.push(leaves.to_vec());
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(prev.len().div_ceil(2));
        let n = prev.len();
        let mut i = 0;
        while i < n {
            let left = prev[i];
            let right = if i + 1 < n { prev[i + 1] } else { prev[i] };
            next.push(dhash(MERKLE_NODE, &[&left, &right]));
            i += 2;
        }
        levels.push(next);
    }
    Ok(MerkleTree { levels })
}

/// Convenience: just the Merkle root, or `[0u8; 32]` for empty input.
///
/// Matches the TS reference's `txMerkleRoot([])` and `storageMerkleRoot([])`
/// behavior.
pub fn merkle_root_or_zero(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    merkle_tree_from_leaves(leaves).unwrap().root()
}

/// Build a Merkle inclusion proof for the leaf at `leaf_idx`.
pub fn merkle_proof(tree: &MerkleTree, leaf_idx: usize) -> Result<MerkleProof, MerkleError> {
    let count = tree.levels[0].len();
    if leaf_idx >= count {
        return Err(MerkleError::IndexOutOfRange {
            idx: leaf_idx,
            count,
        });
    }
    let mut siblings = Vec::with_capacity(tree.levels.len());
    let mut right_side = Vec::with_capacity(tree.levels.len());
    let mut idx = leaf_idx;
    for lvl in 0..tree.levels.len() - 1 {
        let layer = &tree.levels[lvl];
        let is_right = idx & 1 == 1;
        let sibling_idx = if is_right {
            idx - 1
        } else {
            (idx + 1).min(layer.len() - 1)
        };
        siblings.push(layer[sibling_idx]);
        right_side.push(is_right);
        idx >>= 1;
    }
    Ok(MerkleProof {
        siblings,
        right_side,
        index: leaf_idx,
    })
}

/// Verify a Merkle inclusion proof. Returns `true` iff `leaf` hashes up to
/// `root` along `proof`.
///
/// Note: the leaf is treated as ALREADY a 32-byte digest (it is not
/// re-hashed). For data-chunk Merkle proofs that wrap chunks with
/// `MERKLE_LEAF`-tagged hashing, see `mfn-storage`.
pub fn verify_merkle_proof(leaf: &[u8; 32], proof: &MerkleProof, root: &[u8; 32]) -> bool {
    if proof.siblings.len() != proof.right_side.len() {
        return false;
    }
    let mut acc = *leaf;
    for i in 0..proof.siblings.len() {
        let sib = proof.siblings[i];
        acc = if proof.right_side[i] {
            dhash(MERKLE_NODE, &[&sib, &acc])
        } else {
            dhash(MERKLE_NODE, &[&acc, &sib])
        };
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn empty_root_is_zero_sentinel() {
        assert_eq!(merkle_root_or_zero(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let l = leaf(42);
        let t = merkle_tree_from_leaves(&[l]).unwrap();
        assert_eq!(t.root(), l);
    }

    #[test]
    fn two_leaves_root_is_node_hash() {
        let l0 = leaf(1);
        let l1 = leaf(2);
        let t = merkle_tree_from_leaves(&[l0, l1]).unwrap();
        assert_eq!(t.root(), dhash(MERKLE_NODE, &[&l0, &l1]));
    }

    #[test]
    fn odd_count_duplicates_last() {
        let l0 = leaf(1);
        let l1 = leaf(2);
        let l2 = leaf(3);
        let t = merkle_tree_from_leaves(&[l0, l1, l2]).unwrap();
        let lvl1_left = dhash(MERKLE_NODE, &[&l0, &l1]);
        let lvl1_right = dhash(MERKLE_NODE, &[&l2, &l2]);
        let root = dhash(MERKLE_NODE, &[&lvl1_left, &lvl1_right]);
        assert_eq!(t.root(), root);
    }

    #[test]
    fn proof_round_trip_each_leaf() {
        let leaves: Vec<[u8; 32]> = (0..7u8).map(leaf).collect();
        let t = merkle_tree_from_leaves(&leaves).unwrap();
        let root = t.root();
        for (idx, l) in leaves.iter().enumerate() {
            let p = merkle_proof(&t, idx).unwrap();
            assert!(
                verify_merkle_proof(l, &p, &root),
                "leaf {idx} proof must verify"
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(leaf).collect();
        let t = merkle_tree_from_leaves(&leaves).unwrap();
        let p = merkle_proof(&t, 2).unwrap();
        let mut bad = t.root();
        bad[0] ^= 0xff;
        assert!(!verify_merkle_proof(&leaves[2], &p, &bad));
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(leaf).collect();
        let t = merkle_tree_from_leaves(&leaves).unwrap();
        let p = merkle_proof(&t, 2).unwrap();
        let bogus = leaf(99);
        assert!(!verify_merkle_proof(&bogus, &p, &t.root()));
    }

    #[test]
    fn proof_rejects_swapped_side_flags() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(leaf).collect();
        let t = merkle_tree_from_leaves(&leaves).unwrap();
        let mut p = merkle_proof(&t, 1).unwrap();
        for b in p.right_side.iter_mut() {
            *b = !*b;
        }
        assert!(!verify_merkle_proof(&leaves[1], &p, &t.root()));
    }

    #[test]
    fn empty_returns_error() {
        assert_eq!(
            merkle_tree_from_leaves(&[]).unwrap_err(),
            MerkleError::Empty
        );
    }

    #[test]
    fn out_of_range_proof_request_errors() {
        let leaves = vec![leaf(1)];
        let t = merkle_tree_from_leaves(&leaves).unwrap();
        assert_eq!(
            merkle_proof(&t, 1).unwrap_err(),
            MerkleError::IndexOutOfRange { idx: 1, count: 1 }
        );
    }
}
