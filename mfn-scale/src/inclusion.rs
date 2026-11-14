//! Light-client inclusion checks.
//!
//! A proof is accepted only against a header this book has already linked
//! from a trusted genesis id. A server that offers a proof for some other
//! header id is refused. The book does not learn which output the caller
//! cares about beyond the proof the caller chose to check locally.

use mfn_crypto::{
    append_utxo, empty_utxo_tree, utxo_membership_proof, utxo_tree_root, verify_merkle_proof,
    verify_utxo_membership, MerkleProof, UtxoMembershipProof, UtxoTreeState,
};

/// A header commitment the book is willing to check proofs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedHeader {
    /// Height. The first admitted header is height 1.
    pub height: u32,
    /// Header id.
    pub block_id: [u8; 32],
    /// Previous header id.
    pub prev_id: [u8; 32],
    /// Transaction Merkle root.
    pub tx_root: [u8; 32],
    /// UTXO accumulator root.
    pub utxo_root: [u8; 32],
}

/// Why a header was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmitHeaderError {
    /// Height was not the next height.
    #[error("height {got}, expected {expected}")]
    Height {
        /// Next height.
        expected: u32,
        /// Offered height.
        got: u32,
    },
    /// Previous id did not match the current tip.
    #[error("previous id does not match the book tip")]
    Prev,
}

/// Why an inclusion check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InclusionError {
    /// No admitted header has this id.
    #[error("header is not in the book")]
    UnknownHeader,
    /// The proof does not reach the admitted root.
    #[error("proof does not match the admitted root")]
    NotIncluded,
}

/// Headers linked from a trusted genesis id.
#[derive(Clone, Debug)]
pub struct HeaderBook {
    tip: [u8; 32],
    next_height: u32,
    headers: Vec<AdmittedHeader>,
}

impl HeaderBook {
    /// Empty book. The tip is the trusted genesis id. Nothing is admitted.
    #[must_use]
    pub fn from_genesis(genesis_id: [u8; 32]) -> Self {
        Self {
            tip: genesis_id,
            next_height: 1,
            headers: Vec::new(),
        }
    }

    /// Admitted headers, in order.
    #[must_use]
    pub fn headers(&self) -> &[AdmittedHeader] {
        &self.headers
    }

    /// Link `header` onto the book.
    ///
    /// # Errors
    ///
    /// [`AdmitHeaderError`] when the height or previous id does not continue
    /// the book. The book is unchanged.
    pub fn admit(&mut self, header: AdmittedHeader) -> Result<(), AdmitHeaderError> {
        if header.height != self.next_height {
            return Err(AdmitHeaderError::Height {
                expected: self.next_height,
                got: header.height,
            });
        }
        if header.prev_id != self.tip {
            return Err(AdmitHeaderError::Prev);
        }
        self.tip = header.block_id;
        self.next_height = self.next_height.saturating_add(1);
        self.headers.push(header);
        Ok(())
    }

    /// `true` when `leaf` is in the admitted header's transaction root.
    ///
    /// # Errors
    ///
    /// [`InclusionError::UnknownHeader`] when `block_id` was never admitted.
    /// [`InclusionError::NotIncluded`] when the proof does not match.
    pub fn prove_tx(
        &self,
        block_id: &[u8; 32],
        leaf: &[u8; 32],
        proof: &MerkleProof,
    ) -> Result<(), InclusionError> {
        let header = self
            .headers
            .iter()
            .find(|header| header.block_id == *block_id)
            .ok_or(InclusionError::UnknownHeader)?;
        if verify_merkle_proof(leaf, proof, &header.tx_root) {
            Ok(())
        } else {
            Err(InclusionError::NotIncluded)
        }
    }

    /// `true` when `leaf` is in the admitted header's UTXO root.
    ///
    /// # Errors
    ///
    /// Same as [`Self::prove_tx`].
    pub fn prove_utxo(
        &self,
        block_id: &[u8; 32],
        leaf: &[u8; 32],
        proof: &UtxoMembershipProof,
    ) -> Result<(), InclusionError> {
        let header = self
            .headers
            .iter()
            .find(|header| header.block_id == *block_id)
            .ok_or(InclusionError::UnknownHeader)?;
        if verify_utxo_membership(leaf, proof, &header.utxo_root) {
            Ok(())
        } else {
            Err(InclusionError::NotIncluded)
        }
    }
}

/// Build a small UTXO tree and return `(state, root)`.
///
/// # Errors
///
/// Returns the append error string if a leaf does not fit.
pub fn sample_utxo_tree(leaves: &[[u8; 32]]) -> Result<(UtxoTreeState, [u8; 32]), String> {
    let mut state = empty_utxo_tree();
    for leaf in leaves {
        state = append_utxo(&state, *leaf).map_err(|err| err.to_string())?;
    }
    let root = utxo_tree_root(&state);
    Ok((state, root))
}

/// Membership proof for `index` in `state`.
///
/// # Errors
///
/// Returns the proof error string when `index` is out of range.
pub fn sample_utxo_proof(state: &UtxoTreeState, index: u64) -> Result<UtxoMembershipProof, String> {
    utxo_membership_proof(state, index).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::{merkle_proof, merkle_tree_from_leaves};

    fn genesis() -> [u8; 32] {
        [0xA1; 32]
    }

    fn tx_leaves() -> Vec<[u8; 32]> {
        (0..4u8)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i;
                leaf
            })
            .collect()
    }

    #[test]
    fn a_linked_header_accepts_its_tx_proof_and_rejects_a_foreign_one() {
        let leaves = tx_leaves();
        let tree = merkle_tree_from_leaves(&leaves).expect("tree");
        let proof = merkle_proof(&tree, 2).expect("proof");
        let mut book = HeaderBook::from_genesis(genesis());
        let header = AdmittedHeader {
            height: 1,
            block_id: [0xB1; 32],
            prev_id: genesis(),
            tx_root: tree.root(),
            utxo_root: [0u8; 32],
        };
        book.admit(header).expect("admit");
        book.prove_tx(&header.block_id, &leaves[2], &proof)
            .expect("included");
        let mut bad = proof.clone();
        bad.siblings[0][0] ^= 0xff;
        assert_eq!(
            book.prove_tx(&header.block_id, &leaves[2], &bad)
                .unwrap_err(),
            InclusionError::NotIncluded
        );
        assert_eq!(
            book.prove_tx(&[0xEE; 32], &leaves[2], &proof).unwrap_err(),
            InclusionError::UnknownHeader
        );
    }

    #[test]
    fn a_header_that_does_not_link_is_not_admitted() {
        let mut book = HeaderBook::from_genesis(genesis());
        let err = book
            .admit(AdmittedHeader {
                height: 1,
                block_id: [2; 32],
                prev_id: [3; 32],
                tx_root: [0; 32],
                utxo_root: [0; 32],
            })
            .expect_err("prev");
        assert_eq!(err, AdmitHeaderError::Prev);
        assert!(book.headers().is_empty());
        let err = book
            .admit(AdmittedHeader {
                height: 4,
                block_id: [2; 32],
                prev_id: genesis(),
                tx_root: [0; 32],
                utxo_root: [0; 32],
            })
            .expect_err("height");
        assert_eq!(
            err,
            AdmitHeaderError::Height {
                expected: 1,
                got: 4
            }
        );
    }

    #[test]
    fn a_utxo_proof_matches_only_the_admitted_root() {
        let leaves = tx_leaves();
        let (state, root) = sample_utxo_tree(&leaves).expect("tree");
        let proof = sample_utxo_proof(&state, 1).expect("proof");
        let mut book = HeaderBook::from_genesis(genesis());
        let header = AdmittedHeader {
            height: 1,
            block_id: [0xC1; 32],
            prev_id: genesis(),
            tx_root: [0u8; 32],
            utxo_root: root,
        };
        book.admit(header).expect("admit");
        book.prove_utxo(&header.block_id, &leaves[1], &proof)
            .expect("member");
        let mut other = header;
        other.height = 2;
        other.prev_id = header.block_id;
        other.block_id = [0xC2; 32];
        other.utxo_root = [0x11; 32];
        book.admit(other).expect("second");
        assert_eq!(
            book.prove_utxo(&other.block_id, &leaves[1], &proof)
                .unwrap_err(),
            InclusionError::NotIncluded
        );
    }
}
