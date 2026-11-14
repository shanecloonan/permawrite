//! Light wallet path.
//!
//! One object follows linked headers, checks inclusion against those
//! headers, scans stealth outputs on the device, and keeps block bodies
//! inside a byte cap. The only network request it builds is an
//! [`OutputWindowRequest`]: two heights, eight bytes, no view key.

use mfn_crypto::{point_to_bytes, stealth_detect, StealthOutput, StealthWallet};

use crate::inclusion::{AdmitHeaderError, AdmittedHeader, HeaderBook, InclusionError};
use crate::memory::{AdmitError, BodyCache};
use crate::private_scan::{OutputWindowRequest, ScanError};
use mfn_crypto::MerkleProof;

/// A wallet that does not send its keys to a server.
#[derive(Clone, Debug)]
pub struct LightWallet {
    book: HeaderBook,
    cache: BodyCache,
    wallet: StealthWallet,
}

impl LightWallet {
    /// Start from a trusted genesis id, a body-cache cap, and a local wallet.
    #[must_use]
    pub fn open(genesis_id: [u8; 32], body_cap: u64, wallet: StealthWallet) -> Self {
        Self {
            book: HeaderBook::from_genesis(genesis_id),
            cache: BodyCache::new(body_cap),
            wallet,
        }
    }

    /// Public view key bytes. This is for the owner. It is not a request.
    #[must_use]
    pub fn view_public_bytes(&self) -> [u8; 32] {
        point_to_bytes(&self.wallet.view_pub)
    }

    /// Admit the next header. It must continue the book's tip.
    ///
    /// # Errors
    ///
    /// [`AdmitHeaderError`] when the height or previous id does not link.
    /// The book is unchanged.
    pub fn follow(&mut self, header: AdmittedHeader) -> Result<(), AdmitHeaderError> {
        self.book.admit(header)
    }

    /// Height window to ask the network for. No key material.
    ///
    /// # Errors
    ///
    /// [`ScanError::Inverted`] when the range is backwards.
    pub fn output_window(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Result<OutputWindowRequest, ScanError> {
        let _ = self;
        OutputWindowRequest::new(start_height, end_height)
    }

    /// Outputs in `outputs` that this wallet can see. Detection is local.
    #[must_use]
    pub fn scan(&self, outputs: &[StealthOutput]) -> Vec<usize> {
        outputs
            .iter()
            .enumerate()
            .filter_map(|(index, output)| stealth_detect(output, &self.wallet).then_some(index))
            .collect()
    }

    /// Check that `leaf` sits in an admitted header's transaction root.
    ///
    /// # Errors
    ///
    /// [`InclusionError`] when the header was never followed or the proof fails.
    pub fn prove_tx(
        &self,
        block_id: &[u8; 32],
        leaf: &[u8; 32],
        proof: &MerkleProof,
    ) -> Result<(), InclusionError> {
        self.book.prove_tx(block_id, leaf, proof)
    }

    /// Keep a block body in the cache. Pinned bodies are not evicted.
    ///
    /// # Errors
    ///
    /// [`AdmitError`] when the body does not fit. The cache is unchanged then.
    pub fn remember_body(
        &mut self,
        height: u32,
        body: Vec<u8>,
        pinned: bool,
    ) -> Result<usize, AdmitError> {
        self.cache.insert(height, body, pinned)
    }

    /// Heights still in the body cache, oldest first.
    #[must_use]
    pub fn cached_heights(&self) -> Vec<u32> {
        self.cache.heights()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inclusion::AdmittedHeader;
    use mfn_crypto::stealth::StealthPubKeys;
    use mfn_crypto::{merkle_proof, merkle_tree_from_leaves, stealth_gen, stealth_send_to};

    fn genesis() -> [u8; 32] {
        [0xA1; 32]
    }

    #[test]
    fn follow_prove_scan_and_cache_without_sending_the_view_key() {
        let wallet_keys = stealth_gen();
        let other = stealth_gen();
        let mut wallet = LightWallet::open(genesis(), 8, wallet_keys.clone());

        let leaves: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i;
                leaf
            })
            .collect();
        let tree = merkle_tree_from_leaves(&leaves).expect("tree");
        let proof = merkle_proof(&tree, 1).expect("proof");
        let header = AdmittedHeader {
            height: 1,
            block_id: [0xB2; 32],
            prev_id: genesis(),
            tx_root: tree.root(),
            utxo_root: [0u8; 32],
        };
        wallet.follow(header).expect("follow");
        wallet
            .prove_tx(&header.block_id, &leaves[1], &proof)
            .expect("included");
        assert_eq!(
            wallet
                .prove_tx(&[0xEE; 32], &leaves[1], &proof)
                .unwrap_err(),
            InclusionError::UnknownHeader
        );

        let outputs = vec![
            stealth_send_to(&StealthPubKeys::from(&wallet_keys)),
            stealth_send_to(&StealthPubKeys::from(&other)),
            stealth_send_to(&StealthPubKeys::from(&wallet_keys)),
        ];
        assert_eq!(wallet.scan(&outputs), vec![0, 2]);

        let window = wallet.output_window(4, 9).expect("window");
        let other_wallet = LightWallet::open(genesis(), 8, other);
        let other_window = other_wallet.output_window(4, 9).expect("window");
        assert_eq!(window.encode(), other_window.encode());
        assert!(window.encode().len() < wallet.view_public_bytes().len());

        wallet.remember_body(1, vec![1; 4], true).expect("pin");
        wallet.remember_body(2, vec![2; 4], false).expect("fit");
        let evicted = wallet.remember_body(3, vec![3; 4], false).expect("evict");
        assert_eq!(evicted, 1);
        assert_eq!(wallet.cached_heights(), vec![1, 3]);
    }

    #[test]
    fn a_header_that_does_not_link_is_ignored() {
        let mut wallet = LightWallet::open(genesis(), 16, stealth_gen());
        let err = wallet
            .follow(AdmittedHeader {
                height: 1,
                block_id: [2; 32],
                prev_id: [9; 32],
                tx_root: [0; 32],
                utxo_root: [0; 32],
            })
            .expect_err("prev");
        assert_eq!(err, AdmitHeaderError::Prev);
        assert_eq!(
            wallet
                .prove_tx(&[2; 32], &[0; 32], &empty_proof())
                .unwrap_err(),
            InclusionError::UnknownHeader
        );
    }

    fn empty_proof() -> MerkleProof {
        MerkleProof {
            siblings: Vec::new(),
            right_side: Vec::new(),
            index: 0,
        }
    }
}
