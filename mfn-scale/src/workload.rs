//! Deterministic verification workload shared by the unit test and the
//! criterion bench.
//!
//! Merkle leaves and the header-link chain are pure functions of their
//! index. Ring and range proofs draw blinding from the OS RNG inside the
//! existing provers, so the proof bytes are not pinned — acceptance is.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use mfn_crypto::{
    bp_prove, bp_verify, clsag_sign, clsag_verify, generator_g, hash_to_scalar, merkle_proof,
    merkle_tree_from_leaves, pedersen_commit, range_prove, range_verify, verify_merkle_proof,
    BulletproofRange, ClsagRing, ClsagSignature, MerkleProof, RangeProof,
};

use crate::baseline::{
    BASELINE_BULLETPROOF_BITS, BASELINE_CLSAG_RING, BASELINE_HEADER_LINK_BLOCKS,
    BASELINE_MERKLE_LEAVES, BASELINE_MERKLE_PROOFS, BASELINE_RANGE_BITS,
};

const HEADER_LINK_DOMAIN: &[u8] = b"MFN-1/scale-header-link/v1";
const MERKLE_LEAF_DOMAIN: &[u8] = b"MFN-1/scale-merkle-leaf/v1";
/// Message the pinned CLSAG signs. Batch checks must use the same bytes.
pub const CLSAG_WORKLOAD_MESSAGE: &[u8] = b"MFN-1/scale-clsag/v1";

const CLSAG_MESSAGE: &[u8] = CLSAG_WORKLOAD_MESSAGE;

/// Why [`prepare_verify_workload`] could not build a proof.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    /// Merkle construction rejected the leaf vector.
    #[error("merkle workload: {0}")]
    Merkle(String),
    /// CLSAG signing rejected the deterministic ring.
    #[error("clsag workload: {0}")]
    Clsag(String),
    /// Borromean range prover failed.
    #[error("range workload: {0}")]
    Range(String),
    /// Bulletproof prover failed.
    #[error("bulletproof workload: {0}")]
    Bulletproof(String),
}

/// One prepared pass: proofs already built, ready to verify.
pub struct PreparedWorkload {
    merkle_root: [u8; 32],
    merkle_items: Vec<([u8; 32], MerkleProof)>,
    clsag_ring: ClsagRing,
    clsag_pseudo: EdwardsPoint,
    clsag_sig: ClsagSignature,
    range_commit: EdwardsPoint,
    range_proof: RangeProof,
    bulletproof: BulletproofRange,
}

/// What one verification pass accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// Merkle proofs that reconstructed the root.
    pub merkle_ok: usize,
    /// CLSAG accepted the pinned message.
    pub clsag_ok: bool,
    /// Borromean range proof accepted.
    pub range_ok: bool,
    /// Bulletproof accepted.
    pub bulletproof_ok: bool,
    /// Header-link digest over [`BASELINE_HEADER_LINK_BLOCKS`] steps.
    pub header_link: [u8; 32],
}

impl PreparedWorkload {
    /// Merkle leaves in this pass.
    #[must_use]
    pub fn merkle_leaf_count(&self) -> usize {
        BASELINE_MERKLE_LEAVES
    }

    /// Inclusion proofs carried by this pass.
    #[must_use]
    pub fn merkle_proof_count(&self) -> usize {
        self.merkle_items.len()
    }

    /// CLSAG ring width.
    #[must_use]
    pub fn clsag_ring_len(&self) -> usize {
        self.clsag_ring.len()
    }

    /// Borromean bit width.
    #[must_use]
    pub fn range_bits(&self) -> u32 {
        self.range_proof.n
    }

    /// Bulletproof bit width.
    #[must_use]
    pub fn bulletproof_bits(&self) -> u32 {
        self.bulletproof.n
    }

    /// Root the inclusion proofs must reach.
    #[must_use]
    pub fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    /// Borrowed Merkle root.
    #[must_use]
    pub fn merkle_root_ref(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Leaf and inclusion proof pairs, in index order.
    #[must_use]
    pub fn merkle_entries(&self) -> &[([u8; 32], MerkleProof)] {
        &self.merkle_items
    }

    /// Ring the CLSAG was signed under.
    #[must_use]
    pub fn clsag_ring(&self) -> &ClsagRing {
        &self.clsag_ring
    }

    /// Pseudo-output commitment for the CLSAG.
    #[must_use]
    pub fn clsag_pseudo(&self) -> &EdwardsPoint {
        &self.clsag_pseudo
    }

    /// CLSAG signature over the pinned message.
    #[must_use]
    pub fn clsag_signature(&self) -> &ClsagSignature {
        &self.clsag_sig
    }

    /// Commitment the Borromean proof opens.
    #[must_use]
    pub fn range_commitment(&self) -> &EdwardsPoint {
        &self.range_commit
    }

    /// Borromean range proof.
    #[must_use]
    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    /// Bulletproof for the workload value.
    #[must_use]
    pub fn bulletproof(&self) -> &BulletproofRange {
        &self.bulletproof
    }
}

/// Hash-chain of `blocks` synthetic header links.
///
/// Each step is SHA-256 over the domain, the previous digest, and the
/// height. Used as the sync-throughput stand-in: real `apply_block` stays
/// in `mfn-consensus` and is not invoked here.
#[must_use]
pub fn header_link_digest(blocks: u32) -> [u8; 32] {
    let mut prev = [0u8; 32];
    for height in 0..blocks {
        let mut hasher = Sha256::new();
        hasher.update(HEADER_LINK_DOMAIN);
        hasher.update(prev);
        hasher.update(height.to_be_bytes());
        prev.copy_from_slice(&hasher.finalize());
    }
    prev
}

fn det_scalar(label: &[u8]) -> Scalar {
    let mut n = 0u32;
    loop {
        let mut material = Vec::with_capacity(label.len() + 4);
        material.extend_from_slice(label);
        material.extend_from_slice(&n.to_be_bytes());
        let scalar = hash_to_scalar(&[b"MFN-1/scale/v1", &material]);
        if scalar != Scalar::ZERO {
            return scalar;
        }
        n = n.saturating_add(1);
    }
}

fn merkle_leaf(index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MERKLE_LEAF_DOMAIN);
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn proof_indexes(leaves: usize, proofs: usize) -> Vec<usize> {
    let step = leaves / proofs;
    (0..proofs).map(|i| i * step).collect()
}

/// Build the pinned workload. Proof bytes depend on OS randomness inside
/// the range provers; sizes and the Merkle root do not.
///
/// # Errors
///
/// Returns [`WorkloadError`] when a prover rejects the pinned inputs.
pub fn prepare_verify_workload() -> Result<PreparedWorkload, WorkloadError> {
    let leaves: Vec<[u8; 32]> = (0..BASELINE_MERKLE_LEAVES)
        .map(|i| merkle_leaf(u32::try_from(i).unwrap_or(u32::MAX)))
        .collect();
    let tree =
        merkle_tree_from_leaves(&leaves).map_err(|err| WorkloadError::Merkle(err.to_string()))?;
    let mut merkle_items = Vec::with_capacity(BASELINE_MERKLE_PROOFS);
    for index in proof_indexes(BASELINE_MERKLE_LEAVES, BASELINE_MERKLE_PROOFS) {
        let proof =
            merkle_proof(&tree, index).map_err(|err| WorkloadError::Merkle(err.to_string()))?;
        merkle_items.push((leaves[index], proof));
    }

    let signer = 3usize;
    let mut spend_keys = Vec::with_capacity(BASELINE_CLSAG_RING);
    let mut blindings = Vec::with_capacity(BASELINE_CLSAG_RING);
    let mut points = Vec::with_capacity(BASELINE_CLSAG_RING);
    let mut commits = Vec::with_capacity(BASELINE_CLSAG_RING);
    for i in 0..BASELINE_CLSAG_RING {
        let label_spend = format!("spend-{i}");
        let label_blind = format!("blind-{i}");
        let spend = det_scalar(label_spend.as_bytes());
        let blinding = det_scalar(label_blind.as_bytes());
        let value = 50u64 + u64::try_from(i).unwrap_or(0);
        points.push(generator_g() * spend);
        commits.push(pedersen_commit(Scalar::from(value), Some(blinding)).c);
        spend_keys.push(spend);
        blindings.push(blinding);
    }
    let value = 50u64 + u64::try_from(signer).unwrap_or(0);
    let pseudo_blind = det_scalar(b"pseudo");
    let clsag_pseudo = pedersen_commit(Scalar::from(value), Some(pseudo_blind)).c;
    let blinding_diff = blindings[signer] - pseudo_blind;
    let clsag_ring = ClsagRing {
        p: points,
        c: commits,
    };
    let clsag_sig = clsag_sign(
        CLSAG_MESSAGE,
        &clsag_ring,
        &clsag_pseudo,
        signer,
        &spend_keys[signer],
        &blinding_diff,
    )
    .map_err(|err| WorkloadError::Clsag(err.to_string()))?;

    let range_blind = det_scalar(b"range-blind");
    let range = range_prove(1_000, &range_blind, BASELINE_RANGE_BITS)
        .map_err(|err| WorkloadError::Range(err.to_string()))?;
    let bullet = bp_prove(1_000, &det_scalar(b"bp-blind"), BASELINE_BULLETPROOF_BITS)
        .map_err(|err| WorkloadError::Bulletproof(err.to_string()))?;

    Ok(PreparedWorkload {
        merkle_root: tree.root(),
        merkle_items,
        clsag_ring,
        clsag_pseudo,
        clsag_sig,
        range_commit: range.c,
        range_proof: range.proof,
        bulletproof: bullet.proof,
    })
}

impl PreparedWorkload {
    /// How many Merkle proofs reconstruct the root.
    #[must_use]
    pub fn verify_merkle(&self) -> usize {
        self.merkle_items
            .iter()
            .filter(|(leaf, proof)| verify_merkle_proof(leaf, proof, &self.merkle_root))
            .count()
    }

    /// CLSAG over the pinned message.
    #[must_use]
    pub fn verify_clsag(&self) -> bool {
        clsag_verify(
            CLSAG_MESSAGE,
            &self.clsag_ring,
            &self.clsag_pseudo,
            &self.clsag_sig,
        )
    }

    /// Borromean range proof against the workload commitment.
    #[must_use]
    pub fn verify_range(&self) -> bool {
        range_verify(&self.range_commit, &self.range_proof)
    }

    /// Bulletproof against the workload commitment.
    #[must_use]
    pub fn verify_bulletproof(&self) -> bool {
        bp_verify(&self.bulletproof)
    }

    /// Run every verifier once. A `false` flag means that proof was rejected.
    #[must_use]
    pub fn verify(&self) -> VerifyReport {
        VerifyReport {
            merkle_ok: self.verify_merkle(),
            clsag_ok: self.verify_clsag(),
            range_ok: self.verify_range(),
            bulletproof_ok: self.verify_bulletproof(),
            header_link: header_link_digest(BASELINE_HEADER_LINK_BLOCKS),
        }
    }

    /// CLSAG over an altered message. Must reject.
    #[must_use]
    pub fn clsag_rejects_other_message(&self) -> bool {
        !clsag_verify(
            b"MFN-1/scale-clsag/other",
            &self.clsag_ring,
            &self.clsag_pseudo,
            &self.clsag_sig,
        )
    }

    /// Range proof against a commitment to a different value. Must reject.
    #[must_use]
    pub fn range_rejects_other_commitment(&self) -> bool {
        let other = pedersen_commit(Scalar::from(2u64), Some(det_scalar(b"range-other"))).c;
        !range_verify(&other, &self.range_proof)
    }

    /// Inclusion of a leaf that was never in the tree. Must reject.
    #[must_use]
    pub fn merkle_rejects_foreign_leaf(&self) -> bool {
        let (leaf, proof) = &self.merkle_items[0];
        let mut foreign = *leaf;
        foreign[0] ^= 0xff;
        !verify_merkle_proof(&foreign, proof, &self.merkle_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{
        BASELINE_BULLETPROOF_BITS, BASELINE_CLSAG_RING, BASELINE_HEADER_LINK_BLOCKS,
        BASELINE_HEADER_LINK_HEX, BASELINE_MERKLE_LEAVES, BASELINE_MERKLE_PROOFS,
        BASELINE_RANGE_BITS,
    };

    #[test]
    fn header_link_digest_matches_committed_baseline() {
        let got = header_link_digest(BASELINE_HEADER_LINK_BLOCKS);
        assert_eq!(hex::encode(got), BASELINE_HEADER_LINK_HEX);
        assert_ne!(header_link_digest(1), got);
        assert_eq!(header_link_digest(0), [0u8; 32]);
    }

    #[test]
    fn workload_sizes_match_baseline_and_verifiers_accept() {
        let prepared = prepare_verify_workload().expect("workload");
        assert_eq!(prepared.merkle_leaf_count(), BASELINE_MERKLE_LEAVES);
        assert_eq!(prepared.merkle_proof_count(), BASELINE_MERKLE_PROOFS);
        assert_eq!(prepared.clsag_ring_len(), BASELINE_CLSAG_RING);
        assert_eq!(prepared.range_bits(), BASELINE_RANGE_BITS);
        assert_eq!(prepared.bulletproof_bits(), BASELINE_BULLETPROOF_BITS);
        let report = prepared.verify();
        assert_eq!(report.merkle_ok, BASELINE_MERKLE_PROOFS);
        assert!(report.clsag_ok);
        assert!(report.range_ok);
        assert!(report.bulletproof_ok);
        assert_eq!(hex::encode(report.header_link), BASELINE_HEADER_LINK_HEX);
        assert!(prepared.clsag_rejects_other_message());
        assert!(prepared.range_rejects_other_commitment());
        assert!(prepared.merkle_rejects_foreign_leaf());
        let mut forged = prepared.bulletproof.clone();
        forged.v = generator_g();
        assert!(!bp_verify(&forged));
    }
}
