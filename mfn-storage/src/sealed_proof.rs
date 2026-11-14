//! Header version 10 storage proofs carry a sealed replica, not plaintext.
//!
//! The Merkle leaf is still the plaintext chunk hash, so the commitment's
//! `data_root` does not change. The bytes inside the proof are the
//! operator-salted seal of that chunk. A copied seal fails the other
//! operator's MAC and does not open the root.
//!
//! Header versions below [`HEADER_VERSION_SEALED_REPLICA`] keep verifying
//! plaintext chunks. Path A and F-A stay there. Version 8 is left for Seat B.
//! Version 9 is the shard stripe.

use mfn_crypto::merkle::verify_merkle_proof;

use crate::commitment::{storage_commitment_hash, StorageCommitment};
use crate::replica_encode::{open_replica_seal, seal_replica, RECOMMENDED_SEAL_ROUNDS};
use crate::spora::{
    chunk_hash, chunk_index_for_challenge, chunk_index_for_operator_challenge,
    operator_identity_from_payout, operator_payout_is_valid, StorageProof, StorageProofCheck,
};

/// Header version whose storage proofs must open a sealed replica.
pub const HEADER_VERSION_SEALED_REPLICA: u32 = 10;

/// Replace `proof.chunk` with this operator's seal of the plaintext chunk.
///
/// The Merkle path is left pointing at the plaintext leaf.
///
/// # Errors
///
/// [`crate::replica_encode::SealError`] when the seal cannot be built.
pub fn seal_storage_proof(
    proof: &StorageProof,
    commit: &StorageCommitment,
) -> Result<StorageProof, crate::replica_encode::SealError> {
    let operator =
        operator_identity_from_payout(&proof.operator_view_pub, &proof.operator_spend_pub);
    let sealed = seal_replica(
        &proof.chunk,
        &operator,
        &commit.data_root,
        0,
        RECOMMENDED_SEAL_ROUNDS,
    )?;
    let mut out = proof.clone();
    out.chunk = sealed.bytes;
    Ok(out)
}

/// Verify a proof whose chunk bytes are a sealed replica.
///
/// `operator_salted` selects the challenge index the same way the plaintext
/// verifier does. The leaf check uses the unsealed plaintext.
pub fn verify_storage_proof_sealed(
    commit: &StorageCommitment,
    prev_block_id: &[u8; 32],
    slot: u32,
    proof: &StorageProof,
    operator_salted: bool,
) -> StorageProofCheck {
    if !operator_payout_is_valid(&proof.operator_view_pub, &proof.operator_spend_pub) {
        return StorageProofCheck::InvalidOperatorPayout;
    }
    let c_hash = storage_commitment_hash(commit);
    if c_hash != proof.commit_hash {
        return StorageProofCheck::CommitHashMismatch;
    }
    let operator =
        operator_identity_from_payout(&proof.operator_view_pub, &proof.operator_spend_pub);
    let expected = if operator_salted {
        chunk_index_for_operator_challenge(
            prev_block_id,
            slot,
            &c_hash,
            &operator,
            commit.num_chunks,
        )
    } else {
        chunk_index_for_challenge(prev_block_id, slot, &c_hash, commit.num_chunks)
    };
    let got = proof.proof.index as u32;
    if got != expected {
        return StorageProofCheck::WrongChunkIndex { expected, got };
    }
    let Ok(plain) = open_replica_seal(&proof.chunk, &operator, &commit.data_root) else {
        return StorageProofCheck::MerkleInvalid;
    };
    let leaf = chunk_hash(&plain);
    if !verify_merkle_proof(&leaf, &proof.proof, &commit.data_root) {
        return StorageProofCheck::MerkleInvalid;
    }
    StorageProofCheck::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spora::{build_storage_commitment, build_test_storage_proof, verify_storage_proof};

    #[test]
    fn a_sealed_proof_opens_and_a_plaintext_verifier_rejects_it() {
        let data = vec![7u8; 64];
        let built = build_storage_commitment(&data, 1, Some(64), 3, None).expect("commit");
        let prev = [1u8; 32];
        let proof = build_test_storage_proof(&built.commit, &prev, 0, &data, &built.tree);
        assert!(verify_storage_proof(&built.commit, &prev, 0, &proof).is_valid());
        let sealed = seal_storage_proof(&proof, &built.commit).expect("seal");
        assert!(!verify_storage_proof(&built.commit, &prev, 0, &sealed).is_valid());
        assert!(verify_storage_proof_sealed(&built.commit, &prev, 0, &sealed, false).is_valid());
    }
}
