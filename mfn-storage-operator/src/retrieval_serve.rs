//! Build a retrieval response from bytes the operator actually holds.
//!
//! Seat B's header-v7 challenge slashes silence. This is the storage side:
//! given the payload and the open challenge, produce the chunk and the
//! Merkle path that `RetrievalRegistry` accepts. A payload that does not
//! open the challenged root is refused here, so the operator does not
//! publish a bad answer.
//!
//! Header version 1 chains never ask. This module does not post challenges
//! and does not change Path A or F-A.

use mfn_consensus::retrieval::{challenge_id, RetrievalChallenge, RetrievalResponse};
use mfn_crypto::merkle::merkle_proof;
use mfn_storage::{chunk_data, merkle_tree_from_chunks};

/// Why the operator cannot answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    /// The payload does not chunk under this size.
    #[error("chunk payload: {0}")]
    Chunk(String),
    /// `chunk_index` is outside the payload.
    #[error("chunk index {0} is outside the payload")]
    MissingChunk(u32),
    /// The payload's Merkle root is not the challenged root.
    #[error("payload root does not match the challenge")]
    NotOurFile,
    /// The Merkle path could not be built.
    #[error("merkle path: {0}")]
    Proof(String),
}

/// Chunk and Merkle path for `challenge`, using the height it was posted at.
///
/// # Errors
///
/// [`AnswerError`] when the payload is not the challenged file or does not
/// contain the index.
pub fn answer_retrieval_challenge(
    payload: &[u8],
    chunk_size: u32,
    posted_height: u32,
    challenge: &RetrievalChallenge,
) -> Result<RetrievalResponse, AnswerError> {
    let chunks =
        chunk_data(payload, chunk_size as usize).map_err(|e| AnswerError::Chunk(e.to_string()))?;
    let tree = merkle_tree_from_chunks(&chunks).map_err(|e| AnswerError::Chunk(e.to_string()))?;
    if tree.root() != challenge.commitment {
        return Err(AnswerError::NotOurFile);
    }
    let idx = usize::try_from(challenge.chunk_index).unwrap_or(usize::MAX);
    let chunk = chunks
        .get(idx)
        .ok_or(AnswerError::MissingChunk(challenge.chunk_index))?;
    let proof = merkle_proof(&tree, idx).map_err(|e| AnswerError::Proof(e.to_string()))?;
    Ok(RetrievalResponse {
        challenge_id: challenge_id(posted_height, challenge),
        chunk: chunk.to_vec(),
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use mfn_consensus::retrieval::{RetrievalOp, RetrievalRegistry};
    use mfn_consensus::HEADER_VERSION_RETRIEVAL;
    use mfn_storage::build_storage_commitment;
    use std::collections::BTreeMap;

    #[test]
    fn an_honest_answer_clears_the_challenge_without_a_slash() {
        let payload: Vec<u8> = (0u16..300).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(&payload, 1, Some(128), 3, None).expect("commit");
        let challenge = RetrievalChallenge {
            commitment: built.commit.data_root,
            chunk_index: 1,
            operator_index: 0,
            one_time_refund: ED25519_BASEPOINT_POINT.compress().to_bytes(),
            deposit: 1_000,
        };
        let mut bonds = BTreeMap::from([(0u32, 10_000u64)]);
        let mut treasury = 0u128;
        let mut registry = RetrievalRegistry::default();
        registry
            .apply_ops(
                HEADER_VERSION_RETRIEVAL,
                1,
                &[RetrievalOp::Challenge(challenge.clone())],
                &mut bonds,
                &mut treasury,
            )
            .expect("post");
        let response = answer_retrieval_challenge(&payload, 128, 1, &challenge).expect("answer");
        registry
            .apply_ops(
                HEADER_VERSION_RETRIEVAL,
                2,
                &[RetrievalOp::Response(response)],
                &mut bonds,
                &mut treasury,
            )
            .expect("respond");
        assert!(!registry.blocks_unbond(0));
        assert_eq!(bonds.get(&0).copied(), Some(10_125));
    }

    #[test]
    fn a_different_file_is_not_answered() {
        let payload = b"the file we hold".to_vec();
        let challenge = RetrievalChallenge {
            commitment: [9u8; 32],
            chunk_index: 0,
            operator_index: 0,
            one_time_refund: ED25519_BASEPOINT_POINT.compress().to_bytes(),
            deposit: 1,
        };
        assert!(matches!(
            answer_retrieval_challenge(&payload, 64, 1, &challenge),
            Err(AnswerError::NotOurFile)
        ));
    }
}
