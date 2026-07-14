//! Succinct block validity proofs (**F5** phase 4a).
//!
//! Phase **4a** ships the wire format and an **apply-block replay** witness
//! (witness-heavy prototype before STARK backends). Full nodes verify by
//! restoring parent state from a checkpoint and re-running [`crate::block::apply_block`].

use crate::block::{
    apply_block, block_id, decode_block, encode_block, ApplyOutcome, Block, BlockDecodeError,
    ChainState,
};
use crate::chain_checkpoint::{decode_chain_checkpoint, encode_chain_checkpoint, ChainCheckpoint};
use mfn_crypto::codec::{Reader, Writer};
use thiserror::Error;

/// Wire format version for [`ValidityProofV1`].
pub const VALIDITY_PROOF_V1_VERSION: u32 = 1;

/// Witness kind: parent checkpoint + block wire; verifier replays `apply_block`.
pub const VALIDITY_WITNESS_APPLY_BLOCK_REPLAY: u8 = 1;

/// Upper bound on encoded validity-proof bytes (matches P2P frame budget).
pub const MAX_VALIDITY_PROOF_BYTES: usize = 4 * 1024 * 1024;

/// Apply-block replay witness for phase **4a** (STARK `proof_bytes` reserved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityProofV1 {
    /// Format version ([`VALIDITY_PROOF_V1_VERSION`]).
    pub version: u32,
    /// Contested / attested block id.
    pub block_id: [u8; 32],
    /// Witness discriminant ([`VALIDITY_WITNESS_APPLY_BLOCK_REPLAY`] today).
    pub witness_kind: u8,
    /// [`encode_chain_checkpoint`] bytes for parent tip state.
    pub parent_checkpoint: Vec<u8>,
    /// [`encode_block`] bytes for the block under test.
    pub block_wire: Vec<u8>,
    /// Circuit digest (zero sentinel for replay witness until STARK lands).
    pub circuit_digest: [u8; 32],
    /// Reserved STARK proof bytes (empty for replay witness).
    pub proof_bytes: Vec<u8>,
}

/// Outcome of [`verify_validity_proof_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidityProofVerdict {
    /// Replay witness confirms `apply_block` accepts the block at the claimed id.
    ValidAccept {
        /// Block height from the decoded header.
        height: u32,
    },
}

/// Failure decoding or verifying a validity proof.
#[derive(Debug, Error)]
pub enum ValidityProofError {
    /// Unsupported format version.
    #[error("unsupported validity proof version {got}")]
    UnsupportedVersion {
        /// Wire version field.
        got: u32,
    },
    /// Unknown witness kind.
    #[error("unknown validity witness kind {got}")]
    UnknownWitnessKind {
        /// Wire witness discriminant.
        got: u8,
    },
    /// Encoded proof exceeds [`MAX_VALIDITY_PROOF_BYTES`].
    #[error("validity proof too large ({len} > {max})")]
    TooLarge {
        /// Actual byte length.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// Truncated or malformed length fields.
    #[error("validity proof wire truncated")]
    Truncated,
    /// Parent checkpoint decode failure.
    #[error("parent checkpoint: {0}")]
    ParentCheckpoint(#[from] crate::ChainCheckpointError),
    /// Block decode failure.
    #[error("block wire: {0}")]
    BlockWire(#[from] BlockDecodeError),
    /// Declared `block_id` does not match recomputed header id.
    #[error("block_id mismatch")]
    BlockIdMismatch,
    /// Replay `apply_block` rejected the block.
    #[error("apply_block rejected replay: {errors:?}")]
    ApplyRejected {
        /// Consensus errors from the STF.
        errors: Vec<crate::block::BlockError>,
    },
    /// STARK proof bytes present but not yet verified in phase 4a.
    #[error("stark proof bytes not supported in phase 4a")]
    StarkProofNotSupported,
}

/// Build an apply-block replay proof from a known parent tip and child block.
#[must_use]
pub fn build_apply_block_replay_validity_proof(
    genesis_id: [u8; 32],
    parent: &ChainState,
    block: &Block,
) -> ValidityProofV1 {
    let cp = ChainCheckpoint {
        genesis_id,
        state: parent.clone(),
    };
    ValidityProofV1 {
        version: VALIDITY_PROOF_V1_VERSION,
        block_id: block_id(&block.header),
        witness_kind: VALIDITY_WITNESS_APPLY_BLOCK_REPLAY,
        parent_checkpoint: encode_chain_checkpoint(&cp),
        block_wire: encode_block(block),
        circuit_digest: [0u8; 32],
        proof_bytes: Vec::new(),
    }
}

/// Encode a [`ValidityProofV1`] for P2P / archive.
#[must_use]
pub fn encode_validity_proof_v1(proof: &ValidityProofV1) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(proof.version);
    w.push(&proof.block_id);
    w.u8(proof.witness_kind);
    w.blob(&proof.parent_checkpoint);
    w.blob(&proof.block_wire);
    w.push(&proof.circuit_digest);
    w.blob(&proof.proof_bytes);
    w.into_bytes()
}

/// Decode [`encode_validity_proof_v1`] bytes.
pub fn decode_validity_proof_v1(bytes: &[u8]) -> Result<ValidityProofV1, ValidityProofError> {
    if bytes.len() > MAX_VALIDITY_PROOF_BYTES {
        return Err(ValidityProofError::TooLarge {
            len: bytes.len(),
            max: MAX_VALIDITY_PROOF_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    let version = r.u32().map_err(|_| ValidityProofError::Truncated)?;
    let block_id = r
        .bytes(32)
        .map_err(|_| ValidityProofError::Truncated)?
        .try_into()
        .expect("32 bytes");
    let witness_kind = r.u8().map_err(|_| ValidityProofError::Truncated)?;
    let parent_checkpoint = r
        .blob()
        .map_err(|_| ValidityProofError::Truncated)?
        .to_vec();
    let block_wire = r
        .blob()
        .map_err(|_| ValidityProofError::Truncated)?
        .to_vec();
    let circuit_digest = r
        .bytes(32)
        .map_err(|_| ValidityProofError::Truncated)?
        .try_into()
        .expect("32 bytes");
    let proof_bytes = r
        .blob()
        .map_err(|_| ValidityProofError::Truncated)?
        .to_vec();
    if !r.end() {
        return Err(ValidityProofError::Truncated);
    }
    Ok(ValidityProofV1 {
        version,
        block_id,
        witness_kind,
        parent_checkpoint,
        block_wire,
        circuit_digest,
        proof_bytes,
    })
}

/// Verify a phase **4a** validity proof (apply-block replay witness today).
pub fn verify_validity_proof_v1(wire: &[u8]) -> Result<ValidityProofVerdict, ValidityProofError> {
    let proof = decode_validity_proof_v1(wire)?;
    if proof.version != VALIDITY_PROOF_V1_VERSION {
        return Err(ValidityProofError::UnsupportedVersion { got: proof.version });
    }
    if proof.witness_kind != VALIDITY_WITNESS_APPLY_BLOCK_REPLAY {
        return Err(ValidityProofError::UnknownWitnessKind {
            got: proof.witness_kind,
        });
    }
    if !proof.proof_bytes.is_empty() {
        return Err(ValidityProofError::StarkProofNotSupported);
    }
    let cp = decode_chain_checkpoint(&proof.parent_checkpoint)?;
    let block = decode_block(&proof.block_wire)?;
    if block_id(&block.header) != proof.block_id {
        return Err(ValidityProofError::BlockIdMismatch);
    }
    match apply_block(&cp.state, &block) {
        ApplyOutcome::Ok { .. } => Ok(ValidityProofVerdict::ValidAccept {
            height: block.header.height,
        }),
        ApplyOutcome::Err { errors, .. } => Err(ValidityProofError::ApplyRejected { errors }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{
        apply_genesis, build_genesis, build_unsealed_header, seal_block, GenesisConfig,
    };
    use crate::{DEFAULT_EMISSION_PARAMS, TEST_CONSENSUS_PARAMS};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn legacy_genesis() -> (ChainState, [u8; 32]) {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
        };
        let g = build_genesis(&cfg);
        let genesis_id = block_id(&g.header);
        let state = apply_genesis(&g, &cfg).expect("genesis");
        (state, genesis_id)
    }

    #[test]
    fn validity_proof_roundtrip() {
        let (parent, genesis_id) = legacy_genesis();
        let unsealed = build_unsealed_header(&parent, &[], &[], &[], &[], 1, 100);
        let block = seal_block(unsealed, vec![], vec![], vec![], vec![], vec![]);
        let proof = build_apply_block_replay_validity_proof(genesis_id, &parent, &block);
        let wire = encode_validity_proof_v1(&proof);
        assert!(wire.len() <= MAX_VALIDITY_PROOF_BYTES);
        let decoded = decode_validity_proof_v1(&wire).expect("decode");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn validity_proof_accepts_empty_block() {
        let (parent, genesis_id) = legacy_genesis();
        let unsealed = build_unsealed_header(&parent, &[], &[], &[], &[], 1, 100);
        let block = seal_block(unsealed, vec![], vec![], vec![], vec![], vec![]);
        let proof = build_apply_block_replay_validity_proof(genesis_id, &parent, &block);
        let wire = encode_validity_proof_v1(&proof);
        match verify_validity_proof_v1(&wire).expect("verify") {
            ValidityProofVerdict::ValidAccept { height } => assert_eq!(height, 1),
        }
    }

    #[test]
    fn validity_proof_rejects_tampered_block() {
        let (parent, genesis_id) = legacy_genesis();
        let unsealed = build_unsealed_header(&parent, &[], &[], &[], &[], 1, 100);
        let block = seal_block(unsealed, vec![], vec![], vec![], vec![], vec![]);
        let mut proof = build_apply_block_replay_validity_proof(genesis_id, &parent, &block);
        if let Some(b) = proof.block_wire.last_mut() {
            *b ^= 0x01;
        }
        let wire = encode_validity_proof_v1(&proof);
        assert!(verify_validity_proof_v1(&wire).is_err());
    }

    #[test]
    fn validity_proof_rejects_block_id_mismatch() {
        let (parent, genesis_id) = legacy_genesis();
        let unsealed = build_unsealed_header(&parent, &[], &[], &[], &[], 1, 100);
        let block = seal_block(unsealed, vec![], vec![], vec![], vec![], vec![]);
        let mut proof = build_apply_block_replay_validity_proof(genesis_id, &parent, &block);
        proof.block_id = [0xAA; 32];
        let wire = encode_validity_proof_v1(&proof);
        assert!(matches!(
            verify_validity_proof_v1(&wire),
            Err(ValidityProofError::BlockIdMismatch)
        ));
    }
}
