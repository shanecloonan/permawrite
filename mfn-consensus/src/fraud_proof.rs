//! Interactive body-root fraud proofs for light clients (**F5** phase 0).
//!
//! A finality quorum signs header bytes; it does **not** prove
//! [`crate::block::apply_block`] would accept the block ([`docs/PROBLEMS.md`]
//! item 11). Phase 0 lets any full node publish a succinct challenge that a
//! light client can verify **without the UTXO set**: the attached body
//! recomputes a Merkle root that disagrees with the finalized header.
//!
//! Later phases (CLSAG / SPoRA / coinbase fraud) need state witnesses and
//! stay deferred. Gossip + slash hooks are phase 1 (`mfn-net` tag `0x13`).

use crate::block::{decode_block, encode_block, tx_merkle_root, Block, BlockDecodeError};
use crate::slashing::slashing_merkle_root;
use crate::storage_operator_wire::bond_section_merkle_root;
use mfn_storage::storage_proof_merkle_root;
use thiserror::Error;

/// Wire format version for [`BodyRootFraudProof`].
pub const FRAUD_PROOF_VERSION: u32 = 1;

/// Soft confirmation guidance for light clients (slots to wait for fraud).
///
/// Phase 0 does not enforce this on-chain; wallets/docs use it as a UX default.
pub const FRAUD_PROOF_SOFT_FINALITY_SLOTS: u32 = 32;

/// Which header root the challenger claims is inconsistent with the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BodyRootFraudKind {
    /// `header.tx_root != tx_merkle_root(body.txs)`.
    TxRoot = 1,
    /// `header.bond_root != bond_section_merkle_root(...)`.
    BondRoot = 2,
    /// `header.slashing_root != slashing_merkle_root(...)`.
    SlashingRoot = 3,
    /// `header.storage_proof_root != storage_proof_merkle_root(...)`.
    StorageProofRoot = 4,
}

impl BodyRootFraudKind {
    /// Parse a wire discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::TxRoot),
            2 => Some(Self::BondRoot),
            3 => Some(Self::SlashingRoot),
            4 => Some(Self::StorageProofRoot),
            _ => None,
        }
    }
}

/// Challenge: this finalized header claimed root does not match the body.
#[derive(Debug, Clone)]
pub struct BodyRootFraudProof {
    /// Format version ([`FRAUD_PROOF_VERSION`]).
    pub version: u32,
    /// Which root is disputed.
    pub kind: BodyRootFraudKind,
    /// Full block (header + body) as gossiped / archived.
    pub block: Block,
}

/// Outcome of [`verify_body_root_fraud_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudProofVerdict {
    /// Light clients MUST reject the header (or treat finality as soft).
    ValidFraud {
        /// Kind that mismatched.
        kind: BodyRootFraudKind,
        /// Root claimed in the header.
        claimed: [u8; 32],
        /// Root recomputed from the body.
        recomputed: [u8; 32],
    },
}

/// Errors when a challenge is malformed or does not demonstrate fraud.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FraudProofError {
    /// Unsupported `version`.
    #[error("unsupported fraud proof version {got} (expected {FRAUD_PROOF_VERSION})")]
    UnsupportedVersion {
        /// Version in the proof.
        got: u32,
    },
    /// Unknown `kind` discriminant.
    #[error("unknown fraud proof kind {0}")]
    UnknownKind(u8),
    /// Body roots actually match the header -- not fraud.
    #[error("challenge does not demonstrate fraud: header root matches body")]
    NotFraud,
    /// Block wire decode failed.
    #[error("block decode: {0}")]
    BlockDecode(String),
}

/// Recompute the body root named by `kind` and compare to the header.
///
/// Returns [`FraudProofVerdict::ValidFraud`] only when the header is wrong
/// relative to the attached body. Does not run CLSAG, SPoRA, or `apply_block`.
pub fn verify_body_root_fraud_proof(
    proof: &BodyRootFraudProof,
) -> Result<FraudProofVerdict, FraudProofError> {
    if proof.version != FRAUD_PROOF_VERSION {
        return Err(FraudProofError::UnsupportedVersion { got: proof.version });
    }
    let (claimed, recomputed) = match proof.kind {
        BodyRootFraudKind::TxRoot => (proof.block.header.tx_root, tx_merkle_root(&proof.block.txs)),
        BodyRootFraudKind::BondRoot => (
            proof.block.header.bond_root,
            bond_section_merkle_root(&proof.block.bond_ops, &proof.block.storage_operator_ops),
        ),
        BodyRootFraudKind::SlashingRoot => (
            proof.block.header.slashing_root,
            slashing_merkle_root(&proof.block.slashings),
        ),
        BodyRootFraudKind::StorageProofRoot => (
            proof.block.header.storage_proof_root,
            storage_proof_merkle_root(&proof.block.storage_proofs),
        ),
    };
    if claimed == recomputed {
        return Err(FraudProofError::NotFraud);
    }
    Ok(FraudProofVerdict::ValidFraud {
        kind: proof.kind,
        claimed,
        recomputed,
    })
}

/// Encode a fraud proof for P2P / archive (version + kind + `encode_block`).
#[must_use]
pub fn encode_body_root_fraud_proof(proof: &BodyRootFraudProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.version.to_le_bytes());
    out.push(proof.kind as u8);
    out.extend_from_slice(&encode_block(&proof.block));
    out
}

/// Decode [`encode_body_root_fraud_proof`] bytes.
pub fn decode_body_root_fraud_proof(bytes: &[u8]) -> Result<BodyRootFraudProof, FraudProofError> {
    if bytes.len() < 5 {
        return Err(FraudProofError::BlockDecode("fraud proof too short".into()));
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let kind =
        BodyRootFraudKind::from_u8(bytes[4]).ok_or(FraudProofError::UnknownKind(bytes[4]))?;
    let block = decode_block(&bytes[5..])
        .map_err(|e: BlockDecodeError| FraudProofError::BlockDecode(e.to_string()))?;
    Ok(BodyRootFraudProof {
        version,
        kind,
        block,
    })
}

/// Convenience: build a tx-root challenge from a block whose header was tampered.
#[must_use]
pub fn tx_root_fraud_proof(block: Block) -> BodyRootFraudProof {
    BodyRootFraudProof {
        version: FRAUD_PROOF_VERSION,
        kind: BodyRootFraudKind::TxRoot,
        block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{
        apply_genesis, build_genesis, build_unsealed_header, seal_block, GenesisConfig,
    };
    use crate::{BondingParams, ConsensusParams, HEADER_VERSION, TEST_CONSENSUS_PARAMS};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn empty_sealed_block() -> Block {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6670,
                liveness_max_consecutive_missed: 3,
                liveness_slash_bps: 100,
                ..TEST_CONSENSUS_PARAMS
            },
            emission_params: crate::DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(BondingParams {
                min_validator_stake: 1,
                unbond_delay_heights: 1,
                max_entry_churn_per_epoch: 1,
                max_exit_churn_per_epoch: 1,
                slots_per_epoch: 1,
            }),
            header_version: HEADER_VERSION,
        };
        let genesis = build_genesis(&cfg);
        let state = apply_genesis(&genesis, &cfg).expect("genesis");
        let header = build_unsealed_header(&state, &[], &[], &[], &[], 1, 1);
        seal_block(header, vec![], vec![], vec![], vec![], vec![])
    }

    #[test]
    fn valid_block_is_not_fraud() {
        let block = empty_sealed_block();
        let proof = tx_root_fraud_proof(block);
        assert!(matches!(
            verify_body_root_fraud_proof(&proof),
            Err(FraudProofError::NotFraud)
        ));
    }

    #[test]
    fn tampered_tx_root_is_valid_fraud() {
        let mut block = empty_sealed_block();
        block.header.tx_root = [0xAB; 32];
        let proof = tx_root_fraud_proof(block);
        let v = verify_body_root_fraud_proof(&proof).expect("fraud");
        match v {
            FraudProofVerdict::ValidFraud {
                kind,
                claimed,
                recomputed,
            } => {
                assert_eq!(kind, BodyRootFraudKind::TxRoot);
                assert_eq!(claimed, [0xAB; 32]);
                assert_eq!(recomputed, tx_merkle_root(&[]));
            }
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut block = empty_sealed_block();
        block.header.tx_root = [0xCD; 32];
        let proof = tx_root_fraud_proof(block);
        let wire = encode_body_root_fraud_proof(&proof);
        let decoded = decode_body_root_fraud_proof(&wire).expect("decode");
        assert_eq!(decoded.version, proof.version);
        assert_eq!(decoded.kind, proof.kind);
        assert_eq!(decoded.block.header.tx_root, proof.block.header.tx_root);
        verify_body_root_fraud_proof(&decoded).expect("still fraud");
    }
}
