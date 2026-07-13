//! Interactive body-root fraud proofs for light clients (**F5** phase 0).
//!
//! A finality quorum signs header bytes; it does **not** prove
//! [`crate::block::apply_block`] would accept the block ([`docs/PROBLEMS.md`]
//! item 11). Phase 0 lets any full node publish a succinct challenge that a
//! light client can verify **without the UTXO set**: the attached body
//! recomputes a Merkle root that disagrees with the finalized header.
//!
//! Later phases (CLSAG / SPoRA) need state witnesses. Coinbase amount fraud
//! (phase 2) uses fee_sum + settlement witnesses. Gossip ships on `mfn-net`
//! tag `0x13`; slash deferred.

use crate::block::{decode_block, encode_block, tx_merkle_root, Block, BlockDecodeError};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase_outputs, PayoutAddress};
use crate::emission::{block_coinbase_specs, EmissionParams};
use crate::slashing::slashing_merkle_root;
use crate::storage_operator_wire::bond_section_merkle_root;
use mfn_crypto::codec::{Reader, Writer};
use mfn_storage::{
    decode_storage_proof, encode_storage_proof, storage_proof_merkle_root, SporaError, StorageProof,
};
use thiserror::Error;

/// Wire format version for [`BodyRootFraudProof`].
pub const FRAUD_PROOF_VERSION: u32 = 1;

/// Wire format version for [`CoinbaseAmountFraudProof`] (**F5** phase 2).
pub const COINBASE_FRAUD_PROOF_VERSION: u32 = 2;

/// Dedup tag for coinbase fraud fan-out (distinct from [`BodyRootFraudKind`]).
pub const COINBASE_FRAUD_DEDUP_KIND: u8 = 5;

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
    /// `fee_sum` witness does not match fees in the block body.
    #[error("fee_sum witness {witness} != recomputed {recomputed}")]
    FeeSumMismatch {
        /// Challenger-supplied sum.
        witness: u128,
        /// Sum of non-coinbase tx fees in the body.
        recomputed: u128,
    },
    /// Storage proof witness decode failed.
    #[error("storage proof decode: {0}")]
    StorageProofDecode(String),
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

/// Sum fees from non-coinbase transactions in a block body.
#[must_use]
pub fn recompute_block_fee_sum(block: &Block) -> u128 {
    block
        .txs
        .iter()
        .enumerate()
        .filter(|(ti, tx)| !(*ti == 0 && is_coinbase_shaped(tx)))
        .map(|(_, tx)| u128::from(tx.fee))
        .fold(0u128, u128::saturating_add)
}

/// Coinbase mint mismatch challenge (**F5** phase 2).
#[derive(Debug, Clone)]
pub struct CoinbaseAmountFraudProof {
    /// Format version ([`COINBASE_FRAUD_PROOF_VERSION`]).
    pub version: u32,
    /// Full block including the disputed coinbase at `txs[0]` when present.
    pub block: Block,
    /// Witness: Σ fees from non-coinbase txs (must match [`recompute_block_fee_sum`]).
    pub fee_sum: u128,
    /// Witness: producer payout keys from the elected producer.
    pub producer_payout: PayoutAddress,
    /// Witness: accepted storage proofs + PPB bonuses (`apply_block` settlement).
    pub accepted_settlements: Vec<(StorageProof, u128)>,
}

/// Outcome of [`verify_coinbase_amount_fraud_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinbaseAmountFraudVerdict {
    /// Coinbase absent or does not match emission + fee + settlement witness.
    ValidFraud {
        /// Block height.
        height: u32,
        /// Expected total mint from specs.
        expected_total: u64,
        /// Diagnostics from [`verify_coinbase_outputs`] or absence.
        verify_errors: Vec<String>,
    },
}

/// Unified verdict for gossip admission (body-root or coinbase amount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveFraudVerdict {
    /// Body-root mismatch (phase 0).
    BodyRoot(FraudProofVerdict),
    /// Coinbase economics mismatch (phase 2).
    CoinbaseAmount(CoinbaseAmountFraudVerdict),
}

/// Recompute expected coinbase outputs and compare to the body coinbase tx.
pub fn verify_coinbase_amount_fraud_proof(
    proof: &CoinbaseAmountFraudProof,
    emission_params: &EmissionParams,
) -> Result<CoinbaseAmountFraudVerdict, FraudProofError> {
    if proof.version != COINBASE_FRAUD_PROOF_VERSION {
        return Err(FraudProofError::UnsupportedVersion { got: proof.version });
    }
    let recomputed = recompute_block_fee_sum(&proof.block);
    if proof.fee_sum != recomputed {
        return Err(FraudProofError::FeeSumMismatch {
            witness: proof.fee_sum,
            recomputed,
        });
    }
    let height = proof.block.header.height;
    let specs = block_coinbase_specs(
        u64::from(height),
        emission_params,
        proof.fee_sum,
        proof.producer_payout,
        &proof.accepted_settlements,
    );
    let expected_total: u64 = specs
        .iter()
        .map(|s| s.amount)
        .fold(0u64, u64::saturating_add);
    let coinbase_tx = proof.block.txs.first().filter(|tx| is_coinbase_shaped(tx));
    let (ok, errors) = match coinbase_tx {
        None => (false, vec!["coinbase required but absent".into()]),
        Some(cb) => {
            let cv = verify_coinbase_outputs(
                cb,
                u64::from(height),
                &proof.producer_payout.spend_pub,
                &specs,
            );
            (cv.ok, cv.errors)
        }
    };
    if ok {
        return Err(FraudProofError::NotFraud);
    }
    Ok(CoinbaseAmountFraudVerdict::ValidFraud {
        height,
        expected_total,
        verify_errors: errors,
    })
}

/// Encode a coinbase amount fraud proof for P2P / archive.
#[must_use]
pub fn encode_coinbase_amount_fraud_proof(proof: &CoinbaseAmountFraudProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.version.to_le_bytes());
    out.extend_from_slice(&proof.fee_sum.to_le_bytes());
    let count = u16::try_from(proof.accepted_settlements.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for (sp, bonus) in &proof.accepted_settlements {
        let wire = encode_storage_proof(sp);
        let len = u32::try_from(wire.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&wire);
        out.extend_from_slice(&bonus.to_le_bytes());
    }
    let mut w = Writer::new();
    w.point(&proof.producer_payout.view_pub);
    w.point(&proof.producer_payout.spend_pub);
    out.extend_from_slice(w.bytes());
    out.extend_from_slice(&encode_block(&proof.block));
    out
}

/// Decode [`encode_coinbase_amount_fraud_proof`] bytes.
pub fn decode_coinbase_amount_fraud_proof(
    bytes: &[u8],
) -> Result<CoinbaseAmountFraudProof, FraudProofError> {
    if bytes.len() < 26 {
        return Err(FraudProofError::BlockDecode(
            "coinbase fraud proof too short".into(),
        ));
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fee_sum = u128::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let settlement_count = u16::from_le_bytes([bytes[20], bytes[21]]) as usize;
    let mut offset = 22usize;
    let mut accepted_settlements = Vec::with_capacity(settlement_count.min(64));
    for _ in 0..settlement_count {
        if offset + 4 > bytes.len() {
            return Err(FraudProofError::BlockDecode(
                "truncated settlement length".into(),
            ));
        }
        let wire_len = usize::try_from(u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]))
        .unwrap_or(usize::MAX);
        offset = offset.saturating_add(4);
        if offset.saturating_add(wire_len).saturating_add(16) > bytes.len() {
            return Err(FraudProofError::BlockDecode(
                "truncated settlement wire".into(),
            ));
        }
        let wire = &bytes[offset..offset.saturating_add(wire_len)];
        offset = offset.saturating_add(wire_len);
        let proof = decode_storage_proof(wire)
            .map_err(|e: SporaError| FraudProofError::StorageProofDecode(e.to_string()))?;
        let bonus = u128::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
            bytes[offset + 9],
            bytes[offset + 10],
            bytes[offset + 11],
            bytes[offset + 12],
            bytes[offset + 13],
            bytes[offset + 14],
            bytes[offset + 15],
        ]);
        offset = offset.saturating_add(16);
        accepted_settlements.push((proof, bonus));
    }
    if offset + 64 > bytes.len() {
        return Err(FraudProofError::BlockDecode(
            "truncated producer payout".into(),
        ));
    }
    let mut r = Reader::new(&bytes[offset..]);
    let view_pub = r
        .point()
        .map_err(|e| FraudProofError::BlockDecode(format!("payout view_pub: {e}")))?;
    let spend_pub = r
        .point()
        .map_err(|e| FraudProofError::BlockDecode(format!("payout spend_pub: {e}")))?;
    let payout_len = bytes[offset..].len().saturating_sub(r.remaining());
    offset = offset.saturating_add(payout_len);
    let block = decode_block(&bytes[offset..])
        .map_err(|e: BlockDecodeError| FraudProofError::BlockDecode(e.to_string()))?;
    Ok(CoinbaseAmountFraudProof {
        version,
        block,
        fee_sum,
        producer_payout: PayoutAddress {
            view_pub,
            spend_pub,
        },
        accepted_settlements,
    })
}

/// Verify any supported interactive fraud proof wire (version 1 or 2).
pub fn verify_interactive_fraud_proof(
    consensus_wire: &[u8],
    emission_params: &EmissionParams,
) -> Result<InteractiveFraudVerdict, FraudProofError> {
    if consensus_wire.len() < 4 {
        return Err(FraudProofError::BlockDecode("fraud proof too short".into()));
    }
    let version = u32::from_le_bytes([
        consensus_wire[0],
        consensus_wire[1],
        consensus_wire[2],
        consensus_wire[3],
    ]);
    match version {
        FRAUD_PROOF_VERSION => {
            let proof = decode_body_root_fraud_proof(consensus_wire)?;
            Ok(InteractiveFraudVerdict::BodyRoot(
                verify_body_root_fraud_proof(&proof)?,
            ))
        }
        COINBASE_FRAUD_PROOF_VERSION => {
            let proof = decode_coinbase_amount_fraud_proof(consensus_wire)?;
            Ok(InteractiveFraudVerdict::CoinbaseAmount(
                verify_coinbase_amount_fraud_proof(&proof, emission_params)?,
            ))
        }
        got => Err(FraudProofError::UnsupportedVersion { got }),
    }
}

/// Fan-out dedup key `(block_id, kind_tag)` when wire decodes.
#[must_use]
pub fn fraud_proof_fanout_key(consensus_wire: &[u8]) -> Option<([u8; 32], u8)> {
    use crate::block::block_id;
    if let Ok(p) = decode_body_root_fraud_proof(consensus_wire) {
        return Some((block_id(&p.block.header), p.kind as u8));
    }
    if let Ok(p) = decode_coinbase_amount_fraud_proof(consensus_wire) {
        return Some((block_id(&p.block.header), COINBASE_FRAUD_DEDUP_KIND));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{
        apply_genesis, build_genesis, build_unsealed_header, seal_block, GenesisConfig,
    };
    use crate::{
        BondingParams, ConsensusParams, DEFAULT_EMISSION_PARAMS, HEADER_VERSION,
        TEST_CONSENSUS_PARAMS,
    };
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

    #[test]
    fn coinbase_amount_fraud_round_trip_and_detect() {
        use crate::coinbase::{build_coinbase, PayoutAddress};
        use crate::emission::producer_portion_amount;
        use mfn_crypto::stealth::stealth_gen;

        let w = stealth_gen();
        let payout = PayoutAddress {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        };
        let height = 1u64;
        let fee_sum = 0u128;
        let expected = producer_portion_amount(height, &DEFAULT_EMISSION_PARAMS, fee_sum);
        let wrong_cb = build_coinbase(height, expected.saturating_add(1), &payout).expect("cb");
        let block = {
            let genesis = build_genesis(&GenesisConfig {
                timestamp: 0,
                initial_outputs: Vec::new(),
                initial_storage: Vec::new(),
                initial_storage_operators: Vec::new(),
                validators: Vec::new(),
                params: TEST_CONSENSUS_PARAMS,
                emission_params: DEFAULT_EMISSION_PARAMS,
                endowment_params: DEFAULT_ENDOWMENT_PARAMS,
                bonding_params: None,
                header_version: HEADER_VERSION,
            });
            let state = apply_genesis(
                &genesis,
                &GenesisConfig {
                    timestamp: 0,
                    initial_outputs: Vec::new(),
                    initial_storage: Vec::new(),
                    initial_storage_operators: Vec::new(),
                    validators: Vec::new(),
                    params: TEST_CONSENSUS_PARAMS,
                    emission_params: DEFAULT_EMISSION_PARAMS,
                    endowment_params: DEFAULT_ENDOWMENT_PARAMS,
                    bonding_params: None,
                    header_version: HEADER_VERSION,
                },
            )
            .expect("genesis");
            let header =
                build_unsealed_header(&state, std::slice::from_ref(&wrong_cb), &[], &[], &[], 1, 1);
            seal_block(header, vec![wrong_cb], vec![], vec![], vec![], vec![])
        };
        let proof = CoinbaseAmountFraudProof {
            version: COINBASE_FRAUD_PROOF_VERSION,
            block,
            fee_sum,
            producer_payout: payout,
            accepted_settlements: Vec::new(),
        };
        let wire = encode_coinbase_amount_fraud_proof(&proof);
        let decoded = decode_coinbase_amount_fraud_proof(&wire).expect("decode");
        verify_coinbase_amount_fraud_proof(&decoded, &DEFAULT_EMISSION_PARAMS).expect("fraud");
        verify_interactive_fraud_proof(&wire, &DEFAULT_EMISSION_PARAMS).expect("interactive");
    }
}
