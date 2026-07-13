//! Interactive body-root fraud proofs for light clients (**F5** phase 0).
//!
//! A finality quorum signs header bytes; it does **not** prove
//! [`crate::block::apply_block`] would accept the block ([`docs/PROBLEMS.md`]
//! item 11). Phase 0 lets any full node publish a succinct challenge that a
//! light client can verify **without the UTXO set**: the attached body
//! recomputes a Merkle root that disagrees with the finalized header.
//!
//! Later phases (CLSAG / SPoRA) attach compact witnesses. Coinbase amount fraud
//! (phase 2) uses fee_sum + settlement witnesses; phase 3 adds invalid CLSAG
//! (stateless) and invalid SPoRA (parent-state `StorageCommitment` witness).
//! Phase 3b adds ring-membership mint fraud (parent UTXO witness) and producer
//! slash hooks (`fraud_proof_producer_slash_hint`). Gossip ships on `mfn-net`
//! tag `0x13`; on-chain producer slash for invalid blocks remains deferred.

use crate::block::{
    decode_block, encode_block, tx_merkle_root, Block, BlockDecodeError, RingPolicy, UtxoEntry,
};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase_outputs, PayoutAddress};
use crate::emission::{block_coinbase_specs, EmissionParams};
use crate::slashing::slashing_merkle_root;
use crate::storage::{decode_storage_commitment, encode_storage_commitment, StorageCommitment};
use crate::storage_operator_wire::bond_section_merkle_root;
use crate::transaction::verify_transaction;
use mfn_crypto::codec::{Reader, Writer};
use mfn_storage::{
    decode_storage_proof, encode_storage_proof, storage_proof_merkle_root, verify_storage_proof,
    SporaError, StorageProof, StorageProofCheck,
};
use thiserror::Error;

/// Wire format version for [`BodyRootFraudProof`].
pub const FRAUD_PROOF_VERSION: u32 = 1;

/// Wire format version for [`CoinbaseAmountFraudProof`] (**F5** phase 2).
pub const COINBASE_FRAUD_PROOF_VERSION: u32 = 2;

/// Wire format version for CLSAG / SPoRA fraud (**F5** phase 3).
pub const TX_FRAUD_PROOF_VERSION: u32 = 3;

/// Dedup tag for coinbase fraud fan-out (distinct from [`BodyRootFraudKind`]).
pub const COINBASE_FRAUD_DEDUP_KIND: u8 = 5;

/// Dedup tag for invalid-CLSAG fraud fan-out.
pub const CLSAG_FRAUD_DEDUP_KIND: u8 = 6;

/// Dedup tag for invalid-SPoRA fraud fan-out.
pub const SPORA_FRAUD_DEDUP_KIND: u8 = 7;

/// Dedup tag for ring-membership fraud fan-out.
pub const RING_FRAUD_DEDUP_KIND: u8 = 8;

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
    /// `tx_index` / `proof_index` out of range for the attached block.
    #[error("fraud index {index} out of range for {kind} (len {len})")]
    IndexOutOfRange {
        /// Which index field failed.
        kind: &'static str,
        /// Supplied index.
        index: u16,
        /// Body section length.
        len: usize,
    },
    /// CLSAG fraud does not apply to coinbase-shaped txs.
    #[error("coinbase tx at index {0} is not a CLSAG fraud target")]
    CoinbaseNotClsagTarget(usize),
    /// SPoRA fraud requires a parent-state commitment witness.
    #[error("missing storage commitment witness for SPoRA fraud")]
    MissingStorageWitness,
    /// Storage commitment witness decode failed.
    #[error("storage commitment decode: {0}")]
    StorageCommitmentDecode(String),
    /// Ring fraud requires `input_index` and `ring_index`.
    #[error("missing ring indices for ring-membership fraud")]
    MissingRingIndices,
    /// Ring fraud requires a parent UTXO witness.
    #[error("missing parent UTXO witness for ring-membership fraud")]
    MissingParentUtxoWitness,
    /// Parent UTXO witness decode failed.
    #[error("parent UTXO witness decode: {0}")]
    ParentUtxoWitnessDecode(String),
    /// Ring column length mismatch inside the disputed input.
    #[error("input {input}: ring P/C length mismatch")]
    RingLengthMismatch {
        /// Input index in the tx.
        input: usize,
    },
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

/// Unified verdict for gossip admission (body-root, coinbase, or tx/storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveFraudVerdict {
    /// Body-root mismatch (phase 0).
    BodyRoot(FraudProofVerdict),
    /// Coinbase economics mismatch (phase 2).
    CoinbaseAmount(CoinbaseAmountFraudVerdict),
    /// CLSAG or SPoRA invalidity (phase 3).
    Tx(TxFraudVerdict),
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

/// Which tx/storage proof class phase 3 disputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxFraudKind {
    /// `verify_transaction` rejects the tx at `index` (stateless).
    InvalidClsag = 1,
    /// `verify_storage_proof` rejects the proof at `index` given witness commit.
    InvalidSpora = 2,
    /// Parent-state UTXO witness shows ring member absent or commit mismatch.
    RingMemberUtxo = 3,
}

impl TxFraudKind {
    /// Parse a wire discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::InvalidClsag),
            2 => Some(Self::InvalidSpora),
            3 => Some(Self::RingMemberUtxo),
            _ => None,
        }
    }
}

/// Parent-state witness for one ring member at block application time.
#[derive(Debug, Clone)]
pub enum ParentUtxoWitness {
    /// `one_time_addr` was not in the parent UTXO map.
    Absent,
    /// On-chain entry for the ring member's `P` key.
    Present(UtxoEntry),
}

/// CLSAG or SPoRA invalidity challenge (**F5** phase 3).
#[derive(Debug, Clone)]
pub struct TxFraudProof {
    /// Format version ([`TX_FRAUD_PROOF_VERSION`]).
    pub version: u32,
    /// Which check failed.
    pub kind: TxFraudKind,
    /// `txs` index (CLSAG / ring) or `storage_proofs` index (SPoRA).
    pub index: u16,
    /// Input index for [`TxFraudKind::RingMemberUtxo`].
    pub input_index: Option<u16>,
    /// Ring index for [`TxFraudKind::RingMemberUtxo`].
    pub ring_index: Option<u16>,
    /// Parent UTXO witness for [`TxFraudKind::RingMemberUtxo`].
    pub parent_utxo_witness: Option<ParentUtxoWitness>,
    /// Parent-state commitment witness (required for [`TxFraudKind::InvalidSpora`]).
    pub storage_commit_witness: Option<StorageCommitment>,
    /// Full block including the disputed tx or storage proof.
    pub block: Block,
}

/// Outcome of [`verify_tx_fraud_proof`] for invalid CLSAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsagFraudVerdict {
    /// Index in `block.txs`.
    pub tx_index: usize,
    /// Diagnostics from [`verify_transaction`].
    pub verify_errors: Vec<String>,
}

/// Outcome of [`verify_tx_fraud_proof`] for invalid SPoRA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporaFraudVerdict {
    /// Index in `block.storage_proofs`.
    pub proof_index: usize,
    /// Why [`verify_storage_proof`] rejected the proof.
    pub reason: StorageProofCheck,
}

/// Why a ring member fails the chain-level UTXO guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingMemberFraudReason {
    /// Ring `P` was not in the parent UTXO set.
    NotInUtxoSet,
    /// Ring `C` does not match the on-chain commitment for `P`.
    CommitMismatch,
}

/// Outcome of [`verify_tx_fraud_proof`] for ring-membership fraud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingMemberFraudVerdict {
    /// Index in `block.txs`.
    pub tx_index: usize,
    /// Input index within the tx.
    pub input_index: usize,
    /// Ring index within the input.
    pub ring_index: usize,
    /// Which `apply_block` ring guard would reject.
    pub reason: RingMemberFraudReason,
}

/// Verify a phase-3 CLSAG or SPoRA fraud proof.
pub fn verify_tx_fraud_proof(proof: &TxFraudProof) -> Result<TxFraudVerdict, FraudProofError> {
    if proof.version != TX_FRAUD_PROOF_VERSION {
        return Err(FraudProofError::UnsupportedVersion { got: proof.version });
    }
    match proof.kind {
        TxFraudKind::InvalidClsag => verify_clsag_fraud_proof(proof),
        TxFraudKind::InvalidSpora => verify_spora_fraud_proof(proof),
        TxFraudKind::RingMemberUtxo => verify_ring_member_utxo_fraud_proof(proof),
    }
}

fn verify_clsag_fraud_proof(proof: &TxFraudProof) -> Result<TxFraudVerdict, FraudProofError> {
    let tx_index = usize::from(proof.index);
    let tx = proof
        .block
        .txs
        .get(tx_index)
        .ok_or(FraudProofError::IndexOutOfRange {
            kind: "tx",
            index: proof.index,
            len: proof.block.txs.len(),
        })?;
    if tx_index == 0 && is_coinbase_shaped(tx) {
        return Err(FraudProofError::CoinbaseNotClsagTarget(tx_index));
    }
    let v = verify_transaction(tx, &RingPolicy::PRODUCTION);
    if v.ok {
        return Err(FraudProofError::NotFraud);
    }
    Ok(TxFraudVerdict::InvalidClsag(ClsagFraudVerdict {
        tx_index,
        verify_errors: v.errors,
    }))
}

fn verify_spora_fraud_proof(proof: &TxFraudProof) -> Result<TxFraudVerdict, FraudProofError> {
    let proof_index = usize::from(proof.index);
    let storage_proof =
        proof
            .block
            .storage_proofs
            .get(proof_index)
            .ok_or(FraudProofError::IndexOutOfRange {
                kind: "storage_proof",
                index: proof.index,
                len: proof.block.storage_proofs.len(),
            })?;
    let commit = proof
        .storage_commit_witness
        .as_ref()
        .ok_or(FraudProofError::MissingStorageWitness)?;
    let verdict = verify_storage_proof(
        commit,
        &proof.block.header.prev_hash,
        proof.block.header.slot,
        storage_proof,
    );
    if verdict.is_valid() {
        return Err(FraudProofError::NotFraud);
    }
    Ok(TxFraudVerdict::InvalidSpora(SporaFraudVerdict {
        proof_index,
        reason: verdict,
    }))
}

fn verify_ring_member_utxo_fraud_proof(
    proof: &TxFraudProof,
) -> Result<TxFraudVerdict, FraudProofError> {
    let tx_index = usize::from(proof.index);
    let input_index = usize::from(
        proof
            .input_index
            .ok_or(FraudProofError::MissingRingIndices)?,
    );
    let ring_index = usize::from(
        proof
            .ring_index
            .ok_or(FraudProofError::MissingRingIndices)?,
    );
    let witness = proof
        .parent_utxo_witness
        .as_ref()
        .ok_or(FraudProofError::MissingParentUtxoWitness)?;
    let tx = proof
        .block
        .txs
        .get(tx_index)
        .ok_or(FraudProofError::IndexOutOfRange {
            kind: "tx",
            index: proof.index,
            len: proof.block.txs.len(),
        })?;
    if tx_index == 0 && is_coinbase_shaped(tx) {
        return Err(FraudProofError::CoinbaseNotClsagTarget(tx_index));
    }
    let inp = tx
        .inputs
        .get(input_index)
        .ok_or(FraudProofError::IndexOutOfRange {
            kind: "input",
            index: proof.input_index.unwrap_or(0),
            len: tx.inputs.len(),
        })?;
    if inp.ring.p.len() != inp.ring.c.len() {
        return Err(FraudProofError::RingLengthMismatch { input: input_index });
    }
    let (_p, c) = inp
        .ring
        .p
        .get(ring_index)
        .zip(inp.ring.c.get(ring_index))
        .ok_or(FraudProofError::IndexOutOfRange {
            kind: "ring",
            index: proof.ring_index.unwrap_or(0),
            len: inp.ring.p.len(),
        })?;
    let reason = match witness {
        ParentUtxoWitness::Absent => RingMemberFraudReason::NotInUtxoSet,
        ParentUtxoWitness::Present(entry) => {
            if entry.commit == *c {
                return Err(FraudProofError::NotFraud);
            }
            RingMemberFraudReason::CommitMismatch
        }
    };
    Ok(TxFraudVerdict::RingMember(RingMemberFraudVerdict {
        tx_index,
        input_index,
        ring_index,
        reason,
    }))
}

fn encode_parent_utxo_witness(witness: &ParentUtxoWitness) -> Vec<u8> {
    let mut out = Vec::new();
    match witness {
        ParentUtxoWitness::Absent => out.push(0),
        ParentUtxoWitness::Present(entry) => {
            out.push(1);
            out.extend_from_slice(&entry.commit.compress().to_bytes());
            out.extend_from_slice(&entry.height.to_le_bytes());
        }
    }
    out
}

fn decode_parent_utxo_witness(bytes: &[u8]) -> Result<ParentUtxoWitness, FraudProofError> {
    if bytes.is_empty() {
        return Err(FraudProofError::ParentUtxoWitnessDecode(
            "witness too short".into(),
        ));
    }
    match bytes[0] {
        0 => Ok(ParentUtxoWitness::Absent),
        1 => {
            if bytes.len() < 37 {
                return Err(FraudProofError::ParentUtxoWitnessDecode(
                    "truncated present witness".into(),
                ));
            }
            let commit = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&bytes[1..33])
                .map_err(|e| FraudProofError::ParentUtxoWitnessDecode(e.to_string()))?
                .decompress()
                .ok_or_else(|| {
                    FraudProofError::ParentUtxoWitnessDecode("invalid commit point".into())
                })?;
            let height = u32::from_le_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
            Ok(ParentUtxoWitness::Present(UtxoEntry { commit, height }))
        }
        tag => Err(FraudProofError::ParentUtxoWitnessDecode(format!(
            "unknown witness tag {tag}"
        ))),
    }
}

/// Unified phase-3 verdict for gossip admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxFraudVerdict {
    /// CLSAG / balance / range proof failure (stateless).
    InvalidClsag(ClsagFraudVerdict),
    /// SPoRA proof failure given parent-state commitment witness.
    InvalidSpora(SporaFraudVerdict),
    /// Ring member absent from parent UTXO or commit mismatch.
    RingMember(RingMemberFraudVerdict),
}

/// Encode a phase-3 fraud proof for P2P / archive.
#[must_use]
pub fn encode_tx_fraud_proof(proof: &TxFraudProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.version.to_le_bytes());
    out.push(proof.kind as u8);
    out.extend_from_slice(&proof.index.to_le_bytes());
    if proof.kind == TxFraudKind::InvalidSpora {
        let commit_wire = encode_storage_commitment(
            proof
                .storage_commit_witness
                .as_ref()
                .expect("SPoRA fraud requires storage witness"),
        );
        let len = u32::try_from(commit_wire.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&commit_wire);
    } else if proof.kind == TxFraudKind::RingMemberUtxo {
        let input_index = proof.input_index.expect("ring fraud requires input_index");
        let ring_index = proof.ring_index.expect("ring fraud requires ring_index");
        out.extend_from_slice(&input_index.to_le_bytes());
        out.extend_from_slice(&ring_index.to_le_bytes());
        out.extend_from_slice(&encode_parent_utxo_witness(
            proof
                .parent_utxo_witness
                .as_ref()
                .expect("ring fraud requires parent UTXO witness"),
        ));
    }
    out.extend_from_slice(&encode_block(&proof.block));
    out
}

/// Decode [`encode_tx_fraud_proof`] bytes.
pub fn decode_tx_fraud_proof(bytes: &[u8]) -> Result<TxFraudProof, FraudProofError> {
    if bytes.len() < 7 {
        return Err(FraudProofError::BlockDecode(
            "tx fraud proof too short".into(),
        ));
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let kind = TxFraudKind::from_u8(bytes[4]).ok_or(FraudProofError::UnknownKind(bytes[4]))?;
    let index = u16::from_le_bytes([bytes[5], bytes[6]]);
    let mut offset = 7usize;
    let (input_index, ring_index, parent_utxo_witness, storage_commit_witness) =
        if kind == TxFraudKind::InvalidSpora {
            if offset + 4 > bytes.len() {
                return Err(FraudProofError::BlockDecode(
                    "truncated commitment length".into(),
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
            if offset.saturating_add(wire_len) > bytes.len() {
                return Err(FraudProofError::BlockDecode(
                    "truncated commitment wire".into(),
                ));
            }
            let wire = &bytes[offset..offset.saturating_add(wire_len)];
            offset = offset.saturating_add(wire_len);
            let commit = decode_storage_commitment(wire)
                .map_err(|e| FraudProofError::StorageCommitmentDecode(e.to_string()))?;
            (None, None, None, Some(commit))
        } else if kind == TxFraudKind::RingMemberUtxo {
            if offset + 4 > bytes.len() {
                return Err(FraudProofError::BlockDecode(
                    "truncated ring indices".into(),
                ));
            }
            let input_index = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            let ring_index = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
            offset = offset.saturating_add(4);
            if offset >= bytes.len() {
                return Err(FraudProofError::BlockDecode(
                    "truncated parent UTXO witness".into(),
                ));
            }
            let witness_wire = match bytes[offset] {
                0 => {
                    offset = offset.saturating_add(1);
                    &bytes[offset - 1..offset]
                }
                1 => {
                    if offset.saturating_add(37) > bytes.len() {
                        return Err(FraudProofError::BlockDecode(
                            "truncated parent UTXO witness".into(),
                        ));
                    }
                    let wire = &bytes[offset..offset.saturating_add(37)];
                    offset = offset.saturating_add(37);
                    wire
                }
                tag => {
                    return Err(FraudProofError::ParentUtxoWitnessDecode(format!(
                        "unknown witness tag {tag}"
                    )));
                }
            };
            let witness = decode_parent_utxo_witness(witness_wire)?;
            (Some(input_index), Some(ring_index), Some(witness), None)
        } else {
            (None, None, None, None)
        };
    let block = decode_block(&bytes[offset..])
        .map_err(|e: BlockDecodeError| FraudProofError::BlockDecode(e.to_string()))?;
    Ok(TxFraudProof {
        version,
        kind,
        index,
        input_index,
        ring_index,
        parent_utxo_witness,
        storage_commit_witness,
        block,
    })
}

/// Verify any supported interactive fraud proof wire (version 1, 2, or 3).
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
        TX_FRAUD_PROOF_VERSION => {
            let proof = decode_tx_fraud_proof(consensus_wire)?;
            Ok(InteractiveFraudVerdict::Tx(verify_tx_fraud_proof(&proof)?))
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
    if let Ok(p) = decode_tx_fraud_proof(consensus_wire) {
        let kind_tag = match p.kind {
            TxFraudKind::InvalidClsag => CLSAG_FRAUD_DEDUP_KIND,
            TxFraudKind::InvalidSpora => SPORA_FRAUD_DEDUP_KIND,
            TxFraudKind::RingMemberUtxo => RING_FRAUD_DEDUP_KIND,
        };
        return Some((block_id(&p.block.header), kind_tag));
    }
    None
}

/// Producer slash hook (**F5** phase 3b): identifies the block producer when
/// interactive fraud is valid. On-chain slashing remains equivocation-only;
/// this is an ops hook for PM1 bonding and future invalid-block evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FraudProducerSlashHint {
    /// Block height attached to the fraud proof.
    pub height: u32,
    /// `block_id` of the disputed header.
    pub block_id: [u8; 32],
    /// Producer validator index from `header.producer_proof`.
    pub producer_index: u32,
}

/// Extract producer slash hint from any decodable interactive fraud wire.
pub fn fraud_proof_producer_slash_hint(consensus_wire: &[u8]) -> Option<FraudProducerSlashHint> {
    use crate::block::block_id;
    use crate::consensus::decode_producer_proof;
    let block = fraud_proof_attached_block(consensus_wire)?;
    let producer_index = decode_producer_proof(&block.header.producer_proof)
        .ok()
        .map(|p| p.validator_index)?;
    Some(FraudProducerSlashHint {
        height: block.header.height,
        block_id: block_id(&block.header),
        producer_index,
    })
}

/// Block identity for any valid interactive fraud attachment (producer index
/// optional — `None` when `producer_proof` is absent on test harness blocks).
pub fn fraud_proof_contested_block(consensus_wire: &[u8]) -> Option<(u32, [u8; 32], Option<u32>)> {
    use crate::block::block_id;
    use crate::consensus::decode_producer_proof;
    let block = fraud_proof_attached_block(consensus_wire)?;
    let producer_index = decode_producer_proof(&block.header.producer_proof)
        .ok()
        .map(|p| p.validator_index);
    Some((block.header.height, block_id(&block.header), producer_index))
}

fn fraud_proof_attached_block(consensus_wire: &[u8]) -> Option<Block> {
    if consensus_wire.len() < 4 {
        return None;
    }
    let version = u32::from_le_bytes([
        consensus_wire[0],
        consensus_wire[1],
        consensus_wire[2],
        consensus_wire[3],
    ]);
    match version {
        FRAUD_PROOF_VERSION => decode_body_root_fraud_proof(consensus_wire)
            .ok()
            .map(|p| p.block),
        COINBASE_FRAUD_PROOF_VERSION => decode_coinbase_amount_fraud_proof(consensus_wire)
            .ok()
            .map(|p| p.block),
        TX_FRAUD_PROOF_VERSION => decode_tx_fraud_proof(consensus_wire).ok().map(|p| p.block),
        _ => None,
    }
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

    #[test]
    fn clsag_fraud_round_trip_and_detect() {
        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};
        use curve25519_dalek::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::stealth::stealth_gen;
        use mfn_crypto::{generator_g, generator_h, random_scalar};

        fn ring16_input(value: u64) -> InputSpec {
            let signer_idx = 8usize;
            let signer_spend = random_scalar();
            let signer_blinding = random_scalar();
            let signer_p = generator_g() * signer_spend;
            let signer_c =
                (generator_g() * signer_blinding) + (generator_h() * Scalar::from(value));
            let mut p = Vec::with_capacity(16);
            let mut c = Vec::with_capacity(16);
            for i in 0..16 {
                if i == signer_idx {
                    p.push(signer_p);
                    c.push(signer_c);
                } else {
                    p.push(generator_g() * random_scalar());
                    c.push(generator_g() * random_scalar());
                }
            }
            InputSpec {
                ring: ClsagRing { p, c },
                signer_idx,
                spend_priv: signer_spend,
                value,
                blinding: signer_blinding,
            }
        }

        let w_a = stealth_gen();
        let w_b = stealth_gen();
        let signed = sign_transaction(
            vec![ring16_input(1_000_000)],
            vec![
                OutputSpec::ToRecipient {
                    recipient: Recipient {
                        view_pub: w_a.view_pub,
                        spend_pub: w_a.spend_pub,
                    },
                    value: 600_000,
                    storage: None,
                },
                OutputSpec::ToRecipient {
                    recipient: Recipient {
                        view_pub: w_b.view_pub,
                        spend_pub: w_b.spend_pub,
                    },
                    value: 399_000,
                    storage: None,
                },
            ],
            1_000,
            Vec::new(),
        )
        .expect("sign");
        let mut bad_tx = signed.tx.clone();
        bad_tx.fee = bad_tx.fee.saturating_add(1);
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
                build_unsealed_header(&state, std::slice::from_ref(&bad_tx), &[], &[], &[], 1, 1);
            seal_block(header, vec![bad_tx], vec![], vec![], vec![], vec![])
        };
        let proof = TxFraudProof {
            version: TX_FRAUD_PROOF_VERSION,
            kind: TxFraudKind::InvalidClsag,
            index: 0,
            input_index: None,
            ring_index: None,
            parent_utxo_witness: None,
            storage_commit_witness: None,
            block,
        };
        let wire = encode_tx_fraud_proof(&proof);
        let decoded = decode_tx_fraud_proof(&wire).expect("decode");
        match verify_tx_fraud_proof(&decoded).expect("fraud") {
            TxFraudVerdict::InvalidClsag(v) => assert!(!v.verify_errors.is_empty()),
            _ => panic!("expected CLSAG fraud"),
        }
        verify_interactive_fraud_proof(&wire, &DEFAULT_EMISSION_PARAMS).expect("interactive");
    }

    #[test]
    fn spora_fraud_round_trip_and_detect() {
        use mfn_crypto::stealth::stealth_gen;
        use mfn_storage::{build_storage_commitment, build_storage_proof, DEFAULT_CHUNK_SIZE};

        let data = vec![0xABu8; 8192];
        let built = build_storage_commitment(&data, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None)
            .expect("commit");
        let prev = [42u8; 32];
        let slot = 3u32;
        let op = stealth_gen();
        let mut proof = build_storage_proof(
            &built.commit,
            &prev,
            slot,
            &data,
            &built.tree,
            op.view_pub,
            op.spend_pub,
        )
        .expect("proof");
        proof.chunk[0] ^= 0xff;
        let mut block = {
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
                build_unsealed_header(&state, &[], &[], &[], std::slice::from_ref(&proof), slot, 1);
            seal_block(header, vec![], vec![], vec![], vec![], vec![proof])
        };
        block.header.prev_hash = prev;
        let fraud = TxFraudProof {
            version: TX_FRAUD_PROOF_VERSION,
            kind: TxFraudKind::InvalidSpora,
            index: 0,
            input_index: None,
            ring_index: None,
            parent_utxo_witness: None,
            storage_commit_witness: Some(built.commit.clone()),
            block,
        };
        let wire = encode_tx_fraud_proof(&fraud);
        let decoded = decode_tx_fraud_proof(&wire).expect("decode");
        match verify_tx_fraud_proof(&decoded).expect("fraud") {
            TxFraudVerdict::InvalidSpora(v) => {
                assert_eq!(v.proof_index, 0);
                assert!(!v.reason.is_valid());
            }
            _ => panic!("expected SPoRA fraud"),
        }
        verify_interactive_fraud_proof(&wire, &DEFAULT_EMISSION_PARAMS).expect("interactive");
    }

    #[test]
    fn ring_member_absent_utxo_fraud_round_trip() {
        use curve25519_dalek::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::stealth::stealth_gen;
        use mfn_crypto::{generator_g, generator_h, random_scalar};

        use crate::block::GenesisOutput;
        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        const RING: usize = 16;
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));
        let fake_slot = 7usize;
        let mut decoys = Vec::with_capacity(RING - 1);
        let mut initial_outputs = vec![GenesisOutput {
            one_time_addr: signer_p,
            amount: signer_c,
        }];
        for i in 0..RING - 1 {
            let spend = random_scalar();
            let blinding = random_scalar();
            let p = generator_g() * spend;
            let c = (generator_g() * blinding) + (generator_h() * Scalar::from(1u64 + i as u64));
            decoys.push((p, c));
            initial_outputs.push(GenesisOutput {
                one_time_addr: p,
                amount: c,
            });
        }
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs,
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: HEADER_VERSION,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).expect("genesis");
        let mut ring_p = Vec::with_capacity(RING);
        let mut ring_c = Vec::with_capacity(RING);
        for slot in 0..RING {
            if slot == 0 {
                ring_p.push(signer_p);
                ring_c.push(signer_c);
            } else if slot == fake_slot {
                ring_p.push(generator_g() * random_scalar());
                ring_c.push(generator_g() * random_scalar());
            } else {
                let decoy_idx = if slot < fake_slot { slot - 1 } else { slot - 2 };
                let (dp, dc) = decoys[decoy_idx];
                ring_p.push(dp);
                ring_c.push(dc);
            }
        }
        let w = stealth_gen();
        let r = Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        };
        let signed = sign_transaction(
            vec![InputSpec {
                ring: ClsagRing {
                    p: ring_p,
                    c: ring_c,
                },
                signer_idx: 0,
                spend_priv: signer_spend,
                value: init_value,
                blinding: init_blinding,
            }],
            vec![
                OutputSpec::ToRecipient {
                    recipient: r,
                    value: init_value - 2_000,
                    storage: None,
                },
                OutputSpec::ToRecipient {
                    recipient: r,
                    value: 1_000,
                    storage: None,
                },
            ],
            1_000,
            b"absent".to_vec(),
        )
        .expect("sign");
        let block = {
            let header = build_unsealed_header(
                &state0,
                std::slice::from_ref(&signed.tx),
                &[],
                &[],
                &[],
                1,
                1,
            );
            seal_block(header, vec![signed.tx], vec![], vec![], vec![], vec![])
        };
        let proof = TxFraudProof {
            version: TX_FRAUD_PROOF_VERSION,
            kind: TxFraudKind::RingMemberUtxo,
            index: 0,
            input_index: Some(0),
            ring_index: Some(fake_slot as u16),
            parent_utxo_witness: Some(ParentUtxoWitness::Absent),
            storage_commit_witness: None,
            block,
        };
        let wire = encode_tx_fraud_proof(&proof);
        match verify_tx_fraud_proof(&decode_tx_fraud_proof(&wire).expect("decode")).expect("fraud")
        {
            TxFraudVerdict::RingMember(v) => {
                assert_eq!(v.reason, RingMemberFraudReason::NotInUtxoSet);
            }
            _ => panic!("expected absent ring fraud"),
        }
        verify_interactive_fraud_proof(&wire, &DEFAULT_EMISSION_PARAMS).expect("interactive");
    }

    #[test]
    fn ring_member_commit_mismatch_fraud_round_trip() {
        use curve25519_dalek::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::stealth::stealth_gen;
        use mfn_crypto::{generator_g, generator_h, random_scalar};

        use crate::block::GenesisOutput;
        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        const RING: usize = 16;
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));
        let inflated_slot = 5usize;
        let mut decoys = Vec::with_capacity(RING - 1);
        let mut initial_outputs = vec![GenesisOutput {
            one_time_addr: signer_p,
            amount: signer_c,
        }];
        for i in 0..RING - 1 {
            let spend = random_scalar();
            let blinding = random_scalar();
            let p = generator_g() * spend;
            let c = (generator_g() * blinding) + (generator_h() * Scalar::from(100u64 + i as u64));
            decoys.push((p, c));
            initial_outputs.push(GenesisOutput {
                one_time_addr: p,
                amount: c,
            });
        }
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs,
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: HEADER_VERSION,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).expect("genesis");
        let inflated_c =
            (generator_g() * random_scalar()) + (generator_h() * Scalar::from(1_000_000_000u64));
        let mut ring_p = Vec::with_capacity(RING);
        let mut ring_c = Vec::with_capacity(RING);
        for slot in 0..RING {
            if slot == 0 {
                ring_p.push(signer_p);
                ring_c.push(signer_c);
            } else {
                let (dp, dc) = decoys[slot - 1];
                ring_p.push(dp);
                ring_c.push(if slot == inflated_slot {
                    inflated_c
                } else {
                    dc
                });
            }
        }
        let w = stealth_gen();
        let r = Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        };
        let signed = sign_transaction(
            vec![InputSpec {
                ring: ClsagRing {
                    p: ring_p,
                    c: ring_c,
                },
                signer_idx: 0,
                spend_priv: signer_spend,
                value: init_value,
                blinding: init_blinding,
            }],
            vec![
                OutputSpec::ToRecipient {
                    recipient: r,
                    value: init_value - 2_000,
                    storage: None,
                },
                OutputSpec::ToRecipient {
                    recipient: r,
                    value: 1_000,
                    storage: None,
                },
            ],
            1_000,
            b"mismatch".to_vec(),
        )
        .expect("sign");
        let block = {
            let header = build_unsealed_header(
                &state0,
                std::slice::from_ref(&signed.tx),
                &[],
                &[],
                &[],
                1,
                1,
            );
            seal_block(header, vec![signed.tx], vec![], vec![], vec![], vec![])
        };
        let (_, real_dc) = decoys[inflated_slot - 1];
        let proof = TxFraudProof {
            version: TX_FRAUD_PROOF_VERSION,
            kind: TxFraudKind::RingMemberUtxo,
            index: 0,
            input_index: Some(0),
            ring_index: Some(inflated_slot as u16),
            parent_utxo_witness: Some(ParentUtxoWitness::Present(UtxoEntry {
                commit: real_dc,
                height: 0,
            })),
            storage_commit_witness: None,
            block,
        };
        let wire = encode_tx_fraud_proof(&proof);
        match verify_tx_fraud_proof(&decode_tx_fraud_proof(&wire).expect("decode")).expect("fraud")
        {
            TxFraudVerdict::RingMember(v) => {
                assert_eq!(v.reason, RingMemberFraudReason::CommitMismatch);
            }
            _ => panic!("expected mismatch ring fraud"),
        }
        verify_interactive_fraud_proof(&wire, &DEFAULT_EMISSION_PARAMS).expect("interactive");
    }
}
