//! Structured errors returned by [`apply_block`](super::apply::apply_block).

use crate::slashing::EvidenceCheck;
use mfn_storage::StorageProofCheck;

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Block-application errors. Surfaced via [`ApplyOutcome::Err`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    /// Genesis block must have `height == 0`.
    #[error("genesis height must be 0")]
    GenesisHeightNotZero,
    /// Header height didn't match `state.height + 1`.
    #[error("bad height: expected {expected}, got {got}")]
    BadHeight {
        /// Expected (current tip + 1).
        expected: u32,
        /// What the header carried.
        got: u32,
    },
    /// `prev_hash` didn't match the chain tip.
    #[error("prev_hash does not match tip")]
    PrevHashMismatch,
    /// Header `tx_root` didn't match the locally-recomputed root.
    #[error("tx_root mismatch")]
    TxRootMismatch,
    /// Header `bond_root` didn't match the locally-recomputed bond Merkle root.
    #[error("bond_root mismatch")]
    BondRootMismatch,
    /// Header `slashing_root` didn't match the locally-recomputed
    /// Merkle root over `block.slashings` (M2.0.1).
    #[error("slashing_root mismatch")]
    SlashingRootMismatch,
    /// Header `storage_proof_root` didn't match the locally-recomputed
    /// Merkle root over `block.storage_proofs` (M2.0.2).
    #[error("storage_proof_root mismatch")]
    StorageProofRootMismatch,
    /// Header `validator_root` didn't match the locally-recomputed Merkle
    /// root over the pre-block validator set (M2.0).
    #[error("validator_root mismatch")]
    ValidatorRootMismatch,
    /// Header `claims_root` didn't match the Merkle root recomputed from
    /// this block's non-coinbase `tx.extra` authorship payloads (M2.2.x).
    #[error("claims_root mismatch")]
    ClaimsRootMismatch,
    /// Authorship claim parse or signature verification failed for a tx.
    #[error("authorship claims: {0}")]
    AuthorshipClaims(String),
    /// A bond operation failed validation or conflicted with on-chain state.
    #[error("bond_ops[{index}]: {message}")]
    BondOpRejected {
        /// Index in `block.bond_ops`.
        index: usize,
        /// Human-readable reason.
        message: String,
    },
    /// Chain has a validator set but the header lacks a producer proof.
    #[error("missing producer proof")]
    MissingProducerProof,
    /// The producer proof failed to decode.
    #[error("producer proof decode failed: {0}")]
    FinalityDecode(String),
    /// The producer proof decoded but failed verification.
    #[cfg(feature = "bls")]
    #[error("finality invalid: {0:?}")]
    FinalityInvalid(crate::consensus::ConsensusCheck),
    /// A tx past index 0 was coinbase-shaped (no inputs).
    #[error("tx[{0}]: coinbase-shaped tx not allowed past position 0")]
    CoinbaseOutOfPosition(usize),
    /// The chain expected a coinbase at position 0 but got a non-coinbase
    /// (real-input tx).
    #[error("tx[0]: expected coinbase but got {got_inputs}-input tx")]
    MissingCoinbase {
        /// Number of inputs in the bogus first tx.
        got_inputs: usize,
    },
    /// `verify_transaction` rejected the tx.
    #[error("tx[{index}] invalid: {errors:?}")]
    TxInvalid {
        /// Position in `block.txs`.
        index: usize,
        /// Per-error strings from `verify_transaction`.
        errors: Vec<String>,
    },
    /// A key image already exists in the chain or this block.
    #[error("tx[{index}] double-spend: key image {key_image}")]
    DoubleSpend {
        /// Position of the offending tx.
        index: usize,
        /// Hex prefix of the duplicate key image.
        key_image: String,
    },
    /// A CLSAG ring member references a one-time address that is not in
    /// the chain's UTXO set. This is the chain-level guard against fake
    /// ring members; without it, a spender could mint MFN out of thin
    /// air by inventing a ring member with an arbitrary hidden value.
    #[error(
        "tx[{tx}].inputs[{input}].ring[{ring_index}]: one-time address {one_time_addr} not in UTXO set"
    )]
    RingMemberNotInUtxoSet {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending input within the tx.
        input: usize,
        /// Position of the offending member within the ring.
        ring_index: usize,
        /// Hex prefix of the one-time address.
        one_time_addr: String,
    },
    /// A CLSAG ring member references a real UTXO but with a Pedersen
    /// commitment that doesn't match the on-chain commitment for that
    /// output. The ring's `C` column would let the spender inflate the
    /// hidden value of a real UTXO, so the chain enforces exact match.
    #[error(
        "tx[{tx}].inputs[{input}].ring[{ring_index}]: commitment mismatch for {one_time_addr}"
    )]
    RingMemberCommitMismatch {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending input within the tx.
        input: usize,
        /// Position of the offending member within the ring.
        ring_index: usize,
        /// Hex prefix of the one-time address.
        one_time_addr: String,
    },
    /// The UTXO accumulator is full (depth-32 tree exhausted).
    #[error("utxo accumulator full: {0}")]
    AccumulatorFull(String),
    /// Two slashing pieces target the same validator.
    #[error("slashings[{index}]: duplicate evidence for validator {voter_index}")]
    DuplicateSlash {
        /// Index in `block.slashings`.
        index: usize,
        /// Validator index referenced twice.
        voter_index: u32,
    },
    /// A piece of slashing evidence failed verification.
    #[error("slashings[{index}]: {reason:?}")]
    SlashInvalid {
        /// Index in `block.slashings`.
        index: usize,
        /// Reason from the slashing verifier.
        reason: EvidenceCheck,
    },
    /// Producer has a payout but the block has no coinbase tx.
    #[error("coinbase required (producer has payout) but absent")]
    CoinbaseRequiredButAbsent,
    /// `verify_coinbase` rejected the tx.
    #[error("coinbase invalid: {0:?}")]
    CoinbaseInvalid(Vec<String>),
    /// Block has a coinbase but the producer has no payout (or there is
    /// no producer at all).
    #[error("unexpected coinbase: producer has no payout")]
    UnexpectedCoinbase,
    /// Storage Merkle root mismatch.
    #[error("storage_root mismatch")]
    StorageRootMismatch,
    /// UTXO accumulator root mismatch.
    #[error("utxo_root mismatch")]
    UtxoRootMismatch,
    /// A NEW storage commitment declared an internally inconsistent
    /// geometry (`chunk_size` not a positive power of two, or
    /// `num_chunks != ceil(size_bytes / chunk_size)`). Anchoring it would
    /// let the SPoRA audit surface diverge from the priced payload —
    /// e.g. a gigabyte upload that only ever proves one chunk (M5.49).
    #[error("tx[{tx}].outputs[{output}]: malformed storage commitment: {reason}")]
    StorageCommitmentMalformed {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending output within the tx.
        output: usize,
        /// Structured reason from the shape validator.
        reason: mfn_storage::CommitmentShapeError,
    },
    /// A storage commitment declared replication below the configured
    /// `min_replication`.
    #[error("tx[{tx}].outputs[{output}]: storage replication {got} < min {min}")]
    StorageReplicationTooLow {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending output within the tx.
        output: usize,
        /// Caller-supplied replication factor.
        got: u8,
        /// Configured minimum.
        min: u8,
    },
    /// A storage commitment declared replication above the configured
    /// `max_replication`.
    #[error("tx[{tx}].outputs[{output}]: storage replication {got} > max {max}")]
    StorageReplicationTooHigh {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending output within the tx.
        output: usize,
        /// Caller-supplied replication factor.
        got: u8,
        /// Configured maximum.
        max: u8,
    },
    /// A tx introduced new storage commitments but didn't contribute
    /// enough treasury-fee to cover the protocol's required endowment.
    #[error(
        "tx[{tx}]: storage endowment burden {burden} exceeds tx treasury share {treasury_share} \
         (fee={fee}, fee_to_treasury_bps={fee_to_treasury_bps})"
    )]
    UploadUnderfunded {
        /// Position of the offending tx.
        tx: usize,
        /// Total required endowment for this tx's new storage commitments.
        burden: u128,
        /// Treasury-bound share of the tx fee available to cover it.
        treasury_share: u128,
        /// The tx's declared fee (base units).
        fee: u64,
        /// Chain's `fee_to_treasury_bps`.
        fee_to_treasury_bps: u16,
    },
    /// Underlying endowment math returned an error (overflow, validation).
    #[error("tx[{tx}].outputs[{output}]: endowment math failed: {reason}")]
    EndowmentMathFailed {
        /// Position of the related tx (or `0` for non-tx contexts).
        tx: usize,
        /// Position within outputs/proofs.
        output: usize,
        /// Stringified upstream error.
        reason: String,
    },
    /// B-11: new storage anchor requires `MFEO` opening in `tx.extra`.
    #[error("tx[{tx}]: endowment opening required for new storage anchor at output {output}")]
    EndowmentOpeningRequired {
        /// Position of the offending tx.
        tx: usize,
        /// Output index carrying the new storage commitment.
        output: usize,
    },
    /// B-11: `MFEO` count does not match new storage anchors in this tx.
    #[error("tx[{tx}]: expected {expected} endowment opening(s) in extra, got {got}")]
    EndowmentOpeningCountMismatch {
        /// Position of the offending tx.
        tx: usize,
        /// Number of new storage anchors.
        expected: usize,
        /// Parsed `MFEO` frames.
        got: usize,
    },
    /// B-11: `tx.extra` MFEX/MFEO parse failure.
    #[error("tx[{tx}]: endowment opening parse: {reason}")]
    EndowmentOpeningParse {
        /// Position of the offending tx.
        tx: usize,
        /// Parse error detail.
        reason: String,
    },
    /// B-11: Pedersen opening does not verify against `StorageCommitment.endowment`.
    #[error("tx[{tx}].outputs[{output}]: endowment opening does not verify")]
    EndowmentOpeningInvalid {
        /// Position of the offending tx.
        tx: usize,
        /// Output index.
        output: usize,
    },
    /// B-11: opened endowment value is below `required_endowment`.
    #[error("tx[{tx}].outputs[{output}]: opened endowment {opened} < required {required}")]
    EndowmentOpeningUnderfund {
        /// Position of the offending tx.
        tx: usize,
        /// Output index.
        output: usize,
        /// Opened amount (base units).
        opened: u64,
        /// Protocol-required minimum.
        required: u64,
    },
    /// Two storage proofs in the block target the same commitment.
    #[error("storage_proofs[{index}]: duplicate proof for {commit_hash}")]
    DuplicateStorageProof {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the duplicated commit hash.
        commit_hash: String,
    },
    /// A storage proof referenced a commitment that isn't anchored in the
    /// chain's storage registry.
    #[error("storage_proofs[{index}]: commit {commit_hash} not in storage registry")]
    StorageProofUnknownCommit {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the unknown commit hash.
        commit_hash: String,
    },
    /// A storage proof failed verification.
    #[error("storage_proofs[{index}]: {reason:?}")]
    StorageProofInvalid {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Structured reason from the SPoRA verifier.
        reason: StorageProofCheck,
    },
    /// Two operator-salted proofs in the block target the same commitment
    /// and operator identity (B3).
    #[error("storage_proofs[{index}]: duplicate operator {operator_id} for commit {commit_hash}")]
    DuplicateStorageProofOperator {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the commitment hash.
        commit_hash: String,
        /// Hex prefix of the operator identity.
        operator_id: String,
    },
    /// A block carried more distinct operator proofs for one commitment than
    /// its replication factor allows (B3).
    #[error("storage_proofs[{index}]: replication cap exceeded for {commit_hash} (max {max})")]
    StorageProofReplicationExceeded {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the commitment hash.
        commit_hash: String,
        /// Configured replication for the commitment.
        max: u8,
    },
    /// Operator-salted proof from an unregistered operator (B3 phase 3).
    #[error("storage_proofs[{index}]: unregistered operator {operator_id}")]
    StorageProofUnregisteredOperator {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the operator identity.
        operator_id: String,
    },
}
