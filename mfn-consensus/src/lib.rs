//! # `mfn-consensus`
//!
//! State-transition function for the Permawrite protocol.
//!
//! This crate turns the raw primitives in [`mfn_crypto`] into a **chain**:
//!
//! - [`emission`] — the protocol's monetary policy (initial subsidy, halvings,
//!   tail emission, treasury split).
//! - [`storage`] — `StorageCommitment` (the optional per-output binding that
//!   anchors a permanent data payload to a transaction). Minimal subset for
//!   v0; the full SPoRA prover + Merkle tree lives in the future
//!   `mfn-storage` crate.
//! - [`transaction`] — RingCT-style confidential transaction: ring-signed
//!   inputs, Pedersen-committed amounts, bulletproof range proofs, stealth
//!   addresses, pseudo-output blindings that prove balance without revealing
//!   amounts.
//! - [`bonding`] — validator rotation **defaults** (M1): min stake, unbond
//!   delay, per-epoch churn caps; [`bond_wire`] + [`block::apply_block`]
//!   integrate register ops under the header `bond_root`. Every successful
//!   register burns `stake` into [`block::ChainState::treasury`]; every
//!   equivocation and liveness slash routes the forfeited stake back to
//!   the same sink — closing the chain's permanence-funding loop on the
//!   validator economic side.
//! - [`bond_wire`] — canonical [`BondOp`] encoding and bond Merkle tree.
//! - [`coinbase`] — synthetic block-reward transaction, deterministic so any
//!   node can replay history byte-for-byte.
//! - [`consensus`] — slot-based PoS engine: stake-weighted VRF leader
//!   election (ed25519), BLS12-381 committee finality, and the
//!   [`consensus::FinalityProof`] that becomes a block header's
//!   `producer_proof`.
//! - [`slashing`] — on-chain equivocation evidence: two BLS-signed headers
//!   at the same slot from the same validator → stake slashed to zero.
//! - [`constitution`] — the fork-legitimacy test (F5:PM13): invariants no
//!   genesis or future upgrade may violate (`tail_emission > 0`, uniform
//!   rings ≥ 16, well-formed endowment pricing).
//!
//! ## Canonical bytes
//!
//! Encoders, decoders, state transitions, and golden vectors in this crate define
//! the protocol bytes used by Rust nodes. Byte drift is treated as a consensus bug.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - Secret material — output blindings, ephemeral tx-private scalars,
//!   coinbase blinding factors — is held in [`curve25519_dalek::scalar::Scalar`]
//!   and zeroized on drop (via `mfn_crypto`'s `random_scalar` flow).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

#[cfg(feature = "bls")]
pub(crate) use mfn_bls as bls;
#[cfg(not(feature = "bls"))]
pub(crate) mod bls_stub;
#[cfg(not(feature = "bls"))]
pub(crate) use bls_stub as bls;

pub mod block;
pub mod bond_wire;
pub mod bonding;
#[cfg(feature = "bls")]
pub mod chain_checkpoint;
#[cfg(feature = "bls")]
pub mod checkpoint_codec;
pub mod claims;
pub mod coinbase;
pub mod consensus;
pub mod constitution;
pub mod emission;
pub mod extra_codec;
#[cfg(feature = "bls")]
pub mod header_verify;
pub mod slashing;
pub mod storage;
pub mod storage_operator_evolution;
pub mod storage_operator_wire;
pub mod transaction;
#[cfg(feature = "bls")]
pub mod validator_evolution;

#[cfg(feature = "bls")]
pub use block::{
    apply_block, build_unsealed_header, build_unsealed_header_storage_ops, seal_block,
    seal_block_storage_ops, ApplyOutcome,
};
pub use block::{
    apply_genesis, block_header_bytes, block_id, build_genesis, decode_block, decode_block_body,
    decode_block_header, encode_block, encode_block_body, header_signing_bytes,
    header_signing_hash, storage_merkle_root, tx_merkle_root, Block, BlockBody, BlockDecodeError,
    BlockError, BlockHeader, ChainState, ConsensusParams, GenesisConfig, GenesisOutput,
    GenesisStorageOperator, HeaderDecodeError, PendingUnbond, RingPolicy, StorageOperatorEntry,
    UtxoEntry, ValidatorStats, DEFAULT_CONSENSUS_PARAMS, HEADER_VERSION,
    MIN_TX_INPUTS_UNIFORM_TIER, MIN_TX_OUTPUTS_UNIFORM_TIER, TEST_CONSENSUS_PARAMS,
};
pub use bond_wire::{
    bond_merkle_root, bond_op_leaf_hash, decode_bond_op, encode_bond_op, BondOp, BondWireError,
    BOND_OP_REGISTER, BOND_OP_UNBOND,
};
#[cfg(feature = "bls")]
pub use bond_wire::{
    register_signing_bytes, register_signing_hash, sign_register, sign_unbond,
    unbond_signing_bytes, unbond_signing_hash, verify_register_sig, verify_unbond_sig,
};
pub use bonding::{
    epoch_id_for_height, height_of_next_epoch, try_register_entry_churn, try_register_exit_churn,
    unbond_unlock_height, validate_stake, BondingError, BondingParams, DEFAULT_BONDING_PARAMS,
};
#[cfg(feature = "bls")]
pub use chain_checkpoint::{
    decode_chain_checkpoint, encode_chain_checkpoint, ChainCheckpoint, ChainCheckpointError,
    CHAIN_CHECKPOINT_MAGIC, CHAIN_CHECKPOINT_VERSION,
};
#[cfg(feature = "bls")]
pub use checkpoint_codec::{
    check_validator_assignment, decode_bonding_params, decode_consensus_params,
    decode_pending_unbond, decode_validator, decode_validator_stats, encode_bonding_params,
    encode_consensus_params, encode_pending_unbond, encode_validator, encode_validator_stats,
    CheckpointReadError,
};
pub use claims::{
    authorship_claim_key, authorship_claim_merkle_leaf, build_mfex_extra, build_mfex_extra_v2,
    build_mfex_extra_v3, claim_to_record, claims_merkle_root, collect_claim_merkle_leaves_for_txs,
    verified_claims_for_tx, AuthorshipClaimKey, AuthorshipClaimRecord, AuthorshipClaimVerifyError,
    VerifiedClaimsForTxResult, VerifiedTxClaims,
};
pub use coinbase::{
    build_coinbase, build_coinbase_outputs, coinbase_tx_priv, describe_coinbase,
    is_coinbase_shaped, verify_coinbase, verify_coinbase_outputs, CoinbaseError,
    CoinbaseOutputSpec, CoinbaseVerifyResult, PayoutAddress,
};
#[cfg(feature = "bls")]
pub use consensus::{
    cast_vote, decode_committee_aggregate, decode_finality_proof, decode_producer_proof,
    eligibility_threshold, encode_committee_aggregate, encode_finality_proof,
    encode_producer_proof, finalize, is_eligible, pick_winner, slot_seed, try_produce_slot,
    verify_finality_proof, verify_producer_proof, ConsensusCheck, ConsensusDecodeError,
    ConsensusError, FinalityProof, ProducerProof, SlotContext, ValidatorSecrets,
};
pub use consensus::{
    validator_leaf_bytes, validator_leaf_hash, validator_set_root, Validator, ValidatorPayout,
};
pub use constitution::{validate_constitution, ConstitutionError, CONSTITUTIONAL_MIN_RING_SIZE};
pub use emission::{
    annual_tail_emission, annualized_inflation_ppb, block_coinbase_specs, cumulative_emission,
    emission_at_height, pre_tail_supply_cap, producer_coinbase_amount, producer_portion_amount,
    storage_payout_amount, storage_proof_coinbase_bonus, storage_proof_operator_settlements,
    validate_emission_params, EmissionError, EmissionParams, DEFAULT_EMISSION_PARAMS, MFN_BASE,
    MFN_DECIMALS,
};
#[cfg(feature = "bls")]
pub use header_verify::{
    verify_block_body, verify_header, BodyVerifyError, HeaderCheck, HeaderVerifyError,
};
#[cfg(feature = "bls")]
pub use slashing::{canonicalize, verify_evidence, EvidenceCheck};
pub use slashing::{
    decode_evidence, encode_evidence, slashing_leaf_hash, slashing_merkle_root, SlashDecodeError,
    SlashEvidence,
};
pub use storage::{
    decode_storage_commitment, encode_storage_commitment, storage_commitment_hash,
    StorageCommitment,
};
pub use storage_operator_wire::{
    apply_storage_operator_ops, bond_section_merkle_root, decode_storage_operator_op,
    encode_storage_operator_op, register_signing_bytes as storage_operator_register_signing_bytes,
    register_signing_hash as storage_operator_register_signing_hash, storage_operator_op_leaf_hash,
    verify_register_sig as verify_storage_operator_register_sig, StorageOperatorOp,
    StorageOperatorOpError, StorageOperatorWireError, STORAGE_OP_REGISTER,
};
pub use transaction::{
    decode_transaction, encode_transaction, sign_transaction, tx_id, tx_preimage,
    tx_version_supported, verify_transaction, InputSpec, OutputSpec, Recipient, SignedTransaction,
    TransactionWire, TxBuildError, TxDecodeError, TxInputWire, TxOutputWire, VerifyResult,
    TX_RANGE_BITS, TX_VERSION, TX_VERSION_LEGACY,
};
#[cfg(feature = "bls")]
pub use validator_evolution::{
    apply_bond_ops_evolution, apply_equivocation_slashings, apply_liveness_evolution,
    apply_unbond_settlements, finality_bitmap_from_header, BondEpochCounters, BondOpError,
    EquivocationError, EquivocationOutcome, LivenessOutcome,
};
