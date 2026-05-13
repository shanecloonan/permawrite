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
//!
//! ## Byte-for-byte parity
//!
//! Every encoder in this crate matches the TypeScript reference in
//! `cloonan-group/lib/network/*.ts` exactly. Test vectors flow TS → Rust
//! initially; once a primitive lands here it becomes the ground truth.
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

pub mod block;
pub mod bond_wire;
pub mod bonding;
pub mod coinbase;
pub mod consensus;
pub mod emission;
pub mod header_verify;
pub mod slashing;
pub mod storage;
pub mod transaction;
pub mod validator_evolution;

pub use block::{
    apply_block, apply_genesis, block_header_bytes, block_id, build_genesis, build_unsealed_header,
    decode_block, decode_block_header, encode_block, header_signing_bytes, header_signing_hash,
    seal_block, storage_merkle_root, tx_merkle_root, ApplyOutcome, Block, BlockDecodeError,
    BlockError, BlockHeader, ChainState, ConsensusParams, GenesisConfig, GenesisOutput,
    HeaderDecodeError, PendingUnbond, UtxoEntry, ValidatorStats, DEFAULT_CONSENSUS_PARAMS,
    HEADER_VERSION,
};
pub use bond_wire::{
    bond_merkle_root, bond_op_leaf_hash, decode_bond_op, encode_bond_op, register_signing_bytes,
    register_signing_hash, sign_register, sign_unbond, unbond_signing_bytes, unbond_signing_hash,
    verify_register_sig, verify_unbond_sig, BondOp, BondWireError, BOND_OP_REGISTER,
    BOND_OP_UNBOND,
};
pub use bonding::{
    epoch_id_for_height, height_of_next_epoch, try_register_entry_churn, try_register_exit_churn,
    unbond_unlock_height, validate_stake, BondingError, BondingParams, DEFAULT_BONDING_PARAMS,
};
pub use coinbase::{
    build_coinbase, coinbase_tx_priv, describe_coinbase, is_coinbase_shaped, verify_coinbase,
    CoinbaseError, CoinbaseVerifyResult, PayoutAddress,
};
pub use consensus::{
    cast_vote, decode_committee_aggregate, decode_finality_proof, decode_producer_proof,
    eligibility_threshold, encode_committee_aggregate, encode_finality_proof,
    encode_producer_proof, finalize, is_eligible, pick_winner, slot_seed, try_produce_slot,
    validator_leaf_bytes, validator_leaf_hash, validator_set_root, verify_finality_proof,
    verify_producer_proof, ConsensusCheck, ConsensusDecodeError, ConsensusError, FinalityProof,
    ProducerProof, SlotContext, Validator, ValidatorPayout, ValidatorSecrets,
};
pub use emission::{
    annual_tail_emission, annualized_inflation_ppb, cumulative_emission, emission_at_height,
    pre_tail_supply_cap, validate_emission_params, EmissionError, EmissionParams,
    DEFAULT_EMISSION_PARAMS, MFN_BASE, MFN_DECIMALS,
};
pub use header_verify::{
    verify_block_body, verify_header, BodyVerifyError, HeaderCheck, HeaderVerifyError,
};
pub use slashing::{
    canonicalize, decode_evidence, encode_evidence, slashing_leaf_hash, slashing_merkle_root,
    verify_evidence, EvidenceCheck, SlashDecodeError, SlashEvidence,
};
pub use storage::{
    decode_storage_commitment, encode_storage_commitment, storage_commitment_hash,
    StorageCommitment,
};
pub use transaction::{
    decode_transaction, encode_transaction, sign_transaction, tx_id, tx_preimage,
    verify_transaction, InputSpec, OutputSpec, Recipient, SignedTransaction, TransactionWire,
    TxBuildError, TxDecodeError, TxInputWire, TxOutputWire, VerifyResult, TX_RANGE_BITS,
    TX_VERSION,
};
pub use validator_evolution::{
    apply_bond_ops_evolution, apply_equivocation_slashings, apply_liveness_evolution,
    apply_unbond_settlements, finality_bitmap_from_header, BondEpochCounters, BondOpError,
    EquivocationError, EquivocationOutcome, LivenessOutcome,
};
