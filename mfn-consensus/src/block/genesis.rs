//! Block + chain-state machine.
//!
//! Port of `cloonan-group/lib/network/block.ts`. This module turns the
//! crate's other primitives — transactions, coinbase, emission, slashing,
//! consensus finality — into an **actual chain** with a deterministic
//! state-transition function.
//!
//! Three concepts:
//!
//! - [`BlockHeader`] / [`Block`] — header + body, deterministically hashed.
//! - [`ChainState`] — known UTXOs, spent key images, storage registry,
//!   validator set, treasury, accumulator root, and the block-id chain.
//! - [`apply_block`] — pure function that validates a candidate block
//!   against the current state and returns either a new state or a list
//!   of errors. Same inputs always produce the same outputs (modulo
//!   hashing the same bytes).
//!
//! ## v0.1 scope
//!
//! This is the consensus-critical subset. The rest of the TS reference
//! (storage proof verification, endowment-based per-tx burden, treasury
//! drain → storage reward routing, storage proof reward bonuses) lives
//! gated behind the future [`mfn-storage`](https://github.com/...)
//! crate. Block application here:
//!
//! - verifies header sanity (height, prev hash);
//! - checks the tx Merkle root;
//! - verifies the producer's [`crate::consensus::FinalityProof`] when
//!   the chain has a validator set;
//! - walks the tx list: position 0 may be a coinbase, all others go
//!   through [`crate::transaction::verify_transaction`];
//! - rejects cross-tx and cross-chain double-spends;
//! - inserts new UTXOs into both the map and the cryptographic
//!   accumulator;
//! - registers new storage commitments (without enforcing endowment);
//! - applies slashing evidence (stake zeroed);
//! - verifies the coinbase against `emission(height) + producer_fee` when
//!   the producer has a payout address;
//! - checks the storage Merkle root + the UTXO accumulator root.
//!
//! When the storage layer lands, the per-block apply function will gain
//! storage-proof verification, endowment-burden enforcement, and the
//! two-sided treasury/emission settlement. The wire format is forward-
//! compatible: blocks produced today will still validate then.

#![allow(unused_imports)]

use std::collections::{BTreeMap, HashMap, HashSet};

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{BLOCK_HEADER, BLOCK_ID};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::utxo_tree::{
    append_utxo, empty_utxo_tree, utxo_leaf_hash, utxo_tree_root, UtxoTreeState,
};
use mfn_storage::{
    accrue_proof_reward, decode_storage_proof, encode_storage_proof, required_endowment,
    storage_commitment_hash, verify_storage_proof, AccrueArgs, EndowmentParams, StorageCommitment,
    StorageProof, StorageProofCheck, DEFAULT_ENDOWMENT_PARAMS,
};

use crate::bond_wire::{bond_merkle_root, decode_bond_op, encode_bond_op, BondOp, BondWireError};
use crate::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use crate::claims::{
    authorship_claim_key, check_claim_key_unique, check_claim_storage_binding, claim_to_record,
    claims_merkle_root, collect_claim_merkle_leaves_for_txs, verified_claims_for_tx,
    AuthorshipClaimVerifyError, VerifiedClaimsForTxResult,
};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase};
use crate::consensus::{decode_finality_proof, verify_finality_proof, SlotContext, Validator};
use crate::emission::{emission_at_height, EmissionParams, DEFAULT_EMISSION_PARAMS};
use crate::slashing::{
    decode_evidence, encode_evidence, EvidenceCheck, SlashDecodeError, SlashEvidence,
};
use crate::transaction::{
    encode_transaction, read_transaction, tx_id, verify_transaction, TransactionWire, TxDecodeError,
};

use super::error::BlockError;
use super::header::{block_id, Block, BlockHeader, HEADER_VERSION};
use super::state::{
    ChainState, ConsensusParams, StorageEntry, UtxoEntry, ValidatorStats, DEFAULT_CONSENSUS_PARAMS,
};
use super::wire::storage_merkle_root;

/* ----------------------------------------------------------------------- *
 *  Genesis                                                                 *
 * ----------------------------------------------------------------------- */

/// One initial output baked into genesis (no signatures — genesis is
/// trusted setup).
#[derive(Clone, Debug)]
pub struct GenesisOutput {
    /// Stealth one-time address.
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment to the hidden amount.
    pub amount: EdwardsPoint,
}

/// Configuration for the genesis block (height 0).
#[derive(Clone, Debug)]
pub struct GenesisConfig {
    /// Wall-clock timestamp at chain start.
    pub timestamp: u64,
    /// Initial UTXO set.
    pub initial_outputs: Vec<GenesisOutput>,
    /// Initial storage commitments.
    pub initial_storage: Vec<StorageCommitment>,
    /// Validator set at genesis. Empty ⇒ chain runs without consensus
    /// validation (tests only).
    pub validators: Vec<Validator>,
    /// Consensus parameters (defaults if omitted at type level).
    pub params: ConsensusParams,
    /// Emission schedule (defaults if omitted at type level).
    pub emission_params: EmissionParams,
    /// Endowment schedule (defaults if omitted at type level).
    pub endowment_params: EndowmentParams,
    /// Bonding / churn limits. [`None`] ⇒ [`DEFAULT_BONDING_PARAMS`](bonding::DEFAULT_BONDING_PARAMS).
    pub bonding_params: Option<BondingParams>,
}

/// Build the genesis [`Block`].
pub fn build_genesis(cfg: &GenesisConfig) -> Block {
    let mut tree = empty_utxo_tree();
    for o in &cfg.initial_outputs {
        let leaf = utxo_leaf_hash(&o.one_time_addr, &o.amount, 0);
        tree = append_utxo(&tree, leaf).expect("genesis output count fits in accumulator");
    }
    let storage_root = storage_merkle_root(&cfg.initial_storage);
    // Genesis commits to the **pre-genesis** validator set (empty) — the
    // genesis block itself installs `cfg.validators`. The next block's
    // header will commit to `validator_set_root(&cfg.validators)`.
    let header = BlockHeader {
        version: HEADER_VERSION,
        prev_hash: [0u8; 32],
        height: 0,
        slot: 0,
        timestamp: cfg.timestamp,
        tx_root: [0u8; 32],
        storage_root,
        bond_root: [0u8; 32],
        slashing_root: [0u8; 32],
        storage_proof_root: [0u8; 32],
        validator_root: [0u8; 32],
        claims_root: [0u8; 32],
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&tree),
    };
    Block {
        header,
        txs: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
        bond_ops: Vec::new(),
    }
}

/// Apply genesis to an empty state.
pub fn apply_genesis(genesis: &Block, cfg: &GenesisConfig) -> Result<ChainState, BlockError> {
    if genesis.header.height != 0 {
        return Err(BlockError::GenesisHeightNotZero);
    }
    let mut state = ChainState::empty();
    state.params = cfg.params;
    state.emission_params = cfg.emission_params;
    state.endowment_params = cfg.endowment_params;
    state.bonding_params = cfg.bonding_params.unwrap_or(DEFAULT_BONDING_PARAMS);
    state.validators = cfg.validators.clone();
    state.validator_stats = vec![ValidatorStats::default(); cfg.validators.len()];
    state.next_validator_index = cfg
        .validators
        .iter()
        .map(|v| v.index)
        .max()
        .map(|m| m.saturating_add(1))
        .unwrap_or(0);

    for o in &cfg.initial_outputs {
        let key = o.one_time_addr.compress().to_bytes();
        state.utxo.insert(
            key,
            UtxoEntry {
                commit: o.amount,
                height: 0,
            },
        );
        let leaf = utxo_leaf_hash(&o.one_time_addr, &o.amount, 0);
        state.utxo_tree = append_utxo(&state.utxo_tree, leaf).expect("genesis output count fits");
    }
    for s in &cfg.initial_storage {
        state.storage.insert(
            storage_commitment_hash(s),
            StorageEntry {
                commit: s.clone(),
                last_proven_height: 0,
                last_proven_slot: 0,
                pending_yield_ppb: 0,
            },
        );
    }

    state.height = Some(0);
    state.block_ids.push(block_id(&genesis.header));
    Ok(state)
}
