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

/* ----------------------------------------------------------------------- *
 *  Chain state                                                             *
 * ----------------------------------------------------------------------- */

/// An unspent transaction output's record in the chain's UTXO set.
#[derive(Clone, Debug)]
pub struct UtxoEntry {
    /// Pedersen commitment to the output's hidden amount. Future spenders
    /// include this in their CLSAG ring's `C` column.
    pub commit: EdwardsPoint,
    /// Block height at which this output was anchored. Drives the gamma
    /// decoy-selection age weighting.
    pub height: u32,
}

/// Per-validator participation statistics. Tracked by `apply_block` from
/// the finality proof's bitmap; once `consecutive_missed` exceeds the
/// configured liveness threshold the validator's stake is slashed by
/// `ConsensusParams::liveness_slash_bps` and the counter resets.
///
/// Zeroed-stake (already-slashed) validators are excluded from stats
/// updates — they're zombies until validator rotation lands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStats {
    /// Consecutive blocks (since this validator's last successful vote)
    /// at which their bit was not set in the finality bitmap.
    pub consecutive_missed: u32,
    /// Lifetime count of finality votes successfully contributed.
    pub total_signed: u64,
    /// Lifetime count of finality votes missed.
    pub total_missed: u64,
    /// Number of times this validator has been liveness-slashed (capped
    /// at `u32::MAX`).
    pub liveness_slashes: u32,
}

/// A validator's pending exit, tracked from the moment their
/// [`BondOp::Unbond`] is accepted until the unlock height passes and
/// settlement zeroes their voting weight (M1 rotation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingUnbond {
    /// Validator's `index` field (matches `Validator::index`).
    pub validator_index: u32,
    /// Block height at which this exit may be settled (`request_height + unbond_delay_heights`).
    pub unlock_height: u32,
    /// Stake the validator held when they requested unbond. Recorded for
    /// observability; M1 leaves the underlying MFN as a permanent
    /// treasury contribution (no payout path yet).
    pub stake_at_request: u64,
    /// Block height the unbond was requested at.
    pub request_height: u32,
}

/// Per-storage-commitment chain state.
#[derive(Clone, Debug)]
pub struct StorageEntry {
    /// The anchored commitment.
    pub commit: StorageCommitment,
    /// Height of the most recent successful storage proof (or anchoring
    /// height on first registration).
    pub last_proven_height: u32,
    /// Slot of the most recent successful storage proof. Drives
    /// per-proof yield accrual (slots, not heights, are the natural unit
    /// because misses make `slot >= height`).
    pub last_proven_slot: u64,
    /// Sub-base-unit yield accumulator, in PPB. Carries the fractional
    /// per-slot yield across proofs so even commitments whose per-slot
    /// payout is `<< 1` base unit eventually earn integer base units.
    pub pending_yield_ppb: u128,
}

/// Consensus parameters baked into the chain at genesis. Changing any of
/// these is a hard fork.
#[derive(Clone, Copy, Debug)]
pub struct ConsensusParams {
    /// Average number of validators eligible to propose per slot. Typical
    /// configs: `1.0` (Algorand-style) or `1.5` (extra liveness slack).
    pub expected_proposers_per_slot: f64,
    /// Stake-weighted quorum threshold in basis points. `6667` = 2/3 + 1bp.
    pub quorum_stake_bps: u32,
    /// Liveness threshold: a validator that misses this many CONSECUTIVE
    /// finality votes is auto-slashed by `liveness_slash_bps` and their
    /// counter is reset. Default `32` ≈ 6.4 minutes at 12-second slots —
    /// long enough to absorb a transient outage, short enough to deter
    /// chronic absenteeism.
    pub liveness_max_consecutive_missed: u32,
    /// Stake reduction per liveness slash, in basis points. Default `100`
    /// = 1% per offense. Repeated offenses compound multiplicatively, so
    /// 100 successive trip-ups reduce stake by roughly `e^{-1}` ≈ 63%.
    /// Equivocation slashing remains its own thing (`SlashEvidence`),
    /// which zeros stake outright.
    pub liveness_slash_bps: u32,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            expected_proposers_per_slot: 1.5,
            quorum_stake_bps: 6667,
            liveness_max_consecutive_missed: 32,
            liveness_slash_bps: 100,
        }
    }
}

/// Canonical default consensus parameters.
pub const DEFAULT_CONSENSUS_PARAMS: ConsensusParams = ConsensusParams {
    expected_proposers_per_slot: 1.5,
    quorum_stake_bps: 6667,
    liveness_max_consecutive_missed: 32,
    liveness_slash_bps: 100,
};

/// The mutable state of a Permawrite chain.
#[derive(Clone, Debug)]
pub struct ChainState {
    /// Height of the last applied block (`None` before genesis).
    pub height: Option<u32>,
    /// Live UTXO set, keyed by compressed one-time-address bytes.
    pub utxo: HashMap<[u8; 32], UtxoEntry>,
    /// Spent key images, keyed by compressed point bytes. Cross-block
    /// double-spend gate.
    pub spent_key_images: HashSet<[u8; 32]>,
    /// Storage commitments anchored on-chain, keyed by commitment hash.
    /// Each entry carries the commitment plus per-commitment proof state
    /// (last-proven slot, pending PPB yield) updated by each accepted
    /// SPoRA proof.
    pub storage: HashMap<[u8; 32], StorageEntry>,
    /// Authorship claims indexed by (`data_root`, `claim_pubkey` bytes).
    pub claims: BTreeMap<crate::claims::AuthorshipClaimKey, crate::claims::AuthorshipClaimRecord>,
    /// Block-id chain: `[genesis_id, block1_id, ...]`.
    pub block_ids: Vec<[u8; 32]>,
    /// Active validator set. Frozen at genesis in v0.1; epoch reconfig
    /// is a future upgrade.
    pub validators: Vec<Validator>,
    /// Per-validator participation stats, aligned with `validators` by
    /// index (`validator_stats[i]` is the stats for `validators[i]`).
    /// `apply_block` updates this from each block's finality bitmap and
    /// auto-slashes validators that exceed the configured consecutive-
    /// missed-votes threshold.
    pub validator_stats: Vec<ValidatorStats>,
    /// Consensus parameters.
    pub params: ConsensusParams,
    /// Emission schedule (defaults to [`DEFAULT_EMISSION_PARAMS`]).
    pub emission_params: EmissionParams,
    /// Endowment schedule (defaults to [`DEFAULT_ENDOWMENT_PARAMS`]).
    pub endowment_params: EndowmentParams,
    /// Permanence treasury, in base units (gains the fee→treasury share
    /// of every regular tx).
    pub treasury: u128,
    /// Cryptographic UTXO accumulator. Every output the chain ever
    /// anchors is appended in deterministic order.
    pub utxo_tree: UtxoTreeState,
    /// Bonding / rotation parameters (defaults at genesis).
    pub bonding_params: BondingParams,
    /// Epoch id (`height / slots_per_epoch`) for which the churn
    /// counters apply. Updated when the epoch rolls forward.
    pub bond_epoch_id: u64,
    /// Validators registered via [`BondOp::Register`] in the current epoch.
    pub bond_epoch_entry_count: u32,
    /// Validators that **fully exited** (unbond-settled) in the current
    /// epoch, gated by [`BondingParams::max_exit_churn_per_epoch`].
    pub bond_epoch_exit_count: u32,
    /// Next [`Validator::index`] assigned to a newly bonded validator.
    pub next_validator_index: u32,
    /// In-flight unbond requests keyed by `Validator::index`. Settled
    /// when `unlock_height <= current_height`, in deterministic sorted
    /// order during [`apply_block`]. A validator with an entry here is
    /// still subject to equivocation/liveness slashing during the delay.
    pub pending_unbonds: BTreeMap<u32, PendingUnbond>,
}

impl ChainState {
    /// Empty pre-genesis state.
    pub fn empty() -> Self {
        Self {
            height: None,
            utxo: HashMap::new(),
            spent_key_images: HashSet::new(),
            storage: HashMap::new(),
            claims: BTreeMap::new(),
            block_ids: Vec::new(),
            validators: Vec::new(),
            validator_stats: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            treasury: 0,
            utxo_tree: empty_utxo_tree(),
            bonding_params: DEFAULT_BONDING_PARAMS,
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index: 0,
            pending_unbonds: BTreeMap::new(),
        }
    }

    /// The block id of the chain's current tip (`None` before genesis).
    pub fn tip_id(&self) -> Option<&[u8; 32]> {
        self.block_ids.last()
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::empty()
    }
}
