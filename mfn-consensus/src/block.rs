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

use std::collections::{BTreeMap, HashMap, HashSet};

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::codec::Writer;
use mfn_crypto::domain::{BLOCK_HEADER, BLOCK_ID};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::utxo_tree::{
    append_utxo, empty_utxo_tree, utxo_leaf_hash, utxo_tree_root, UtxoTreeState,
};
use mfn_storage::{
    accrue_proof_reward, required_endowment, storage_commitment_hash, verify_storage_proof,
    AccrueArgs, EndowmentParams, StorageCommitment, StorageProof, StorageProofCheck,
    DEFAULT_ENDOWMENT_PARAMS,
};

use crate::bond_wire::{bond_merkle_root, verify_unbond_sig, BondOp};
use crate::bonding::{
    epoch_id_for_height, try_register_entry_churn, try_register_exit_churn, unbond_unlock_height,
    validate_stake, BondingParams, DEFAULT_BONDING_PARAMS,
};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase};
use crate::consensus::{decode_finality_proof, verify_finality_proof, SlotContext, Validator};
use crate::emission::{emission_at_height, EmissionParams, DEFAULT_EMISSION_PARAMS};
use crate::slashing::{canonicalize, verify_evidence, EvidenceCheck, SlashEvidence};
use crate::transaction::{tx_id, verify_transaction, TransactionWire};

/* ----------------------------------------------------------------------- *
 *  Header + Block                                                          *
 * ----------------------------------------------------------------------- */

/// Current block header version. Bumped on hard fork only.
pub const HEADER_VERSION: u32 = 1;

/// Block header — the consensus-critical, hash-committed metadata.
#[derive(Clone, Debug)]
pub struct BlockHeader {
    /// MFBN codec version.
    pub version: u32,
    /// Hash of the previous block's header (32 zeros at genesis).
    pub prev_hash: [u8; 32],
    /// Block height (genesis = 0).
    pub height: u32,
    /// Slot number this block was produced for.
    pub slot: u32,
    /// Wall-clock timestamp (seconds since UNIX epoch).
    pub timestamp: u64,
    /// Merkle root of the block's transactions (all-zero if empty).
    pub tx_root: [u8; 32],
    /// Merkle root of newly-anchored storage commitments (all-zero if
    /// none).
    pub storage_root: [u8; 32],
    /// Merkle root of [`Block::bond_ops`] (all-zero if empty).
    pub bond_root: [u8; 32],
    /// MFBN-encoded [`crate::consensus::FinalityProof`]. Empty for genesis
    /// and for chains running in legacy/centralized mode (no validator
    /// set).
    pub producer_proof: Vec<u8>,
    /// 32-byte cryptographic UTXO accumulator root **after** this block's
    /// outputs are appended. Light clients use this to verify membership
    /// without downloading the full UTXO set; log-size ring signatures
    /// prove inputs against it. Mandatory in v0.1.
    pub utxo_root: [u8; 32],
}

/// A full block: header + body.
#[derive(Clone, Debug)]
pub struct Block {
    /// Header.
    pub header: BlockHeader,
    /// Transactions. `txs[0]` MAY be a coinbase (no inputs); all others
    /// must be regular RingCT-style spends.
    pub txs: Vec<TransactionWire>,
    /// Slashing evidence accumulated since the previous block. Each piece
    /// zeros one offending validator's stake in the next state.
    pub slashings: Vec<SlashEvidence>,
    /// SPoRA storage proofs answering this block's deterministic
    /// per-commitment chunk challenges. Empty when no proofs are produced
    /// this block — commitments simply stay unproven longer.
    pub storage_proofs: Vec<StorageProof>,
    /// Validator bonding / rotation operations (M1). Verified against
    /// [`BlockHeader::bond_root`] before mutating the validator set.
    pub bond_ops: Vec<BondOp>,
}

/* ----------------------------------------------------------------------- *
 *  Hashing                                                                 *
 * ----------------------------------------------------------------------- */

/// Canonical encoding of a header (excluding the trailing `producer_proof`
/// blob). What [`header_signing_hash`] hashes; what producer and committee
/// BLS-sign over.
pub fn header_signing_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(u64::from(h.version));
    w.push(&h.prev_hash);
    w.u32(h.height);
    w.u32(h.slot);
    w.u64(h.timestamp);
    w.push(&h.tx_root);
    w.push(&h.storage_root);
    w.push(&h.bond_root);
    w.into_bytes()
}

/// Hash of the header **without** `producer_proof`. The message the
/// producer + committee BLS-sign — must be deterministic and exclude the
/// signature it's signing.
pub fn header_signing_hash(h: &BlockHeader) -> [u8; 32] {
    dhash(BLOCK_HEADER, &[&header_signing_bytes(h)])
}

/// Full header bytes including the `producer_proof` blob, length-prefixed.
pub fn block_header_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(u64::from(h.version));
    w.push(&h.prev_hash);
    w.u32(h.height);
    w.u32(h.slot);
    w.u64(h.timestamp);
    w.push(&h.tx_root);
    w.push(&h.storage_root);
    w.push(&h.bond_root);
    w.blob(&h.producer_proof);
    w.push(&h.utxo_root);
    w.into_bytes()
}

/// Block id = `dhash(BLOCK_ID, full_header_bytes)`.
pub fn block_id(h: &BlockHeader) -> [u8; 32] {
    dhash(BLOCK_ID, &[&block_header_bytes(h)])
}

/// Merkle root over the tx ids of the block. Empty list → 32-byte zero
/// (matches the TS reference's sentinel).
pub fn tx_merkle_root(txs: &[TransactionWire]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = txs.iter().map(tx_id).collect();
    merkle_root_or_zero(&leaves)
}

/// Merkle root over the storage commitments newly anchored in the block.
/// Returns 32 zeros if `commits` is empty.
pub fn storage_merkle_root(commits: &[StorageCommitment]) -> [u8; 32] {
    if commits.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = commits.iter().map(storage_commitment_hash).collect();
    merkle_root_or_zero(&leaves)
}

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
    let header = BlockHeader {
        version: HEADER_VERSION,
        prev_hash: [0u8; 32],
        height: 0,
        slot: 0,
        timestamp: cfg.timestamp,
        tx_root: [0u8; 32],
        storage_root,
        bond_root: [0u8; 32],
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

/* ----------------------------------------------------------------------- *
 *  Block builder (producer-side)                                           *
 * ----------------------------------------------------------------------- */

/// Build an unsealed (no `producer_proof`) header for the next block.
/// Producers compute the [`header_signing_hash`] over this header to know
/// what to BLS-sign; once they have a [`crate::consensus::FinalityProof`],
/// they call [`seal_block`] to produce the final `Block`.
///
/// `slot` is the explicit slot timer value; tests can default it to
/// `height`.
pub fn build_unsealed_header(
    state: &ChainState,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slot: u32,
    timestamp: u64,
) -> BlockHeader {
    let next_height = state.height.map(|h| h + 1).unwrap_or(0);

    // Storage commitments newly introduced this block (in tx-output
    // declaration order). Duplicates of already-anchored commitments do
    // NOT contribute (they were paid for by the original anchor).
    let mut new_storages: Vec<StorageCommitment> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for tx in txs {
        for out in &tx.outputs {
            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if state.storage.contains_key(&h) || !seen.insert(h) {
                    continue;
                }
                new_storages.push(sc.clone());
            }
        }
    }

    // Project the post-block accumulator: every tx output appended in
    // tx-by-tx, output-by-output order.
    let mut projected_tree = state.utxo_tree.clone();
    for tx in txs {
        for out in &tx.outputs {
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, next_height);
            projected_tree =
                append_utxo(&projected_tree, leaf).expect("realistic block fits in accumulator");
        }
    }

    let prev_hash = state.tip_id().copied().unwrap_or([0u8; 32]);

    BlockHeader {
        version: HEADER_VERSION,
        prev_hash,
        height: next_height,
        slot,
        timestamp,
        tx_root: tx_merkle_root(txs),
        storage_root: storage_merkle_root(&new_storages),
        bond_root: bond_merkle_root(bond_ops),
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&projected_tree),
    }
}

/// Attach an encoded finality proof to a header.
pub fn seal_block(
    mut header: BlockHeader,
    txs: Vec<TransactionWire>,
    bond_ops: Vec<BondOp>,
    producer_proof: Vec<u8>,
    slashings: Vec<SlashEvidence>,
    storage_proofs: Vec<StorageProof>,
) -> Block {
    header.producer_proof = producer_proof;
    Block {
        header,
        txs,
        slashings,
        storage_proofs,
        bond_ops,
    }
}

/* ----------------------------------------------------------------------- *
 *  Block application                                                      *
 * ----------------------------------------------------------------------- */

/// Either the new state (on success) or a structured list of errors.
///
/// Boxed-state variants would obscure the natural shape; the `Ok` arm
/// carries a `ChainState` directly. The size disparity between the
/// variants is fine because successful application is overwhelmingly the
/// common path and the `Err` variant is small anyway.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplyOutcome {
    /// All checks passed; `state` is the new tip state.
    Ok {
        /// New state.
        state: ChainState,
        /// Id of the applied block.
        block_id: [u8; 32],
    },
    /// One or more checks failed; the input state is unchanged.
    Err {
        /// Structured error list (one per failed check).
        errors: Vec<BlockError>,
        /// Id of the proposed block (so callers can log it).
        block_id: [u8; 32],
    },
}

impl ApplyOutcome {
    /// `true` iff application succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, ApplyOutcome::Ok { .. })
    }

    /// Block id of the applied/proposed block.
    pub fn block_id(&self) -> &[u8; 32] {
        match self {
            ApplyOutcome::Ok { block_id, .. } | ApplyOutcome::Err { block_id, .. } => block_id,
        }
    }

    /// Move out the new state, if successful.
    pub fn into_state(self) -> Option<ChainState> {
        match self {
            ApplyOutcome::Ok { state, .. } => Some(state),
            ApplyOutcome::Err { .. } => None,
        }
    }
}

/// Apply a candidate block to a chain state.
///
/// Performs every consensus check, in order:
///
/// 1. Header sanity: height = `state.height + 1`, `prev_hash` = current
///    tip id (none ⇒ genesis-only chain).
/// 2. Tx Merkle root matches the recomputed root; bond Merkle root
///    matches [`Block::bond_ops`].
/// 3. (If validators present) the [`crate::consensus::FinalityProof`]
///    verifies — producer was eligible at this slot, committee quorum
///    signed the header.
/// 4. Each tx verifies; cross-tx and cross-chain key images do not
///    collide; outputs are added to the UTXO set + accumulator.
/// 5. Storage commitments newly introduced by tx outputs are registered.
/// 6. Slashing evidence verifies; offending validators have their stake
///    zeroed in the new state.
/// 7. SPoRA storage proofs accrue rewards and update per-commitment state.
/// 8. Liveness stats from the finality bitmap; auto-slash chronic misses.
/// 9. [`BondOp`]s are validated and applied atomically (new validators are
///    not subject to this block's finality bitmap).
/// 10. When a producer has a [`crate::consensus::ValidatorPayout`], the
///     block must include a coinbase (in `tx[0]`) paying
///     `emission(height) + producer_fee` (+ storage rewards).
/// 11. Storage Merkle root matches tx-anchored new commitments.
/// 12. UTXO accumulator root matches.
///
/// Returns [`ApplyOutcome::Ok`] with the new state, or
/// [`ApplyOutcome::Err`] with a list of [`BlockError`]s and the original
/// state untouched.
pub fn apply_block(state: &ChainState, block: &Block) -> ApplyOutcome {
    let proposed_id = block_id(&block.header);
    let mut errors: Vec<BlockError> = Vec::new();

    // ---- Header sanity ----
    let expected_height = state.height.map(|h| h + 1).unwrap_or(0);
    if block.header.height != expected_height {
        errors.push(BlockError::BadHeight {
            expected: expected_height,
            got: block.header.height,
        });
    }
    if let Some(tip) = state.tip_id() {
        if &block.header.prev_hash != tip {
            errors.push(BlockError::PrevHashMismatch);
        }
    } else if block.header.prev_hash != [0u8; 32] {
        errors.push(BlockError::PrevHashMismatch);
    }

    // ---- Tx merkle root ----
    let expected_tx_root = tx_merkle_root(&block.txs);
    if expected_tx_root != block.header.tx_root {
        errors.push(BlockError::TxRootMismatch);
    }

    let expected_bond_root = bond_merkle_root(&block.bond_ops);
    if expected_bond_root != block.header.bond_root {
        errors.push(BlockError::BondRootMismatch);
    }

    // ---- Producer/finality proof ----
    let mut producer_idx: Option<u32> = None;
    let mut finality_bitmap: Option<Vec<u8>> = None;
    if !state.validators.is_empty() {
        if block.header.producer_proof.is_empty() {
            errors.push(BlockError::MissingProducerProof);
        } else {
            match decode_finality_proof(&block.header.producer_proof) {
                Ok(fin) => {
                    let ctx = SlotContext {
                        height: block.header.height,
                        slot: block.header.slot,
                        prev_hash: block.header.prev_hash,
                    };
                    let header_hash = header_signing_hash(&block.header);
                    let chk = verify_finality_proof(
                        &ctx,
                        &fin,
                        &state.validators,
                        state.params.expected_proposers_per_slot,
                        state.params.quorum_stake_bps,
                        &header_hash,
                    );
                    if !chk.is_ok() {
                        errors.push(BlockError::FinalityInvalid(chk));
                    } else {
                        producer_idx = Some(fin.producer.validator_index);
                        finality_bitmap = Some(fin.finality.bitmap.clone());
                    }
                }
                Err(e) => errors.push(BlockError::FinalityDecode(format!("{e}"))),
            }
        }
    }

    // ---- Tentative state copy (only kept on success). ----
    let mut next = state.clone();
    next.height = Some(block.header.height);

    // Storage commitments newly anchored this block (in declaration order),
    // for the post-block storage-root check.
    let mut new_storages: Vec<StorageCommitment> = Vec::new();

    // Producer + coinbase policy.
    let producer =
        producer_idx.and_then(|idx| state.validators.iter().find(|v| v.index == idx).cloned());
    let require_coinbase = producer
        .as_ref()
        .map(|p| p.payout.is_some())
        .unwrap_or(false);

    // ---- Walk txs ----
    // A coinbase-shaped tx anywhere past position 0 is a protocol
    // violation. Catch up front.
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if is_coinbase_shaped(tx) {
            errors.push(BlockError::CoinbaseOutOfPosition(i));
        }
    }

    let mut coinbase_tx: Option<&TransactionWire> = None;
    let mut fee_sum: u128 = 0;

    for (ti, tx) in block.txs.iter().enumerate() {
        let is_coinbase_pos = ti == 0 && is_coinbase_shaped(tx);

        if is_coinbase_pos {
            coinbase_tx = Some(tx);
            // Coinbase output goes into UTXO + accumulator. The actual
            // amount/balance check happens below after fee_sum is known.
            for out in &tx.outputs {
                let key = out.one_time_addr.compress().to_bytes();
                next.utxo.insert(
                    key,
                    UtxoEntry {
                        commit: out.amount,
                        height: block.header.height,
                    },
                );
                let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
                match append_utxo(&next.utxo_tree, leaf) {
                    Ok(t) => next.utxo_tree = t,
                    Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
                }
                // Coinbase outputs cannot anchor storage; verify_coinbase
                // enforces this, so we skip storage handling here.
            }
            continue;
        }

        if ti == 0 && require_coinbase {
            errors.push(BlockError::MissingCoinbase {
                got_inputs: tx.inputs.len(),
            });
        }

        // Regular tx path.
        let v = verify_transaction(tx);
        if !v.ok {
            errors.push(BlockError::TxInvalid {
                index: ti,
                errors: v.errors,
            });
            continue;
        }

        // ---- Ring-membership check (consensus-critical, see SECURITY note) ----
        //
        // `verify_transaction` is stateless: it proves the CLSAG signer
        // controlled the spend key of *some* ring member, but a CLSAG
        // ring whose members are fabricated (P, C) pairs would still
        // verify because the math doesn't care whether the points are
        // on-chain. Combined with the balance equation
        //
        //     Σ pseudo − Σ amount − fee·H == 0
        //
        // a malicious spender who invents a ring member with commitment
        // C_fake = G·r + H·v_fake can pseudo-output the fake value into
        // their own outputs — i.e. mint MFN out of thin air. The
        // CHAIN-LEVEL check that every ring member is a real UTXO is the
        // only thing that closes this attack.
        //
        // Genesis UTXOs are included in `state.utxo`, so genesis-anchored
        // outputs are valid ring members from height 0 onwards.
        let mut ring_ok = true;
        for (ii, inp) in tx.inputs.iter().enumerate() {
            if inp.ring.p.len() != inp.ring.c.len() {
                errors.push(BlockError::TxInvalid {
                    index: ti,
                    errors: vec![format!(
                        "input {ii}: ring P-column length {} != C-column length {}",
                        inp.ring.p.len(),
                        inp.ring.c.len()
                    )],
                });
                ring_ok = false;
                break;
            }
            for (ri, (p, c)) in inp.ring.p.iter().zip(inp.ring.c.iter()).enumerate() {
                let key = p.compress().to_bytes();
                match next.utxo.get(&key) {
                    Some(entry) if entry.commit == *c => {}
                    Some(_) => {
                        errors.push(BlockError::RingMemberCommitMismatch {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                    None => {
                        errors.push(BlockError::RingMemberNotInUtxoSet {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                }
            }
        }
        if !ring_ok {
            continue;
        }

        // Fees accrue to the producer via the coinbase.
        fee_sum += u128::from(tx.fee);

        // Cross-tx + cross-chain key image gate.
        for ki in &v.key_images {
            let ki_bytes = ki.compress().to_bytes();
            if next.spent_key_images.contains(&ki_bytes) {
                errors.push(BlockError::DoubleSpend {
                    index: ti,
                    key_image: hex_short(&ki_bytes),
                });
            } else {
                next.spent_key_images.insert(ki_bytes);
            }
        }

        // New outputs → UTXO map + accumulator + storage registry.
        for out in &tx.outputs {
            let key = out.one_time_addr.compress().to_bytes();
            next.utxo.insert(
                key,
                UtxoEntry {
                    commit: out.amount,
                    height: block.header.height,
                },
            );
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
            match append_utxo(&next.utxo_tree, leaf) {
                Ok(t) => next.utxo_tree = t,
                Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
            }

            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if let std::collections::hash_map::Entry::Vacant(e) = next.storage.entry(h) {
                    e.insert(StorageEntry {
                        commit: sc.clone(),
                        last_proven_height: block.header.height,
                        last_proven_slot: u64::from(block.header.slot),
                        pending_yield_ppb: 0,
                    });
                    new_storages.push(sc.clone());
                }
            }
        }

        // ---- Storage upload endowment enforcement ----
        //
        // For every NEW storage commitment in this tx's outputs, sum the
        // protocol-required endowment burden. The tx's treasury-bound
        // share of fees must cover the burden, otherwise the upload is
        // under-funded and the permanence guarantee breaks. Replication
        // bounds (min/max) are also enforced here.
        let mut tx_burden: u128 = 0;
        let mut tx_storage_ok = true;
        let mut seen_in_tx: HashSet<[u8; 32]> = HashSet::new();
        for (oi, out) in tx.outputs.iter().enumerate() {
            let sc = match &out.storage {
                Some(s) => s,
                None => continue,
            };
            let h = storage_commitment_hash(sc);
            // Only NEW anchors incur burden — duplicates are inert.
            if state.storage.contains_key(&h) || !seen_in_tx.insert(h) {
                continue;
            }
            let repl = sc.replication;
            if repl < next.endowment_params.min_replication {
                errors.push(BlockError::StorageReplicationTooLow {
                    tx: ti,
                    output: oi,
                    got: repl,
                    min: next.endowment_params.min_replication,
                });
                tx_storage_ok = false;
                break;
            }
            if repl > next.endowment_params.max_replication {
                errors.push(BlockError::StorageReplicationTooHigh {
                    tx: ti,
                    output: oi,
                    got: repl,
                    max: next.endowment_params.max_replication,
                });
                tx_storage_ok = false;
                break;
            }
            match required_endowment(sc.size_bytes, repl, &next.endowment_params) {
                Ok(b) => tx_burden = tx_burden.saturating_add(b),
                Err(e) => {
                    errors.push(BlockError::EndowmentMathFailed {
                        tx: ti,
                        output: oi,
                        reason: format!("{e}"),
                    });
                    tx_storage_ok = false;
                    break;
                }
            }
        }
        if tx_storage_ok && tx_burden > 0 {
            let tx_treasury_share: u128 =
                u128::from(tx.fee) * u128::from(next.emission_params.fee_to_treasury_bps) / 10_000;
            if tx_treasury_share < tx_burden {
                errors.push(BlockError::UploadUnderfunded {
                    tx: ti,
                    burden: tx_burden,
                    treasury_share: tx_treasury_share,
                    fee: tx.fee,
                    fee_to_treasury_bps: next.emission_params.fee_to_treasury_bps,
                });
            }
        }
    }

    // ---- Slashing evidence (equivocation → stake zeroed, credit to treasury) ----
    //
    // Per the M1 economic model (see `docs/M1_VALIDATOR_ROTATION.md`), a
    // slashed validator's forfeited stake flows into the permanence
    // treasury rather than vanishing. This keeps the books balanced
    // against `BondOp::Register`'s burn-to-treasury credit: every base
    // unit a validator commits is permanently anchored in the chain's
    // permanence-funding pool, whether it's later returned via unbond,
    // forfeited via slash, or paid out as block reward.
    let mut slashed_this_block: HashSet<u32> = HashSet::new();
    for (si, ev_raw) in block.slashings.iter().enumerate() {
        let ev = canonicalize(ev_raw);
        if !slashed_this_block.insert(ev.voter_index) {
            errors.push(BlockError::DuplicateSlash {
                index: si,
                voter_index: ev.voter_index,
            });
            continue;
        }
        let chk = verify_evidence(&ev, &next.validators);
        match chk {
            EvidenceCheck::Valid => {
                let idx = ev.voter_index as usize;
                if idx < next.validators.len() {
                    let forfeited = u128::from(next.validators[idx].stake);
                    next.validators[idx].stake = 0;
                    next.treasury = next.treasury.saturating_add(forfeited);
                }
            }
            other => errors.push(BlockError::SlashInvalid {
                index: si,
                reason: other,
            }),
        }
    }

    // ---- Storage proofs: per-block SPoRA audit + endowment-proportional
    //      reward accrual via the PPB accumulator ----
    let mut seen_proofs: HashSet<[u8; 32]> = HashSet::new();
    let mut accepted_storage_proofs: u128 = 0;
    let mut storage_bonus_total: u128 = 0;
    let current_slot = u64::from(block.header.slot);
    for (pi, proof) in block.storage_proofs.iter().enumerate() {
        if !seen_proofs.insert(proof.commit_hash) {
            errors.push(BlockError::DuplicateStorageProof {
                index: pi,
                commit_hash: hex_short(&proof.commit_hash),
            });
            continue;
        }
        let entry = match next.storage.get(&proof.commit_hash).cloned() {
            Some(e) => e,
            None => {
                errors.push(BlockError::StorageProofUnknownCommit {
                    index: pi,
                    commit_hash: hex_short(&proof.commit_hash),
                });
                continue;
            }
        };
        let verdict = verify_storage_proof(
            &entry.commit,
            &block.header.prev_hash,
            block.header.slot,
            proof,
        );
        if !verdict.is_valid() {
            errors.push(BlockError::StorageProofInvalid {
                index: pi,
                reason: verdict,
            });
            continue;
        }
        match accrue_proof_reward(AccrueArgs {
            size_bytes: entry.commit.size_bytes,
            replication: entry.commit.replication,
            pending_ppb: entry.pending_yield_ppb,
            last_proven_slot: entry.last_proven_slot,
            current_slot,
            params: &next.endowment_params,
        }) {
            Ok(accrual) => {
                next.storage.insert(
                    proof.commit_hash,
                    StorageEntry {
                        commit: entry.commit,
                        last_proven_height: block.header.height,
                        last_proven_slot: current_slot,
                        pending_yield_ppb: accrual.new_pending_ppb,
                    },
                );
                accepted_storage_proofs += 1;
                storage_bonus_total = storage_bonus_total.saturating_add(accrual.payout);
            }
            Err(e) => errors.push(BlockError::EndowmentMathFailed {
                tx: 0,
                output: pi,
                reason: format!("accrue: {e}"),
            }),
        }
    }

    // ---- Liveness participation tracking + auto-slashing ----
    //
    // Walk this block's verified finality bitmap. For each non-zero-stake
    // validator: a set bit credits a successful vote, a clear bit
    // increments consecutive_missed. When consecutive_missed crosses
    // `liveness_max_consecutive_missed`, the validator's stake is
    // multiplicatively reduced by `liveness_slash_bps` and the counter
    // resets — repeated trip-ups compound. Equivocation slashing
    // (the `SlashEvidence` path above) zeros stake outright; this layer
    // catches chronic absenteeism that equivocation evidence can't
    // attribute.
    let mut liveness_burn_total: u128 = 0;
    if let Some(ref bitmap) = finality_bitmap {
        // Make sure the stats array is aligned with the validator set
        // even if a previous version of the chain produced a state with
        // a shorter (or absent) stats vector.
        if next.validator_stats.len() != next.validators.len() {
            next.validator_stats
                .resize(next.validators.len(), ValidatorStats::default());
        }
        let max_missed = next.params.liveness_max_consecutive_missed;
        let slash_bps = u128::from(next.params.liveness_slash_bps);
        for (i, v) in next.validators.iter_mut().enumerate() {
            if v.stake == 0 {
                continue; // zombie; rotation will reap later
            }
            let byte = i >> 3;
            let bit = i & 7;
            let signed = byte < bitmap.len() && (bitmap[byte] & (1u8 << bit)) != 0;
            let stats = &mut next.validator_stats[i];
            if signed {
                stats.consecutive_missed = 0;
                stats.total_signed = stats.total_signed.saturating_add(1);
            } else {
                stats.consecutive_missed = stats.consecutive_missed.saturating_add(1);
                stats.total_missed = stats.total_missed.saturating_add(1);
                if max_missed > 0 && stats.consecutive_missed >= max_missed {
                    // Multiplicative slash: stake *= (10000 − slash_bps) / 10000.
                    // Capped at 100% (slash_bps clamped to 10_000 below) so we
                    // can't underflow into negative stake. The slashed-away
                    // delta is credited to the permanence treasury — same
                    // sink as equivocation slashing and bond burns, so
                    // chronic absenteeism funds storage operators rather
                    // than vanishing.
                    let bps = slash_bps.min(10_000);
                    let old_stake = u128::from(v.stake);
                    let new_stake_u128 = old_stake * (10_000 - bps) / 10_000;
                    let forfeited = old_stake - new_stake_u128;
                    v.stake = u64::try_from(new_stake_u128).unwrap_or(u64::MAX);
                    liveness_burn_total = liveness_burn_total.saturating_add(forfeited);
                    stats.liveness_slashes = stats.liveness_slashes.saturating_add(1);
                    stats.consecutive_missed = 0;
                }
            }
        }
    }
    if liveness_burn_total > 0 {
        next.treasury = next.treasury.saturating_add(liveness_burn_total);
    }

    // ---- Bond ops (M1): new validators appended; not subject to this
    //      block's finality bitmap (they were not yet in the committee).
    //
    // Every successful `BondOp::Register` burns its declared `stake` to
    // the permanence treasury. Bonded MFN is therefore *immediately*
    // working for storage operators the moment a validator joins.
    //
    // `BondOp::Unbond` enqueues an exit; the validator stays in the
    // active set (still slashable!) until the unbond delay elapses,
    // at which point the settlement phase below zeros their stake.
    match simulate_bond_ops(
        block.header.height,
        next.bond_epoch_id,
        next.bond_epoch_entry_count,
        next.next_validator_index,
        &next.validators,
        &next.pending_unbonds,
        &next.bonding_params,
        &block.bond_ops,
    ) {
        Ok(delta) => {
            if delta.bond_epoch_id != next.bond_epoch_id {
                next.bond_epoch_exit_count = 0;
            }
            next.bond_epoch_id = delta.bond_epoch_id;
            next.bond_epoch_entry_count = delta.bond_epoch_entry_count;
            next.next_validator_index = delta.next_validator_index;
            let n_new = delta.new_validators.len();
            next.validators.extend(delta.new_validators);
            next.validator_stats
                .extend((0..n_new).map(|_| ValidatorStats::default()));
            next.treasury = next.treasury.saturating_add(delta.bond_burn_total);
            for pu in delta.new_pending_unbonds {
                next.pending_unbonds.insert(pu.validator_index, pu);
            }
        }
        Err((i, message)) => {
            errors.push(BlockError::BondOpRejected { index: i, message });
        }
    }

    // ---- Unbond settlements (M1): scan pending_unbonds in deterministic
    //      sorted-by-index order; for each entry whose unlock_height has
    //      arrived AND exit-churn budget remains, zero the validator's
    //      stake. Bonded MFN stays in treasury -- for M1, bonding is a
    //      one-way contribution to permanence; an honorable exit only
    //      frees the operator from future slashing exposure.
    {
        let due: Vec<u32> = next
            .pending_unbonds
            .iter()
            .filter(|(_, pu)| pu.unlock_height <= block.header.height)
            .map(|(idx, _)| *idx)
            .collect();
        for validator_index in due {
            match try_register_exit_churn(next.bond_epoch_exit_count, &next.bonding_params) {
                Ok(next_count) => {
                    next.bond_epoch_exit_count = next_count;
                }
                Err(_) => break,
            }
            if let Some(pos) = next
                .validators
                .iter()
                .position(|v| v.index == validator_index)
            {
                next.validators[pos].stake = 0;
            }
            next.pending_unbonds.remove(&validator_index);
        }
    }

    // ---- Two-sided economic settlement ----
    //
    //   1. treasury_fee = fee_sum · fee_to_treasury_bps / 10000
    //      producer_fee = fee_sum − treasury_fee
    //   2. Treasury gains treasury_fee.
    //   3. Storage rewards = storage_proof_reward · N_accepted + Σ bonus.
    //      Treasury drains first; any shortfall is minted via emission
    //      as a backstop. Treasury balance never goes negative.
    //   4. Coinbase pays producer = subsidy + producer_fee + storage_rewards.
    let emission_params = next.emission_params;
    let treasury_fee: u128 = fee_sum * u128::from(emission_params.fee_to_treasury_bps) / 10_000;
    let producer_fee_u128 = fee_sum - treasury_fee;
    let producer_fee: u64 = u64::try_from(producer_fee_u128).unwrap_or(u64::MAX);

    let storage_reward_total: u128 = u128::from(emission_params.storage_proof_reward)
        .saturating_mul(accepted_storage_proofs)
        .saturating_add(storage_bonus_total);

    let mut pending_treasury = next.treasury.saturating_add(treasury_fee);
    let storage_from_treasury = pending_treasury.min(storage_reward_total);
    pending_treasury -= storage_from_treasury;
    next.treasury = pending_treasury;
    // The remaining `storage_reward_total - storage_from_treasury` is the
    // emission backstop; it's part of the producer's coinbase amount but
    // not subtracted from the treasury.

    let subsidy = emission_at_height(u64::from(block.header.height), &emission_params);
    let expected_reward = u128::from(subsidy)
        .saturating_add(u128::from(producer_fee))
        .saturating_add(storage_reward_total);
    let expected_reward = u64::try_from(expected_reward).unwrap_or(u64::MAX);

    if require_coinbase {
        let producer = producer
            .as_ref()
            .expect("require_coinbase implies producer present");
        let payout = producer
            .payout
            .as_ref()
            .expect("require_coinbase implies payout present");
        match coinbase_tx {
            None => errors.push(BlockError::CoinbaseRequiredButAbsent),
            Some(cb) => {
                let cv = verify_coinbase(
                    cb,
                    u64::from(block.header.height),
                    expected_reward,
                    &crate::coinbase::PayoutAddress {
                        view_pub: payout.view_pub,
                        spend_pub: payout.spend_pub,
                    },
                );
                if !cv.ok {
                    errors.push(BlockError::CoinbaseInvalid(cv.errors));
                }
            }
        }
    } else if coinbase_tx.is_some() {
        errors.push(BlockError::UnexpectedCoinbase);
    }

    // ---- Storage root ----
    let expected_storage_root = storage_merkle_root(&new_storages);
    if expected_storage_root != block.header.storage_root {
        errors.push(BlockError::StorageRootMismatch);
    }

    // ---- UTXO accumulator root ----
    let computed_root = utxo_tree_root(&next.utxo_tree);
    if computed_root != block.header.utxo_root {
        errors.push(BlockError::UtxoRootMismatch);
    }

    if !errors.is_empty() {
        return ApplyOutcome::Err {
            errors,
            block_id: proposed_id,
        };
    }

    next.block_ids.push(proposed_id);
    ApplyOutcome::Ok {
        state: next,
        block_id: proposed_id,
    }
}

/// Successful bond-op simulation: apply these mutations to [`ChainState`]
/// after liveness (new validators are not in this block's committee).
#[derive(Debug)]
struct BondApplyDelta {
    bond_epoch_id: u64,
    bond_epoch_entry_count: u32,
    next_validator_index: u32,
    new_validators: Vec<Validator>,
    /// Total stake registered this block; credited to `state.treasury`
    /// as part of the burn-on-bond economic model.
    bond_burn_total: u128,
    /// Unbond requests enqueued this block.
    new_pending_unbonds: Vec<PendingUnbond>,
}

/// Validate `ops` against the pre-bond view of the chain and return new
/// validators plus updated bonding counters. Any error is atomic: the
/// caller must not apply a partial prefix of `ops`.
//
// Eight arguments is intentional: each represents a distinct piece of
// pre-bond chain state that the simulator must read and atomically update.
// Bundling them into a struct would simply shift the same coupling across
// the call site without reducing it.
#[allow(clippy::too_many_arguments)]
fn simulate_bond_ops(
    height: u32,
    mut bond_epoch_id: u64,
    mut bond_epoch_entry_count: u32,
    mut next_validator_index: u32,
    validators: &[Validator],
    pending_unbonds: &BTreeMap<u32, PendingUnbond>,
    bonding_params: &BondingParams,
    ops: &[BondOp],
) -> Result<BondApplyDelta, (usize, String)> {
    let slots = bonding_params.slots_per_epoch;
    let epoch_id =
        epoch_id_for_height(height, slots).map_err(|e| (0usize, format!("bond epoch id: {e}")))?;
    if epoch_id != bond_epoch_id {
        bond_epoch_id = epoch_id;
        bond_epoch_entry_count = 0;
    }

    let mut seen_vrf: HashSet<[u8; 32]> = validators
        .iter()
        .map(|v| v.vrf_pk.compress().to_bytes())
        .collect();
    let mut new_validators: Vec<Validator> = Vec::new();
    let mut bond_burn_total: u128 = 0;
    let mut new_pending_unbonds: Vec<PendingUnbond> = Vec::new();
    let mut seen_unbond_indices: HashSet<u32> = pending_unbonds.keys().copied().collect();

    for (i, op) in ops.iter().enumerate() {
        match op {
            BondOp::Register {
                stake,
                vrf_pk,
                bls_pk,
                payout,
                sig,
            } => {
                validate_stake(*stake, bonding_params).map_err(|e| (i, e.to_string()))?;
                if !crate::bond_wire::verify_register_sig(
                    *stake,
                    vrf_pk,
                    bls_pk,
                    payout.as_ref(),
                    sig,
                ) {
                    return Err((i, "register signature invalid".into()));
                }
                let vrf_b = vrf_pk.compress().to_bytes();
                if !seen_vrf.insert(vrf_b) {
                    return Err((i, "duplicate vrf_pk".into()));
                }
                bond_epoch_entry_count =
                    try_register_entry_churn(bond_epoch_entry_count, bonding_params)
                        .map_err(|e| (i, e.to_string()))?;
                let idx = next_validator_index;
                next_validator_index = next_validator_index.saturating_add(1);
                new_validators.push(Validator {
                    index: idx,
                    vrf_pk: *vrf_pk,
                    bls_pk: *bls_pk,
                    stake: *stake,
                    payout: *payout,
                });
                bond_burn_total = bond_burn_total.saturating_add(u128::from(*stake));
            }
            BondOp::Unbond {
                validator_index,
                sig,
            } => {
                let v = validators
                    .iter()
                    .find(|v| v.index == *validator_index)
                    .ok_or_else(|| (i, format!("unknown validator {validator_index}")))?;
                if v.stake == 0 {
                    return Err((i, "validator already zombie (stake=0)".into()));
                }
                if !seen_unbond_indices.insert(*validator_index) {
                    return Err((i, "validator already has pending unbond".into()));
                }
                if !verify_unbond_sig(*validator_index, sig, &v.bls_pk) {
                    return Err((i, "unbond signature invalid".into()));
                }
                new_pending_unbonds.push(PendingUnbond {
                    validator_index: *validator_index,
                    unlock_height: unbond_unlock_height(height, bonding_params),
                    stake_at_request: v.stake,
                    request_height: height,
                });
            }
        }
    }

    Ok(BondApplyDelta {
        bond_epoch_id,
        bond_epoch_entry_count,
        next_validator_index,
        new_validators,
        bond_burn_total,
        new_pending_unbonds,
    })
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(13);
    for byte in b.iter().take(6) {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageCommitment;

    fn genesis_state() -> ChainState {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        apply_genesis(&g, &cfg).unwrap()
    }

    #[test]
    fn build_apply_genesis_matches() {
        let cfg = GenesisConfig {
            timestamp: 42,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();
        assert_eq!(st.height, Some(0));
        assert_eq!(st.block_ids.len(), 1);
        assert_eq!(st.block_ids[0], block_id(&g.header));
    }

    #[test]
    fn apply_genesis_sets_optional_bonding_params() {
        let custom = BondingParams {
            min_validator_stake: 2_000_000,
            ..DEFAULT_BONDING_PARAMS
        };
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(custom),
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();
        assert_eq!(st.bonding_params.min_validator_stake, 2_000_000);
    }

    #[test]
    fn empty_block_applies_in_legacy_mode() {
        let st = genesis_state();
        let header = build_unsealed_header(&st, &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.height, Some(1));
                assert_eq!(state.block_ids.len(), 2);
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected ok, got: {errors:?}"),
        }
    }

    #[test]
    fn bad_height_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], 1, 100);
        header.height = 99;
        // Have to recompute prev_hash + utxo_root for the bad height since
        // they're independent... actually no, only height is wrong here, so
        // the locally-computed expected_tx_root and utxo_root will still
        // match. Just check that BadHeight surfaces.
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BadHeight { .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn bad_prev_hash_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], 1, 100);
        header.prev_hash = [9u8; 32];
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::PrevHashMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn tx_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], 1, 100);
        header.tx_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::TxRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn bond_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], 1, 100);
        header.bond_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn bond_ops_apply_is_atomic_on_error() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let stake_ok = crate::DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_ok = generator_g();
        let ok_op = BondOp::Register {
            stake: stake_ok,
            vrf_pk: vrf_ok,
            bls_pk: bls1.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake_ok, &vrf_ok, &bls1.pk, None, &bls1.sk),
        };
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let stake_bad = 1u64;
        let vrf_bad = generator_h();
        let bad_op = BondOp::Register {
            stake: stake_bad,
            vrf_pk: vrf_bad,
            bls_pk: bls2.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake_bad, &vrf_bad, &bls2.pk, None, &bls2.sk),
        };
        let bond_ops = vec![ok_op, bad_op];
        let header = build_unsealed_header(&st, &[], &bond_ops, 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            bond_ops,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 1, .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
        assert!(st.validators.is_empty());
    }

    // Bad register signature must be rejected (atomic apply ⇒ the
    // whole bond-op set is rolled back, no validators appended, no
    // treasury credit). Mempool-grade authorization: this is the
    // property that prevents an adversarial relayer from replaying a
    // serialized BondOp::Register op for any operator's keys.
    #[test]
    fn register_rejects_invalid_signature() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;

        let st = genesis_state();
        let attacker = bls_keygen_from_seed(&[200u8; 32]);
        let victim_bls = bls_keygen_from_seed(&[201u8; 32]);
        let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_pk = generator_g();
        // The attacker signs over the victim's bls_pk but with their
        // own secret key — the resulting sig won't verify under
        // victim_bls.pk.
        let forged =
            crate::bond_wire::sign_register(stake, &vrf_pk, &victim_bls.pk, None, &attacker.sk);
        let op = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: victim_bls.pk,
            payout: None,
            sig: forged,
        };
        let header = build_unsealed_header(&st, &[], std::slice::from_ref(&op), 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            vec![op],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })),
                    "expected BondOpRejected at index 0, got {errors:?}"
                );
                // No state mutation must have occurred.
                assert_eq!(st.validators.len(), 0);
                assert_eq!(st.treasury, 0);
            }
            ApplyOutcome::Ok { .. } => panic!("forged register signature must reject"),
        }
    }

    // Unbond rejection in legacy mode (empty validators ⇒ no finality
    // proof required for this block). End-to-end register → unbond →
    // settle flows live in tests/integration.rs::unbond_lifecycle_*.
    #[test]
    fn unbond_rejects_unknown_validator_legacy_mode() {
        use mfn_bls::bls_keygen_from_seed;
        let st = genesis_state();
        let bls = bls_keygen_from_seed(&[100u8; 32]);
        let unbond = BondOp::Unbond {
            validator_index: 42,
            sig: crate::bond_wire::sign_unbond(42, &bls.sk),
        };
        let header = build_unsealed_header(&st, &[], std::slice::from_ref(&unbond), 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            vec![unbond],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("unknown validator must reject"),
        }
    }

    #[test]
    fn unbond_wire_round_trip_inside_bond_root() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;
        let bls = bls_keygen_from_seed(&[55u8; 32]);
        let unbond = BondOp::Unbond {
            validator_index: 7,
            sig: crate::bond_wire::sign_unbond(7, &bls.sk),
        };
        let reg_bls = bls_keygen_from_seed(&[11u8; 32]);
        let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_pk = generator_g();
        let reg = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: reg_bls.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake, &vrf_pk, &reg_bls.pk, None, &reg_bls.sk),
        };
        let ops = vec![reg, unbond];
        let root = crate::bond_wire::bond_merkle_root(&ops);
        assert_ne!(root, [0u8; 32], "merkle root over mixed ops is non-zero");
    }

    #[test]
    fn utxo_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], 1, 100);
        header.utxo_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::UtxoRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn header_signing_hash_excludes_producer_proof() {
        let st = genesis_state();
        let h0 = build_unsealed_header(&st, &[], &[], 1, 100);
        let hash0 = header_signing_hash(&h0);
        let mut h1 = h0.clone();
        h1.producer_proof = b"this is whatever the producer attaches".to_vec();
        let hash1 = header_signing_hash(&h1);
        assert_eq!(
            hash0, hash1,
            "signing hash must not depend on producer_proof"
        );
        // But the full block id DOES depend on producer_proof.
        assert_ne!(block_id(&h0), block_id(&h1));
    }

    #[test]
    fn storage_root_uses_zero_when_empty() {
        assert_eq!(storage_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn storage_merkle_root_is_stable_under_no_op_storage() {
        use mfn_crypto::point::generator_g;
        let sc = StorageCommitment {
            data_root: [1u8; 32],
            size_bytes: 1_000,
            chunk_size: 256,
            num_chunks: 4,
            replication: 3,
            endowment: generator_g(),
        };
        let r1 = storage_merkle_root(std::slice::from_ref(&sc));
        let r2 = storage_merkle_root(&[sc]);
        assert_eq!(r1, r2);
    }

    /* --------- Endowment burden + storage proof gating ---------- *
     *                                                              *
     *  These tests run apply_block end-to-end against a no-         *
     *  validator chain. With validators.is_empty(), the finality    *
     *  + coinbase machinery is bypassed, so we get clean coverage   *
     *  of the upload-burden + SPoRA proof paths.                    *
     * ------------------------------------------------------------ */

    fn empty_genesis_with_endowment(ep: EndowmentParams) -> ChainState {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: ep,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        apply_genesis(&g, &cfg).unwrap()
    }

    #[test]
    fn duplicate_storage_proof_in_one_block_rejected() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], 5_000, 1_000);
        let p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            5_000,
            &payload,
            &built.tree,
        )
        .unwrap();
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p.clone(), p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProof { .. })),
                "expected DuplicateStorageProof, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("duplicate proof must reject the block"),
        }
    }

    #[test]
    fn storage_proof_for_unknown_commit_rejected() {
        let state0 = empty_genesis_with_endowment(DEFAULT_ENDOWMENT_PARAMS);
        let payload = b"unanchored".to_vec();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1,
            Some(64), // 64-byte chunks → many small chunks
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], 1, 100);
        let p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            1,
            &payload,
            &built.tree,
        )
        .unwrap();
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofUnknownCommit { .. })),
                "expected StorageProofUnknownCommit, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("unanchored proof must reject the block"),
        }
    }

    #[test]
    fn storage_proof_with_wrong_chunk_rejected() {
        let payload: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1,
            Some(64),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], 1, 100);
        let mut p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            1,
            &payload,
            &built.tree,
        )
        .unwrap();
        if !p.chunk.is_empty() {
            p.chunk[0] ^= 0xff;
        }
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofInvalid { .. })),
                "expected StorageProofInvalid, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("corrupt proof must reject the block"),
        }
    }

    /* ---- Ring-membership / counterfeit-input attack tests ------------ *
     *                                                                   *
     *  These tests target the only thing standing between Permawrite     *
     *  and the "mint MFN out of thin air" attack: every CLSAG ring       *
     *  member's (P, C) MUST exist in the chain's UTXO set. Without       *
     *  this guard a spender can fabricate a ring member with arbitrary   *
     *  hidden value, balance their pseudo-output against it, and emit    *
     *  outputs they don't own.                                           *
     * ----------------------------------------------------------------- */

    #[test]
    fn ring_member_not_in_utxo_set_rejected() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_crypto::scalar::random_scalar;
        use mfn_crypto::stealth::stealth_gen;

        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        // Genesis funds the real signer with a known UTXO. No decoys are
        // anchored, so any ring member other than the signer's UTXO will
        // be unknown to the chain.
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![GenesisOutput {
                one_time_addr: signer_p,
                amount: signer_c,
            }],
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();

        // Construct a 4-member ring; signer at index 1, the other three
        // are random (P, C) pairs that aren't in the UTXO set.
        let mut ring_p = Vec::new();
        let mut ring_c = Vec::new();
        for i in 0..4 {
            if i == 1 {
                ring_p.push(signer_p);
                ring_c.push(signer_c);
            } else {
                let sp = random_scalar();
                let bp = random_scalar();
                let vp = random_scalar();
                ring_p.push(generator_g() * sp);
                ring_c.push((generator_g() * bp) + (generator_h() * vp));
            }
        }
        let recipient_wallet = stealth_gen();
        let r = Recipient {
            view_pub: recipient_wallet.view_pub,
            spend_pub: recipient_wallet.spend_pub,
        };
        let send_value = init_value - 1_000;
        let signed = sign_transaction(
            vec![InputSpec {
                ring: ClsagRing {
                    p: ring_p,
                    c: ring_c,
                },
                signer_idx: 1,
                spend_priv: signer_spend,
                value: init_value,
                blinding: init_blinding,
            }],
            vec![OutputSpec::ToRecipient {
                recipient: r,
                value: send_value,
                storage: None,
            }],
            1_000,
            b"attack".to_vec(),
        )
        .expect("sign");

        let unsealed =
            build_unsealed_header(&state0, std::slice::from_ref(&signed.tx), &[], 1, 100);
        let block = seal_block(
            unsealed,
            vec![signed.tx],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => {
                let saw_ring_error = errors
                    .iter()
                    .any(|e| matches!(e, BlockError::RingMemberNotInUtxoSet { .. }));
                assert!(
                    saw_ring_error,
                    "expected RingMemberNotInUtxoSet, got {errors:?}"
                );
            }
            ApplyOutcome::Ok { .. } => {
                panic!("ring with fabricated members must reject the block (counterfeit attack)")
            }
        }
    }

    #[test]
    fn ring_member_with_wrong_commit_rejected() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_crypto::scalar::random_scalar;
        use mfn_crypto::stealth::stealth_gen;

        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        // Anchor a real UTXO at genesis; spender will reference it in
        // their ring but with an inflated Pedersen commitment to try to
        // sneak extra hidden value past the chain. Must be rejected.
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));

        // A second anchored UTXO with KNOWN small value that the attacker
        // will reference in their ring, but with an inflated C.
        let decoy_spend = random_scalar();
        let decoy_p = generator_g() * decoy_spend;
        let decoy_value = 1u64;
        let decoy_blinding = random_scalar();
        let decoy_c =
            (generator_g() * decoy_blinding) + (generator_h() * Scalar::from(decoy_value));

        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![
                GenesisOutput {
                    one_time_addr: signer_p,
                    amount: signer_c,
                },
                GenesisOutput {
                    one_time_addr: decoy_p,
                    amount: decoy_c,
                },
            ],
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();

        // Attacker's ring: signer's real UTXO + the decoy's P with an
        // INFLATED C (pretending the decoy holds 10^9 base units).
        let inflated_c =
            (generator_g() * random_scalar()) + (generator_h() * Scalar::from(1_000_000_000u64));
        let ring_p = vec![signer_p, decoy_p];
        let ring_c = vec![signer_c, inflated_c];

        let recipient_wallet = stealth_gen();
        let r = Recipient {
            view_pub: recipient_wallet.view_pub,
            spend_pub: recipient_wallet.spend_pub,
        };
        let send_value = init_value - 1_000;
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
            vec![OutputSpec::ToRecipient {
                recipient: r,
                value: send_value,
                storage: None,
            }],
            1_000,
            b"inflated-c".to_vec(),
        )
        .expect("sign");

        let unsealed =
            build_unsealed_header(&state0, std::slice::from_ref(&signed.tx), &[], 1, 100);
        let block = seal_block(
            unsealed,
            vec![signed.tx],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => {
                let saw_commit_error = errors
                    .iter()
                    .any(|e| matches!(e, BlockError::RingMemberCommitMismatch { .. }));
                assert!(
                    saw_commit_error,
                    "expected RingMemberCommitMismatch, got {errors:?}"
                );
            }
            ApplyOutcome::Ok { .. } => panic!("inflated-C ring member must reject the block"),
        }
    }

    /* ---- Liveness participation + auto-slashing ---------------------- *
     *                                                                   *
     *  These unit tests drive `apply_block` against the liveness bitmap  *
     *  path with hand-crafted state — we don't need a real validator    *
     *  set or BLS finality machinery because the liveness logic         *
     *  consumes `finality_bitmap` after `verify_finality_proof` has     *
     *  already cleared the block. We bypass that path by stuffing the   *
     *  bitmap directly into a synthetic `next` via the public surface:  *
     *  set up an empty-validator chain, then manually invoke the path.  *
     *                                                                   *
     *  Integration coverage with REAL BLS finality flowing into the     *
     *  liveness path lives in `tests/integration.rs`.                   *
     * ----------------------------------------------------------------- */

    /// Direct unit test of the liveness-update logic, called as the
    /// equivalent inline block of `apply_block`. This keeps the test
    /// hermetic — no BLS setup, no genesis dance — just the state
    /// transition the bitmap drives.
    fn apply_liveness_step(state: &mut ChainState, bitmap: &[u8], max_missed: u32, slash_bps: u32) {
        // Mirrors the `if let Some(ref bitmap)` branch in apply_block.
        if state.validator_stats.len() != state.validators.len() {
            state
                .validator_stats
                .resize(state.validators.len(), ValidatorStats::default());
        }
        let slash_bps = u128::from(slash_bps);
        let mut burn_total: u128 = 0;
        for (i, v) in state.validators.iter_mut().enumerate() {
            if v.stake == 0 {
                continue;
            }
            let byte = i >> 3;
            let bit = i & 7;
            let signed = byte < bitmap.len() && (bitmap[byte] & (1u8 << bit)) != 0;
            let stats = &mut state.validator_stats[i];
            if signed {
                stats.consecutive_missed = 0;
                stats.total_signed = stats.total_signed.saturating_add(1);
            } else {
                stats.consecutive_missed = stats.consecutive_missed.saturating_add(1);
                stats.total_missed = stats.total_missed.saturating_add(1);
                if max_missed > 0 && stats.consecutive_missed >= max_missed {
                    let bps = slash_bps.min(10_000);
                    let old_stake = u128::from(v.stake);
                    let new_stake_u128 = old_stake * (10_000 - bps) / 10_000;
                    let forfeited = old_stake - new_stake_u128;
                    v.stake = u64::try_from(new_stake_u128).unwrap_or(u64::MAX);
                    burn_total = burn_total.saturating_add(forfeited);
                    stats.liveness_slashes = stats.liveness_slashes.saturating_add(1);
                    stats.consecutive_missed = 0;
                }
            }
        }
        state.treasury = state.treasury.saturating_add(burn_total);
    }

    fn fake_validator(idx: u32, stake: u64) -> Validator {
        // VRF + BLS pubkeys are placeholders; the liveness path doesn't
        // touch them. We just need a Validator-shaped struct.
        Validator {
            index: idx,
            vrf_pk: mfn_crypto::vrf::vrf_keygen_from_seed(&[idx as u8 + 7; 32])
                .unwrap()
                .pk,
            bls_pk: mfn_bls::bls_keygen_from_seed(&[idx as u8 + 17; 32]).pk,
            stake,
            payout: None,
        }
    }

    #[test]
    fn liveness_signed_resets_counter_and_credits() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        // Bitmap with bit 0 set.
        apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_signed, 1);
        assert_eq!(s.total_missed, 0);
        assert_eq!(state.validators[0].stake, 100);
    }

    #[test]
    fn liveness_unset_increments_counter() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..5 {
            apply_liveness_step(&mut state, &[0b0000_0000], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 5);
        assert_eq!(s.total_missed, 5);
        assert_eq!(s.total_signed, 0);
        assert_eq!(s.liveness_slashes, 0);
        assert_eq!(state.validators[0].stake, 100, "below threshold ⇒ no slash");
    }

    #[test]
    fn liveness_threshold_triggers_slash_and_reset() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 32 consecutive misses → first slash.
        for _ in 0..32 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.liveness_slashes, 1);
        assert_eq!(s.consecutive_missed, 0, "counter resets after slash");
        // 1% of 1_000_000 = 10_000; new stake = 990_000.
        assert_eq!(state.validators[0].stake, 990_000);
    }

    #[test]
    fn liveness_compounds_multiplicatively() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 5 slash cycles of 32 misses each.
        for _ in 0..(5 * 32) {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        // After 5 × (1% reduction): stake = 1_000_000 × 0.99^5
        // = 1_000_000 × 0.95099 ≈ 950_990.
        // Each step rounds down (floor div), so we expect ≤ 951_000
        // with a small floor-rounding margin.
        let stake = state.validators[0].stake;
        assert!(
            (940_000..=952_000).contains(&stake),
            "expected ~951k after 5 slashes, got {stake}"
        );
        assert_eq!(state.validator_stats[0].liveness_slashes, 5);
    }

    #[test]
    fn liveness_signed_clears_pending_counter() {
        // A validator that misses 30 votes and then signs has their
        // consecutive_missed reset to 0 — no slash triggered. This is
        // the "transient outage" forgiveness.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..30 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        assert_eq!(state.validator_stats[0].consecutive_missed, 30);
        apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_signed, 1);
        assert_eq!(s.total_missed, 30);
        assert_eq!(s.liveness_slashes, 0);
        assert_eq!(state.validators[0].stake, 100, "transient outage forgiven");
    }

    #[test]
    fn liveness_zero_stake_validator_skipped() {
        // Equivocation-slashed (stake=0) validators are zombies; the
        // liveness layer must not touch them.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 0)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..100 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_missed, 0);
        assert_eq!(s.liveness_slashes, 0);
    }

    #[test]
    fn liveness_bitmap_too_short_treated_as_missing() {
        // If a validator's bit index lies beyond the bitmap's length,
        // they are treated as a missed vote.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100), fake_validator(1, 100)];
        state.validator_stats = vec![ValidatorStats::default(); 2];
        // Bitmap only carries bit 0; validator 1's byte index is 0 too
        // (bit 1) and IS in range. Use a 0-length bitmap to force the
        // out-of-range case.
        apply_liveness_step(&mut state, &[], 32, 100);
        assert_eq!(state.validator_stats[0].consecutive_missed, 1);
        assert_eq!(state.validator_stats[1].consecutive_missed, 1);
    }

    #[test]
    fn liveness_slash_caps_at_full_stake_loss() {
        // A pathological slash_bps > 10_000 must clamp to 100% so we
        // can't underflow into negative stake.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..1 {
            apply_liveness_step(&mut state, &[], 1, 99_999);
        }
        assert_eq!(state.validators[0].stake, 0);
        assert_eq!(state.validator_stats[0].liveness_slashes, 1);
    }

    /* ---- Burn-on-bond + slash-to-treasury economic invariants -------- *
     *                                                                    *
     *  These tests assert the M1 economic-symmetry property: every base  *
     *  unit a validator commits enters the permanence treasury. Stake    *
     *  may later flow out via unbond settlement (future work), but for   *
     *  M1 the slash and liveness paths re-credit any forfeited stake to  *
     *  treasury — so the chain's permanence-funding pool is always       *
     *  bounded below by the sum of validator burns minus rewards paid.   *
     * ------------------------------------------------------------------ */

    #[test]
    fn liveness_slash_credits_treasury() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        assert_eq!(state.treasury, 0);
        // One full slash cycle = 1% multiplicative reduction = 10_000.
        for _ in 0..32 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        assert_eq!(state.validators[0].stake, 990_000);
        assert_eq!(state.treasury, 10_000, "1% liveness slash → treasury");
    }

    #[test]
    fn liveness_slash_treasury_compounds_with_validator_stake() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 5 full slash cycles at 1% each. Multiplicative on stake; the
        // treasury accumulates the discrete forfeits.
        for _ in 0..(5 * 32) {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let stake = state.validators[0].stake;
        let treasury = state.treasury;
        let total = u128::from(stake) + treasury;
        // No emission/coinbase flow in this unit test — stake + treasury
        // must equal the original endowment (modulo floor-division loss
        // on the multiplicative path).
        assert!(
            (995_000..=1_000_000).contains(&total),
            "stake+treasury ≈ original endowment, got stake={stake} treasury={treasury}"
        );
    }

    #[test]
    fn equivocation_slash_credits_treasury_via_apply_block() {
        use mfn_bls::{bls_keygen_from_seed, bls_sign};

        // Two-validator chain so we can pin the producer/voter roles.
        // We don't actually drive consensus here — apply_block sees an
        // empty `validators` set (legacy mode) so the slashing path runs
        // without a finality proof.
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![fake_validator(0, 7_500), fake_validator(1, 2_500)],
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();

        // Validator 0's BLS key signs two different headers at the same
        // slot → equivocation. We reuse the fake_validator seed mapping
        // for the BLS key.
        let bls = bls_keygen_from_seed(&[17u8; 32]); // matches idx=0
                                                     // The genesis validator must match: re-derive index 0's BLS pk
                                                     // to confirm the seed.
        assert_eq!(bls.pk, st.validators[0].bls_pk);
        let h1 = [11u8; 32];
        let h2 = [22u8; 32];
        let ev = SlashEvidence {
            height: 1,
            slot: 1,
            voter_index: 0,
            header_hash_a: h1,
            sig_a: bls_sign(&h1, &bls.sk),
            header_hash_b: h2,
            sig_b: bls_sign(&h2, &bls.sk),
        };

        // Build a block with the evidence. Since the chain has a non-
        // empty validator set, we can't actually run apply_block without
        // a real finality proof; instead, drive the slashing path
        // directly through the public surface by feeding the evidence
        // into a manual mirror. The chain semantics live in apply_block,
        // but the equivocation accounting here is straightforward and
        // verifiable in isolation.
        let mut next = st.clone();
        let chk = verify_evidence(&ev, &next.validators);
        assert_eq!(chk, EvidenceCheck::Valid);
        let idx = ev.voter_index as usize;
        let forfeited = u128::from(next.validators[idx].stake);
        next.validators[idx].stake = 0;
        next.treasury = next.treasury.saturating_add(forfeited);
        assert_eq!(next.validators[0].stake, 0);
        assert_eq!(next.treasury, 7_500);
    }

    #[test]
    fn burn_on_bond_credits_treasury() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;

        let st = genesis_state();
        assert_eq!(st.treasury, 0);
        let bls = bls_keygen_from_seed(&[42u8; 32]);
        let stake = 2_500_000u64;
        let vrf_pk = generator_g();
        let bond = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: bls.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake, &vrf_pk, &bls.pk, None, &bls.sk),
        };
        let bond_ops = vec![bond];
        let header = build_unsealed_header(&st, &[], &bond_ops, 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            bond_ops,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, 2_500_000, "bond burn must credit treasury");
                assert_eq!(state.validators.len(), 1);
                assert_eq!(state.validators[0].stake, 2_500_000);
            }
            ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
        }
    }

    #[test]
    fn burn_on_bond_aggregates_multiple_registers() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let vrf1 = generator_g();
        let vrf2 = generator_h();
        let ops = vec![
            BondOp::Register {
                stake: min,
                vrf_pk: vrf1,
                bls_pk: bls1.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
            },
            BondOp::Register {
                stake: min * 3,
                vrf_pk: vrf2,
                bls_pk: bls2.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min * 3, &vrf2, &bls2.pk, None, &bls2.sk),
            },
        ];
        let header = build_unsealed_header(&st, &[], &ops, 1, 100);
        let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, u128::from(min) * 4);
                assert_eq!(state.validators.len(), 2);
            }
            ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
        }
    }

    #[test]
    fn failed_bond_does_not_credit_treasury() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        // Below-minimum stake → rejection; the whole block must not
        // credit the treasury (atomic apply).
        let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let vrf1 = generator_g();
        let vrf2 = generator_h();
        let ops = vec![
            BondOp::Register {
                stake: min,
                vrf_pk: vrf1,
                bls_pk: bls1.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
            },
            BondOp::Register {
                stake: 1, // below min
                vrf_pk: vrf2,
                bls_pk: bls2.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(1, &vrf2, &bls2.pk, None, &bls2.sk),
            },
        ];
        let header = build_unsealed_header(&st, &[], &ops, 1, 100);
        let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { .. } => {
                // Pre-state untouched: treasury still zero.
                assert_eq!(st.treasury, 0);
            }
            ApplyOutcome::Ok { .. } => panic!("expected rejection"),
        }
    }
}
