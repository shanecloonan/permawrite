//! Chain state types (ChainState, UTXO entries, consensus params).

use super::internal::*;

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

/// Registered storage-operator record (B3 phase 3). Keyed by
/// [`operator_identity_from_payout`] in [`ChainState::storage_operators`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageOperatorEntry {
    /// Operator payout view public key (must match proof).
    pub operator_view_pub: EdwardsPoint,
    /// Operator payout spend public key (must match proof).
    pub operator_spend_pub: EdwardsPoint,
    /// Height at which this operator was registered (genesis = 0).
    pub registration_height: u32,
    /// Escrowed bond in base units (`0` = bondless tier).
    pub bond_amount: u64,
}

/// Minimum output count enforced on regular transactions whenever the
/// uniform-ring privacy tier is active (**F5-P5** first half / B1).
///
/// A single-output transaction reveals a no-change sweep or exact-amount
/// payment — a fingerprint that partitions the anonymity set. The
/// reference wallets have always padded to two outputs
/// (`mfn_wallet::WALLET_MIN_TX_OUTPUTS`); this constant lifts that floor
/// into consensus so the guarantee is network-wide, not
/// wallet-by-courtesy. Tied to the uniform-ring tier by the same
/// argument that justified uniform rings: any tx-shape degree of freedom
/// the sender controls is a degree of freedom that distinguishes senders.
pub const MIN_TX_OUTPUTS_UNIFORM_TIER: u32 = 2;

/// Minimum input count enforced on regular transactions whenever the
/// uniform-ring privacy tier is active (**F7** / B15 consensus tail).
///
/// A lone input on-chain reveals that the spender had a single UTXO
/// large enough to cover the payment — a fingerprint distinct from the
/// common two-input Monero default. Reference wallets pad to
/// [`mfn_wallet::WALLET_MIN_TX_INPUTS`] when a second spendable UTXO
/// exists; this constant lifts the floor into consensus for the
/// uniform-ring tier. Wallets with only one UTXO cannot broadcast until
/// they hold a second spendable output (e.g. multi-output faucet fund).
pub const MIN_TX_INPUTS_UNIFORM_TIER: u32 = 2;

/// Consensus-enforced CLSAG ring policy (privacy Tier 1).
///
/// `uniform_ring_size > 0` requires every input ring to have exactly that
/// many members; otherwise only `min_ring_size` is enforced.
/// `min_output_count > 0` additionally requires every regular tx to carry
/// at least that many outputs (coinbase is exempt — it is verified by
/// `verify_coinbase_outputs`, never `verify_transaction`).
/// `min_input_count > 0` additionally requires every regular tx to carry
/// at least that many inputs (**F7** / B15 consensus tail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingPolicy {
    /// Minimum ring members per input (including the real spend).
    pub min_ring_size: u32,
    /// When non-zero, every input ring must have exactly this size.
    pub uniform_ring_size: u32,
    /// When non-zero, every regular tx must have at least this many
    /// outputs (**F5-P5** / B1 anti-fingerprinting floor).
    pub min_output_count: u32,
    /// When non-zero, every regular tx must have at least this many
    /// inputs (**F7** / B15 anti-fingerprinting floor).
    pub min_input_count: u32,
}

impl RingPolicy {
    /// Production defaults: Monero-parity uniform rings of 16 and the
    /// two-input / two-output floors.
    pub const PRODUCTION: Self = Self {
        min_ring_size: 16,
        uniform_ring_size: 16,
        min_output_count: MIN_TX_OUTPUTS_UNIFORM_TIER,
        min_input_count: MIN_TX_INPUTS_UNIFORM_TIER,
    };

    /// Test harness: allow small rings; uniform + shape floors not enforced.
    pub const TEST: Self = Self {
        min_ring_size: 2,
        uniform_ring_size: 0,
        min_output_count: 0,
        min_input_count: 0,
    };
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
    /// Minimum CLSAG ring size per input (privacy floor).
    pub min_ring_size: u32,
    /// Uniform ring size; `0` = only `min_ring_size` enforced.
    pub uniform_ring_size: u32,
}

impl ConsensusParams {
    /// Ring policy derived from these consensus params.
    ///
    /// The output floor is derived, not stored: chains running the
    /// uniform-ring privacy tier (`uniform_ring_size != 0`) also enforce
    /// [`MIN_TX_OUTPUTS_UNIFORM_TIER`] outputs and
    /// [`MIN_TX_INPUTS_UNIFORM_TIER`] inputs per regular tx. Deriving
    /// keeps `ConsensusParams`' checkpoint serialization unchanged (no
    /// codec version bump) and makes the uniformity guarantees —
    /// ring shape, output-count shape, and input-count shape — engage
    /// together.
    #[inline]
    pub fn ring_policy(&self) -> RingPolicy {
        let uniform_tier = self.uniform_ring_size != 0;
        RingPolicy {
            min_ring_size: self.min_ring_size,
            uniform_ring_size: self.uniform_ring_size,
            min_output_count: if uniform_tier {
                MIN_TX_OUTPUTS_UNIFORM_TIER
            } else {
                0
            },
            min_input_count: if uniform_tier {
                MIN_TX_INPUTS_UNIFORM_TIER
            } else {
                0
            },
        }
    }
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            expected_proposers_per_slot: 1.5,
            quorum_stake_bps: 6667,
            liveness_max_consecutive_missed: 32,
            liveness_slash_bps: 100,
            min_ring_size: 16,
            uniform_ring_size: 16,
        }
    }
}

/// Canonical default consensus parameters.
pub const DEFAULT_CONSENSUS_PARAMS: ConsensusParams = ConsensusParams {
    expected_proposers_per_slot: 1.5,
    quorum_stake_bps: 6667,
    liveness_max_consecutive_missed: 32,
    liveness_slash_bps: 100,
    min_ring_size: 16,
    uniform_ring_size: 16,
};

/// Compact params for unit/integration tests (small rings allowed).
pub const TEST_CONSENSUS_PARAMS: ConsensusParams = ConsensusParams {
    expected_proposers_per_slot: 1.5,
    quorum_stake_bps: 6667,
    liveness_max_consecutive_missed: 32,
    liveness_slash_bps: 100,
    min_ring_size: 2,
    uniform_ring_size: 0,
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
    /// Registered storage operators (B3), keyed by operator identity hash.
    pub storage_operators: BTreeMap<[u8; 32], StorageOperatorEntry>,
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
            storage_operators: BTreeMap::new(),
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
