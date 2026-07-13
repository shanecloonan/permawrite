//! Genesis block construction and application.

use super::internal::*;

use super::error::BlockError;
use super::header::{
    block_id, Block, BlockHeader, HEADER_VERSION, HEADER_VERSION_FRAUD_SLASH,
    HEADER_VERSION_UTXO_QUORUM,
};
use super::state::{
    ChainState, ConsensusParams, StorageEntry, StorageOperatorEntry, UtxoEntry, ValidatorStats,
};
use super::wire::storage_merkle_root;
use mfn_storage::{operator_identity_from_payout, operator_payout_is_valid};

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

/// One genesis-seeded storage operator (trusted setup; no wire op or burn).
#[derive(Clone, Debug)]
pub struct GenesisStorageOperator {
    /// Operator payout view public key.
    pub operator_view_pub: EdwardsPoint,
    /// Operator payout spend public key.
    pub operator_spend_pub: EdwardsPoint,
    /// Escrowed bond in base units (`0` = bondless tier).
    pub bond_amount: u64,
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
    /// Storage operators registered at genesis (B3 phase 3c).
    pub initial_storage_operators: Vec<GenesisStorageOperator>,
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
    /// Block header version for this chain (`1` or `2`). `2` includes
    /// `utxo_root` in BLS signing bytes ([`HEADER_VERSION_UTXO_QUORUM`]).
    pub header_version: u32,
}

/// Resolve the header version for a genesis spec (defaults to [`HEADER_VERSION`]).
#[must_use]
pub fn genesis_header_version(cfg: &GenesisConfig) -> u32 {
    cfg.header_version
}

/// Supported header versions at genesis (Path B may opt into v2).
pub const SUPPORTED_GENESIS_HEADER_VERSIONS: &[u32] = &[
    HEADER_VERSION,
    HEADER_VERSION_UTXO_QUORUM,
    HEADER_VERSION_FRAUD_SLASH,
];

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
        version: genesis_header_version(cfg),
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
        storage_operator_ops: Vec::new(),
    }
}

/// Apply genesis to an empty state.
pub fn apply_genesis(genesis: &Block, cfg: &GenesisConfig) -> Result<ChainState, BlockError> {
    if genesis.header.height != 0 {
        return Err(BlockError::GenesisHeightNotZero);
    }
    let expected_version = genesis_header_version(cfg);
    if genesis.header.version != expected_version {
        return Err(BlockError::HeaderVersionMismatch {
            expected: expected_version,
            got: genesis.header.version,
        });
    }
    let mut state = ChainState::empty();
    state.header_version = expected_version;
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

    let mut prev_op_id: Option<[u8; 32]> = None;
    for (index, op) in cfg.initial_storage_operators.iter().enumerate() {
        if !operator_payout_is_valid(&op.operator_view_pub, &op.operator_spend_pub) {
            return Err(BlockError::GenesisStorageOperatorInvalid { index });
        }
        if cfg.endowment_params.min_storage_operator_bond > 0
            && op.bond_amount < cfg.endowment_params.min_storage_operator_bond
        {
            return Err(BlockError::GenesisStorageOperatorBondTooLow {
                index,
                bond_amount: op.bond_amount,
                min_bond: cfg.endowment_params.min_storage_operator_bond,
            });
        }
        let id = operator_identity_from_payout(&op.operator_view_pub, &op.operator_spend_pub);
        if let Some(prev) = prev_op_id {
            if id <= prev {
                return Err(BlockError::GenesisStorageOperatorsNotSorted { index });
            }
        }
        prev_op_id = Some(id);
        if state
            .storage_operators
            .insert(
                id,
                StorageOperatorEntry {
                    operator_view_pub: op.operator_view_pub,
                    operator_spend_pub: op.operator_spend_pub,
                    registration_height: 0,
                    bond_amount: op.bond_amount,
                },
            )
            .is_some()
        {
            return Err(BlockError::GenesisDuplicateStorageOperator { index });
        }
    }

    state.height = Some(0);
    state.block_ids.push(block_id(&genesis.header));
    Ok(state)
}
