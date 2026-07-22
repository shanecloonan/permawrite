//! Property-based fuzzing of [`apply_block`] (**M5.2**–**M5.50**, **M5.51**, **B-11**).
//!
//! CI runs a bounded case count; all deep chains are in default CI (**M5.36–M5.39**).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::{bls_keygen_from_seed, bls_sign, BlsSecretKey};
use mfn_consensus::{
    apply_block, apply_genesis, block_coinbase_specs, build_coinbase, build_coinbase_outputs,
    build_genesis, build_mfex_extra_v2, build_mfex_extra_v3, build_unsealed_header, cast_vote,
    emission_at_height, encode_chain_checkpoint, encode_finality_proof,
    extra_codec::EndowmentOpening, finalize, header_signing_hash, pick_winner,
    producer_portion_amount, seal_block, sign_register, sign_transaction, storage_payout_amount,
    storage_proof_coinbase_bonus, storage_proof_operator_settlements, try_produce_slot,
    ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint, ChainState, ConsensusParams,
    EmissionParams, EquivocationEvidence, FinalityProof, GenesisConfig, GenesisOutput,
    GenesisStorageOperator, InputSpec, OutputSpec, PayoutAddress, ProducerProof, SlashEvidence,
    SlotContext, TransactionWire, Validator, ValidatorPayout, ValidatorSecrets,
    DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    TEST_CONSENSUS_PARAMS,
};
use mfn_crypto::bulletproofs::bp_prove;
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    accrue_proof_reward, build_storage_commitment, build_storage_proof_operator_salted,
    build_test_storage_proof, build_test_storage_proof_operator_salted,
    operator_identity_from_payout, required_endowment, storage_commitment_hash,
    test_operator_payout_keys, test_operator_payout_keys_alt, AccrueArgs, BuiltCommitment,
    EndowmentParams, DEFAULT_CHUNK_SIZE, DEFAULT_ENDOWMENT_PARAMS, PPB,
};
use proptest::prelude::*;

/// Compact emission schedule (matches `emission_simulation::SIM_EMISSION`).
const PROP_MIXED_EMISSION: EmissionParams = EmissionParams {
    initial_reward: 1_000,
    halving_period: 64,
    halving_count: 4,
    tail_emission: 50,
    storage_proof_reward: 25,
    fee_to_treasury_bps: 9000,
    subsidy_to_treasury_bps: 0,
};

/// Genesis UTXO value large enough for many fee-bearing self-transfers.
const PROP_MIXED_SPEND_VALUE: u64 = 10_000_000_000;

/// Companion input recycled each block so F7 `min_input_count = 2` is satisfied.
const PROP_INPUT_PAD_VALUE: u64 = 1_000_000;

/// Ring width for proptest CLSAG spends under production `DEFAULT_CONSENSUS_PARAMS`.
const PROP_RING_SIZE: usize = 16;

const PROP_PPB_ENDOWMENT: EndowmentParams = EndowmentParams {
    real_yield_ppb: 40_000_000,
    ..DEFAULT_ENDOWMENT_PARAMS
};

/// B-11: consensus requires `MFEO` Pedersen openings in `tx.extra` for new anchors.
const PROP_ENDOWMENT_REQUIRE_OPENING: EndowmentParams = EndowmentParams {
    require_endowment_opening: 1,
    ..DEFAULT_ENDOWMENT_PARAMS
};

/// B-11 phase 2: consensus requires `MFER` surplus range proofs for new anchors.
const PROP_ENDOWMENT_REQUIRE_RANGE_PROOF: EndowmentParams = EndowmentParams {
    require_endowment_range_proof: 1,
    ..DEFAULT_ENDOWMENT_PARAMS
};

/// B3: operator-salted replication accounting at consensus (test genesis only).
const PROP_ENDOWMENT_B3: EndowmentParams = EndowmentParams {
    operator_salted_challenges: 1,
    real_yield_ppb: 40_000_000,
    min_replication: 1,
    ..DEFAULT_ENDOWMENT_PARAMS
};

/// B5: operator audit miss + slash (test genesis only; cap=2, 10% slash).
const PROP_ENDOWMENT_B5: EndowmentParams = EndowmentParams {
    operator_salted_challenges: 1,
    require_registered_operators: 1,
    operator_audit_missed_cap: 2,
    operator_slash_bps: 1_000,
    proof_reward_window_slots: 100,
    min_replication: 1,
    real_yield_ppb: 40_000_000,
    ..DEFAULT_ENDOWMENT_PARAMS
};

const PROP_B5_OPERATOR_BOND: u64 = 1_000_000;

const PROP_STORAGE_ENDOWMENT_AMOUNT: u64 = 1_000;

fn prop_storage_upload_extra(
    built: &BuiltCommitment,
    endowment_amount: u64,
    endowment_params: &EndowmentParams,
) -> Vec<u8> {
    if endowment_params.require_endowment_range_proof != 0 {
        let required = required_endowment(
            built.commit.size_bytes,
            built.commit.replication,
            endowment_params,
        )
        .expect("required endowment");
        assert!(required <= u128::from(u64::MAX));
        let required = required as u64;
        assert!(endowment_amount >= required);
        let surplus = endowment_amount - required;
        let proof = bp_prove(surplus, &built.blinding, 64)
            .expect("surplus proof")
            .proof;
        return build_mfex_extra_v3(&[], std::slice::from_ref(&proof)).expect("mfex v3");
    }
    if endowment_params.require_endowment_opening == 0 {
        return Vec::new();
    }
    let opening = EndowmentOpening {
        value: endowment_amount,
        blinding: built.blinding,
    };
    build_mfex_extra_v2(&[], std::slice::from_ref(&opening)).expect("mfex v2")
}

fn genesis_state() -> ChainState {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    apply_genesis(&g, &cfg).expect("genesis")
}

/// Fields that must be unchanged when `apply_block` returns [`ApplyOutcome::Err`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct StateSnap {
    height: Option<u32>,
    treasury: u128,
    block_ids_len: usize,
    tip: Option<[u8; 32]>,
    utxo_len: usize,
    spent_key_images_len: usize,
    validators_len: usize,
}

fn snap(st: &ChainState) -> StateSnap {
    StateSnap {
        height: st.height,
        treasury: st.treasury,
        block_ids_len: st.block_ids.len(),
        tip: st.tip_id().copied(),
        utxo_len: st.utxo.len(),
        spent_key_images_len: st.spent_key_images.len(),
        validators_len: st.validators.len(),
    }
}

fn checkpoint_bytes(st: &ChainState) -> Vec<u8> {
    encode_chain_checkpoint(&ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: st.clone(),
    })
}

fn genesis_with_bonding() -> ChainState {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    apply_genesis(&g, &cfg).expect("genesis")
}

struct StorageGenesis {
    state: ChainState,
    built: BuiltCommitment,
    payload: Vec<u8>,
}

/// Multi-chunk payload so SPoRA challenge indices change as the tip advances.
fn genesis_with_storage() -> StorageGenesis {
    let payload: Vec<u8> = (0u32..(1024 * 1024)).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(DEFAULT_CHUNK_SIZE),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    StorageGenesis {
        state,
        built,
        payload,
    }
}

/// Storage genesis plus validator bonding enabled (**M5.4** treasury props).
fn genesis_with_storage_and_bonding() -> StorageGenesis {
    let mut gen = genesis_with_storage();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![gen.built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    gen.state = apply_genesis(&g, &cfg).expect("genesis");
    gen
}

fn genesis_with_b3_storage() -> StorageGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let built = build_storage_commitment(&payload, 1_000, Some(256), 3, None).expect("commitment");
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: PROP_ENDOWMENT_B3,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    StorageGenesis {
        state,
        built,
        payload,
    }
}

struct B5SlashGenesis {
    state: ChainState,
    built: BuiltCommitment,
    payload: Vec<u8>,
    operator_id: [u8; 32],
}

fn genesis_with_b5_slash_storage() -> B5SlashGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let built = build_storage_commitment(&payload, 1_000, Some(256), 3, None).expect("commitment");
    let (v0, s0) = test_operator_payout_keys();
    let operator_id = operator_identity_from_payout(&v0, &s0);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: vec![GenesisStorageOperator {
            operator_view_pub: v0,
            operator_spend_pub: s0,
            bond_amount: PROP_B5_OPERATOR_BOND,
        }],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: PROP_ENDOWMENT_B5,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    B5SlashGenesis {
        state,
        built,
        payload,
        operator_id,
    }
}

struct B5TwoOpGenesis {
    state: ChainState,
    built: BuiltCommitment,
    payload: Vec<u8>,
    id0: [u8; 32],
    id1: [u8; 32],
}

/// B5 audit genesis with two bonded operators (B-63 partial-set settle).
fn genesis_with_b5_two_operators() -> B5TwoOpGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let built = build_storage_commitment(&payload, 1_000, Some(256), 3, None).expect("commitment");
    let (v0, s0) = test_operator_payout_keys();
    let (v1, s1) = test_operator_payout_keys_alt();
    let id0 = operator_identity_from_payout(&v0, &s0);
    let id1 = operator_identity_from_payout(&v1, &s1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: vec![
            GenesisStorageOperator {
                operator_view_pub: v0,
                operator_spend_pub: s0,
                bond_amount: PROP_B5_OPERATOR_BOND,
            },
            GenesisStorageOperator {
                operator_view_pub: v1,
                operator_spend_pub: s1,
                bond_amount: PROP_B5_OPERATOR_BOND.saturating_mul(2),
            },
        ],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: EndowmentParams {
            operator_audit_missed_cap: 5,
            operator_slash_bps: 250,
            ..PROP_ENDOWMENT_B5
        },
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    B5TwoOpGenesis {
        state,
        built,
        payload,
        id0,
        id1,
    }
}

fn treasury_after_b5_slash(treasury: u128, bond: u64, slash_bps: u32) -> (u128, u64) {
    let forfeited = u128::from(bond) * u128::from(slash_bps.min(10_000)) / 10_000;
    let new_bond = u128::from(bond).saturating_sub(forfeited);
    (
        treasury.saturating_add(forfeited),
        u64::try_from(new_bond).unwrap_or(u64::MAX),
    )
}

fn apply_b5_operator_proof_at(
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    slot: u32,
) -> ChainState {
    let scratch = build_unsealed_header(st, &[], &[], &[], &[], slot, 1_000);
    let proof = build_test_storage_proof_operator_salted(
        &built.commit,
        &scratch.prev_hash,
        slot,
        payload,
        &built.tree,
    );
    apply_with_storage_proofs_at_slot(st, slot, slot, vec![proof])
}

/// Chains with no producer coinbase path: full `fee_sum` credits treasury.
fn treasury_after_legacy_block(
    treasury: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    let storage_reward_total = u128::from(params.storage_proof_reward) * proofs;
    let mut pending = treasury.saturating_add(fee_sum);
    let from_treasury = pending.min(storage_reward_total);
    pending -= from_treasury;
    pending
}

/// Validator chains: treasury fee tranche per `fee_to_treasury_bps`.
fn treasury_after_block(
    treasury: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let storage_reward_total = u128::from(params.storage_proof_reward) * proofs;
    let mut pending = treasury.saturating_add(treasury_fee);
    let from_treasury = pending.min(storage_reward_total);
    pending -= from_treasury;
    pending
}

fn treasury_after_register(treasury: u128, stake: u128) -> u128 {
    treasury.saturating_add(stake)
}

fn treasury_after_combined_inflow_block(
    treasury: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_block(
        treasury
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        proofs,
        params,
    )
}

fn treasury_after_equivocation_combined_inflow_block(
    treasury: u128,
    equivocation_credit: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_block(
        treasury
            .saturating_add(equivocation_credit)
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        proofs,
        params,
    )
}

fn treasury_after_settlement_with_ppb_bonus(
    treasury: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    ppb_bonus: u128,
    params: &EmissionParams,
) -> u128 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let storage_reward = u128::from(params.storage_proof_reward) * accepted_proofs + ppb_bonus;
    let mut pending = treasury.saturating_add(treasury_fee);
    let from_treasury = pending.min(storage_reward);
    pending -= from_treasury;
    pending
}

fn treasury_after_combined_inflow_block_with_ppb_bonus(
    treasury: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    proofs: u128,
    ppb_bonus: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement_with_ppb_bonus(
        treasury
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        proofs,
        ppb_bonus,
        params,
    )
}

#[allow(clippy::too_many_arguments)]
fn treasury_after_equivocation_combined_inflow_block_with_ppb_bonus(
    treasury: u128,
    equivocation_credit: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    proofs: u128,
    ppb_bonus: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement_with_ppb_bonus(
        treasury
            .saturating_add(equivocation_credit)
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        proofs,
        ppb_bonus,
        params,
    )
}

fn seed_ppb_pending_and_expected_payout(
    st: &mut ChainState,
    commit_hash: &[u8; 32],
    slot: u32,
    ep: &EndowmentParams,
) -> u128 {
    let entry = st.storage.get_mut(commit_hash).expect("storage entry");
    entry.pending_yield_ppb = PPB - 1;
    let accrual = accrue_proof_reward(AccrueArgs {
        size_bytes: entry.commit.size_bytes,
        replication: entry.commit.replication,
        pending_ppb: entry.pending_yield_ppb,
        last_proven_slot: entry.last_proven_slot,
        current_slot: u64::from(slot),
        params: ep,
    })
    .expect("accrue PPB payout");
    accrual.payout
}

/// Deterministic spend material for proptest (**M5.5**).
#[derive(Clone)]
struct PropSpendState {
    spend_priv: Scalar,
    blinding: Scalar,
    value: u64,
    one_time_addr: EdwardsPoint,
}

/// Parameters for [`PropSpendState::sign_storage_upload`].
struct PropStorageUploadArgs<'a> {
    fee: u64,
    built: &'a BuiltCommitment,
    endowment_amount: u64,
    endowment_params: &'a EndowmentParams,
    next_seed: u32,
    extra_override: Option<Vec<u8>>,
}

impl<'a> PropStorageUploadArgs<'a> {
    fn new(
        fee: u64,
        built: &'a BuiltCommitment,
        endowment_amount: u64,
        endowment_params: &'a EndowmentParams,
        next_seed: u32,
    ) -> Self {
        Self {
            fee,
            built,
            endowment_amount,
            endowment_params,
            next_seed,
            extra_override: None,
        }
    }

    fn with_extra_override(mut self, extra: Vec<u8>) -> Self {
        self.extra_override = Some(extra);
        self
    }
}

impl PropSpendState {
    fn from_seed(seed: u32, value: u64) -> Self {
        let spend_priv = hash_to_scalar(&[b"M5.5/spend", &seed.to_le_bytes()]);
        let blinding = hash_to_scalar(&[b"M5.5/blind", &seed.to_le_bytes()]);
        Self {
            spend_priv,
            blinding,
            value,
            one_time_addr: generator_g() * spend_priv,
        }
    }

    fn commitment(&self) -> EdwardsPoint {
        (generator_g() * self.blinding) + (generator_h() * Scalar::from(self.value))
    }

    fn genesis_decoy_at(i: usize) -> GenesisOutput {
        let genesis_spend = hash_to_scalar(&[b"M5.5/spend", &1u32.to_le_bytes()]);
        let decoy_spend = hash_to_scalar(&[
            b"M5.5/decoy-spend",
            &genesis_spend.to_bytes(),
            &(i as u32).to_le_bytes(),
        ]);
        let decoy_blind = hash_to_scalar(&[
            b"M5.5/decoy-blind",
            &genesis_spend.to_bytes(),
            &(i as u32).to_le_bytes(),
        ]);
        GenesisOutput {
            one_time_addr: generator_g() * decoy_spend,
            amount: (generator_g() * decoy_blind) + (generator_h() * Scalar::from(1u64)),
        }
    }

    fn input_spec(&self) -> InputSpec {
        let signer_idx = PROP_RING_SIZE - 1;
        let mut p = Vec::with_capacity(PROP_RING_SIZE);
        let mut c = Vec::with_capacity(PROP_RING_SIZE);
        for i in 0..PROP_RING_SIZE - 1 {
            let decoy = Self::genesis_decoy_at(i);
            p.push(decoy.one_time_addr);
            c.push(decoy.amount);
        }
        p.push(self.one_time_addr);
        c.push(self.commitment());
        InputSpec {
            ring: ClsagRing { p, c },
            signer_idx,
            spend_priv: self.spend_priv,
            value: self.value,
            blinding: self.blinding,
        }
    }

    /// Self-transfer with public fee; next state uses deterministic change keys.
    ///
    /// Spends `pad` as the second real input (F7 floor) and emits change,
    /// recycled pad, and zero-value output (F5 output floor).
    fn sign_self_transfer(
        &self,
        pad: &PropSpendState,
        fee: u64,
        next_seed: u32,
    ) -> (TransactionWire, Self, PropSpendState) {
        assert!(fee < self.value, "fee must leave positive change");
        let change_value = self.value - fee;
        let next_spend = hash_to_scalar(&[b"M5.5/change-spend", &next_seed.to_le_bytes()]);
        let change_addr = generator_g() * next_spend;
        let next_pad_spend = hash_to_scalar(&[b"F7/pad-spend", &next_seed.to_le_bytes()]);
        let pad_addr = generator_g() * next_pad_spend;
        let zero_spend = hash_to_scalar(&[b"B1/pad-spend", &next_seed.to_le_bytes()]);
        let zero_addr = generator_g() * zero_spend;
        let signed = sign_transaction(
            vec![self.input_spec(), pad.input_spec()],
            vec![
                OutputSpec::Raw {
                    one_time_addr: change_addr,
                    value: change_value,
                    storage: None,
                },
                OutputSpec::Raw {
                    one_time_addr: pad_addr,
                    value: pad.value,
                    storage: None,
                },
                OutputSpec::Raw {
                    one_time_addr: zero_addr,
                    value: 0,
                    storage: None,
                },
            ],
            fee,
            Vec::new(),
        )
        .expect("sign self-transfer");
        let next = Self {
            spend_priv: next_spend,
            blinding: signed.output_blindings[0],
            value: change_value,
            one_time_addr: change_addr,
        };
        let next_pad = Self {
            spend_priv: next_pad_spend,
            blinding: signed.output_blindings[1],
            value: pad.value,
            one_time_addr: pad_addr,
        };
        (signed.tx, next, next_pad)
    }

    /// Storage-anchoring spend with a NEW commitment; next state uses deterministic change keys.
    fn sign_storage_upload(
        &self,
        pad: &PropSpendState,
        args: PropStorageUploadArgs<'_>,
    ) -> (TransactionWire, Self, PropSpendState) {
        assert!(
            args.fee < self.value,
            "fee must leave positive anchor output"
        );
        let anchor_value = self.value - args.fee;
        let next_spend = hash_to_scalar(&[b"M5.33/change-spend", &args.next_seed.to_le_bytes()]);
        let change_addr = generator_g() * next_spend;
        let next_pad_spend =
            hash_to_scalar(&[b"F7/upload-pad-spend", &args.next_seed.to_le_bytes()]);
        let pad_addr = generator_g() * next_pad_spend;
        let zero_spend = hash_to_scalar(&[b"B1/upload-pad-spend", &args.next_seed.to_le_bytes()]);
        let zero_addr = generator_g() * zero_spend;
        let extra = args.extra_override.unwrap_or_else(|| {
            prop_storage_upload_extra(args.built, args.endowment_amount, args.endowment_params)
        });
        let signed = sign_transaction(
            vec![self.input_spec(), pad.input_spec()],
            vec![
                OutputSpec::Raw {
                    one_time_addr: change_addr,
                    value: anchor_value,
                    storage: Some(args.built.commit.clone()),
                },
                OutputSpec::Raw {
                    one_time_addr: pad_addr,
                    value: pad.value,
                    storage: None,
                },
                OutputSpec::Raw {
                    one_time_addr: zero_addr,
                    value: 0,
                    storage: None,
                },
            ],
            args.fee,
            extra,
        )
        .expect("sign storage upload");
        let next = Self {
            spend_priv: next_spend,
            blinding: signed.output_blindings[0],
            value: anchor_value,
            one_time_addr: change_addr,
        };
        let next_pad = Self {
            spend_priv: next_pad_spend,
            blinding: signed.output_blindings[1],
            value: pad.value,
            one_time_addr: pad_addr,
        };
        (signed.tx, next, next_pad)
    }
}

fn prop_input_pad_for(spend_seed: u32) -> PropSpendState {
    PropSpendState::from_seed(spend_seed.wrapping_add(0xF7_0000), PROP_INPUT_PAD_VALUE)
}

/// Genesis UTXOs: signer output, F7 pad, plus deterministic decoys for ring-16 spends.
fn prop_spend_genesis_outputs(spend: &PropSpendState, pad: &PropSpendState) -> Vec<GenesisOutput> {
    let mut outputs = Vec::with_capacity(PROP_RING_SIZE + 1);
    for i in 0..PROP_RING_SIZE - 1 {
        outputs.push(PropSpendState::genesis_decoy_at(i));
    }
    outputs.push(GenesisOutput {
        one_time_addr: spend.one_time_addr,
        amount: spend.commitment(),
    });
    outputs.push(GenesisOutput {
        one_time_addr: pad.one_time_addr,
        amount: pad.commitment(),
    });
    outputs
}

/// Genesis UTXOs for two independent ring-16 spenders (CLSAG fee + upload).
fn prop_dual_spend_genesis_outputs(
    clsag: &PropSpendState,
    clsag_pad: &PropSpendState,
    upload: &PropSpendState,
    upload_pad: &PropSpendState,
) -> Vec<GenesisOutput> {
    let mut outputs = Vec::with_capacity(PROP_RING_SIZE + 3);
    for i in 0..PROP_RING_SIZE - 1 {
        outputs.push(PropSpendState::genesis_decoy_at(i));
    }
    outputs.push(GenesisOutput {
        one_time_addr: clsag.one_time_addr,
        amount: clsag.commitment(),
    });
    outputs.push(GenesisOutput {
        one_time_addr: clsag_pad.one_time_addr,
        amount: clsag_pad.commitment(),
    });
    outputs.push(GenesisOutput {
        one_time_addr: upload.one_time_addr,
        amount: upload.commitment(),
    });
    outputs.push(GenesisOutput {
        one_time_addr: upload_pad.one_time_addr,
        amount: upload_pad.commitment(),
    });
    outputs
}

struct PropDualSpendGenesis {
    state: ChainState,
    clsag_spend: PropSpendState,
    clsag_pad: PropSpendState,
    upload_spend: PropSpendState,
    upload_pad: PropSpendState,
}

fn genesis_dual_spend_for_upload_proptest() -> PropDualSpendGenesis {
    let clsag_spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let clsag_pad = prop_input_pad_for(1);
    let upload_spend = PropSpendState::from_seed(2, PROP_MIXED_SPEND_VALUE);
    let upload_pad = prop_input_pad_for(2);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_dual_spend_genesis_outputs(
            &clsag_spend,
            &clsag_pad,
            &upload_spend,
            &upload_pad,
        ),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropDualSpendGenesis {
        state,
        clsag_spend,
        clsag_pad,
        upload_spend,
        upload_pad,
    }
}

fn genesis_dual_spend_for_upload_opening_proptest() -> PropDualSpendGenesis {
    let clsag_spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let clsag_pad = prop_input_pad_for(1);
    let upload_spend = PropSpendState::from_seed(2, PROP_MIXED_SPEND_VALUE);
    let upload_pad = prop_input_pad_for(2);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_dual_spend_genesis_outputs(
            &clsag_spend,
            &clsag_pad,
            &upload_spend,
            &upload_pad,
        ),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: PROP_ENDOWMENT_REQUIRE_OPENING,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropDualSpendGenesis {
        state,
        clsag_spend,
        clsag_pad,
        upload_spend,
        upload_pad,
    }
}

fn genesis_dual_spend_for_upload_range_proof_proptest() -> PropDualSpendGenesis {
    let clsag_spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let clsag_pad = prop_input_pad_for(1);
    let upload_spend = PropSpendState::from_seed(2, PROP_MIXED_SPEND_VALUE);
    let upload_pad = prop_input_pad_for(2);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_dual_spend_genesis_outputs(
            &clsag_spend,
            &clsag_pad,
            &upload_spend,
            &upload_pad,
        ),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropDualSpendGenesis {
        state,
        clsag_spend,
        clsag_pad,
        upload_spend,
        upload_pad,
    }
}

/// Minimum upload fee whose treasury share covers the endowment burden for `payload_len`.
fn prop_min_upload_fee(payload_len: usize) -> u64 {
    let payload: Vec<u8> = vec![0u8; payload_len];
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(256),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let burden = required_endowment(
        built.commit.size_bytes,
        built.commit.replication,
        &DEFAULT_ENDOWMENT_PARAMS,
    )
    .expect("burden");
    let treasury_bps = u128::from(PROP_MIXED_EMISSION.fee_to_treasury_bps);
    let min_fee = burden.saturating_mul(10_000).div_ceil(treasury_bps).max(1);
    u64::try_from(min_fee).unwrap_or(u64::MAX)
}

struct PropPrivacyStorageGenesis {
    state: ChainState,
    spend: PropSpendState,
    input_pad: PropSpendState,
    built: BuiltCommitment,
    payload: Vec<u8>,
}

fn genesis_privacy_storage_for_proptest() -> PropPrivacyStorageGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let input_pad = prop_input_pad_for(1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_spend_genesis_outputs(&spend, &input_pad),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropPrivacyStorageGenesis {
        state,
        spend,
        input_pad,
        built,
        payload,
    }
}

fn genesis_privacy_storage_bonding_for_proptest() -> PropPrivacyStorageGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let input_pad = prop_input_pad_for(1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_spend_genesis_outputs(&spend, &input_pad),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropPrivacyStorageGenesis {
        state,
        spend,
        input_pad,
        built,
        payload,
    }
}

/// Three-validator quorum with deterministic keys (**M5.6**).
struct PropValidatorFixture {
    validators: Vec<Validator>,
    secrets: Vec<ValidatorSecrets>,
    payout: PayoutAddress,
    params: ConsensusParams,
    total_stake: u64,
}

impl PropValidatorFixture {
    fn three_deterministic() -> Self {
        let stake = 100u64;
        let mk = |i: u32| -> (Validator, ValidatorSecrets, PayoutAddress) {
            let vrf = vrf_keygen_from_seed(&[i.wrapping_add(1) as u8; 32]).expect("vrf");
            let bls = bls_keygen_from_seed(&[i.wrapping_add(101) as u8; 32]);
            let view_priv = hash_to_scalar(&[b"M5.6/view", &i.to_le_bytes()]);
            let spend_priv = hash_to_scalar(&[b"M5.6/spend", &i.to_le_bytes()]);
            let view_pub = generator_g() * view_priv;
            let spend_pub = generator_g() * spend_priv;
            let val = Validator {
                index: i,
                vrf_pk: vrf.pk,
                bls_pk: bls.pk,
                stake,
                payout: Some(ValidatorPayout {
                    view_pub,
                    spend_pub,
                }),
            };
            let secrets = ValidatorSecrets { index: i, vrf, bls };
            let payout = PayoutAddress {
                view_pub,
                spend_pub,
            };
            (val, secrets, payout)
        };
        let (v0, s0, payout) = mk(0);
        let (v1, s1, _) = mk(1);
        let (v2, s2, _) = mk(2);
        let validators = vec![v0, v1, v2];
        let secrets = vec![s0, s1, s2];
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6667,
            ..TEST_CONSENSUS_PARAMS
        };
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            secrets,
            payout,
            params,
            total_stake,
        }
    }

    /// High-stake absentee harness for combined inflow treasury props (**M5.8**).
    fn liveness_absentee_long_sim() -> Self {
        let stake = 1_000_000u64;
        let mk = |i: u32| -> (Validator, ValidatorSecrets, PayoutAddress) {
            let vrf = vrf_keygen_from_seed(&[i.wrapping_add(1) as u8; 32]).expect("vrf");
            let bls = bls_keygen_from_seed(&[i.wrapping_add(101) as u8; 32]);
            let view_priv = hash_to_scalar(&[b"M5.8/view", &i.to_le_bytes()]);
            let spend_priv = hash_to_scalar(&[b"M5.8/spend", &i.to_le_bytes()]);
            let view_pub = generator_g() * view_priv;
            let spend_pub = generator_g() * spend_priv;
            let val = Validator {
                index: i,
                vrf_pk: vrf.pk,
                bls_pk: bls.pk,
                stake,
                payout: Some(ValidatorPayout {
                    view_pub,
                    spend_pub,
                }),
            };
            let secrets = ValidatorSecrets { index: i, vrf, bls };
            let payout = PayoutAddress {
                view_pub,
                spend_pub,
            };
            (val, secrets, payout)
        };
        let (v0, s0, payout) = mk(0);
        let (v1, s1, _) = mk(1);
        let (v2, s2, _) = mk(2);
        let validators = vec![v0, v1, v2];
        let secrets = vec![s0, s1, s2];
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 5000,
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 100,
            ..TEST_CONSENSUS_PARAMS
        };
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            secrets,
            payout,
            params,
            total_stake,
        }
    }
}

fn expected_coinbase_amount(
    height: u32,
    fee_sum: u128,
    storage_proofs: u128,
    params: &EmissionParams,
) -> u64 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let producer_fee = fee_sum - treasury_fee;
    let storage_reward_total = u128::from(params.storage_proof_reward) * storage_proofs;
    let subsidy = u128::from(emission_at_height(u64::from(height), params));
    let total = subsidy
        .saturating_add(producer_fee)
        .saturating_add(storage_reward_total);
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// Coinbase matching M2.5.0 multi-output settlement (producer + operator payouts).
fn prop_build_coinbase(
    height: u32,
    emission: &EmissionParams,
    fee_sum: u128,
    payout: &PayoutAddress,
    st: &ChainState,
    slot: u32,
    proofs: &[mfn_storage::StorageProof],
) -> TransactionWire {
    let ep = &st.endowment_params;
    let accepted = storage_proof_operator_settlements(proofs, &st.storage, slot, ep);
    let specs = block_coinbase_specs(u64::from(height), emission, fee_sum, *payout, &accepted);
    build_coinbase_outputs(u64::from(height), &payout.spend_pub, &specs).expect("coinbase")
}

fn prop_coinbase_for_block(
    height: u32,
    emission: &EmissionParams,
    fee_sum: u128,
    payout: &PayoutAddress,
    st: &ChainState,
    storage_proofs: &[mfn_storage::StorageProof],
) -> TransactionWire {
    if storage_proofs.is_empty() {
        let cb_amount = expected_coinbase_amount(height, fee_sum, 0, emission);
        build_coinbase(u64::from(height), cb_amount, payout).expect("coinbase")
    } else {
        prop_build_coinbase(
            height,
            emission,
            fee_sum,
            payout,
            st,
            height,
            storage_proofs,
        )
    }
}

struct PropValidatorPrivacyStorageGenesis {
    state: ChainState,
    spend: PropSpendState,
    input_pad: PropSpendState,
    built: BuiltCommitment,
    payload: Vec<u8>,
    fixture: PropValidatorFixture,
}

fn genesis_validator_combined_inflow_for_proptest() -> PropValidatorPrivacyStorageGenesis {
    let fixture = PropValidatorFixture::liveness_absentee_long_sim();
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let input_pad = prop_input_pad_for(1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_spend_genesis_outputs(&spend, &input_pad),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropValidatorPrivacyStorageGenesis {
        state,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    }
}

fn genesis_validator_combined_inflow_ppb_for_proptest() -> PropValidatorPrivacyStorageGenesis {
    let fixture = PropValidatorFixture::liveness_absentee_long_sim();
    let payload: Vec<u8> = vec![0u8; 1 << 20];
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        PROP_PPB_ENDOWMENT.min_replication,
        None,
    )
    .expect("commitment");
    let spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let input_pad = prop_input_pad_for(1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_spend_genesis_outputs(&spend, &input_pad),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: PROP_PPB_ENDOWMENT,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropValidatorPrivacyStorageGenesis {
        state,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    }
}

fn signing_stake_for_voters_from_state(st: &ChainState, voter_indices: &[u32]) -> u64 {
    voter_indices
        .iter()
        .map(|&i| st.validators[i as usize].stake)
        .sum()
}

/// Validator block with partial finality; uses live `st.validators` stake totals (**M5.8**).
#[allow(clippy::too_many_arguments)]
fn apply_validator_block_with_voters(
    fixture: &PropValidatorFixture,
    voter_indices: &[u32],
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
    bond_ops: Vec<BondOp>,
    slashings: Vec<SlashEvidence>,
) -> ChainState {
    let slot = height;
    let ts = u64::from(height) * 1_000;
    let unsealed =
        build_unsealed_header(st, &txs, &bond_ops, &slashings, &storage_proofs, slot, ts);
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height,
        slot,
        prev_hash: unsealed.prev_hash,
    };
    let producer = &st.validators[0];
    let producer_secrets = &fixture.secrets[0];
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let producer_proof = try_produce_slot(
        &ctx,
        producer_secrets,
        producer,
        total_stake,
        fixture.params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("produce")
    .expect("producer eligible");
    let votes: Vec<_> = voter_indices
        .iter()
        .map(|&i| {
            let secrets = &fixture.secrets[i as usize];
            cast_vote(
                &header_hash,
                secrets,
                &ctx,
                &producer_proof,
                producer,
                total_stake,
                fixture.params.expected_proposers_per_slot,
            )
            .expect("vote")
        })
        .collect();
    let agg = finalize(&header_hash, &votes, st.validators.len()).expect("finalize");
    let signing_stake = signing_stake_for_voters_from_state(st, voter_indices);
    let fin = FinalityProof {
        producer: producer_proof,
        finality: agg,
        signing_stake,
    };
    let blk = seal_block(
        unsealed,
        txs,
        bond_ops,
        encode_finality_proof(&fin),
        slashings,
        storage_proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn genesis_validator_privacy_storage_for_proptest() -> PropValidatorPrivacyStorageGenesis {
    let fixture = PropValidatorFixture::three_deterministic();
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let spend = PropSpendState::from_seed(1, PROP_MIXED_SPEND_VALUE);
    let input_pad = prop_input_pad_for(1);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: prop_spend_genesis_outputs(&spend, &input_pad),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    PropValidatorPrivacyStorageGenesis {
        state,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    }
}

/// Seal a validator-mode mixed block (BLS quorum + coinbase + CLSAG + SPoRA)
/// without applying it (**M5.6+** rollback fixtures).
fn build_validator_mixed_block(
    fixture: &PropValidatorFixture,
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    proofs: &[mfn_storage::StorageProof],
    voter_indices: &[usize],
) -> Block {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &txs, &[], &[], proofs, height, ts);
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height,
        slot: height,
        prev_hash: unsealed.prev_hash,
    };
    let producer = &fixture.validators[0];
    let producer_secrets = &fixture.secrets[0];
    let producer_proof = try_produce_slot(
        &ctx,
        producer_secrets,
        producer,
        fixture.total_stake,
        fixture.params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("produce")
    .expect("producer eligible");
    let mut votes = Vec::new();
    let mut signing_stake: u64 = 0;
    for &i in voter_indices {
        let secrets = &fixture.secrets[i];
        let v = &fixture.validators[i];
        votes.push(
            cast_vote(
                &header_hash,
                secrets,
                &ctx,
                &producer_proof,
                producer,
                fixture.total_stake,
                fixture.params.expected_proposers_per_slot,
            )
            .expect("vote"),
        );
        signing_stake += v.stake;
    }
    let agg = finalize(&header_hash, &votes, fixture.validators.len()).expect("finalize");
    let fin = FinalityProof {
        producer: producer_proof,
        finality: agg,
        signing_stake,
    };
    seal_block(
        unsealed,
        txs,
        Vec::new(),
        encode_finality_proof(&fin),
        Vec::new(),
        proofs.to_vec(),
    )
}

fn apply_validator_mixed_clsag_fee_and_storage_proof(
    fixture: &PropValidatorFixture,
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    proof: &mfn_storage::StorageProof,
) -> ChainState {
    let all_voters: Vec<usize> = (0..fixture.validators.len()).collect();
    let blk = build_validator_mixed_block(
        fixture,
        st,
        height,
        txs,
        std::slice::from_ref(proof),
        &all_voters,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn validator_mixed_block_material(
    spend: &PropSpendState,
    pad: &PropSpendState,
    built: &BuiltCommitment,
    payload: &[u8],
    payout: &PayoutAddress,
    st: &ChainState,
    height: u32,
    fee: u64,
) -> (Vec<TransactionWire>, mfn_storage::StorageProof) {
    let (tx, _, _) = spend.sign_self_transfer(pad, fee, height);
    let fee_sum = u128::from(fee);
    let prev = *st.tip_id().expect("tip");
    let proof = build_test_storage_proof(&built.commit, &prev, height, payload, &built.tree);
    let coinbase = prop_build_coinbase(
        height,
        &PROP_MIXED_EMISSION,
        fee_sum,
        payout,
        st,
        height,
        std::slice::from_ref(&proof),
    );
    let txs = vec![coinbase, tx];
    (txs, proof)
}

fn assert_reject_preserves_state<F>(
    st: &ChainState,
    before_snap: &StateSnap,
    before_bytes: &[u8],
    blk: Block,
    expect: F,
    label: &str,
) where
    F: Fn(&BlockError) -> bool,
{
    match apply_block(st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(expect),
                "{label}: expected matching BlockError in {errors:?}"
            );
            assert_eq!(snap(st), *before_snap, "{label}: snap must be unchanged");
            assert_eq!(
                checkpoint_bytes(st),
                before_bytes,
                "{label}: checkpoint must be unchanged"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("{label}: expected reject"),
    }
}

#[allow(clippy::too_many_arguments)]
fn legacy_mixed_block_material(
    spend: &PropSpendState,
    pad: &PropSpendState,
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    height: u32,
    fee: u64,
) -> (Vec<TransactionWire>, mfn_storage::StorageProof) {
    let (tx, _, _) = spend.sign_self_transfer(pad, fee, height);
    let txs = vec![tx];
    let prev = *st.tip_id().expect("tip");
    let proof = build_test_storage_proof(&built.commit, &prev, height, payload, &built.tree);
    (txs, proof)
}

fn apply_mixed_clsag_fee_and_storage_proof(
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    proof: &mfn_storage::StorageProof,
) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let unsealed =
        build_unsealed_header(st, &txs, &[], &[], std::slice::from_ref(proof), height, ts);
    let blk = seal_with_test_finality(
        st,
        unsealed,
        txs,
        Vec::new(),
        Vec::new(),
        vec![proof.clone()],
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn apply_mixed_clsag_fee_and_storage_upload(
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &txs, &[], &[], &[], height, ts);
    let blk = seal_with_test_finality(st, unsealed, txs, Vec::new(), Vec::new(), Vec::new());
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn register_op(seed: u8) -> BondOp {
    let bls = bls_keygen_from_seed(&[seed.wrapping_add(1); 32]);
    let vrf = vrf_keygen_from_seed(&[seed.wrapping_add(101); 32]).expect("vrf");
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &bls.pk, None, &bls.sk),
    }
}

/// Secrets matching [`register_op`] / on-chain [`Validator::index`].
fn validator_secrets_for_index(index: u32) -> ValidatorSecrets {
    let seed = index.wrapping_add(1) as u8;
    let bls = bls_keygen_from_seed(&[seed.wrapping_add(1); 32]);
    let vrf = vrf_keygen_from_seed(&[seed.wrapping_add(101); 32]).expect("vrf");
    ValidatorSecrets { index, vrf, bls }
}

fn equivocation_evidence(
    height: u32,
    slot: u32,
    voter_index: u32,
    bls_sk: &BlsSecretKey,
) -> SlashEvidence {
    let h1 = [voter_index.wrapping_add(11) as u8; 32];
    let h2 = [voter_index.wrapping_add(22) as u8; 32];
    SlashEvidence::Equivocation(EquivocationEvidence {
        height,
        slot,
        voter_index,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, bls_sk),
    })
}
/// Attach a valid MFBN finality blob when the pre-state has validators (**M5.4**).
///
/// Returns the header (possibly with an adjusted `slot` for VRF eligibility) and
/// encoded finality bytes. The header and proof must use the same `slot`.
fn attach_test_finality(
    st: &ChainState,
    mut unsealed: mfn_consensus::BlockHeader,
) -> (mfn_consensus::BlockHeader, Vec<u8>) {
    if st.validators.is_empty() {
        return (unsealed, Vec::new());
    }
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;
    let base_slot = unsealed.slot;

    for bump in 0u32..=512u32 {
        unsealed.slot = base_slot.saturating_add(bump);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: unsealed.height,
            slot: unsealed.slot,
            prev_hash: unsealed.prev_hash,
        };

        let mut candidates: Vec<ProducerProof> = Vec::new();
        for v in &st.validators {
            let secrets = validator_secrets_for_index(v.index);
            if let Ok(Some(p)) = try_produce_slot(&ctx, &secrets, v, total_stake, f, &header_hash) {
                candidates.push(p);
            }
        }
        let producer_proof = match pick_winner(&candidates) {
            None => continue,
            Some(p) => p.clone(),
        };
        let producer_validator = st
            .validators
            .iter()
            .find(|v| v.index == producer_proof.validator_index)
            .expect("producer index in validator set");

        let mut votes = Vec::with_capacity(st.validators.len());
        for v in &st.validators {
            let secrets = validator_secrets_for_index(v.index);
            votes.push(
                cast_vote(
                    &header_hash,
                    &secrets,
                    &ctx,
                    &producer_proof,
                    producer_validator,
                    total_stake,
                    f,
                )
                .expect("committee vote"),
            );
        }
        let agg = finalize(&header_hash, &votes, st.validators.len()).expect("finalize");
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake: total_stake,
        };
        return (unsealed, encode_finality_proof(&fin));
    }
    panic!(
        "attach_test_finality: no VRF-eligible producer in 512 slot attempts (validators={})",
        st.validators.len()
    );
}

fn seal_with_test_finality(
    st: &ChainState,
    unsealed: mfn_consensus::BlockHeader,
    txs: Vec<mfn_consensus::TransactionWire>,
    bond_ops: Vec<BondOp>,
    slashings: Vec<mfn_consensus::SlashEvidence>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
) -> mfn_consensus::Block {
    let (unsealed, fin) = attach_test_finality(st, unsealed);
    seal_block(unsealed, txs, bond_ops, fin, slashings, storage_proofs)
}

fn forged_register_op() -> BondOp {
    let attacker = bls_keygen_from_seed(&[200u8; 32]);
    let victim = bls_keygen_from_seed(&[201u8; 32]);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let vrf_pk = generator_g();
    let sig = sign_register(stake, &vrf_pk, &victim.pk, None, &attacker.sk);
    BondOp::Register {
        stake,
        vrf_pk,
        bls_pk: victim.pk,
        payout: None,
        sig,
    }
}

fn apply_with_bond_ops(st: &ChainState, height: u32, bond_ops: Vec<BondOp>) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &[], &bond_ops, &[], &[], height, ts);
    let blk = seal_with_test_finality(st, unsealed, Vec::new(), bond_ops, Vec::new(), Vec::new());
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn apply_with_storage_proofs_at_slot(
    st: &ChainState,
    height: u32,
    slot: u32,
    proofs: Vec<mfn_storage::StorageProof>,
) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, slot, ts);
    // Single finality attach: `seal_with_test_finality` would run attach again and can
    // bump `header.slot` away from the SPoRA proof's challenge slot.
    let (unsealed, fin) = attach_test_finality(st, unsealed);
    assert_eq!(
        unsealed.slot, slot,
        "sealed slot {} != proof slot {slot} at height {height}",
        unsealed.slot
    );
    let blk = seal_block(unsealed, Vec::new(), Vec::new(), fin, Vec::new(), proofs);
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

/// Build a SPoRA proof whose `proof.index` matches the `slot` on the sealed block.
///
/// [`attach_test_finality`] may bump `header.slot` for VRF eligibility when the
/// pre-state has validators; the proof must target that final slot, not `height`.
fn build_storage_proof_for_sealed_slot(
    st: &ChainState,
    height: u32,
    built: &BuiltCommitment,
    payload: &[u8],
) -> (mfn_storage::StorageProof, u32) {
    let ts = u64::from(height) * 1_000;
    let prev = *st.tip_id().expect("tip");
    let mut slot = height;
    for _ in 0..=512u32 {
        let proof = build_test_storage_proof(&built.commit, &prev, slot, payload, &built.tree);
        let unsealed =
            build_unsealed_header(st, &[], &[], &[], std::slice::from_ref(&proof), slot, ts);
        let (final_hdr, _) = attach_test_finality(st, unsealed);
        if final_hdr.slot == slot {
            return (proof, slot);
        }
        slot = final_hdr.slot;
    }
    panic!("build_storage_proof_for_sealed_slot: no stable slot at height {height}");
}

fn apply_valid_proof_at(
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    height: u32,
) -> ChainState {
    let (proof, slot) = build_storage_proof_for_sealed_slot(st, height, built, payload);
    apply_with_storage_proofs_at_slot(st, height, slot, vec![proof])
}

fn apply_b3_two_operator_proofs_at(
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    height: u32,
) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let scratch = build_unsealed_header(st, &[], &[], &[], &[], height, ts);
    let p0 = build_test_storage_proof_operator_salted(
        &built.commit,
        &scratch.prev_hash,
        height,
        payload,
        &built.tree,
    );
    let (v1, s1) = test_operator_payout_keys_alt();
    let p1 = build_storage_proof_operator_salted(
        &built.commit,
        &scratch.prev_hash,
        height,
        payload,
        &built.tree,
        v1,
        s1,
    )
    .expect("b3 proof");
    apply_with_storage_proofs_at_slot(st, height, height, vec![p0, p1])
}

fn treasury_after_b3_two_operator_block(
    treasury: u128,
    bonus_total: u128,
    params: &EmissionParams,
) -> u128 {
    let storage_reward_total = u128::from(params.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    treasury.saturating_sub(storage_reward_total.min(treasury))
}

fn seal_empty(st: &ChainState, header: mfn_consensus::BlockHeader) -> mfn_consensus::Block {
    seal_with_test_finality(st, header, Vec::new(), Vec::new(), Vec::new(), Vec::new())
}

fn next_height(st: &ChainState) -> u32 {
    st.height.map(|h| h + 1).unwrap_or(0)
}

fn apply_empty_at(st: &ChainState, height: u32, timestamp: u64) -> ChainState {
    let header = build_unsealed_header(st, &[], &[], &[], &[], height, timestamp);
    let blk = seal_empty(st, header);
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

/// Empty block at a high slot so B5 stale-storage audit challenges are active.
fn apply_empty_at_audit_slot(st: &ChainState, slot: u32) -> ChainState {
    apply_empty_at(st, slot, 1_000)
}

#[derive(Debug, Clone)]
enum HeaderTamper {
    HeightOffset(u32),
    PrevHash,
    TxRoot,
    BondRoot,
    StorageProofRoot,
}

fn tamper(
    mut header: mfn_consensus::BlockHeader,
    kind: HeaderTamper,
) -> mfn_consensus::BlockHeader {
    match kind {
        HeaderTamper::HeightOffset(bump) => {
            header.height = header.height.saturating_add(bump.max(1));
        }
        HeaderTamper::PrevHash => header.prev_hash = [0xab; 32],
        HeaderTamper::TxRoot => header.tx_root[0] ^= 0xff,
        HeaderTamper::BondRoot => header.bond_root[0] ^= 0xff,
        HeaderTamper::StorageProofRoot => header.storage_proof_root[0] ^= 0xff,
    }
    header
}

fn expected_error(kind: &HeaderTamper) -> fn(&BlockError) -> bool {
    match kind {
        HeaderTamper::HeightOffset(_) => |e| matches!(e, BlockError::BadHeight { .. }),
        HeaderTamper::PrevHash => |e| matches!(e, BlockError::PrevHashMismatch),
        HeaderTamper::TxRoot => |e| matches!(e, BlockError::TxRootMismatch),
        HeaderTamper::BondRoot => |e| matches!(e, BlockError::BondRootMismatch),
        HeaderTamper::StorageProofRoot => |e| matches!(e, BlockError::StorageProofRootMismatch),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_valid_empty_block_chains(
        n_blocks in 1u32..=24u32,
        ts_base in 0u64..=10_000_000u64,
    ) {
        let mut st = genesis_state();
        let before = snap(&st);
        assert_eq!(before.height, Some(0));

        for i in 0..n_blocks {
            let h = next_height(&st);
            let ts = ts_base.saturating_add(u64::from(i).saturating_mul(1_000));
            let prev_snap = snap(&st);
            st = apply_empty_at(&st, h, ts);
            let after = snap(&st);
            assert_eq!(after.height, Some(h));
            assert_eq!(after.block_ids_len, prev_snap.block_ids_len + 1);
            assert_ne!(after.tip, prev_snap.tip);
        }
    }

    #[test]
    fn prop_reject_tampered_header_without_state_change(
        tamper_kind in prop_oneof![
            (2u32..=64u32).prop_map(HeaderTamper::HeightOffset),
            Just(HeaderTamper::PrevHash),
            Just(HeaderTamper::TxRoot),
            Just(HeaderTamper::BondRoot),
            Just(HeaderTamper::StorageProofRoot),
        ],
    ) {
        let st = genesis_state();
        let before = snap(&st);
        let h = next_height(&st);
        let header = build_unsealed_header(&st, &[], &[], &[], &[], h, 100);
        let header = tamper(header, tamper_kind.clone());
        let blk = seal_empty(&st, header);
        let expect = expected_error(&tamper_kind);

        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors.iter().any(expect), "errors: {errors:?}");
                assert_eq!(snap(&st), before);
            }
            ApplyOutcome::Ok { .. } => prop_assert!(false, "expected reject for {tamper_kind:?}"),
        }
    }

    #[test]
    fn prop_reject_after_partial_chain(
        prefix_len in 1u32..=8u32,
        bump in 2u32..=32u32,
    ) {
        let mut st = genesis_state();
        for i in 0..prefix_len {
            let h = next_height(&st);
            st = apply_empty_at(&st, h, u64::from(i + 1) * 1_000);
        }
        let before = snap(&st);
        let h = next_height(&st);
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], h, 9_999);
        header.height = header.height.saturating_add(bump);
        let blk = seal_empty(&st, header);

        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BadHeight { .. })));
                assert_eq!(snap(&st), before);
            }
            ApplyOutcome::Ok { .. } => prop_assert!(false, "expected BadHeight"),
        }
    }

    #[test]
    fn prop_alternating_empty_and_storage_chains(n_pairs in 1u32..=8u32) {
        let gen = genesis_with_storage();
        let mut st = gen.state;
        for i in 0..n_pairs {
            let h_empty = next_height(&st);
            st = apply_empty_at(&st, h_empty, u64::from(i).saturating_mul(2_000));
            let h_proof = next_height(&st);
            st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h_proof);
        }
    }

    #[test]
    fn prop_valid_storage_proof_chains(n_blocks in 1u32..=16u32) {
        let gen = genesis_with_storage();
        let mut st = gen.state;
        for _ in 0..n_blocks {
            let h = next_height(&st);
            let prev = snap(&st);
            st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h);
            let after = snap(&st);
            assert_eq!(after.height, Some(h));
            assert_eq!(after.block_ids_len, prev.block_ids_len + 1);
            assert_ne!(after.tip, prev.tip);
        }
    }

    #[test]
    fn prop_valid_register_bond_op_chains(
        n_ops in 1u32..=DEFAULT_BONDING_PARAMS.max_entry_churn_per_epoch,
    ) {
        let st = genesis_with_bonding();
        let before = snap(&st);
        let ops: Vec<_> = (0..n_ops).map(|i| register_op((i + 1) as u8)).collect();
        let h = next_height(&st);
        let st = apply_with_bond_ops(&st, h, ops);
        let min_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        prop_assert_eq!(
            st.treasury,
            min_stake.saturating_mul(u128::from(n_ops))
        );
        prop_assert_eq!(st.validators.len(), before.validators_len + usize::try_from(n_ops).unwrap());
    }

    #[test]
    fn prop_alternating_register_then_storage_treasury(
        n_pairs in 1u32..=DEFAULT_BONDING_PARAMS.max_entry_churn_per_epoch,
    ) {
        let gen = genesis_with_storage_and_bonding();
        let mut st = gen.state;
        let mut model = 0u128;
        let stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let emission = &DEFAULT_EMISSION_PARAMS;

        for i in 0..n_pairs {
            let h_reg = next_height(&st);
            st = apply_with_bond_ops(&st, h_reg, vec![register_op((i + 1) as u8)]);
            model = treasury_after_register(model, stake);
            prop_assert_eq!(st.treasury, model);

            let h_proof = next_height(&st);
            st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h_proof);
            model = treasury_after_legacy_block(model, 0, 1, emission);
            prop_assert_eq!(st.treasury, model);
        }
    }

    #[test]
    fn prop_alternating_storage_then_register_treasury(
        n_pairs in 1u32..=DEFAULT_BONDING_PARAMS.max_entry_churn_per_epoch,
    ) {
        let gen = genesis_with_storage_and_bonding();
        let mut st = gen.state;
        let mut model = 0u128;
        let stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let emission = &DEFAULT_EMISSION_PARAMS;

        for i in 0..n_pairs {
            let h_proof = next_height(&st);
            st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h_proof);
            model = treasury_after_legacy_block(model, 0, 1, emission);
            prop_assert_eq!(st.treasury, model);

            let h_reg = next_height(&st);
            st = apply_with_bond_ops(&st, h_reg, vec![register_op((i + 1) as u8)]);
            model = treasury_after_register(model, stake);
            prop_assert_eq!(st.treasury, model);
        }
    }

    /// B3: duplicate operator identity in one block must reject without state change (**M5.50**).
    #[test]
    fn prop_b3_duplicate_operator_rejects_after_prefix(prefix_len in 0u32..=6u32) {
        let gen = genesis_with_b3_storage();
        let mut st = gen.state;
        for i in 0..prefix_len {
            let h = next_height(&st);
            st = apply_b3_two_operator_proofs_at(&gen.built, &gen.payload, &st, h);
            let _ = i;
        }
        let before = snap(&st);
        let h = next_height(&st);
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof_operator_salted(
            &gen.built.commit,
            &prev,
            h,
            &gen.payload,
            &gen.built.tree,
        );
        let proofs = vec![proof.clone(), proof];
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, h, u64::from(h) * 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                let dup = errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProofOperator { .. }));
                prop_assert!(dup, "errors: {errors:?}");
                prop_assert_eq!(snap(&st), before);
            }
            ApplyOutcome::Ok { .. } => prop_assert!(false, "duplicate B3 operator must reject"),
        }
    }

    /// B3: two-operator blocks drain treasury as `2 × storage_proof_reward + Σ bonuses`
    /// (**M5.41**).
    #[test]
    fn prop_b3_two_operator_proof_chain_treasury(n_blocks in 1u32..=8u32) {
        let gen = genesis_with_b3_storage();
        let mut st = gen.state;
        let mut model = 0u128;
        let emission = &DEFAULT_EMISSION_PARAMS;

        for h in 1..=n_blocks {
            let ts = u64::from(h) * 1_000;
            let scratch = build_unsealed_header(&st, &[], &[], &[], &[], h, ts);
            let p0 = build_test_storage_proof_operator_salted(
                &gen.built.commit,
                &scratch.prev_hash,
                h,
                &gen.payload,
                &gen.built.tree,
            );
            let (v1, s1) = test_operator_payout_keys_alt();
            let p1 = build_storage_proof_operator_salted(
                &gen.built.commit,
                &scratch.prev_hash,
                h,
                &gen.payload,
                &gen.built.tree,
                v1,
                s1,
            )
            .expect("b3 proof");
            let proofs = vec![p0, p1];
            let bonus_total: u128 = storage_proof_operator_settlements(
                &proofs,
                &st.storage,
                h,
                &PROP_ENDOWMENT_B3,
            )
            .into_iter()
            .map(|(_, b)| b)
            .fold(0, u128::saturating_add);
            st = apply_b3_two_operator_proofs_at(&gen.built, &gen.payload, &st, h);
            model = treasury_after_b3_two_operator_block(model, bonus_total, emission);
            prop_assert_eq!(st.treasury, model, "B3 treasury mismatch");
        }
    }

    /// CLSAG fee credit + SPoRA proof drain in the **same block** (**M5.5**).
    #[test]
    fn prop_mixed_clsag_fee_and_storage_proof_treasury(
        n_blocks in 1u32..=12u32,
        fee_base in 1_000u64..=200_000u64,
    ) {
        let gen = genesis_privacy_storage_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 7_001));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let prev = *st.tip_id().expect("tip");
            let proof = build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
            st = apply_mixed_clsag_fee_and_storage_proof(&st, h, vec![tx], &proof);
            model = treasury_after_legacy_block(model, u128::from(fee), 1, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {})",
                h,
                fee
            );
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// CLSAG fee credit + NEW storage upload in the **same block** (**M5.33**).
    #[test]
    fn prop_mixed_clsag_fee_and_storage_upload_treasury(
        n_blocks in 1u32..=12u32,
        clsag_fee_base in 1_000u64..=200_000u64,
        upload_fee_extra in 0u64..=5_000u64,
    ) {
        const UPLOAD_PAYLOAD_LEN: usize = 1024;
        let min_upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN);
        let gen = genesis_dual_spend_for_upload_proptest();
        let mut st = gen.state;
        let mut clsag_spend = gen.clsag_spend;
        let mut clsag_pad = gen.clsag_pad;
        let mut upload_spend = gen.upload_spend;
        let mut upload_pad = gen.upload_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let clsag_fee = clsag_fee_base.saturating_add(u64::from(h % 7_001));
            let upload_fee = min_upload_fee.saturating_add(upload_fee_extra);
            prop_assert!(clsag_fee < PROP_MIXED_SPEND_VALUE, "CLSAG fee must fit genesis UTXO");
            prop_assert!(upload_fee < PROP_MIXED_SPEND_VALUE, "upload fee must fit genesis UTXO");

            let payload: Vec<u8> = vec![h as u8; UPLOAD_PAYLOAD_LEN];
            let built = build_storage_commitment(
                &payload,
                1_000,
                Some(256),
                DEFAULT_ENDOWMENT_PARAMS.min_replication,
                None,
            )
            .expect("commitment");
            let commit_hash = storage_commitment_hash(&built.commit);
            prop_assert!(
                !st.storage.contains_key(&commit_hash),
                "upload must anchor a fresh commitment at height {h}"
            );

            let (clsag_tx, next_clsag, next_clsag_pad) =
                clsag_spend.sign_self_transfer(&clsag_pad, clsag_fee, h);
            clsag_spend = next_clsag;
            clsag_pad = next_clsag_pad;
            let (upload_tx, next_upload, next_upload_pad) = upload_spend.sign_storage_upload(
                &upload_pad,
                PropStorageUploadArgs::new(
                    upload_fee,
                    &built,
                    PROP_STORAGE_ENDOWMENT_AMOUNT,
                    &DEFAULT_ENDOWMENT_PARAMS,
                    h.wrapping_add(10_000),
                ),
            );
            upload_spend = next_upload;
            upload_pad = next_upload_pad;

            let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
            st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
            model = treasury_after_legacy_block(model, fee_sum, 0, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (clsag_fee {} upload_fee {})",
                h,
                clsag_fee,
                upload_fee
            );
            prop_assert!(st.storage.contains_key(&commit_hash));
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// NEW storage upload with `MFEO` opening when `require_endowment_opening=1` (**B-11**).
    #[test]
    fn prop_mfeo_opening_storage_upload_treasury(
        n_blocks in 1u32..=12u32,
        clsag_fee_base in 1_000u64..=200_000u64,
        upload_fee_extra in 0u64..=5_000u64,
    ) {
        const UPLOAD_PAYLOAD_LEN: usize = 1024;
        let min_upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN);
        let gen = genesis_dual_spend_for_upload_opening_proptest();
        let mut st = gen.state;
        let mut clsag_spend = gen.clsag_spend;
        let mut clsag_pad = gen.clsag_pad;
        let mut upload_spend = gen.upload_spend;
        let mut upload_pad = gen.upload_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let clsag_fee = clsag_fee_base.saturating_add(u64::from(h % 7_001));
            let upload_fee = min_upload_fee.saturating_add(upload_fee_extra);
            prop_assert!(clsag_fee < PROP_MIXED_SPEND_VALUE, "CLSAG fee must fit genesis UTXO");
            prop_assert!(upload_fee < PROP_MIXED_SPEND_VALUE, "upload fee must fit genesis UTXO");

            let payload: Vec<u8> = vec![h as u8; UPLOAD_PAYLOAD_LEN];
            let built = build_storage_commitment(
                &payload,
                PROP_STORAGE_ENDOWMENT_AMOUNT,
                Some(256),
                DEFAULT_ENDOWMENT_PARAMS.min_replication,
                None,
            )
            .expect("commitment");
            let commit_hash = storage_commitment_hash(&built.commit);
            prop_assert!(
                !st.storage.contains_key(&commit_hash),
                "upload must anchor a fresh commitment at height {h}"
            );

            let (clsag_tx, next_clsag, next_clsag_pad) =
                clsag_spend.sign_self_transfer(&clsag_pad, clsag_fee, h);
            clsag_spend = next_clsag;
            clsag_pad = next_clsag_pad;
            let (upload_tx, next_upload, next_upload_pad) = upload_spend.sign_storage_upload(
                &upload_pad,
                PropStorageUploadArgs::new(
                    upload_fee,
                    &built,
                    PROP_STORAGE_ENDOWMENT_AMOUNT,
                    &PROP_ENDOWMENT_REQUIRE_OPENING,
                    h.wrapping_add(10_000),
                ),
            );
            upload_spend = next_upload;
            upload_pad = next_upload_pad;

            let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
            st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
            model = treasury_after_legacy_block(model, fee_sum, 0, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (clsag_fee {} upload_fee {})",
                h,
                clsag_fee,
                upload_fee
            );
            prop_assert!(st.storage.contains_key(&commit_hash));
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// NEW storage upload with `MFER` range proof when `require_endowment_range_proof=1` (**B-11 phase 2**).
    #[test]
    fn prop_mfer_range_proof_storage_upload_treasury(
        n_blocks in 1u32..=12u32,
        clsag_fee_base in 1_000u64..=200_000u64,
        upload_fee_extra in 0u64..=5_000u64,
    ) {
        const UPLOAD_PAYLOAD_LEN: usize = 1024;
        let min_upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN);
        let gen = genesis_dual_spend_for_upload_range_proof_proptest();
        let mut st = gen.state;
        let mut clsag_spend = gen.clsag_spend;
        let mut clsag_pad = gen.clsag_pad;
        let mut upload_spend = gen.upload_spend;
        let mut upload_pad = gen.upload_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let clsag_fee = clsag_fee_base.saturating_add(u64::from(h % 7_001));
            let upload_fee = min_upload_fee.saturating_add(upload_fee_extra);
            prop_assert!(clsag_fee < PROP_MIXED_SPEND_VALUE, "CLSAG fee must fit genesis UTXO");
            prop_assert!(upload_fee < PROP_MIXED_SPEND_VALUE, "upload fee must fit genesis UTXO");

            let payload: Vec<u8> = vec![h as u8; UPLOAD_PAYLOAD_LEN];
            let built = build_storage_commitment(
                &payload,
                PROP_STORAGE_ENDOWMENT_AMOUNT,
                Some(256),
                DEFAULT_ENDOWMENT_PARAMS.min_replication,
                None,
            )
            .expect("commitment");
            let commit_hash = storage_commitment_hash(&built.commit);
            prop_assert!(
                !st.storage.contains_key(&commit_hash),
                "upload must anchor a fresh commitment at height {h}"
            );

            let (clsag_tx, next_clsag, next_clsag_pad) =
                clsag_spend.sign_self_transfer(&clsag_pad, clsag_fee, h);
            clsag_spend = next_clsag;
            clsag_pad = next_clsag_pad;
            let (upload_tx, next_upload, next_upload_pad) = upload_spend.sign_storage_upload(
                &upload_pad,
                PropStorageUploadArgs::new(
                    upload_fee,
                    &built,
                    PROP_STORAGE_ENDOWMENT_AMOUNT,
                    &PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
                    h.wrapping_add(10_000),
                ),
            );
            upload_spend = next_upload;
            upload_pad = next_upload_pad;

            let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
            st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
            model = treasury_after_legacy_block(model, fee_sum, 0, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (clsag_fee {} upload_fee {})",
                h,
                clsag_fee,
                upload_fee
            );
            prop_assert!(st.storage.contains_key(&commit_hash));
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// Validator quorum + coinbase + CLSAG fee + SPoRA proof in one block (**M5.6**).
    #[test]
    fn prop_validator_mixed_clsag_fee_and_storage_proof_treasury(
        n_blocks in 1u32..=8u32,
        fee_base in 1_000u64..=200_000u64,
    ) {
        let gen = genesis_validator_privacy_storage_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 7_001));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let prev = *st.tip_id().expect("tip");
            let proof = build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
            let coinbase = prop_build_coinbase(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                h,
                std::slice::from_ref(&proof),
            );
            let txs = vec![coinbase, tx];
            st = apply_validator_mixed_clsag_fee_and_storage_proof(
                &gen.fixture, &st, h, txs, &proof,
            );
            model = treasury_after_block(model, fee_sum, 1, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {})",
                h,
                fee
            );
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// Bond burn inflow + randomized CLSAG fees + SPoRA drain (**M5.7**).
    #[test]
    fn prop_bond_inflow_random_fee_and_proof_outflow_treasury(
        n_fee_blocks in 1u32..=8u32,
        fee_base in 1_000u64..=150_000u64,
    ) {
        let gen = genesis_privacy_storage_bonding_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);

        let h_bond = next_height(&st);
        st = apply_with_bond_ops(&st, h_bond, vec![register_op(1)]);
        model = treasury_after_register(model, stake);
        prop_assert_eq!(st.treasury, model);
        prop_assert!(st.treasury < u128::MAX);

        for i in 0..n_fee_blocks {
            let h = next_height(&st);
            let fee = fee_base.saturating_add(u64::from((i + h) % 5_001));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            st = apply_mixed_clsag_fee_and_storage_proof(
                &st,
                h,
                vec![tx],
                &build_test_storage_proof(
                    &gen.built.commit,
                    &st.tip_id().copied().expect("tip"),
                    h,
                    &gen.payload,
                    &gen.built.tree,
                ),
            );
            model = treasury_after_legacy_block(model, u128::from(fee), 1, emission);
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {})",
                h,
                fee
            );
            prop_assert!(st.treasury < u128::MAX);
        }
    }

    /// Validator-mode bond / liveness / fee / proof inflows with randomized fees (**M5.8**).
    #[test]
    fn prop_validator_combined_inflow_random_fee_treasury(
        n_blocks in 4u32..=12u32,
        fee_base in 1_000u64..=100_000u64,
    ) {
        let gen = genesis_validator_combined_inflow_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 50u8;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == 4;
            let with_proof = h % 4 == 0;
            let with_liveness = h == 8 && n_blocks >= 8;
            let proofs = if with_proof { 1u128 } else { 0 };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                vec![build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                )]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                Vec::new(),
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_combined_inflow_block(
                model,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {})",
                h,
                fee
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
        }
    }

    /// Equivocation slash on the terminal block with bond/liveness/fee/proof inflows (**M5.9**).
    #[test]
    fn prop_validator_equivocation_combined_inflow_random_fee_treasury(
        n_blocks in 6u32..=12u32,
        fee_base in 1_000u64..=100_000u64,
    ) {
        let gen = genesis_validator_combined_inflow_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        const EQUIVOCATION_IDX: u32 = 2;
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 50u8;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == 4;
            let with_proof = h % 4 == 0;
            let with_liveness = h == 8 && n_blocks >= 8;
            let with_equivocation = h == n_blocks;
            let proofs = if with_proof { 1u128 } else { 0 };
            let equivocation_credit = if with_equivocation {
                u128::from(st.validators[EQUIVOCATION_IDX as usize].stake)
            } else {
                0
            };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                vec![build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                )]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            let slashings = if with_equivocation {
                vec![equivocation_evidence(
                    h,
                    h,
                    EQUIVOCATION_IDX,
                    &gen.fixture.secrets[EQUIVOCATION_IDX as usize].bls.sk,
                )]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                slashings,
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_equivocation_combined_inflow_block(
                model,
                equivocation_credit,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {})",
                h,
                fee
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
            if with_equivocation {
                prop_assert_eq!(
                    st.validators[EQUIVOCATION_IDX as usize].stake,
                    0,
                    "equivocation must zero slashed validator stake"
                );
            }
        }
    }

    /// Bond/liveness/proof heights vary by proptest inputs without slash inflow (**M5.11**).
    #[test]
    fn prop_validator_combined_inflow_random_schedule_no_equivocation_treasury(
        n_blocks in 6u32..=14u32,
        fee_base in 1_000u64..=80_000u64,
        bond_offset in 0u32..=4u32,
        liveness_offset in 0u32..=4u32,
        proof_stride in 2u32..=5u32,
    ) {
        let gen = genesis_validator_combined_inflow_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 70u8;

        let bond_span = (n_blocks - 2).max(1);
        let bond_h = 2 + bond_offset % bond_span;
        let liveness_span = n_blocks.saturating_sub(3).max(1);
        let liveness_h = 2 + liveness_offset % liveness_span;
        prop_assert!(bond_h <= n_blocks, "bond height {bond_h} must fit chain length {n_blocks}");
        prop_assert!(
            liveness_h <= n_blocks,
            "liveness height {liveness_h} must fit chain length {n_blocks}"
        );

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == bond_h;
            let with_proof = h % proof_stride == 0;
            let with_liveness = h == liveness_h;
            let proofs = if with_proof { 1u128 } else { 0 };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                vec![build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                )]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                Vec::new(),
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_combined_inflow_block(
                model,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {}, bond_h {}, liveness_h {}, stride {})",
                h,
                fee,
                bond_h,
                liveness_h,
                proof_stride
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
        }
    }

    /// Bond/liveness/proof heights vary by proptest inputs; equivocation on terminal block (**M5.10**).
    #[test]
    fn prop_validator_combined_inflow_random_schedule_treasury(
        n_blocks in 8u32..=16u32,
        fee_base in 1_000u64..=80_000u64,
        bond_offset in 0u32..=4u32,
        liveness_offset in 0u32..=4u32,
        proof_stride in 2u32..=5u32,
    ) {
        let gen = genesis_validator_combined_inflow_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        const EQUIVOCATION_IDX: u32 = 2;
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 60u8;

        let bond_h = 2 + bond_offset % (n_blocks - 3);
        let liveness_span = n_blocks.saturating_sub(5).max(1);
        let liveness_h = 3 + liveness_offset % liveness_span;
        prop_assert!(
            liveness_h < n_blocks,
            "liveness height {liveness_h} must precede terminal equivocation at {n_blocks}"
        );

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == bond_h;
            let with_proof = h % proof_stride == 0;
            let with_liveness = h == liveness_h;
            let with_equivocation = h == n_blocks;
            let proofs = if with_proof { 1u128 } else { 0 };
            let equivocation_credit = if with_equivocation {
                u128::from(st.validators[EQUIVOCATION_IDX as usize].stake)
            } else {
                0
            };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                vec![build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                )]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            let slashings = if with_equivocation {
                vec![equivocation_evidence(
                    h,
                    h,
                    EQUIVOCATION_IDX,
                    &gen.fixture.secrets[EQUIVOCATION_IDX as usize].bls.sk,
                )]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                slashings,
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_equivocation_combined_inflow_block(
                model,
                equivocation_credit,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "treasury mismatch at height {} (fee {}, bond_h {}, liveness_h {}, stride {})",
                h,
                fee,
                bond_h,
                liveness_h,
                proof_stride
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
            if with_equivocation {
                prop_assert_eq!(
                    st.validators[EQUIVOCATION_IDX as usize].stake,
                    0,
                    "equivocation must zero slashed validator stake"
                );
            }
        }
    }

    /// PPB-augmented proof drain composes with bond/liveness/fee inflow (**M5.21**).
    #[test]
    fn prop_validator_combined_inflow_random_schedule_no_equivocation_ppb_treasury(
        n_blocks in 6u32..=14u32,
        fee_base in 1_000u64..=80_000u64,
        bond_offset in 0u32..=4u32,
        liveness_offset in 0u32..=4u32,
        proof_stride in 2u32..=5u32,
    ) {
        let gen = genesis_validator_combined_inflow_ppb_for_proptest();
        let commit_hash = storage_commitment_hash(&gen.built.commit);
        let ep = &PROP_PPB_ENDOWMENT;
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 80u8;

        let bond_span = (n_blocks - 2).max(1);
        let bond_h = 2 + bond_offset % bond_span;
        let liveness_span = n_blocks.saturating_sub(3).max(1);
        let liveness_h = 2 + liveness_offset % liveness_span;
        prop_assert!(bond_h <= n_blocks, "bond height {bond_h} must fit chain length {n_blocks}");
        prop_assert!(
            liveness_h <= n_blocks,
            "liveness height {liveness_h} must fit chain length {n_blocks}"
        );

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == bond_h;
            let with_proof = h % proof_stride == 0;
            let with_liveness = h == liveness_h;
            let proofs = if with_proof { 1u128 } else { 0 };
            let ppb_bonus = if with_proof {
                let payout = seed_ppb_pending_and_expected_payout(&mut st, &commit_hash, h, ep);
                prop_assert!(payout > 0, "seeded PPB must cross integer payout boundary");
                payout
            } else {
                0
            };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                let proof = build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                );
                let bonus =
                    storage_proof_coinbase_bonus(std::slice::from_ref(&proof), &st.storage, h, ep);
                prop_assert_eq!(bonus, ppb_bonus, "PPB bonus must match accrual payout");
                vec![proof]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                Vec::new(),
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_combined_inflow_block_with_ppb_bonus(
                model,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                ppb_bonus,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "PPB treasury mismatch at height {} (fee {}, bond_h {}, liveness_h {}, stride {})",
                h,
                fee,
                bond_h,
                liveness_h,
                proof_stride
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
        }
    }

    /// PPB proof drain with terminal equivocation on combined inflow schedule (**M5.21**).
    #[test]
    fn prop_validator_equivocation_combined_inflow_random_schedule_ppb_treasury(
        n_blocks in 8u32..=16u32,
        fee_base in 1_000u64..=80_000u64,
        bond_offset in 0u32..=4u32,
        liveness_offset in 0u32..=4u32,
        proof_stride in 2u32..=5u32,
    ) {
        let gen = genesis_validator_combined_inflow_ppb_for_proptest();
        let commit_hash = storage_commitment_hash(&gen.built.commit);
        let ep = &PROP_PPB_ENDOWMENT;
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut input_pad = gen.input_pad;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;
        let voters = [0u32, 2];
        const EQUIVOCATION_IDX: u32 = 2;
        let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
        let liveness_forfeit = 10_000u128;
        let mut bond_seed = 90u8;

        let bond_h = 2 + bond_offset % (n_blocks - 3);
        let liveness_span = n_blocks.saturating_sub(5).max(1);
        let liveness_h = 3 + liveness_offset % liveness_span;
        prop_assert!(
            liveness_h < n_blocks,
            "liveness height {liveness_h} must precede terminal equivocation at {n_blocks}"
        );

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 4_501));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
            spend = next_spend;
            input_pad = next_pad;
            let fee_sum = u128::from(fee);
            let with_bond = h == bond_h;
            let with_proof = h % proof_stride == 0;
            let with_liveness = h == liveness_h;
            let with_equivocation = h == n_blocks;
            let proofs = if with_proof { 1u128 } else { 0 };
            let equivocation_credit = if with_equivocation {
                u128::from(st.validators[EQUIVOCATION_IDX as usize].stake)
            } else {
                0
            };
            let ppb_bonus = if with_proof {
                let payout = seed_ppb_pending_and_expected_payout(&mut st, &commit_hash, h, ep);
                prop_assert!(payout > 0, "seeded PPB must cross integer payout boundary");
                payout
            } else {
                0
            };
            let storage_proofs = if with_proof {
                let prev = *st.tip_id().expect("tip");
                let proof = build_test_storage_proof(
                    &gen.built.commit,
                    &prev,
                    h,
                    &gen.payload,
                    &gen.built.tree,
                );
                let bonus =
                    storage_proof_coinbase_bonus(std::slice::from_ref(&proof), &st.storage, h, ep);
                prop_assert_eq!(bonus, ppb_bonus, "PPB bonus must match accrual payout");
                vec![proof]
            } else {
                Vec::new()
            };
            let coinbase = prop_coinbase_for_block(
                h,
                emission,
                fee_sum,
                &gen.fixture.payout,
                &st,
                &storage_proofs,
            );
            let txs = vec![coinbase, tx];
            let bond_ops = if with_bond {
                bond_seed = bond_seed.wrapping_add(1);
                vec![register_op(bond_seed)]
            } else {
                Vec::new()
            };
            let slashings = if with_equivocation {
                vec![equivocation_evidence(
                    h,
                    h,
                    EQUIVOCATION_IDX,
                    &gen.fixture.secrets[EQUIVOCATION_IDX as usize].bls.sk,
                )]
            } else {
                Vec::new()
            };
            if with_liveness {
                st.validator_stats[1].consecutive_missed =
                    gen.fixture.params.liveness_max_consecutive_missed - 1;
            }
            st = apply_validator_block_with_voters(
                &gen.fixture,
                &voters,
                &st,
                h,
                txs,
                storage_proofs,
                bond_ops,
                slashings,
            );
            let bond_credit = if with_bond { bond_stake } else { 0 };
            let liveness_credit = if with_liveness { liveness_forfeit } else { 0 };
            model = treasury_after_equivocation_combined_inflow_block_with_ppb_bonus(
                model,
                equivocation_credit,
                bond_credit,
                liveness_credit,
                fee_sum,
                proofs,
                ppb_bonus,
                emission,
            );
            prop_assert_eq!(
                st.treasury,
                model,
                "PPB treasury mismatch at height {} (fee {}, bond_h {}, liveness_h {}, stride {})",
                h,
                fee,
                bond_h,
                liveness_h,
                proof_stride
            );
            prop_assert!(st.treasury < u128::MAX);
            if with_liveness {
                prop_assert_eq!(st.validators[1].stake, 990_000);
            }
            if with_equivocation {
                prop_assert_eq!(
                    st.validators[EQUIVOCATION_IDX as usize].stake,
                    0,
                    "equivocation must zero slashed validator stake"
                );
            }
        }
    }

}

/// B5: consecutive miss blocks slash bonded stake into treasury (**M5.51**).
#[test]
fn prop_b5_miss_streak_slash_treasury_identity() {
    const AUDIT_SLOT_BASE: u32 = 10_000;
    for extra_misses in 0u32..=1u32 {
        let gen = genesis_with_b5_slash_storage();
        let mut st = gen.state;
        let mut model = 0u128;
        let mut bond = PROP_B5_OPERATOR_BOND;
        let slash_bps = PROP_ENDOWMENT_B5.operator_slash_bps;

        for i in 0..(PROP_ENDOWMENT_B5.operator_audit_missed_cap - 1) {
            let slot = AUDIT_SLOT_BASE + u32::from(i);
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model);
            assert_eq!(st.storage_operators[&gen.operator_id].bond_amount, bond);
            assert_eq!(
                st.storage_operator_stats[&gen.operator_id].consecutive_missed_audits,
                i + 1,
            );
        }

        let slash_slot =
            AUDIT_SLOT_BASE + u32::from(PROP_ENDOWMENT_B5.operator_audit_missed_cap - 1);
        st = apply_empty_at_audit_slot(&st, slash_slot);
        (model, bond) = treasury_after_b5_slash(model, bond, slash_bps);
        assert_eq!(st.treasury, model);
        assert_eq!(st.storage_operators[&gen.operator_id].bond_amount, bond);
        assert_eq!(
            st.storage_operator_stats[&gen.operator_id].consecutive_missed_audits,
            0
        );

        for j in 0..extra_misses {
            let slot = slash_slot + 1 + j;
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model);
            assert_eq!(st.storage_operators[&gen.operator_id].bond_amount, bond);
            assert_eq!(
                st.storage_operator_stats[&gen.operator_id].consecutive_missed_audits,
                u8::try_from(j + 1).expect("miss count"),
            );
        }
    }
}

/// B5: a valid operator proof resets the miss streak before slash (**M5.51**).
#[test]
fn prop_b5_proof_resets_miss_streak_before_slash() {
    const AUDIT_SLOT_BASE: u32 = 10_000;
    let gen = genesis_with_b5_slash_storage();
    let mut st = gen.state;
    st = apply_empty_at_audit_slot(&st, AUDIT_SLOT_BASE);
    assert_eq!(
        st.storage_operator_stats[&gen.operator_id].consecutive_missed_audits,
        1
    );
    st = apply_b5_operator_proof_at(&gen.built, &gen.payload, &st, AUDIT_SLOT_BASE + 1);
    assert_eq!(
        st.storage_operator_stats[&gen.operator_id].consecutive_missed_audits,
        0
    );
    assert_eq!(st.treasury, 0);
    assert_eq!(
        st.storage_operators[&gen.operator_id].bond_amount,
        PROP_B5_OPERATOR_BOND
    );
}

/// B5: alternating prove / miss preserves treasury and bond invariants (**M5.51**).
#[test]
fn prop_b5_alternating_prove_and_miss_treasury() {
    const AUDIT_SLOT_BASE: u32 = 10_000;
    for n_steps in 1u32..=5u32 {
        for prove_first in [false, true] {
            let gen = genesis_with_b5_slash_storage();
            let mut st = gen.state;
            let mut slot = AUDIT_SLOT_BASE;

            for step in 0..n_steps {
                let prove = if step == 0 {
                    prove_first
                } else {
                    step % 2 == 0
                };
                if prove {
                    st = apply_b5_operator_proof_at(&gen.built, &gen.payload, &st, slot);
                } else {
                    st = apply_empty_at_audit_slot(&st, slot);
                }
                let miss = st
                    .storage_operator_stats
                    .get(&gen.operator_id)
                    .map(|s| s.consecutive_missed_audits)
                    .unwrap_or(0);
                assert!(
                    miss < PROP_ENDOWMENT_B5.operator_audit_missed_cap,
                    "slash must reset miss streak"
                );
                slot = slot.saturating_add(1);
            }
        }
    }
}

/// A privacy spend and SPoRA proof in the same block must still reject atomically
/// when the storage-proof set is invalid.
#[test]
fn reject_duplicate_storage_proof_in_mixed_block_without_state_change() {
    let gen = genesis_privacy_storage_for_proptest();
    let st = gen.state;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);

    let h = next_height(&st);
    let (tx, _, _) = gen.spend.sign_self_transfer(&gen.input_pad, 25_000, h);
    let txs = vec![tx];
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
    let proofs = vec![proof.clone(), proof];

    let unsealed = build_unsealed_header(&st, &txs, &[], &[], &proofs, h, u64::from(h) * 1_000);
    let blk = seal_with_test_finality(&st, unsealed, txs, Vec::new(), Vec::new(), proofs);

    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProof { .. })),
                "expected DuplicateStorageProof, got {errors:?}"
            );
            assert_eq!(snap(&st), before_snap);
            assert_eq!(checkpoint_bytes(&st), before_bytes);
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate storage proof must reject"),
    }
}

/// Post-signing `storage_proof_root` tamper on a legacy mixed block (CLSAG +
/// SPoRA, no validators) must reject before state commit (**M5.5+**).
#[test]
fn reject_mixed_tampered_storage_proof_root_without_state_change() {
    let gen = genesis_privacy_storage_for_proptest();
    let PropPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) =
        legacy_mixed_block_material(&spend, &input_pad, &built, &payload, &st, h, 50_000);
    let unsealed = build_unsealed_header(
        &st,
        &txs,
        &[],
        &[],
        std::slice::from_ref(&proof),
        h,
        u64::from(h) * 1_000,
    );
    let mut blk = seal_with_test_finality(&st, unsealed, txs, Vec::new(), Vec::new(), vec![proof]);
    blk.header.storage_proof_root[0] ^= 0xff;
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::StorageProofRootMismatch),
        "legacy tampered storage_proof_root",
    );
}

/// Fee tamper after CLSAG signing on a legacy mixed block must reject without
/// spending inputs (**M5.5+**).
#[test]
fn reject_mixed_invalid_clsag_without_state_change() {
    let gen = genesis_privacy_storage_for_proptest();
    let PropPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (mut txs, proof) =
        legacy_mixed_block_material(&spend, &input_pad, &built, &payload, &st, h, 50_000);
    txs[0].fee = txs[0].fee.wrapping_add(1);
    let unsealed = build_unsealed_header(
        &st,
        &txs,
        &[],
        &[],
        std::slice::from_ref(&proof),
        h,
        u64::from(h) * 1_000,
    );
    let blk = seal_with_test_finality(&st, unsealed, txs, Vec::new(), Vec::new(), vec![proof]);
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::TxInvalid { .. }),
        "legacy invalid CLSAG",
    );
}

/// After a prefix of valid legacy mixed blocks, a rejected block at the
/// next height must not roll back or mutate the accepted prefix (**M5.5+**).
#[test]
fn reject_mixed_after_partial_chain_without_state_change() {
    let gen = genesis_privacy_storage_for_proptest();
    let PropPrivacyStorageGenesis {
        state: mut st,
        mut spend,
        mut input_pad,
        built,
        payload,
    } = gen;
    const PREFIX_LEN: u32 = 3;

    for h in 1..=PREFIX_LEN {
        let fee = 10_000u64 + u64::from(h) * 1_000;
        let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
        spend = next_spend;
        input_pad = next_pad;
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof(&built.commit, &prev, h, &payload, &built.tree);
        st = apply_mixed_clsag_fee_and_storage_proof(&st, h, vec![tx], &proof);
    }
    assert_eq!(st.height, Some(PREFIX_LEN));

    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let fee = 10_000u64 + u64::from(h) * 1_000;
    let (mut txs, proof) =
        legacy_mixed_block_material(&spend, &input_pad, &built, &payload, &st, h, fee);
    txs[0].fee = txs[0].fee.wrapping_add(1);
    let unsealed = build_unsealed_header(
        &st,
        &txs,
        &[],
        &[],
        std::slice::from_ref(&proof),
        h,
        u64::from(h) * 1_000,
    );
    let blk = seal_with_test_finality(&st, unsealed, txs, Vec::new(), Vec::new(), vec![proof]);
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::TxInvalid { .. }),
        "reject after partial legacy mixed chain",
    );
}

/// Validator finality + coinbase do not weaken the same atomicity invariant:
/// duplicate SPoRA proofs reject after verification but before state commit.
#[test]
fn reject_duplicate_storage_proof_in_validator_mixed_block_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let st = gen.state;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);

    let h = next_height(&st);
    let fee = 25_000u64;
    let (tx, _, _) = gen.spend.sign_self_transfer(&gen.input_pad, fee, h);
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
    let coinbase = prop_build_coinbase(
        h,
        &PROP_MIXED_EMISSION,
        u128::from(fee),
        &gen.fixture.payout,
        &st,
        h,
        std::slice::from_ref(&proof),
    );
    let txs = vec![coinbase, tx];
    let proofs = vec![proof.clone(), proof];

    let unsealed = build_unsealed_header(&st, &txs, &[], &[], &proofs, h, u64::from(h) * 1_000);
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height: h,
        slot: h,
        prev_hash: unsealed.prev_hash,
    };
    let producer = &gen.fixture.validators[0];
    let producer_secrets = &gen.fixture.secrets[0];
    let producer_proof = try_produce_slot(
        &ctx,
        producer_secrets,
        producer,
        gen.fixture.total_stake,
        gen.fixture.params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("produce")
    .expect("producer eligible");
    let votes: Vec<_> = gen
        .fixture
        .secrets
        .iter()
        .map(|secrets| {
            cast_vote(
                &header_hash,
                secrets,
                &ctx,
                &producer_proof,
                producer,
                gen.fixture.total_stake,
                gen.fixture.params.expected_proposers_per_slot,
            )
            .expect("vote")
        })
        .collect();
    let finality = FinalityProof {
        producer: producer_proof,
        finality: finalize(&header_hash, &votes, gen.fixture.validators.len()).expect("finalize"),
        signing_stake: gen.fixture.total_stake,
    };
    let blk = seal_block(
        unsealed,
        txs,
        Vec::new(),
        encode_finality_proof(&finality),
        Vec::new(),
        proofs,
    );

    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProof { .. })),
                "expected DuplicateStorageProof, got {errors:?}"
            );
            assert_eq!(snap(&st), before_snap);
            assert_eq!(checkpoint_bytes(&st), before_bytes);
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate storage proof must reject"),
    }
}

/// Post-signing `storage_proof_root` tamper on a validator mixed block must
/// reject before any UTXO/treasury/storage mutation (**M5.6+**).
#[test]
fn reject_validator_mixed_tampered_storage_proof_root_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let PropValidatorPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) = validator_mixed_block_material(
        &spend,
        &input_pad,
        &built,
        &payload,
        &fixture.payout,
        &st,
        h,
        50_000,
    );
    let mut blk = build_validator_mixed_block(
        &fixture,
        &st,
        h,
        txs,
        std::slice::from_ref(&proof),
        &[0, 1, 2],
    );
    blk.header.storage_proof_root[0] ^= 0xff;
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::StorageProofRootMismatch),
        "tampered storage_proof_root",
    );
}

/// Underpaid coinbase on a validator mixed block must reject atomically
/// (**M5.6+** — emission-only coinbase omits fee share + storage reward).
#[test]
fn reject_validator_mixed_invalid_coinbase_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let PropValidatorPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let fee = 50_000u64;
    let (mut txs, proof) = validator_mixed_block_material(
        &spend,
        &input_pad,
        &built,
        &payload,
        &fixture.payout,
        &st,
        h,
        fee,
    );
    let correct = expected_coinbase_amount(h, u128::from(fee), 1, &PROP_MIXED_EMISSION);
    let wrong = emission_at_height(u64::from(h), &PROP_MIXED_EMISSION);
    assert_ne!(wrong, correct);
    txs[0] = build_coinbase(u64::from(h), wrong, &fixture.payout).expect("coinbase");
    let blk = build_validator_mixed_block(
        &fixture,
        &st,
        h,
        txs,
        std::slice::from_ref(&proof),
        &[0, 1, 2],
    );
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::CoinbaseInvalid(_)),
        "invalid coinbase",
    );
}

/// Sub-quorum BLS finality must reject a validator mixed block without
/// touching caller state (**M5.6+**).
#[test]
fn reject_validator_mixed_subquorum_finality_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let PropValidatorPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) = validator_mixed_block_material(
        &spend,
        &input_pad,
        &built,
        &payload,
        &fixture.payout,
        &st,
        h,
        50_000,
    );
    // Two of three validators → 200/300 stake; quorum at 6667 bps requires 201.
    let blk =
        build_validator_mixed_block(&fixture, &st, h, txs, std::slice::from_ref(&proof), &[0, 1]);
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::FinalityInvalid(_)),
        "sub-quorum finality",
    );
}

/// Fee tamper after CLSAG signing must reject without spending inputs
/// (**M5.6+**).
#[test]
fn reject_validator_mixed_invalid_clsag_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let PropValidatorPrivacyStorageGenesis {
        state: st,
        spend,
        input_pad,
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (mut txs, proof) = validator_mixed_block_material(
        &spend,
        &input_pad,
        &built,
        &payload,
        &fixture.payout,
        &st,
        h,
        50_000,
    );
    txs[1].fee = txs[1].fee.wrapping_add(1);
    let blk = build_validator_mixed_block(
        &fixture,
        &st,
        h,
        txs,
        std::slice::from_ref(&proof),
        &[0, 1, 2],
    );
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::TxInvalid { .. }),
        "invalid CLSAG",
    );
}

/// After a prefix of valid validator mixed blocks, a rejected block at the
/// next height must not roll back or mutate the accepted prefix (**M5.6+**).
#[test]
fn reject_validator_mixed_after_partial_chain_without_state_change() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let PropValidatorPrivacyStorageGenesis {
        state: mut st,
        mut spend,
        mut input_pad,
        built,
        payload,
        fixture,
    } = gen;
    const PREFIX_LEN: u32 = 3;

    for h in 1..=PREFIX_LEN {
        let fee = 10_000u64 + u64::from(h) * 1_000;
        let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
        spend = next_spend;
        input_pad = next_pad;
        let fee_sum = u128::from(fee);
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof(&built.commit, &prev, h, &payload, &built.tree);
        let coinbase = prop_build_coinbase(
            h,
            &PROP_MIXED_EMISSION,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            std::slice::from_ref(&proof),
        );
        let txs = vec![coinbase, tx];
        st = apply_validator_mixed_clsag_fee_and_storage_proof(&fixture, &st, h, txs, &proof);
    }
    assert_eq!(st.height, Some(PREFIX_LEN));

    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let fee = 10_000u64 + u64::from(h) * 1_000;
    let (mut txs, proof) = validator_mixed_block_material(
        &spend,
        &input_pad,
        &built,
        &payload,
        &fixture.payout,
        &st,
        h,
        fee,
    );
    txs[1].fee = txs[1].fee.wrapping_add(1);
    let blk = build_validator_mixed_block(
        &fixture,
        &st,
        h,
        txs,
        std::slice::from_ref(&proof),
        &[0, 1, 2],
    );
    assert_reject_preserves_state(
        &st,
        &before_snap,
        &before_bytes,
        blk,
        |e| matches!(e, BlockError::TxInvalid { .. }),
        "reject after partial validator mixed chain",
    );
}

/// Forged bond register must reject without mutating state (plain `#[test]`; sixth
/// case in one `proptest!` block hits `macro_rules!` `$body:block` limits on CI).
#[test]
fn reject_forged_register_bond_op_without_state_change() {
    let st = genesis_with_bonding();
    let before = snap(&st);
    let h = next_height(&st);
    let op = forged_register_op();
    let unsealed = build_unsealed_header(&st, &[], std::slice::from_ref(&op), &[], &[], h, 100);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        vec![op],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })));
            assert_eq!(snap(&st), before);
        }
        ApplyOutcome::Ok { .. } => panic!("forged register must reject"),
    }
}

/// B3: reject duplicate operator proofs in one block (**M5.50**).
#[test]
fn reject_duplicate_b3_operator_proof_without_state_change() {
    let gen = genesis_with_b3_storage();
    let st = gen.state;
    let before = snap(&st);
    let h = next_height(&st);
    let prev = *st.tip_id().expect("tip");
    let proof = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
    );
    let proofs = vec![proof.clone(), proof];
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| { matches!(e, BlockError::DuplicateStorageProofOperator { .. }) }));
            assert_eq!(snap(&st), before);
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate B3 operator must reject"),
    }
}

/// B3: reject proofs exceeding commitment `replication` cap (**M5.50**).
#[test]
fn reject_b3_replication_cap_exceeded_without_state_change() {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let built = build_storage_commitment(&payload, 1_000, Some(256), 2, None).expect("commitment");
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: PROP_ENDOWMENT_B3,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    let before = snap(&st);
    let h = next_height(&st);
    let prev = *st.tip_id().expect("tip");
    let p0 =
        build_test_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree);
    let (v1, s1) = test_operator_payout_keys_alt();
    let p1 =
        build_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree, v1, s1)
            .expect("proof");
    let v2 = generator_g() * Scalar::from(7u64);
    let s2 = generator_g() * Scalar::from(11u64);
    let p2 =
        build_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree, v2, s2)
            .expect("proof");
    let proofs = vec![p0, p1, p2];
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| { matches!(e, BlockError::StorageProofReplicationExceeded { .. }) }));
            assert_eq!(snap(&st), before);
        }
        ApplyOutcome::Ok { .. } => panic!("replication cap exceeded must reject"),
    }
}

/// Reject duplicate SPoRA proofs in one block (plain `#[test]` — avoids `proptest!`
/// `$body:block` brace matching issues with `DuplicateStorageProof { .. }` patterns).
#[test]
fn reject_duplicate_storage_proof_without_state_change() {
    let gen = genesis_with_storage();
    let st = gen.state;
    let before = snap(&st);
    let h = next_height(&st);
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
    let proof_dup = proof.clone();
    let unsealed =
        build_unsealed_header(&st, &[], &[], &[], std::slice::from_ref(&proof), h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof, proof_dup],
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| { matches!(e, BlockError::DuplicateStorageProof { .. }) }));
            assert_eq!(snap(&st), before);
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate proof must reject"),
    }
}

/// B3: two operator proofs settle with frozen-baseline payout split; treasury
/// drain matches `storage_proof_reward × 2 + Σ operator bonuses`.
#[test]
fn b3_two_operator_proof_treasury_and_settlements_match_apply_block() {
    let gen = genesis_with_b3_storage();
    let st = &gen.state;
    let h = 8_000u32;
    let prev = *st.tip_id().expect("tip");
    let p0 = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
    );
    let (v1, s1) = test_operator_payout_keys_alt();
    let p1 = build_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
        v1,
        s1,
    )
    .expect("proof");
    let proofs = vec![p0, p1];
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, h, &PROP_ENDOWMENT_B3);
    assert_eq!(settlements.len(), 2, "expected two operator settlements");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);

    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            let storage_drain = u128::from(DEFAULT_EMISSION_PARAMS.storage_proof_reward)
                .saturating_mul(2)
                .saturating_add(bonus_total);
            let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
            assert_eq!(state.treasury, expected_treasury);
            let ch = storage_commitment_hash(&gen.built.commit);
            let entry = state.storage.get(&ch).expect("entry");
            assert_eq!(entry.last_proven_slot, u64::from(h));
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-63: two salted proofs compose producer + 2 operator coinbase legs.
#[test]
fn b63_b3_two_operator_coinbase_compose_matches_settlements() {
    let gen = genesis_with_b3_storage();
    let st = &gen.state;
    let h = 8_000u32;
    let prev = *st.tip_id().expect("tip");
    let p0 = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
    );
    let (v1, s1) = test_operator_payout_keys_alt();
    let p1 = build_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
        v1,
        s1,
    )
    .expect("proof");
    let proofs = vec![p0, p1];
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, h, &PROP_ENDOWMENT_B3);
    assert_eq!(settlements.len(), 2);

    let (pv, ps) = test_operator_payout_keys();
    let producer = PayoutAddress {
        view_pub: pv,
        spend_pub: ps,
    };
    let emission = &DEFAULT_EMISSION_PARAMS;
    let specs = block_coinbase_specs(u64::from(h), emission, 0, producer, &settlements);
    assert_eq!(specs.len(), 3, "producer + two operator coinbase outputs");
    assert_eq!(
        specs[0].amount,
        producer_portion_amount(u64::from(h), emission, 0)
    );
    assert_eq!(
        specs[1].amount,
        storage_payout_amount(emission.storage_proof_reward, settlements[0].1)
    );
    assert_eq!(
        specs[2].amount,
        storage_payout_amount(emission.storage_proof_reward, settlements[1].1)
    );
    assert_eq!(
        specs[1].payout.spend_pub,
        settlements[0].0.operator_spend_pub
    );
    assert_eq!(
        specs[2].payout.spend_pub,
        settlements[1].0.operator_spend_pub
    );

    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            let storage_drain = u128::from(emission.storage_proof_reward)
                .saturating_mul(2)
                .saturating_add(bonus_total);
            assert_eq!(
                state.treasury,
                st.treasury.saturating_sub(storage_drain.min(st.treasury))
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-63: 1-of-2 operators proves → one settlement/coinbase leg; absentee miss++.
#[test]
fn b63_b5_partial_operator_prove_settlement_and_miss_identity() {
    let gen = genesis_with_b5_two_operators();
    let st = &gen.state;
    let slot = 10_000u32;
    let scratch = build_unsealed_header(st, &[], &[], &[], &[], slot, 1_000);
    let p0 = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &scratch.prev_hash,
        slot,
        &gen.payload,
        &gen.built.tree,
    );
    let proofs = vec![p0];
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only the proving operator settles");

    let (pv, ps) = test_operator_payout_keys();
    let producer = PayoutAddress {
        view_pub: pv,
        spend_pub: ps,
    };
    let emission = &DEFAULT_EMISSION_PARAMS;
    let specs = block_coinbase_specs(u64::from(slot), emission, 0, producer, &settlements);
    assert_eq!(specs.len(), 2, "producer + one operator coinbase");
    assert_eq!(
        specs[1].amount,
        storage_payout_amount(emission.storage_proof_reward, settlements[0].1)
    );

    let bonus = settlements[0].1;
    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
            assert_eq!(
                state.treasury,
                st.treasury.saturating_sub(storage_drain.min(st.treasury))
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss streak resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee accrues audit miss"
            );
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// Build salted proofs for selected B5 operators (bit0=op0, bit1=op1).
fn b5_two_op_proofs_for_mask(
    built: &BuiltCommitment,
    payload: &[u8],
    prev: &[u8; 32],
    slot: u32,
    mask: u8,
) -> Vec<mfn_storage::StorageProof> {
    let mut proofs = Vec::new();
    if mask & 1 != 0 {
        proofs.push(build_test_storage_proof_operator_salted(
            &built.commit,
            prev,
            slot,
            payload,
            &built.tree,
        ));
    }
    if mask & 2 != 0 {
        let (v1, s1) = test_operator_payout_keys_alt();
        proofs.push(
            build_storage_proof_operator_salted(
                &built.commit,
                prev,
                slot,
                payload,
                &built.tree,
                v1,
                s1,
            )
            .expect("op1 proof"),
        );
    }
    proofs
}

/// B-66: op1-only prove is the symmetric twin of B-63 (op0-only).
#[test]
fn b66_b5_op1_only_prove_settlement_and_miss_identity() {
    let gen = genesis_with_b5_two_operators();
    let st = &gen.state;
    let slot = 10_000u32;
    let scratch = build_unsealed_header(st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    assert_eq!(proofs.len(), 1);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1);
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id1
    );
    let emission = &DEFAULT_EMISSION_PARAMS;
    let (pv, ps) = test_operator_payout_keys();
    let specs = block_coinbase_specs(
        u64::from(slot),
        emission,
        0,
        PayoutAddress {
            view_pub: pv,
            spend_pub: ps,
        },
        &settlements,
    );
    assert_eq!(specs.len(), 2);

    let bonus = settlements[0].1;
    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
            assert_eq!(
                state.treasury,
                st.treasury.saturating_sub(storage_drain.min(st.treasury))
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                1
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-66: alternating which-op masks; slots spaced beyond proof_reward_window
/// so B5 audit challenge stays active after each prove.
#[test]
fn b66_which_operator_proves_miss_and_settle_chain() {
    let masks: &[u8] = &[0b01, 0b10, 0b11, 0b01, 0b10, 0b11];
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let window = st.endowment_params.proof_reward_window_slots;
    let mut slot = 10_000u32;
    let mut miss0 = 0u8;
    let mut miss1 = 0u8;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let ch = storage_commitment_hash(&gen.built.commit);

    for &mask in masks {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot = slot.max(min_slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, mask);
        let expected_n = proofs.len();
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), expected_n);
        let (pv, ps) = test_operator_payout_keys();
        let specs = block_coinbase_specs(
            u64::from(slot),
            emission,
            0,
            PayoutAddress {
                view_pub: pv,
                spend_pub: ps,
            },
            &settlements,
        );
        assert_eq!(specs.len(), 1 + expected_n);

        let bonus_total: u128 = settlements.iter().map(|(_, b)| *b).sum();
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(expected_n as u128)
            .saturating_add(bonus_total);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

        if mask & 1 != 0 {
            miss0 = 0;
        } else {
            miss0 = miss0.saturating_add(1);
        }
        if mask & 2 != 0 {
            miss1 = 0;
        } else {
            miss1 = miss1.saturating_add(1);
        }

        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "mask={mask:#b}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, miss0,
                    "mask={mask:#b} op0 miss"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, miss1,
                    "mask={mask:#b} op1 miss"
                );
                assert_eq!(
                    state.storage.get(&ch).expect("entry").last_proven_slot,
                    u64::from(slot)
                );
                st = state;
            }
            ApplyOutcome::Err { errors, .. } => {
                panic!("mask={mask:#b} slot={slot}: {errors:?}")
            }
        }
        slot = slot.saturating_add(1);
    }
}

/// B-67 (early B-24c): absentee hits B5 slash cap while a peer settles in the
/// same block — treasury identity is slash credit then storage drain.
#[test]
fn b67_b5_multi_op_slash_while_peer_settles_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    // Drive both operators to cap-1 via empty audit blocks (challenge active
    // from genesis last_proven_slot=0 vs window=100).
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
        assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
        slot = slot.saturating_add(1);
    }

    // Peer (op0) proves; absentee (op1) crosses cap → slash in the same block.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only prover settles");
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id0
    );
    let (pv, ps) = test_operator_payout_keys();
    let specs = block_coinbase_specs(
        u64::from(slot),
        emission,
        0,
        PayoutAddress {
            view_pub: pv,
            spend_pub: ps,
        },
        &settlements,
    );
    assert_eq!(specs.len(), 2, "producer + prover coinbase");

    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut model = st.treasury;
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    let expected_treasury = model.saturating_sub(storage_drain.min(model));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "slash then storage drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial slash must keep operator registered"
            );
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-76 (early B-24d): both bonded operators cross the audit-miss cap on the
/// same empty block → dual slash credits treasury, resets both miss streaks,
/// and keeps both operators registered with reduced bonds.
#[test]
fn b76_b5_dual_operator_slash_on_empty_audit_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
        assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);

    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "dual slash must credit both forfeitures"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
        "slash resets op0 miss streak"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
        "slash resets op1 miss streak"
    );
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial dual slash must keep both operators registered"
    );
}

/// B-81 (early B-24e): 100% slash deregisters the absentee while the peer
/// settles in the same `apply_block` — complements B-67's partial keep-registered path.
#[test]
fn b81_b5_full_slash_deregister_while_peer_settles_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    st.endowment_params.operator_slash_bps = 10_000;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let bond0 = PROP_B5_OPERATOR_BOND;
    let bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1
        );
        slot = slot.saturating_add(1);
    }

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only prover settles");

    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut model = st.treasury;
    let (after_slash, bond1_after) = treasury_after_b5_slash(model, bond1, slash_bps);
    assert_eq!(bond1_after, 0, "100% slash zeros absentee bond");
    model = after_slash;
    let expected_treasury = model.saturating_sub(storage_drain.min(model));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    let state = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    assert_eq!(
        state.treasury, expected_treasury,
        "full slash credit then storage drain"
    );
    assert_eq!(
        state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
        "prover miss resets"
    );
    assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
    assert!(
        state.storage_operators.contains_key(&gen.id0),
        "prover must stay registered"
    );
    assert!(
        !state.storage_operators.contains_key(&gen.id1),
        "full slash must deregister absentee"
    );
    assert!(
        !state.storage_operator_stats.contains_key(&gen.id1),
        "full slash must drop absentee stats"
    );
    let ch = storage_commitment_hash(&gen.built.commit);
    assert_eq!(
        state.storage.get(&ch).expect("entry").last_proven_slot,
        u64::from(slot)
    );

    // Follow-on: deregistered op1 cannot settle a salted proof.
    let next = slot.saturating_add(1);
    let scratch2 = build_unsealed_header(&state, &[], &[], &[], &[], next, 1_000);
    let bad_proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch2.prev_hash, next, 0b10);
    let unsealed2 = build_unsealed_header(&state, &[], &[], &[], &bad_proofs, next, 1_000);
    let blk2 = seal_block(
        unsealed2,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        bad_proofs,
    );
    match apply_block(&state, &blk2) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofUnregisteredOperator { .. })),
                "expected StorageProofUnregisteredOperator, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("deregistered operator proof must reject"),
    }
}

/// B-83 (early B-24f): both operators settle at miss=cap-1 → prove resets prevent
/// slash; dual treasury drain; both miss streaks clear; bonds unchanged.
/// Complements B-67 (1-of-2 → slash+settle) with the honest multi-op recovery path.
#[test]
fn b83_b5_dual_settle_at_cap_minus_one_no_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let bond0 = PROP_B5_OPERATOR_BOND;
    let bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-settle empty {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1
        );
        slot = slot.saturating_add(1);
    }

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both operators settle");

    let (pv, ps) = test_operator_payout_keys();
    let specs = block_coinbase_specs(
        u64::from(slot),
        emission,
        0,
        PayoutAddress {
            view_pub: pv,
            spend_pub: ps,
        },
        &settlements,
    );
    assert_eq!(specs.len(), 3, "producer + two operator coinbase legs");

    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "dual settle drain with no slash credit"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "op0 miss resets on prove"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "op1 miss resets on prove"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0)
                    && state.storage_operators.contains_key(&gen.id1),
                "both operators stay registered"
            );
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-86 (early B-24g): dual partial slash credits treasury, then both operators
/// settle on the next audit slot — slash→treasury→SPoRA dual drain identity.
/// Complements B-76 (slash only) and B-83 (settle-only at cap-1).
#[test]
fn b86_b5_slash_funded_treasury_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both operators settle");

    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    assert!(
        storage_drain <= st.treasury || expected_treasury == 0,
        "model covers saturating drain"
    );

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-95 (early B-24h): dual partial slash credits treasury, then only one
/// operator settles on the next audit slot — asymmetric recovery after slash.
/// Complements B-86 (dual settle) and B-67 (slash+settle in the same block).
#[test]
fn b95_b5_slash_funded_treasury_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles");
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id0
    );

    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "slash-funded treasury then single SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee starts a new miss streak after slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-98 (early B-24i): dual partial slash credits treasury, then only op1
/// settles on the next audit slot — symmetric twin of B-95 (op0-only).
#[test]
fn b98_b5_slash_funded_treasury_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles");
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id1
    );

    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "slash-funded treasury then op1 SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee (op0) starts a new miss streak after slash reset"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover (op1) miss resets"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-99 (early B-24j): dual partial slash credits treasury, then neither
/// operator proves on the next audit slot -- closes the post-slash prove
/// matrix {00,01,10,11} with the empty both-miss corner.
#[test]
fn b99_b5_slash_funded_treasury_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    let treasury_after_slash = st.treasury;
    let ch = storage_commitment_hash(&gen.built.commit);
    let last_proven_before = st.storage.get(&ch).expect("entry").last_proven_slot;
    slot = slot.saturating_add(1);

    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_slash,
        "empty post-slash audit must not drain slash-funded treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 starts a new miss streak after slash reset"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 starts a new miss streak after slash reset"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "no prove -> last_proven_slot unchanged"
    );
}

/// B-101 (early B-24k): dual partial slash, then op0-only settle (B-95 path),
/// then keep op0 proving on window-spaced slots until op1 alone re-crosses the
/// miss cap and slashes while the peer settles again. Slots must sit beyond
/// `proof_reward_window` after each prove so B5 audit challenge stays active.
#[test]
fn b101_b5_slash_funded_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    slot = slot.saturating_add(1);

    // B-95 corner: only op0 settles; absentee starts miss=1 after slash reset.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    // Climb absentee miss to cap-1 on window-spaced op0-only settles.
    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    // Cap-crossing slot: op0 settles again; op1 alone re-slashes.
    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-101 twin (early B-24l): dual-slash funding, then op1-only settle climb to absentee
/// (op0) miss=`cap-1`, then op1 settles again while op0 alone re-slashes. Treasury =
/// re-slash credit then peer SPoRA drain; prover miss stays 0; re-slash resets absentee;
/// bonds track modeled partial slash; `last_proven_slot` advances; absentee stays registered.
#[test]
fn b102_b5_slash_funded_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, 0, "pre-slash empty {i}");
        slot = slot.saturating_add(1);
    }

    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "dual slash funds treasury");
    assert!(st.treasury > 0, "slash credit must be spendable");
    slot = slot.saturating_add(1);

    // B-98 corner: only op1 settles; absentee (op0) starts miss=1 after slash reset.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    // Climb absentee (op0) miss to cap-1 on window-spaced op1-only settles.
    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    // Cap-crossing slot: op1 settles again; op0 alone re-slashes.
    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-103 (early B-24m): after a first dual empty-audit slash (B-76), both operators
/// re-accumulate miss to `cap` and slash again. Treasury/bonds track two successive
/// modeled dual forfeitures; miss streaks reset after each slash; both stay registered.
#[test]
fn b103_b5_repeated_dual_slash_second_offense_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    // First offense (B-76 path).
    let treasury_before_first = st.treasury;
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, treasury_before_first,
            "pre-first-slash empty {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1
        );
        slot = slot.saturating_add(1);
    }
    let mut model = st.treasury;
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "first dual slash credits both forfeitures"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    slot = slot.saturating_add(1);

    // Second offense: re-climb from reset streaks, then dual slash again.
    let treasury_after_first = st.treasury;
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, treasury_after_first,
            "pre-second-slash empty must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "second-offense op0 miss {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "second-offense op1 miss {i}"
        );
        assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
        assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "second dual slash must credit both forfeitures on reduced bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
        "second slash resets op0"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
        "second slash resets op1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial dual slash must keep both operators registered after second offense"
    );
    assert!(
        st.treasury > treasury_after_first,
        "second offense must grow treasury"
    );
}

/// B-104 (early B-24n): two successive dual empty-audit slashes (B-103), then both
/// operators settle on the next audit slot — second-offense slash credits fund dual
/// SPoRA drain. Complements B-103 (slash-only repeat) and B-86 (first-slash→settle).
#[test]
fn b104_b5_second_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(
                st.treasury, model,
                "pre-slash climb offense {offense} empty {i}"
            );
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "dual slash offense {offense} credits both forfeitures"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
            "slash resets op0 offense {offense}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
            "slash resets op1 offense {offense}"
        );
        assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
        assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
        slot = slot.saturating_add(1);
    }
    assert!(
        st.treasury > 0,
        "second-offense slash credit must be spendable"
    );

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(
        settlements.len(),
        2,
        "both operators settle after second slash"
    );

    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "second-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0)
                    && state.storage_operators.contains_key(&gen.id1),
                "both operators remain registered"
            );
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-105 (early B-24o): two successive dual empty-audit slashes (B-103), then only
/// op0 settles (`mask=0b01`) — second-offense slash credits fund a single SPoRA drain;
/// absentee restarts miss=1. Twin settle corner of B-104. Complements B-95 (first-slash
/// asymmetric) and B-104 (second-slash dual settle).
#[test]
fn b105_b5_second_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(
                st.treasury, model,
                "pre-slash climb offense {offense} empty {i}"
            );
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "dual slash offense {offense} credits both forfeitures"
        );
        slot = slot.saturating_add(1);
    }
    assert!(
        st.treasury > 0,
        "second-offense slash credit must be spendable"
    );

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after second slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "second-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee starts miss=1 after slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-106 (early B-24p): B-105 twin — two successive dual empty-audit slashes, then only
/// op1 settles (`mask=0b10`). Second-offense slash credits fund a single SPoRA drain;
/// absentee (op0) restarts miss=1. Completes the second-offense asymmetric settle pair.
#[test]
fn b106_b5_second_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(
                st.treasury, model,
                "pre-slash climb offense {offense} empty {i}"
            );
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "dual slash offense {offense} credits both forfeitures"
        );
        slot = slot.saturating_add(1);
    }
    assert!(
        st.treasury > 0,
        "second-offense slash credit must be spendable"
    );

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after second slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "second-offense slash-funded treasury then op1 asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee starts miss=1 after slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            let ch = storage_commitment_hash(&gen.built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-107 (early B-24q): two successive dual empty-audit slashes (B-103), then an empty
/// audit slot (`mask=0b00`). Treasury stays at post-second-slash credit (no SPoRA drain);
/// both operators restart miss streaks at 1; bonds unchanged. Closes the second-offense
/// prove matrix {00,01,10,11} with B-104/B-105/B-106.
#[test]
fn b107_b5_second_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(
                st.treasury, model,
                "pre-slash climb offense {offense} empty {i}"
            );
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "dual slash offense {offense} credits both forfeitures"
        );
        slot = slot.saturating_add(1);
    }
    assert!(
        st.treasury > 0,
        "second-offense slash credit must be spendable"
    );
    let treasury_after_second = st.treasury;
    let ch = storage_commitment_hash(&gen.built.commit);
    let last_proven_before = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);

    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_second,
        "empty after second slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-108 (early B-24r): two dual empty-audit slashes, then dual settle (B-104 path) which
/// resets miss streaks and drains treasury, then (past proof-reward window) empty-climb to a
/// **third** dual slash on reduced bonds. Pins settle-reset → re-accumulate → third-offense
/// forfeiture identity. Complements B-103 (slash-only repeat) and B-104 (stops at settle).
#[test]
fn b108_b5_settle_reset_then_third_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
}

/// B-117 (early B-24aa): B-108 arc through third dual slash + dual settle reset, then
/// advance past the proof-reward window and climb to a **fourth** dual empty-audit slash.
/// Proves settle-reset re-arm works across a second post-settle offense cycle (third→fourth).
/// Complements B-108 (stops at third slash) and B-109 (third-slash→dual settle drain).
#[test]
fn b117_b5_settle_reset_then_fourth_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");
}

/// B-126 (early B-24ah): B-117 arc through fourth dual slash + dual settle reset, then
/// advance past the proof-reward window and climb to a **fifth** dual empty-audit slash.
/// Proves settle-reset re-arm across a third post-settle offense cycle (fourth->fifth).
/// Complements B-117 (stops at fourth slash) and B-118 (fourth-slash->dual settle drain).
#[test]
fn b126_b5_settle_reset_then_fifth_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
}

/// B-128 (early B-24ai): B-126 arc through fifth dual slash, then both operators settle
/// (mask=0b11) — fifth-offense slash credits fund dual SPoRA drain. Complements B-126
/// (stops at fifth slash) and B-118 (fourth-slash→dual settle). Note: B-127 is lane1 ops id.
#[test]
fn b128_b5_fifth_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after fifth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fifth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-130 (early B-24aj): B-126 arc through fifth dual slash, then only op0 settles
/// (`mask=0b01`) — fifth-offense slash credits fund a single SPoRA drain; prover miss=0;
/// absentee miss=1. Twin settle corner of B-128. Complements B-119 (fourth-slash asymmetric).
/// Note: B-129 is lane1 tip-ckpt id — skipped.
#[test]
fn b130_b5_fifth_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains fifth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after fifth slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fifth-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-131 (early B-24ak): B-130 twin — B-126 arc through fifth dual slash, then only op1
/// settles (`mask=0b10`) — fifth-offense slash credits fund a single SPoRA drain; absentee
/// (op0) restarts miss=1. Completes fifth-offense asymmetric settle pair (B-130/B-131).
#[test]
fn b131_b5_fifth_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op1 drains fifth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after fifth slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fifth-offense slash-funded treasury then op1 asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-132 (early B-24al): B-126 arc through fifth dual slash, then an empty audit slot
/// (`mask=0b00`). Treasury stays at post-fifth-slash credit; both operators restart miss
/// streaks at 1; bonds unchanged; `last_proven_slot` unchanged. Closes the fifth-offense
/// prove matrix {00,01,10,11} with B-128/B-130/B-131. Complements B-121 (fourth-offense empty).
#[test]
fn b132_b5_fifth_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Empty after fifth slash: no drain; both miss restart at 1.
    let treasury_after_fifth = st.treasury;
    let last_proven_before = st.storage.get(&ch).expect("entry").last_proven_slot;
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_fifth,
        "empty after fifth slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-142 (early B-24am): B-126 arc through fifth dual slash, then B-101 path — op0-only settle,
/// window-spaced climb of absentee miss to `cap-1`, then op0 settles again while op1 alone
/// re-slashes. Elevates B-122/B-115 re-slash to fifth-offense funding. Complements B-132
/// (fifth-slash empty) and B-130 (stops at asymmetric settle).
#[test]
fn b142_b5_fifth_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");

    // B-101 path on fifth-offense funding: op0-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-143 (early B-24an): B-142 twin — B-126 arc through fifth dual slash, then B-102 path:
/// op1-only settle, window-spaced climb of absentee (op0) miss to `cap-1`, then op1 settles
/// again while op0 alone re-slashes. Completes fifth-offense asymmetric re-slash pair
/// (B-142/B-143). Elevates B-124.
#[test]
fn b143_b5_fifth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");

    // B-102 path on fifth-offense funding: op1-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-147 (early B-24ao): B-126 arc through fifth dual slash + dual settle reset, then
/// advance past the proof-reward window and climb to a **sixth** dual empty-audit slash.
/// Proves settle-reset re-arm across a fourth post-settle offense cycle (fifth->sixth).
/// Complements B-126 (stops at fifth slash) and B-128 (fifth-slash->dual settle drain).
#[test]
fn b147_b5_settle_reset_then_sixth_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
}

/// B-148 (early B-24ap): B-147 arc through sixth dual slash, then both operators settle
/// (`mask=0b11`) — sixth-offense slash credits fund dual SPoRA drain. Elevates B-128
/// (fifth-slash→dual settle). Complements B-147 (stops at sixth slash).
#[test]
fn b148_b5_sixth_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-149 (early B-24aq): B-147 arc through sixth dual slash, then op0-only settle
/// (`mask=0b01`) — sixth-offense slash credits fund asymmetric SPoRA drain. Elevates B-130.
/// Complements B-148 (sixth-slash→dual settle).
#[test]
fn b149_b5_sixth_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after sixth slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-150 (early B-24ar): B-147 arc through sixth dual slash, then op1-only settle
/// (`mask=0b10`) — sixth-offense slash credits fund asymmetric SPoRA drain. Elevates B-131.
/// Complements B-149 (sixth-slash→dual settle).
#[test]
fn b150_b5_sixth_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after sixth slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-151 (early B-24as): B-147 arc through sixth dual slash, then empty both-miss
/// (no settle / no drain) — closes sixth-offense prove matrix {00,01,10,11} with B-148/B-149/B-150.
/// Elevates B-132. Does **not** close full **B-24**.
#[test]
fn b151_b5_sixth_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Empty after sixth slash: no drain; both miss restart at 1.
    let treasury_after_sixth = st.treasury;
    let last_proven_before = st.storage.get(&ch).expect("entry").last_proven_slot;
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_sixth,
        "empty after sixth slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-152 (early B-24at): B-147 arc through sixth dual slash, then B-101 path — op0-only settle,
/// window-spaced climb of absentee miss to `cap-1`, then op0 settles again while op1 alone
/// re-slashes. Elevates B-142/B-122 re-slash to sixth-offense funding. Complements B-151
/// (sixth-slash empty) and B-149 (stops at asymmetric settle).
#[test]
fn b152_b5_sixth_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");

    // B-101 path on sixth-offense funding: op0-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-153 (early B-24au): B-147 arc through sixth dual slash, then B-101 path — op1-only settle,
/// window-spaced climb of absentee miss to `cap-1`, then op1 settles again while op1 alone
/// re-slashes. Elevates B-142/B-122 re-slash to sixth-offense funding. B-152 twin; complements B-151
/// (sixth-slash empty) and B-149 (stops at asymmetric settle).
#[test]
fn b153_b5_sixth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");

    // B-101 path on sixth-offense funding: op1-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-154 (early B-24av): B-148 arc through sixth dual slash + dual settle reset, then
/// advance past the proof-reward window and climb to a **seventh** dual empty-audit slash.
/// Elevates B-147 settle-reset re-arm (fifth→sixth) to sixth→seventh. Does **not** close full **B-24**.
#[test]
fn b154_b5_settle_reset_then_seventh_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");
}

/// B-155 (early B-24aw): B-154 arc through seventh dual slash, then both operators settle
/// (`mask=0b11`) — seventh-offense slash credits fund dual SPoRA drain. Elevates B-148.
/// Complements B-154 (stops at seventh slash).
#[test]
fn b155_b5_seventh_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after seventh slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-156 (early B-24ax): B-154 arc through seventh dual slash, then only op0 settles
/// (`mask=0b01`) — seventh-offense slash credits fund a single SPoRA drain; prover miss=0;
/// absentee miss=1. Twin settle corner of B-155. Elevates B-149. Complements B-154
/// (stops at seventh slash).
#[test]
fn b156_b5_seventh_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after seventh slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-157 (early B-24ay): B-154 arc through seventh dual slash, then only op1 settles
/// (`mask=0b10`) — seventh-offense slash credits fund a single SPoRA drain; prover miss=0;
/// absentee miss=1. B-156 twin. Completes seventh-offense asymmetric settle pair. Elevates B-150.
#[test]
fn b157_b5_seventh_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Asymmetric settle: only op1 drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after seventh slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-158 (early B-24az): B-154 arc through seventh dual slash, then empty both-miss
/// (no settle / no drain) — closes seventh-offense prove matrix {00,01,10,11} with B-155/B-156/B-157.
/// Elevates B-151. Does **not** close full **B-24**.
#[test]
fn b158_b5_seventh_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Empty after seventh slash: no drain; both miss restart at 1.
    let treasury_after_seventh = st.treasury;
    let last_proven_before = st.storage.get(&ch).expect("entry").last_proven_slot;
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_seventh,
        "empty after seventh slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-159 (early B-24ba): B-154 arc through seventh dual slash, then B-101 path — op0-only
/// settle, window-spaced climb of absentee miss to `cap-1`, then op0 settles again while op1
/// alone re-slashes. Elevates B-152 re-slash to seventh-offense funding. Complements B-158
/// (seventh empty) and B-156 (stops at asymmetric settle).
#[test]
fn b159_b5_seventh_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after seventh slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    slot = slot.saturating_add(1);

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-160 (early B-24bb): B-154 arc through seventh dual slash, then B-101 path — op0-only
/// settle, window-spaced climb of absentee miss to `cap-1`, then op1 settles again while op1
/// alone re-slashes. Elevates B-152 re-slash to seventh-offense funding. B-159 twin; complements B-158
/// (seventh empty) and B-156 (stops at asymmetric settle).
#[test]
fn b160_b5_seventh_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");

    slot = slot.saturating_add(1);

    // Asymmetric settle: only op1 drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after seventh slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee miss restarts at 1"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    slot = slot.saturating_add(1);

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-162 (early B-24bc): B-154 arc through seventh dual slash + dual settle reset, then
/// advance past the proof-reward window and climb to an **eighth** dual empty-audit slash.
/// Elevates B-154 settle-reset re-arm (sixth->seventh) to seventh->eighth. Does **not** close full **B-24**.
#[test]
fn b162_b5_settle_reset_then_eighth_dual_slash_treasury_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");

    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fourth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fourth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fourth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 5: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fifth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after third settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after third settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fifth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fifth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fifth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fifth-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after fifth slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-fifth settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-fifth settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 6: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-sixth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fourth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fourth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "sixth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial sixth slash must keep both registered"
    );
    assert!(st.treasury > 0, "sixth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains sixth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after sixth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "sixth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    // Offense 7: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-seventh-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after fifth settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after fifth settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "seventh dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial seventh slash must keep both registered"
    );
    assert!(st.treasury > 0, "seventh-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains seventh-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after seventh slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "seventh-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }

    slot = advance_past_window(&st, slot);

    slot = advance_past_window(&st, slot);

    // Offense 8: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-eighth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after seventh settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after seventh settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "eighth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial eighth slash must keep both registered"
    );
    assert!(st.treasury > 0, "eighth-offense credit spendable");
}

/// B-118 (early B-24ab): B-117 arc through fourth dual slash, then both operators settle
/// (`mask=0b11`) — fourth-offense slash credits fund dual SPoRA drain. Complements B-117
/// (stops at fourth slash) and B-109 (third-slash→dual settle).
#[test]
fn b118_b5_fourth_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Dual settle drains fourth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after fourth slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fourth-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-119 (early B-24ac): B-117 arc through fourth dual slash, then only op0
/// settles (`mask=0b01`). Fourth-offense slash credits fund a single SPoRA
/// drain; absentee restarts miss=1. Complements B-118 (dual settle) and B-110
/// (third-slash asymmetric).
#[test]
fn b119_b5_fourth_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Offense 3 after settle-reset (B-108 path).
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    slot = slot.saturating_add(1);

    // Dual settle between offense 3 and 4 (B-117 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected, "settle between 3rd and 4th");
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Offense 4 after second settle-reset.
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-fourth-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op0 drains fourth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after fourth slash");
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id0
    );
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fourth-offense slash-funded treasury then single SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee starts a new miss streak after fourth-slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-120 (early B-24ad): B-119 twin — B-117 arc through fourth dual slash, then only op1
/// settles (`mask=0b10`) — fourth-offense slash credits fund a single SPoRA drain; absentee
/// (op0) restarts miss=1. Completes the fourth-offense asymmetric settle pair (B-119/B-120).
#[test]
fn b120_b5_fourth_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Offense 3 after settle-reset (B-108 path).
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    slot = slot.saturating_add(1);

    // Dual settle between offense 3 and 4 (B-117 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected, "settle between 3rd and 4th");
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Offense 4 after second settle-reset.
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-fourth-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    slot = slot.saturating_add(1);

    // Asymmetric settle: only op1 drains fourth-offense slash credit.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after fourth slash");
    assert_eq!(
        operator_identity_from_payout(
            &settlements[0].0.operator_view_pub,
            &settlements[0].0.operator_spend_pub
        ),
        gen.id1
    );
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "fourth-offense slash-funded treasury then op1 asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee starts a new miss streak after fourth-slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-121 (early B-24ae): B-117 arc through fourth dual slash, then an empty
/// audit slot (`mask=0b00`). Treasury stays at post-fourth-slash credit; both
/// operators restart miss streaks at 1; bonds unchanged; `last_proven_slot`
/// unchanged. Closes the fourth-offense prove matrix {00,01,10,11} with
/// B-118/B-119/B-120. Complements B-112 (third-offense empty).
#[test]
fn b121_b5_fourth_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Offense 3 after settle-reset (B-108 path).
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    slot = slot.saturating_add(1);

    // Dual settle between offense 3 and 4 (B-117 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected, "settle between 3rd and 4th");
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Offense 4 after second settle-reset.
    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-fourth-slash climb {i}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    let treasury_after_fourth = st.treasury;
    let last_proven_before = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
    slot = slot.saturating_add(1);

    // Empty after fourth slash: no drain; both miss restart at 1.
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_fourth,
        "empty after fourth slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-122 (early B-24af): B-117 arc through fourth dual slash, then B-101 path — op0-only settle,
/// window-spaced climb of absentee miss to `cap-1`, then op0 settles again while op1 alone
/// re-slashes. Elevates B-113/B-115 re-slash to fourth-offense funding. Complements B-121
/// (fourth-slash empty) and B-119 (stops at asymmetric settle).
#[test]
fn b122_b5_fourth_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    slot = slot.saturating_add(1);

    // B-101 path on fourth-offense funding: op0-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-124 (early B-24ag): B-122 twin — B-117 arc through fourth dual slash, then B-102 path:
/// op1-only settle, window-spaced climb of absentee (op0) miss to `cap-1`, then op1 settles
/// again while op0 alone re-slashes. Completes fourth-offense asymmetric re-slash pair
/// (B-122/B-124). Note: B-123 is lane1 soak id — skipped.
#[test]
fn b124_b5_fourth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    // Offenses 1 and 2: dual empty-audit slash.
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            0
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            0
        );
        slot = slot.saturating_add(1);
    }

    // Dual settle drains second-offense slash credit and keeps miss at 0.
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after second slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    st = match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, expected_after_settle, "dual settle drain");
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            state
        }
        ApplyOutcome::Err { errors, .. } => panic!("settle accept, got {errors:?}"),
    };
    model = st.treasury;
    slot = slot.saturating_add(1);

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 3: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-third-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "third dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial third slash must keep both registered"
    );
    slot = slot.saturating_add(1);

    // Dual settle drains third-offense credit and resets miss streaks again.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 2, "both settle after third slash");
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected_after_settle = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(
                    state.treasury, expected_after_settle,
                    "post-third settle drain"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("post-third settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    // Past proof-reward window: empties again count as missed audits.
    slot = advance_past_window(&st, slot);

    // Offense 4: re-climb from settle-reset miss=0, then dual slash again.
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(
            st.treasury, model,
            "pre-fourth-slash climb must not change treasury {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
            i + 1,
            "op0 miss after second settle-reset {i}"
        );
        assert_eq!(
            st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
            i + 1,
            "op1 miss after second settle-reset {i}"
        );
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, model,
        "fourth dual slash credits both forfeitures on post-settle bonds"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        0
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        0
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert!(
        st.storage_operators.contains_key(&gen.id0) && st.storage_operators.contains_key(&gen.id1),
        "partial fourth slash must keep both registered"
    );
    assert!(st.treasury > 0, "fourth-offense credit spendable");
    slot = slot.saturating_add(1);

    // B-102 path on fourth-offense funding: op1-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-109 (early B-24s): B-108 arc through third dual slash, then both operators settle
/// (`mask=0b11`) — third-offense slash credits fund dual SPoRA drain. Complements B-108
/// (stops at third slash) and B-104 (second-slash→settle).
#[test]
fn b109_b5_third_dual_slash_then_dual_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    // Settle between offense 2 and 3 (B-108 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 2, "both settle after third slash");
    let bonus_total: u128 = settlements
        .iter()
        .map(|(_, b)| *b)
        .fold(0, u128::saturating_add);
    let storage_drain = u128::from(emission.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(bonus_total);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "third-offense slash-funded treasury then dual SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                0
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                0
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-110 (early B-24t): B-109 twin corner — B-108 arc through third dual slash, then only
/// op0 settles (`mask=0b01`). Third-offense slash credits fund a single SPoRA drain;
/// absentee restarts miss=1. Complements B-109 (dual settle) and B-105 (second-slash asymmetric).
#[test]
fn b110_b5_third_dual_slash_then_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    // Settle between offense 2 and 3 (B-108 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles after third slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "third-offense slash-funded treasury then asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
                "absentee starts miss=1 after slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-111 (early B-24u): B-110 twin — B-108 arc through third dual slash, then only op1
/// settles (`mask=0b10`). Third-offense slash credits fund a single SPoRA drain; absentee
/// (op0) restarts miss=1. Completes the third-offense asymmetric settle pair.
#[test]
fn b111_b5_third_dual_slash_then_op1_asymmetric_settle_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    slot = slot.saturating_add(1);

    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles after third slash");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "third-offense slash-funded treasury then op1 asymmetric SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
                "absentee starts miss=1 after slash reset"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-112 (early B-24v): B-108 arc through third dual slash, then an empty audit slot.
/// Treasury stays at post-third-slash credit (no SPoRA drain); both operators restart miss
/// streaks at 1; bonds unchanged; `last_proven_slot` unchanged. Closes the third-offense
/// prove matrix {00,01,10,11} with B-109/B-110/B-111. Complements B-107 (second-offense empty).
#[test]
fn b112_b5_third_dual_slash_then_empty_both_miss_no_drain_identity() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    // Settle between offense 2 and 3 (B-108 mid-arc).
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    let treasury_after_third = st.treasury;
    let last_proven_before = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
    slot = slot.saturating_add(1);

    // Empty after third slash: no drain; both miss restart at 1.
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(
        st.treasury, treasury_after_third,
        "empty after third slash must not drain treasury"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits, 1,
        "op0 miss restarts at 1"
    );
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits, 1,
        "op1 miss restarts at 1"
    );
    assert_eq!(st.storage_operators[&gen.id0].bond_amount, bond0);
    assert_eq!(st.storage_operators[&gen.id1].bond_amount, bond1);
    assert_eq!(
        st.storage.get(&ch).expect("entry").last_proven_slot,
        last_proven_before,
        "empty audit must not advance last_proven_slot"
    );
}

/// B-113 (early B-24w): B-108 arc through a third dual slash, then B-101 path — op0-only
/// settle, window-spaced climb of absentee miss to `cap-1`, then op0 settles again while
/// op1 alone re-slashes. Pins third-offense funding → asymmetric settle → absentee re-slash
/// treasury identity. Complements B-101 (first-slash funding) and B-110 (stops at asymmetric).
#[test]
fn b113_b5_third_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    // Settle between offense 2 and 3.
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    slot = slot.saturating_add(1);

    // B-101 path on third-offense funding: op0-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-114 (early B-24x): B-113 twin — B-108 arc through a third dual slash, then B-102 path:
/// op1-only settle, window-spaced climb of absentee (op0) miss to `cap-1`, then op1 settles
/// again while op0 alone re-slashes. Completes the third-offense asymmetric re-slash pair.
#[test]
fn b114_b5_third_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }

    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b11);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        let bonus_total: u128 = settlements
            .iter()
            .map(|(_, b)| *b)
            .fold(0, u128::saturating_add);
        let storage_drain = u128::from(emission.storage_proof_reward)
            .saturating_mul(2)
            .saturating_add(bonus_total);
        let expected = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("mid settle, got {errors:?}"),
        };
        model = st.treasury;
        slot = slot.saturating_add(1);
    }

    slot = advance_past_window(&st, slot);
    for i in 0..(cap - 1) {
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "pre-third-slash {i}");
        slot = slot.saturating_add(1);
    }
    (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
    (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
    st = apply_empty_at_audit_slot(&st, slot);
    assert_eq!(st.treasury, model, "third dual slash");
    assert!(st.treasury > 0, "third-offense credit spendable");
    slot = slot.saturating_add(1);

    // B-102 corner: only op1 settles; absentee (op0) starts miss=1.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-115 (early B-24y): two successive dual empty-audit slashes (B-103), then B-101 path —
/// op0-only settle, window-spaced climb of absentee miss to `cap-1`, then op0 settles again
/// while op1 alone re-slashes. Fills the second-offense gap between B-101 (first) and B-113
/// (third). Complements B-104 (second-slash→dual settle) and B-105 (stops at asymmetric).
#[test]
fn b115_b5_second_offense_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }
    assert!(st.treasury > 0, "second-offense credit spendable");

    // B-101 path on second-offense funding: op0-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op0 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op0-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id1].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b01);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op0 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond1) = treasury_after_b5_slash(expected_treasury, bond1, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id1),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-116 (early B-24z): B-115 twin — two successive dual empty-audit slashes (B-103), then
/// B-102 path: op1-only settle, window-spaced climb of absentee (op0) miss to `cap-1`, then
/// op1 settles again while op0 alone re-slashes. Completes second-offense asymmetric re-slash pair
/// (B-115/B-116) between first-offense (B-101/B-102) and third (B-113/B-114).
#[test]
fn b116_b5_second_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles() {
    let gen = genesis_with_b5_two_operators();
    let mut st = gen.state;
    let cap = st.endowment_params.operator_audit_missed_cap;
    let slash_bps = st.endowment_params.operator_slash_bps;
    let window = st.endowment_params.proof_reward_window_slots;
    let emission = &DEFAULT_EMISSION_PARAMS;
    let mut slot = 10_000u32;
    let mut bond0 = PROP_B5_OPERATOR_BOND;
    let mut bond1 = PROP_B5_OPERATOR_BOND.saturating_mul(2);
    let ch = storage_commitment_hash(&gen.built.commit);

    let advance_past_window = |st: &ChainState, slot: u32| -> u32 {
        let last = st.storage.get(&ch).map(|e| e.last_proven_slot).unwrap_or(0);
        let min_slot =
            u32::try_from(last.saturating_add(window).saturating_add(1)).unwrap_or(u32::MAX);
        slot.max(min_slot)
    };

    let mut model = st.treasury;
    for offense in 0..2u32 {
        for i in 0..(cap - 1) {
            st = apply_empty_at_audit_slot(&st, slot);
            assert_eq!(st.treasury, model, "pre-slash climb offense {offense} {i}");
            slot = slot.saturating_add(1);
        }
        (model, bond0) = treasury_after_b5_slash(model, bond0, slash_bps);
        (model, bond1) = treasury_after_b5_slash(model, bond1, slash_bps);
        st = apply_empty_at_audit_slot(&st, slot);
        assert_eq!(st.treasury, model, "dual slash offense {offense}");
        slot = slot.saturating_add(1);
    }
    assert!(st.treasury > 0, "second-offense credit spendable");

    // B-102 path on second-offense funding: op1-only settle.
    slot = advance_past_window(&st, slot);
    {
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1, "only op1 settles");
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "asymmetric settle drain");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits,
                    0
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    1
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }

    assert!(cap >= 2, "cap must allow a climb");
    for i in 0..(cap.saturating_sub(2)) {
        slot = advance_past_window(&st, slot);
        let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
        let proofs =
            b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
        let settlements =
            storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
        assert_eq!(settlements.len(), 1);
        let bonus = settlements[0].1;
        let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
        let expected_treasury = st.treasury.saturating_sub(storage_drain.min(st.treasury));
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            proofs,
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, expected_treasury, "climb settle {i}");
                assert_eq!(
                    state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                    "prover stays reset during climb {i}"
                );
                assert_eq!(
                    state.storage_operator_stats[&gen.id0].consecutive_missed_audits,
                    2 + i,
                    "absentee miss climbs during window-spaced op1-only settle {i}"
                );
                assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
                state
            }
            ApplyOutcome::Err { errors, .. } => panic!("climb accept, got {errors:?}"),
        };
        slot = slot.saturating_add(1);
    }
    assert_eq!(
        st.storage_operator_stats[&gen.id0].consecutive_missed_audits,
        cap - 1,
        "absentee poised at cap-1 before re-slash"
    );

    slot = advance_past_window(&st, slot);
    let scratch = build_unsealed_header(&st, &[], &[], &[], &[], slot, 1_000);
    let proofs =
        b5_two_op_proofs_for_mask(&gen.built, &gen.payload, &scratch.prev_hash, slot, 0b10);
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, slot, &st.endowment_params);
    assert_eq!(settlements.len(), 1, "only op1 settles on re-slash slot");
    let bonus = settlements[0].1;
    let storage_drain = u128::from(emission.storage_proof_reward).saturating_add(bonus);
    let mut expected_treasury = st.treasury;
    (expected_treasury, bond0) = treasury_after_b5_slash(expected_treasury, bond0, slash_bps);
    expected_treasury = expected_treasury.saturating_sub(storage_drain.min(expected_treasury));

    let unsealed = build_unsealed_header(&st, &[], &[], &[], &proofs, slot, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(
                state.treasury, expected_treasury,
                "absentee re-slash credit then peer SPoRA drain"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id1].consecutive_missed_audits, 0,
                "prover miss resets"
            );
            assert_eq!(
                state.storage_operator_stats[&gen.id0].consecutive_missed_audits, 0,
                "re-slash resets absentee miss streak"
            );
            assert_eq!(state.storage_operators[&gen.id0].bond_amount, bond0);
            assert_eq!(state.storage_operators[&gen.id1].bond_amount, bond1);
            assert!(
                state.storage_operators.contains_key(&gen.id0),
                "partial re-slash must keep absentee registered"
            );
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(slot)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// B-64: settlements soft-skip unknown commit; apply hard-rejects.
#[test]
fn b64_unknown_commit_settlements_skip_apply_rejects() {
    let gen = genesis_with_b3_storage();
    let st = &gen.state;
    let h = 8_000u32;
    let prev = *st.tip_id().expect("tip");
    let mut proof = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
    );
    proof.commit_hash = [0xABu8; 32];
    let proofs = vec![proof];
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, h, &PROP_ENDOWMENT_B3);
    assert!(settlements.is_empty(), "unknown commit must soft-skip");

    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::StorageProofUnknownCommit { .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("unknown commit must hard-reject"),
    }
}

/// B-64: settlements keep one of a dup pair; apply hard-rejects the dup block.
#[test]
fn b64_dup_operator_settlements_skip_apply_rejects() {
    let gen = genesis_with_b3_storage();
    let st = &gen.state;
    let h = 8_000u32;
    let prev = *st.tip_id().expect("tip");
    let proof = build_test_storage_proof_operator_salted(
        &gen.built.commit,
        &prev,
        h,
        &gen.payload,
        &gen.built.tree,
    );
    let proofs = vec![proof.clone(), proof];
    let settlements =
        storage_proof_operator_settlements(&proofs, &st.storage, h, &PROP_ENDOWMENT_B3);
    assert_eq!(
        settlements.len(),
        1,
        "dup operator soft-skips to one settlement"
    );

    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::DuplicateStorageProofOperator { .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("dup operator block must hard-reject"),
    }
}

/// B-64: over-replication drain soft-skips to cap; sealing settled prefix accepts.
#[test]
fn b64_replication_cap_settled_prefix_applies() {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let built = build_storage_commitment(&payload, 1_000, Some(256), 2, None).expect("commitment");
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        initial_storage_operators: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: PROP_ENDOWMENT_B3,
        bonding_params: None,
        header_version: 1,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    let h = next_height(&st);
    let prev = *st.tip_id().expect("tip");
    let p0 =
        build_test_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree);
    let (v1, s1) = test_operator_payout_keys_alt();
    let p1 =
        build_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree, v1, s1)
            .expect("proof");
    let v2 = generator_g() * Scalar::from(7u64);
    let s2 = generator_g() * Scalar::from(11u64);
    let p2 =
        build_storage_proof_operator_salted(&built.commit, &prev, h, &payload, &built.tree, v2, s2)
            .expect("proof");
    let drained = vec![p0, p1, p2];
    let settlements =
        storage_proof_operator_settlements(&drained, &st.storage, h, &PROP_ENDOWMENT_B3);
    assert_eq!(settlements.len(), 2, "replication=2 soft-skips the third");

    // Raw over-cap block must reject (producer bug before B-64 filter).
    let unsealed_raw = build_unsealed_header(&st, &[], &[], &[], &drained, h, 1_000);
    let blk_raw = seal_block(
        unsealed_raw,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        drained,
    );
    match apply_block(&st, &blk_raw) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::StorageProofReplicationExceeded { .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("over-replication raw drain must reject"),
    }

    // Sealing only settled proofs (producer filter) must accept.
    let settled: Vec<_> = settlements.iter().map(|(p, _)| p.clone()).collect();
    let unsealed = build_unsealed_header(&st, &[], &[], &[], &settled, h, 1_000);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        settled,
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            let ch = storage_commitment_hash(&built.commit);
            assert_eq!(
                state.storage.get(&ch).expect("entry").last_proven_slot,
                u64::from(h)
            );
        }
        ApplyOutcome::Err { errors, .. } => panic!("settled prefix must accept, got {errors:?}"),
    }
}

/// Longer empty-block chain (**M5.37**).
#[test]
fn deep_empty_block_chain_128() {
    let mut st = genesis_state();
    for h in 1..=128u32 {
        st = apply_empty_at(&st, h, u64::from(h).saturating_mul(500));
    }
    assert_eq!(st.height, Some(128));
    assert_eq!(st.block_ids.len(), 129);
}

/// Longer storage-proof chain (**M5.37**).
#[test]
fn deep_storage_proof_chain_32() {
    let gen = genesis_with_storage();
    let mut st = gen.state;
    for h in 1..=32u32 {
        st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h);
    }
    assert_eq!(st.height, Some(32));
}

/// Deep validator-mode mixed CLSAG + SPoRA treasury chain (**M5.6**, **M5.37**).
#[test]
fn deep_validator_mixed_clsag_fee_and_storage_proof_treasury_32() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let mut st = gen.state;
    let mut spend = gen.spend;
    let mut input_pad = gen.input_pad;
    let mut model = 0u128;
    let emission = &PROP_MIXED_EMISSION;

    for h in 1..=32u32 {
        let fee = 2_000u64 + u64::from(h % 5_001);
        let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
        spend = next_spend;
        input_pad = next_pad;
        let fee_sum = u128::from(fee);
        let prev = *st.tip_id().expect("tip");
        let proof =
            build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
        let coinbase = prop_build_coinbase(
            h,
            emission,
            fee_sum,
            &gen.fixture.payout,
            &st,
            h,
            std::slice::from_ref(&proof),
        );
        let txs = vec![coinbase, tx];
        st = apply_validator_mixed_clsag_fee_and_storage_proof(&gen.fixture, &st, h, txs, &proof);
        model = treasury_after_block(model, fee_sum, 1, emission);
        assert_eq!(st.treasury, model, "treasury mismatch at height {h}");
    }
    assert_eq!(st.height, Some(32));
}

/// Deep CLSAG fee + SPoRA proof same-block treasury chain (**M5.5**, **M5.36**).
#[test]
fn deep_mixed_clsag_fee_and_storage_proof_treasury_64() {
    let gen = genesis_privacy_storage_for_proptest();
    let mut st = gen.state;
    let mut spend = gen.spend;
    let mut input_pad = gen.input_pad;
    let mut model = 0u128;
    let emission = &PROP_MIXED_EMISSION;

    for h in 1..=64u32 {
        let fee = 2_000u64 + u64::from(h % 5_001);
        let (tx, next_spend, next_pad) = spend.sign_self_transfer(&input_pad, fee, h);
        spend = next_spend;
        input_pad = next_pad;
        let prev = *st.tip_id().expect("tip");
        let proof =
            build_test_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree);
        st = apply_mixed_clsag_fee_and_storage_proof(&st, h, vec![tx], &proof);
        model = treasury_after_legacy_block(model, u128::from(fee), 1, emission);
        assert_eq!(st.treasury, model, "treasury mismatch at height {h}");
    }
    assert_eq!(st.height, Some(64));
}

/// Deep CLSAG fee + storage upload same-block treasury chain (**M5.33**, **M5.35**, **M5.38**).
#[test]
fn deep_mixed_clsag_fee_and_storage_upload_treasury_64() {
    const UPLOAD_PAYLOAD_LEN: usize = 1024;
    let min_upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN);
    let gen = genesis_dual_spend_for_upload_proptest();
    let mut st = gen.state;
    let mut clsag_spend = gen.clsag_spend;
    let mut clsag_pad = gen.clsag_pad;
    let mut upload_spend = gen.upload_spend;
    let mut upload_pad = gen.upload_pad;
    let mut model = 0u128;
    let emission = &PROP_MIXED_EMISSION;

    for h in 1..=64u32 {
        let clsag_fee = 2_000u64 + u64::from(h % 5_001);
        let upload_fee = min_upload_fee + u64::from(h % 501);
        let payload: Vec<u8> = vec![h as u8; UPLOAD_PAYLOAD_LEN];
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(256),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commitment");
        let commit_hash = storage_commitment_hash(&built.commit);
        let (clsag_tx, next_clsag, next_clsag_pad) =
            clsag_spend.sign_self_transfer(&clsag_pad, clsag_fee, h);
        clsag_spend = next_clsag;
        clsag_pad = next_clsag_pad;
        let (upload_tx, next_upload, next_upload_pad) = upload_spend.sign_storage_upload(
            &upload_pad,
            PropStorageUploadArgs::new(
                upload_fee,
                &built,
                PROP_STORAGE_ENDOWMENT_AMOUNT,
                &DEFAULT_ENDOWMENT_PARAMS,
                h.wrapping_add(10_000),
            ),
        );
        upload_spend = next_upload;
        upload_pad = next_upload_pad;
        let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
        st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
        model = treasury_after_legacy_block(model, fee_sum, 0, emission);
        assert_eq!(
            st.treasury, model,
            "treasury mismatch at height {h} (clsag_fee {clsag_fee} upload_fee {upload_fee})"
        );
        assert!(st.storage.contains_key(&commit_hash));
    }
    assert_eq!(st.height, Some(64));
}

/// Alternating register + SPoRA proof through one epoch churn cap (**M5.4**, **M5.39**).
#[test]
fn deep_alternating_register_storage_treasury_8() {
    let gen = genesis_with_storage_and_bonding();
    let mut st = gen.state;
    let mut model = 0u128;
    let stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let emission = &DEFAULT_EMISSION_PARAMS;
    let n_pairs = DEFAULT_BONDING_PARAMS.max_entry_churn_per_epoch;

    for i in 0..n_pairs {
        let h_reg = next_height(&st);
        st = apply_with_bond_ops(&st, h_reg, vec![register_op((i + 1) as u8)]);
        model = treasury_after_register(model, stake);
        assert_eq!(st.treasury, model);

        let h_proof = next_height(&st);
        st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h_proof);
        model = treasury_after_legacy_block(model, 0, 1, emission);
        assert_eq!(st.treasury, model);
    }
    assert_eq!(st.height, Some(n_pairs * 2));
}

/// Reject a new storage anchor when `require_endowment_opening=1` but `tx.extra` has no `MFEO` (**B-11**).
#[test]
fn reject_upload_without_mfeo_when_endowment_opening_required() {
    const UPLOAD_PAYLOAD_LEN: usize = 1024;
    let gen = genesis_dual_spend_for_upload_opening_proptest();
    let upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN).saturating_add(100);
    let payload: Vec<u8> = vec![7u8; UPLOAD_PAYLOAD_LEN];
    let built = build_storage_commitment(
        &payload,
        PROP_STORAGE_ENDOWMENT_AMOUNT,
        Some(256),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let (upload_tx, _, _) = gen.upload_spend.sign_storage_upload(
        &gen.upload_pad,
        PropStorageUploadArgs::new(
            upload_fee,
            &built,
            PROP_STORAGE_ENDOWMENT_AMOUNT,
            &DEFAULT_ENDOWMENT_PARAMS,
            99,
        ),
    );
    let height = 1u32;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(
        &gen.state,
        std::slice::from_ref(&upload_tx),
        &[],
        &[],
        &[],
        height,
        ts,
    );
    let blk = seal_with_test_finality(
        &gen.state,
        unsealed,
        vec![upload_tx],
        vec![],
        vec![],
        vec![],
    );
    match apply_block(&gen.state, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::EndowmentOpeningCountMismatch {
                            expected: 1,
                            got: 0,
                            ..
                        }
                    )
                }),
                "expected EndowmentOpeningCountMismatch, got {errors:?}"
            );
        }
        other => panic!("expected apply_block reject, got {other:?}"),
    }
}

/// Reject upload when `require_endowment_range_proof=1` but `tx.extra` has no `MFER` (**B-11 phase 2**).
#[test]
fn reject_upload_without_mfer_when_endowment_range_proof_required() {
    const UPLOAD_PAYLOAD_LEN: usize = 1024;
    let gen = genesis_dual_spend_for_upload_range_proof_proptest();
    let upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN).saturating_add(100);
    let payload: Vec<u8> = vec![7u8; UPLOAD_PAYLOAD_LEN];
    let built = build_storage_commitment(
        &payload,
        PROP_STORAGE_ENDOWMENT_AMOUNT,
        Some(256),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let (upload_tx, _, _) = gen.upload_spend.sign_storage_upload(
        &gen.upload_pad,
        PropStorageUploadArgs::new(
            upload_fee,
            &built,
            PROP_STORAGE_ENDOWMENT_AMOUNT,
            &PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
            99,
        )
        .with_extra_override({
            let mut e = Vec::new();
            e.extend_from_slice(mfn_consensus::extra_codec::MFEX_MAGIC);
            e.push(mfn_consensus::extra_codec::MFEX_VERSION_V3);
            e
        }),
    );
    let height = 1u32;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(
        &gen.state,
        std::slice::from_ref(&upload_tx),
        &[],
        &[],
        &[],
        height,
        ts,
    );
    let blk = seal_with_test_finality(
        &gen.state,
        unsealed,
        vec![upload_tx],
        vec![],
        vec![],
        vec![],
    );
    match apply_block(&gen.state, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::EndowmentRangeProofCountMismatch {
                            expected: 1,
                            got: 0,
                            ..
                        }
                    )
                }),
                "expected EndowmentRangeProofCountMismatch, got {errors:?}"
            );
        }
        other => panic!("expected apply_block reject, got {other:?}"),
    }
}

/// Accept upload with valid `MFER` when `require_endowment_range_proof=1` (**B-11 phase 2**).
#[test]
fn accept_upload_with_mfer_when_endowment_range_proof_required() {
    const UPLOAD_PAYLOAD_LEN: usize = 1024;
    let gen = genesis_dual_spend_for_upload_range_proof_proptest();
    let upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN).saturating_add(100);
    let payload: Vec<u8> = vec![7u8; UPLOAD_PAYLOAD_LEN];
    let built = build_storage_commitment(
        &payload,
        PROP_STORAGE_ENDOWMENT_AMOUNT,
        Some(256),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let (upload_tx, _, _) = gen.upload_spend.sign_storage_upload(
        &gen.upload_pad,
        PropStorageUploadArgs::new(
            upload_fee,
            &built,
            PROP_STORAGE_ENDOWMENT_AMOUNT,
            &PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
            99,
        ),
    );
    let height = 1u32;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(
        &gen.state,
        std::slice::from_ref(&upload_tx),
        &[],
        &[],
        &[],
        height,
        ts,
    );
    let blk = seal_with_test_finality(
        &gen.state,
        unsealed,
        vec![upload_tx],
        vec![],
        vec![],
        vec![],
    );
    match apply_block(&gen.state, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.height, Some(1));
            assert_eq!(state.storage.len(), 1);
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected accept, got {errors:?}"),
    }
}

/// Reject upload when `MFER` surplus proof uses wrong Pedersen blinding (**B-11 phase 2**).
#[test]
fn reject_upload_with_forged_mfer_when_endowment_range_proof_required() {
    const UPLOAD_PAYLOAD_LEN: usize = 1024;
    let gen = genesis_dual_spend_for_upload_range_proof_proptest();
    let upload_fee = prop_min_upload_fee(UPLOAD_PAYLOAD_LEN).saturating_add(100);
    let payload: Vec<u8> = vec![7u8; UPLOAD_PAYLOAD_LEN];
    let built = build_storage_commitment(
        &payload,
        PROP_STORAGE_ENDOWMENT_AMOUNT,
        Some(256),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let required = required_endowment(
        built.commit.size_bytes,
        built.commit.replication,
        &PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
    )
    .expect("required") as u64;
    let surplus = PROP_STORAGE_ENDOWMENT_AMOUNT - required;
    let forged_blinding = hash_to_scalar(&[b"B1/forged-blinding"]);
    let bad_proof = bp_prove(surplus, &forged_blinding, 64)
        .expect("forged proof")
        .proof;
    let forged_extra = build_mfex_extra_v3(&[], std::slice::from_ref(&bad_proof)).expect("mfex v3");
    let (upload_tx, _, _) = gen.upload_spend.sign_storage_upload(
        &gen.upload_pad,
        PropStorageUploadArgs::new(
            upload_fee,
            &built,
            PROP_STORAGE_ENDOWMENT_AMOUNT,
            &PROP_ENDOWMENT_REQUIRE_RANGE_PROOF,
            99,
        )
        .with_extra_override(forged_extra),
    );
    let height = 1u32;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(
        &gen.state,
        std::slice::from_ref(&upload_tx),
        &[],
        &[],
        &[],
        height,
        ts,
    );
    let blk = seal_with_test_finality(
        &gen.state,
        unsealed,
        vec![upload_tx],
        vec![],
        vec![],
        vec![],
    );
    match apply_block(&gen.state, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::EndowmentRangeProofInvalid { tx: 0, output: 0 }
                    )
                }),
                "expected EndowmentRangeProofInvalid, got {errors:?}"
            );
        }
        other => panic!("expected apply_block reject, got {other:?}"),
    }
}
