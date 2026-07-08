//! Property-based fuzzing of [`apply_block`] (**M5.2**, **M5.2+**, **M5.4**, **M5.5**, **M5.6**, **M5.7**, **M5.8**, **M5.9**, **M5.10**, **M5.11**, **M5.21**, **M5.33**, **M5.35**, **M5.36**, **M5.37**, **M5.38**, **M5.39**, **B-11**).
//!
//! CI runs a bounded case count; all deep chains are in default CI (**M5.36–M5.39**).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::{bls_keygen_from_seed, bls_sign, BlsSecretKey};
use mfn_consensus::{
    apply_block, apply_genesis, block_coinbase_specs, build_coinbase, build_coinbase_outputs,
    build_genesis, build_mfex_extra_v2, build_unsealed_header, cast_vote, emission_at_height,
    encode_chain_checkpoint, encode_finality_proof, extra_codec::EndowmentOpening, finalize,
    header_signing_hash, pick_winner, seal_block, sign_register, sign_transaction,
    storage_proof_coinbase_bonus, storage_proof_operator_settlements, try_produce_slot,
    ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint, ChainState, ConsensusParams,
    EmissionParams, FinalityProof, GenesisConfig, GenesisOutput, InputSpec, OutputSpec,
    PayoutAddress, ProducerProof, SlashEvidence, SlotContext, TransactionWire, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS,
    DEFAULT_EMISSION_PARAMS, TEST_CONSENSUS_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    accrue_proof_reward, build_storage_commitment, build_storage_proof_operator_salted,
    build_test_storage_proof, build_test_storage_proof_operator_salted, required_endowment,
    storage_commitment_hash, test_operator_payout_keys_alt, AccrueArgs, BuiltCommitment,
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

/// B3: operator-salted replication accounting at consensus (test genesis only).
const PROP_ENDOWMENT_B3: EndowmentParams = EndowmentParams {
    operator_salted_challenges: 1,
    real_yield_ppb: 40_000_000,
    min_replication: 1,
    ..DEFAULT_ENDOWMENT_PARAMS
};

const PROP_STORAGE_ENDOWMENT_AMOUNT: u64 = 1_000;

fn prop_storage_upload_extra(
    built: &BuiltCommitment,
    endowment_amount: u64,
    endowment_params: &EndowmentParams,
) -> Vec<u8> {
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: PROP_ENDOWMENT_B3,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).expect("genesis");
    StorageGenesis {
        state,
        built,
        payload,
    }
}

/// Mirrors `apply_block` treasury settlement for fee + storage-proof tranche.
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
        fee: u64,
        built: &BuiltCommitment,
        endowment_amount: u64,
        endowment_params: &EndowmentParams,
        next_seed: u32,
    ) -> (TransactionWire, Self, PropSpendState) {
        assert!(fee < self.value, "fee must leave positive anchor output");
        let anchor_value = self.value - fee;
        let next_spend = hash_to_scalar(&[b"M5.33/change-spend", &next_seed.to_le_bytes()]);
        let change_addr = generator_g() * next_spend;
        let next_pad_spend = hash_to_scalar(&[b"F7/upload-pad-spend", &next_seed.to_le_bytes()]);
        let pad_addr = generator_g() * next_pad_spend;
        let zero_spend = hash_to_scalar(&[b"B1/upload-pad-spend", &next_seed.to_le_bytes()]);
        let zero_addr = generator_g() * zero_spend;
        let extra = prop_storage_upload_extra(built, endowment_amount, endowment_params);
        let signed = sign_transaction(
            vec![self.input_spec(), pad.input_spec()],
            vec![
                OutputSpec::Raw {
                    one_time_addr: change_addr,
                    value: anchor_value,
                    storage: Some(built.commit.clone()),
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: PROP_ENDOWMENT_REQUIRE_OPENING,
        bonding_params: None,
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
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
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
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
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: PROP_PPB_ENDOWMENT,
        bonding_params: Some(DEFAULT_BONDING_PARAMS),
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
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: PROP_MIXED_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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
    SlashEvidence {
        height,
        slot,
        voter_index,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, bls_sk),
    }
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
            model = treasury_after_block(model, 0, 1, emission);
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
            model = treasury_after_block(model, 0, 1, emission);
            prop_assert_eq!(st.treasury, model);

            let h_reg = next_height(&st);
            st = apply_with_bond_ops(&st, h_reg, vec![register_op((i + 1) as u8)]);
            model = treasury_after_register(model, stake);
            prop_assert_eq!(st.treasury, model);
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
            model = treasury_after_block(model, u128::from(fee), 1, emission);
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
                upload_fee,
                &built,
                PROP_STORAGE_ENDOWMENT_AMOUNT,
                &DEFAULT_ENDOWMENT_PARAMS,
                h.wrapping_add(10_000),
            );
            upload_spend = next_upload;
            upload_pad = next_upload_pad;

            let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
            st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
            model = treasury_after_block(model, fee_sum, 0, emission);
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
                upload_fee,
                &built,
                PROP_STORAGE_ENDOWMENT_AMOUNT,
                &PROP_ENDOWMENT_REQUIRE_OPENING,
                h.wrapping_add(10_000),
            );
            upload_spend = next_upload;
            upload_pad = next_upload_pad;

            let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
            st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
            model = treasury_after_block(model, fee_sum, 0, emission);
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
            model = treasury_after_block(model, u128::from(fee), 1, emission);
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
        model = treasury_after_block(model, u128::from(fee), 1, emission);
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
            upload_fee,
            &built,
            PROP_STORAGE_ENDOWMENT_AMOUNT,
            &DEFAULT_ENDOWMENT_PARAMS,
            h.wrapping_add(10_000),
        );
        upload_spend = next_upload;
        upload_pad = next_upload_pad;
        let fee_sum = u128::from(clsag_fee) + u128::from(upload_fee);
        st = apply_mixed_clsag_fee_and_storage_upload(&st, h, vec![clsag_tx, upload_tx]);
        model = treasury_after_block(model, fee_sum, 0, emission);
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
        model = treasury_after_block(model, 0, 1, emission);
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
        upload_fee,
        &built,
        PROP_STORAGE_ENDOWMENT_AMOUNT,
        &DEFAULT_ENDOWMENT_PARAMS,
        99,
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
