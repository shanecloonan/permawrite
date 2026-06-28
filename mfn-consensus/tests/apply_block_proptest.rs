//! Property-based fuzzing of [`apply_block`] (**M5.2**, **M5.2+**, **M5.4**, **M5.5**, **M5.6**).
//!
//! CI runs a bounded case count; deeper chains are `#[ignore]` (nightly).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    apply_block, apply_genesis, build_coinbase, build_genesis, build_unsealed_header, cast_vote,
    emission_at_height, encode_chain_checkpoint, encode_finality_proof, finalize,
    header_signing_hash, pick_winner, seal_block, sign_register, sign_transaction,
    try_produce_slot, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint, ChainState,
    ConsensusParams, EmissionParams, FinalityProof, GenesisConfig, GenesisOutput, InputSpec,
    OutputSpec, PayoutAddress, ProducerProof, SlotContext, TransactionWire, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    build_storage_commitment, build_storage_proof, BuiltCommitment, DEFAULT_CHUNK_SIZE,
    DEFAULT_ENDOWMENT_PARAMS,
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

    fn input_spec(&self) -> InputSpec {
        InputSpec {
            ring: ClsagRing {
                p: vec![self.one_time_addr],
                c: vec![self.commitment()],
            },
            signer_idx: 0,
            spend_priv: self.spend_priv,
            value: self.value,
            blinding: self.blinding,
        }
    }

    /// Self-transfer with public fee; next state uses deterministic change keys.
    fn sign_self_transfer(&self, fee: u64, next_seed: u32) -> (TransactionWire, Self) {
        assert!(fee < self.value, "fee must leave positive change");
        let change_value = self.value - fee;
        let next_spend = hash_to_scalar(&[b"M5.5/change-spend", &next_seed.to_le_bytes()]);
        let change_addr = generator_g() * next_spend;
        let signed = sign_transaction(
            vec![self.input_spec()],
            vec![OutputSpec::Raw {
                one_time_addr: change_addr,
                value: change_value,
                storage: None,
            }],
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
        (signed.tx, next)
    }
}

struct PropPrivacyStorageGenesis {
    state: ChainState,
    spend: PropSpendState,
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
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: spend.one_time_addr,
            amount: spend.commitment(),
        }],
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
            ..ConsensusParams::default()
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

struct PropValidatorPrivacyStorageGenesis {
    state: ChainState,
    spend: PropSpendState,
    built: BuiltCommitment,
    payload: Vec<u8>,
    fixture: PropValidatorFixture,
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
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: spend.one_time_addr,
            amount: spend.commitment(),
        }],
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

fn validator_mixed_block_material(
    spend: &PropSpendState,
    built: &BuiltCommitment,
    payload: &[u8],
    payout: &PayoutAddress,
    st: &ChainState,
    height: u32,
    fee: u64,
) -> (Vec<TransactionWire>, mfn_storage::StorageProof) {
    let (tx, _) = spend.sign_self_transfer(fee, height);
    let fee_sum = u128::from(fee);
    let cb_amount = expected_coinbase_amount(height, fee_sum, 1, &PROP_MIXED_EMISSION);
    let coinbase = build_coinbase(u64::from(height), cb_amount, payout).expect("coinbase");
    let txs = vec![coinbase, tx];
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_storage_proof(&built.commit, &prev, height, payload, &built.tree).expect("proof");
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

fn legacy_mixed_block_material(
    spend: &PropSpendState,
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    height: u32,
    fee: u64,
) -> (Vec<TransactionWire>, mfn_storage::StorageProof) {
    let (tx, _) = spend.sign_self_transfer(fee, height);
    let txs = vec![tx];
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_storage_proof(&built.commit, &prev, height, payload, &built.tree).expect("proof");
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
        let proof =
            build_storage_proof(&built.commit, &prev, slot, payload, &built.tree).expect("proof");
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
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 7_001));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend) = spend.sign_self_transfer(fee, h);
            spend = next_spend;
            let prev = *st.tip_id().expect("tip");
            let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
                .expect("proof");
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

    /// Validator quorum + coinbase + CLSAG fee + SPoRA proof in one block (**M5.6**).
    #[test]
    fn prop_validator_mixed_clsag_fee_and_storage_proof_treasury(
        n_blocks in 1u32..=8u32,
        fee_base in 1_000u64..=200_000u64,
    ) {
        let gen = genesis_validator_privacy_storage_for_proptest();
        let mut st = gen.state;
        let mut spend = gen.spend;
        let mut model = 0u128;
        let emission = &PROP_MIXED_EMISSION;

        for h in 1..=n_blocks {
            let fee = fee_base.saturating_add(u64::from(h % 7_001));
            prop_assert!(fee < PROP_MIXED_SPEND_VALUE, "fee must fit genesis UTXO");
            let (tx, next_spend) = spend.sign_self_transfer(fee, h);
            spend = next_spend;
            let fee_sum = u128::from(fee);
            let cb_amount = expected_coinbase_amount(h, fee_sum, 1, emission);
            let coinbase =
                build_coinbase(u64::from(h), cb_amount, &gen.fixture.payout).expect("coinbase");
            let txs = vec![coinbase, tx];
            let prev = *st.tip_id().expect("tip");
            let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
                .expect("proof");
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
    let (tx, _) = gen.spend.sign_self_transfer(25_000, h);
    let txs = vec![tx];
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
        .expect("proof");
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
        built,
        payload,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) = legacy_mixed_block_material(&spend, &built, &payload, &st, h, 50_000);
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
        built,
        payload,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (mut txs, proof) = legacy_mixed_block_material(&spend, &built, &payload, &st, h, 50_000);
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
    let (tx, _) = gen.spend.sign_self_transfer(fee, h);
    let coinbase = build_coinbase(
        u64::from(h),
        expected_coinbase_amount(h, u128::from(fee), 1, &PROP_MIXED_EMISSION),
        &gen.fixture.payout,
    )
    .expect("coinbase");
    let txs = vec![coinbase, tx];
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
        .expect("proof");
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
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) =
        validator_mixed_block_material(&spend, &built, &payload, &fixture.payout, &st, h, 50_000);
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
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let fee = 50_000u64;
    let (mut txs, proof) =
        validator_mixed_block_material(&spend, &built, &payload, &fixture.payout, &st, h, fee);
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
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (txs, proof) =
        validator_mixed_block_material(&spend, &built, &payload, &fixture.payout, &st, h, 50_000);
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
        built,
        payload,
        fixture,
    } = gen;
    let before_snap = snap(&st);
    let before_bytes = checkpoint_bytes(&st);
    let h = next_height(&st);
    let (mut txs, proof) =
        validator_mixed_block_material(&spend, &built, &payload, &fixture.payout, &st, h, 50_000);
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
    let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
        .expect("proof");
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

/// Longer empty-block chain (nightly / local deep fuzz).
#[test]
#[ignore = "deep apply_block chain; run with cargo test -p mfn-consensus --test apply_block_proptest -- --ignored"]
fn deep_empty_block_chain_128() {
    let mut st = genesis_state();
    for h in 1..=128u32 {
        st = apply_empty_at(&st, h, u64::from(h).saturating_mul(500));
    }
    assert_eq!(st.height, Some(128));
    assert_eq!(st.block_ids.len(), 129);
}

/// Longer storage-proof chain (nightly).
#[test]
#[ignore = "deep storage-proof apply_block chain; run with cargo test -p mfn-consensus --test apply_block_proptest -- --ignored"]
fn deep_storage_proof_chain_32() {
    let gen = genesis_with_storage();
    let mut st = gen.state;
    for h in 1..=32u32 {
        st = apply_valid_proof_at(&gen.built, &gen.payload, &st, h);
    }
    assert_eq!(st.height, Some(32));
}

/// Deep validator-mode mixed CLSAG + SPoRA treasury chain (**M5.6**).
#[test]
#[ignore = "deep validator mixed CLSAG+SPoRA treasury chain; run with cargo test -p mfn-consensus --test apply_block_proptest -- --ignored"]
fn deep_validator_mixed_clsag_fee_and_storage_proof_treasury_32() {
    let gen = genesis_validator_privacy_storage_for_proptest();
    let mut st = gen.state;
    let mut spend = gen.spend;
    let mut model = 0u128;
    let emission = &PROP_MIXED_EMISSION;

    for h in 1..=32u32 {
        let fee = 2_000u64 + u64::from(h % 5_001);
        let (tx, next_spend) = spend.sign_self_transfer(fee, h);
        spend = next_spend;
        let fee_sum = u128::from(fee);
        let cb_amount = expected_coinbase_amount(h, fee_sum, 1, emission);
        let coinbase =
            build_coinbase(u64::from(h), cb_amount, &gen.fixture.payout).expect("coinbase");
        let txs = vec![coinbase, tx];
        let prev = *st.tip_id().expect("tip");
        let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
            .expect("proof");
        st = apply_validator_mixed_clsag_fee_and_storage_proof(&gen.fixture, &st, h, txs, &proof);
        model = treasury_after_block(model, fee_sum, 1, emission);
        assert_eq!(st.treasury, model, "treasury mismatch at height {h}");
    }
    assert_eq!(st.height, Some(32));
}

/// Deep CLSAG fee + SPoRA proof same-block treasury chain (**M5.5**).
#[test]
#[ignore = "deep mixed CLSAG+SPoRA treasury chain; run with cargo test -p mfn-consensus --test apply_block_proptest -- --ignored"]
fn deep_mixed_clsag_fee_and_storage_proof_treasury_64() {
    let gen = genesis_privacy_storage_for_proptest();
    let mut st = gen.state;
    let mut spend = gen.spend;
    let mut model = 0u128;
    let emission = &PROP_MIXED_EMISSION;

    for h in 1..=64u32 {
        let fee = 2_000u64 + u64::from(h % 5_001);
        let (tx, next_spend) = spend.sign_self_transfer(fee, h);
        spend = next_spend;
        let prev = *st.tip_id().expect("tip");
        let proof = build_storage_proof(&gen.built.commit, &prev, h, &gen.payload, &gen.built.tree)
            .expect("proof");
        st = apply_mixed_clsag_fee_and_storage_proof(&st, h, vec![tx], &proof);
        model = treasury_after_block(model, u128::from(fee), 1, emission);
        assert_eq!(st.treasury, model, "treasury mismatch at height {h}");
    }
    assert_eq!(st.height, Some(64));
}

/// Alternating register + SPoRA proof through one epoch churn cap (**M5.4**).
#[test]
#[ignore = "deep alternating treasury chain; run with cargo test -p mfn-consensus --test apply_block_proptest -- --ignored"]
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
