//! Long-horizon emission / treasury simulations (**M5.0**, **M5.0+**, **M5.0++**, **M5.1**,
//! **M5.1+**, **M5.3**, **M5.9**, **M5.11**, **M5.12**, **M5.13**, **M5.16**, **M5.17**, **M5.19**, **M5.22**, **M5.23**, **M5.24**, **M5.25**, **M5.26**, **M5.28**, **M5.29**, **M5.30**, **M5.31**, **M5.32**, **M5.33**, **M5.34**, **M5.35**, **M5.39**).
//!
//! Fast curve checks run in default CI; million-block and deep `apply_block`
//! harnesses are `#[ignore]` (see `scripts/ci-ignored.sh` pattern / nightly).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::{bls_keygen_from_seed, bls_sign, BlsSecretKey};
use mfn_consensus::storage::StorageCommitment;
use mfn_consensus::{
    apply_block, apply_genesis, block_coinbase_specs, build_coinbase_outputs, build_genesis,
    build_unsealed_header, cast_vote, cumulative_emission, emission_at_height,
    encode_finality_proof, finalize, header_signing_hash, producer_coinbase_amount,
    producer_portion_amount, seal_block, sign_transaction, storage_proof_coinbase_bonus,
    try_produce_slot, validate_emission_params, ApplyOutcome, ChainState, ConsensusParams,
    EmissionParams, FinalityProof, GenesisConfig, GenesisOutput, InputSpec, OutputSpec,
    PayoutAddress, SignedTransaction, SlashEvidence, SlotContext, TransactionWire, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    TEST_CONSENSUS_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::encrypted_amount::decrypt_output_amount;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::stealth::{stealth_gen, StealthWallet};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    accrue_proof_reward, build_storage_commitment, build_test_storage_proof,
    storage_commitment_hash, AccrueArgs, BuiltCommitment, EndowmentParams, StorageProof,
    DEFAULT_ENDOWMENT_PARAMS, PPB,
};

/// Compact schedule so `apply_block` loops finish in CI while still crossing halvings.
const SIM_EMISSION: EmissionParams = EmissionParams {
    initial_reward: 1_000,
    halving_period: 64,
    halving_count: 4,
    tail_emission: 50,
    storage_proof_reward: 25,
    fee_to_treasury_bps: 9000,
};

const SIM_PPB_ENDOWMENT: EndowmentParams = EndowmentParams {
    real_yield_ppb: 40_000_000,
    ..DEFAULT_ENDOWMENT_PARAMS
};

fn genesis_state(emission: EmissionParams) -> ChainState {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: emission,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    apply_genesis(&g, &cfg).expect("genesis")
}

fn apply_empty_legacy_block(st: &ChainState, height: u32) -> ChainState {
    let header = build_unsealed_header(st, &[], &[], &[], &[], height, u64::from(height) * 1_000);
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

/// Step the same treasury arithmetic as `apply_block` settlement.
fn treasury_after_block(
    treasury: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let storage_reward_total = params.storage_proof_reward as u128 * proofs;
    let mut pending = treasury.saturating_add(treasury_fee);
    let from_treasury = pending.min(storage_reward_total);
    pending -= from_treasury;
    pending
}

fn treasury_after_liveness_block(
    treasury: u128,
    liveness_credit: u128,
    fee_sum: u128,
    proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_block(treasury + liveness_credit, fee_sum, proofs, params)
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
        treasury + bond_burn + liveness_credit,
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

/// Three-validator quorum harness (BLS finality + coinbase payout).
struct ValidatorFixture {
    validators: Vec<Validator>,
    secrets: Vec<ValidatorSecrets>,
    payout: PayoutAddress,
    /// Producer (validator 0) wallet — coinbase decrypt checks (**M5.3**).
    producer_wallet: StealthWallet,
    params: ConsensusParams,
    total_stake: u64,
}

impl ValidatorFixture {
    fn three_validators() -> Self {
        let mk = |i: u32, stake: u64| -> (Validator, ValidatorSecrets, StealthWallet) {
            let vrf = vrf_keygen_from_seed(&[(i.wrapping_add(1)) as u8; 32]).expect("vrf");
            let bls = bls_keygen_from_seed(&[(i.wrapping_add(101)) as u8; 32]);
            let wallet = stealth_gen();
            let val = Validator {
                index: i,
                vrf_pk: vrf.pk,
                bls_pk: bls.pk,
                stake,
                payout: Some(ValidatorPayout {
                    view_pub: wallet.view_pub,
                    spend_pub: wallet.spend_pub,
                }),
            };
            let secrets = ValidatorSecrets { index: i, vrf, bls };
            (val, secrets, wallet)
        };
        let (v0, s0, producer_wallet) = mk(0, 100);
        let (v1, s1, _) = mk(1, 100);
        let (v2, s2, _) = mk(2, 100);
        let validators = vec![v0.clone(), v1, v2];
        let secrets = vec![s0, s1, s2];
        let payout = PayoutAddress {
            view_pub: producer_wallet.view_pub,
            spend_pub: producer_wallet.spend_pub,
        };
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
            producer_wallet,
            params,
            total_stake,
        }
    }

    fn liveness_absentee_three_validators() -> Self {
        let mk = |i: u32, stake: u64| -> (Validator, ValidatorSecrets, StealthWallet) {
            let vrf = vrf_keygen_from_seed(&[(i.wrapping_add(1)) as u8; 32]).expect("vrf");
            let bls = bls_keygen_from_seed(&[(i.wrapping_add(101)) as u8; 32]);
            let wallet = stealth_gen();
            let val = Validator {
                index: i,
                vrf_pk: vrf.pk,
                bls_pk: bls.pk,
                stake,
                payout: Some(ValidatorPayout {
                    view_pub: wallet.view_pub,
                    spend_pub: wallet.spend_pub,
                }),
            };
            let secrets = ValidatorSecrets { index: i, vrf, bls };
            (val, secrets, wallet)
        };
        let (v0, s0, producer_wallet) = mk(0, 1_000_000);
        let (v1, s1, _) = mk(1, 1_000_000);
        let (v2, s2, _) = mk(2, 1_000_000);
        let validators = vec![v0.clone(), v1, v2];
        let secrets = vec![s0, s1, s2];
        let payout = PayoutAddress {
            view_pub: producer_wallet.view_pub,
            spend_pub: producer_wallet.spend_pub,
        };
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 3,
            liveness_slash_bps: 100,
            ..TEST_CONSENSUS_PARAMS
        };
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            secrets,
            payout,
            producer_wallet,
            params,
            total_stake,
        }
    }

    /// Same as [`Self::liveness_absentee_three_validators`] but tuned for multi-block sims.
    fn liveness_absentee_long_sim() -> Self {
        let mut fixture = Self::liveness_absentee_three_validators();
        fixture.params.quorum_stake_bps = 5000;
        fixture.params.liveness_max_consecutive_missed = 64;
        fixture
    }
}

/// Producer decrypts coinbase output 0; amount is subsidy + producer fee share only.
fn assert_producer_coinbase_decryptable(
    coinbase: &TransactionWire,
    fixture: &ValidatorFixture,
    height: u64,
    emission: &EmissionParams,
    fee_sum: u128,
) {
    let expected = producer_portion_amount(height, emission, fee_sum);
    let dec = decrypt_output_amount(
        &coinbase.r_pub,
        0,
        fixture.producer_wallet.view_priv,
        &coinbase.outputs[0].enc_amount,
    )
    .expect("coinbase decrypt");
    assert_eq!(
        dec.value, expected,
        "producer coinbase amount must match subsidy + producer fee share"
    );
}

#[allow(clippy::too_many_arguments)]
fn build_validator_coinbase(
    height: u64,
    emission: &EmissionParams,
    fee_sum: u128,
    payout: &PayoutAddress,
    st: &ChainState,
    slot: u32,
    proofs: &[StorageProof],
) -> TransactionWire {
    let ep = &st.endowment_params;
    let accepted: Vec<_> = proofs
        .iter()
        .map(|p| {
            let bonus =
                storage_proof_coinbase_bonus(std::slice::from_ref(p), &st.storage, slot, ep);
            (p.clone(), bonus)
        })
        .collect();
    let specs = block_coinbase_specs(height, emission, fee_sum, *payout, &accepted);
    build_coinbase_outputs(height, &payout.spend_pub, &specs).expect("coinbase")
}

fn genesis_validator_with_funded_utxo(
    emission: EmissionParams,
    spend_value: u64,
    fixture: &ValidatorFixture,
    initial_storage: Vec<StorageCommitment>,
    endowment_params: EndowmentParams,
    bonding_params: Option<mfn_consensus::BondingParams>,
) -> (ChainState, SpendState) {
    let spend_priv = random_scalar();
    let blinding = random_scalar();
    let ring_size = ring_size_for(&fixture.params);
    let signer_idx = ring_size - 1;
    let mut decoys = Vec::with_capacity(ring_size - 1);
    let mut initial_outputs = Vec::with_capacity(ring_size);
    for i in 0..ring_size - 1 {
        let decoy = genesis_decoy_output(i);
        decoys.push((decoy.one_time_addr, decoy.amount));
        initial_outputs.push(decoy);
    }
    let spend = SpendState::with_ring(spend_priv, blinding, spend_value, decoys, signer_idx);
    initial_outputs.push(GenesisOutput {
        one_time_addr: spend.one_time_addr,
        amount: spend.commitment(),
    });
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage,
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: emission,
        endowment_params,
        bonding_params,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    (st, spend)
}

fn apply_validator_block(
    fixture: &ValidatorFixture,
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
) -> ChainState {
    let slot = height;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &txs, &[], &[], &storage_proofs, slot, ts);
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height,
        slot,
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

    let votes: Vec<_> = fixture
        .secrets
        .iter()
        .map(|secrets| {
            cast_vote(
                &header_hash,
                secrets,
                &ctx,
                &producer_proof,
                producer,
                fixture.total_stake,
                fixture.params.expected_proposers_per_slot,
            )
            .expect("vote")
        })
        .collect();
    let agg = finalize(&header_hash, &votes, fixture.validators.len()).expect("finalize");
    let fin = FinalityProof {
        producer: producer_proof,
        finality: agg,
        signing_stake: fixture.total_stake,
    };
    let blk = seal_block(
        unsealed,
        txs,
        Vec::new(),
        encode_finality_proof(&fin),
        Vec::new(),
        storage_proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn signing_stake_for_voters_from_state(st: &ChainState, voter_indices: &[u32]) -> u64 {
    voter_indices
        .iter()
        .map(|&i| st.validators[i as usize].stake)
        .sum()
}

#[allow(clippy::too_many_arguments)]
fn apply_validator_block_with_voters(
    fixture: &ValidatorFixture,
    bond_secrets: &[ValidatorSecrets],
    voter_indices: &[u32],
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
    bond_ops: Vec<mfn_consensus::BondOp>,
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
            let secrets = validator_secrets_for_index(fixture, bond_secrets, i);
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

/// Validator-mode blocks: BLS finality, coinbase pays subsidy + producer fee share; treasury
/// credits the permanence pool from the fee split (**M5.0+**).
fn run_validator_fee_treasury_sim(blocks: u32, emission: EmissionParams) {
    let fixture = ValidatorFixture::three_validators();
    let initial = 50_000_000_000u64;
    let (mut st, mut spend) = genesis_validator_with_funded_utxo(
        emission,
        initial,
        &fixture,
        Vec::new(),
        DEFAULT_ENDOWMENT_PARAMS,
        None,
    );
    let mut model_treasury = 0u128;

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend.sign_self_transfer(fee);
        spend = next_spend;
        let fee_sum = u128::from(fee);
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &[],
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        st = apply_validator_block(&fixture, &st, h, txs, Vec::new());
        model_treasury = treasury_after_block(model_treasury, fee_sum, 0, &emission);
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h} (fee {fee})"
        );
        assert!(st.treasury < u128::MAX);
    }
}

/// Ring size required by consensus params (uniform size when set, else minimum).
fn ring_size_for(params: &ConsensusParams) -> usize {
    let policy = params.ring_policy();
    if policy.uniform_ring_size > 0 {
        policy.uniform_ring_size as usize
    } else {
        policy.min_ring_size as usize
    }
}

fn genesis_decoy_output(i: usize) -> GenesisOutput {
    let spend = random_scalar();
    let blinding = random_scalar();
    let p = generator_g() * spend;
    let c = (generator_g() * blinding) + (generator_h() * Scalar::from(1u64 + i as u64));
    GenesisOutput {
        one_time_addr: p,
        amount: c,
    }
}

/// Spendable UTXO the simulator chains block-to-block via `OutputSpec::Raw` change.
struct SpendState {
    spend_priv: Scalar,
    blinding: Scalar,
    value: u64,
    one_time_addr: EdwardsPoint,
    ring_decoys: Vec<(EdwardsPoint, EdwardsPoint)>,
    signer_idx: usize,
}

impl SpendState {
    fn with_ring(
        spend_priv: Scalar,
        blinding: Scalar,
        value: u64,
        ring_decoys: Vec<(EdwardsPoint, EdwardsPoint)>,
        signer_idx: usize,
    ) -> Self {
        Self {
            spend_priv,
            blinding,
            value,
            one_time_addr: generator_g() * spend_priv,
            ring_decoys,
            signer_idx,
        }
    }

    fn commitment(&self) -> EdwardsPoint {
        (generator_g() * self.blinding) + (generator_h() * Scalar::from(self.value))
    }

    fn input_spec(&self) -> InputSpec {
        let ring_size = self.ring_decoys.len() + 1;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);
        for slot in 0..ring_size {
            if slot == self.signer_idx {
                p.push(self.one_time_addr);
                c.push(self.commitment());
            } else {
                let decoy_idx = if slot < self.signer_idx {
                    slot
                } else {
                    slot - 1
                };
                let (dp, dc) = self.ring_decoys[decoy_idx];
                p.push(dp);
                c.push(dc);
            }
        }
        InputSpec {
            ring: ClsagRing { p, c },
            signer_idx: self.signer_idx,
            spend_priv: self.spend_priv,
            value: self.value,
            blinding: self.blinding,
        }
    }

    /// Self-transfer with public fee; returns the signed tx and the change UTXO state.
    fn sign_self_transfer(&self, fee: u64) -> (SignedTransaction, Self) {
        assert!(fee < self.value, "fee must leave positive change");
        let change_value = self.value - fee;
        let next_spend = random_scalar();
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
            ring_decoys: self.ring_decoys.clone(),
            signer_idx: self.signer_idx,
        };
        (signed, next)
    }
}

fn genesis_with_funded_utxo(emission: EmissionParams, value: u64) -> (ChainState, SpendState) {
    let spend_priv = random_scalar();
    let blinding = random_scalar();
    let ring_size = ring_size_for(&DEFAULT_CONSENSUS_PARAMS);
    let signer_idx = ring_size - 1;
    let mut decoys = Vec::with_capacity(ring_size - 1);
    let mut initial_outputs = Vec::with_capacity(ring_size);
    for i in 0..ring_size - 1 {
        let decoy = genesis_decoy_output(i);
        decoys.push((decoy.one_time_addr, decoy.amount));
        initial_outputs.push(decoy);
    }
    let spend = SpendState::with_ring(spend_priv, blinding, value, decoys, signer_idx);
    initial_outputs.push(GenesisOutput {
        one_time_addr: spend.one_time_addr,
        amount: spend.commitment(),
    });
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: emission,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    (st, spend)
}

fn apply_legacy_block(st: &ChainState, height: u32, txs: &[TransactionWire]) -> ChainState {
    let header = build_unsealed_header(st, txs, &[], &[], &[], height, u64::from(height) * 1_000);
    let blk = seal_block(
        header,
        txs.to_vec(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

/// Anchored SPoRA payload reused across mixed fee + proof blocks.
struct StorageFixture {
    payload: Vec<u8>,
    built: BuiltCommitment,
}

impl StorageFixture {
    fn sample_4k() -> Self {
        let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commitment");
        Self { payload, built }
    }
}

fn genesis_with_funded_utxo_and_storage(
    emission: EmissionParams,
    spend_value: u64,
    storage: &StorageFixture,
) -> (ChainState, SpendState) {
    let spend_priv = random_scalar();
    let blinding = random_scalar();
    let ring_size = ring_size_for(&DEFAULT_CONSENSUS_PARAMS);
    let signer_idx = ring_size - 1;
    let mut decoys = Vec::with_capacity(ring_size - 1);
    let mut initial_outputs = Vec::with_capacity(ring_size);
    for i in 0..ring_size - 1 {
        let decoy = genesis_decoy_output(i);
        decoys.push((decoy.one_time_addr, decoy.amount));
        initial_outputs.push(decoy);
    }
    let spend = SpendState::with_ring(spend_priv, blinding, spend_value, decoys, signer_idx);
    initial_outputs.push(GenesisOutput {
        one_time_addr: spend.one_time_addr,
        amount: spend.commitment(),
    });
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage: vec![storage.built.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: emission,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    (st, spend)
}

fn apply_legacy_block_mixed(
    st: &ChainState,
    height: u32,
    txs: &[TransactionWire],
    proof: &mfn_storage::StorageProof,
) -> ChainState {
    let slot = height;
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, txs, &[], &[], std::slice::from_ref(proof), slot, ts);
    let blk = seal_block(
        unsealed,
        txs.to_vec(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof.clone()],
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

/// Privacy fees credit the treasury; SPoRA proofs drain it in the same chain (**M5.1+**).
fn run_mixed_fee_and_proof_sim(blocks: u32, emission: EmissionParams) {
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, mut spend) = genesis_with_funded_utxo_and_storage(emission, initial, &storage);
    let mut model_treasury = 0u128;

    for h in 1..=blocks {
        let fee = 2_000u64 + u64::from(h % 7_001);
        let (signed, next_spend) = spend.sign_self_transfer(fee);
        spend = next_spend;
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof(
            &storage.built.commit,
            &prev,
            h,
            &storage.payload,
            &storage.built.tree,
        );
        st = apply_legacy_block_mixed(&st, h, std::slice::from_ref(&signed.tx), &proof);
        model_treasury = treasury_after_block(model_treasury, u128::from(fee), 1, &emission);
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h} (fee {fee}, 1 proof)"
        );
        assert!(st.treasury < u128::MAX);
    }
}

/// Validator quorum + coinbase + CLSAG fee + SPoRA proof per block (**M5.0++**).
fn run_validator_mixed_fee_and_proof_sim(blocks: u32, emission: EmissionParams) {
    let fixture = ValidatorFixture::three_validators();
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, mut spend) = genesis_validator_with_funded_utxo(
        emission,
        initial,
        &fixture,
        vec![storage.built.commit.clone()],
        DEFAULT_ENDOWMENT_PARAMS,
        None,
    );
    let mut model_treasury = 0u128;

    for h in 1..=blocks {
        let fee = 2_000u64 + u64::from(h % 5_001);
        let (signed, next_spend) = spend.sign_self_transfer(fee);
        spend = next_spend;
        let fee_sum = u128::from(fee);
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof(
            &storage.built.commit,
            &prev,
            h,
            &storage.payload,
            &storage.built.tree,
        );
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            std::slice::from_ref(&proof),
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        st = apply_validator_block(&fixture, &st, h, txs, vec![proof]);
        model_treasury = treasury_after_block(model_treasury, fee_sum, 1, &emission);
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h} (fee {fee}, 1 proof)"
        );
        assert!(st.treasury < u128::MAX);
    }
}

fn run_fee_treasury_sim(blocks: u32, emission: EmissionParams) {
    let initial = 50_000_000_000u64;
    let (mut st, mut spend) = genesis_with_funded_utxo(emission, initial);
    let mut model_treasury = 0u128;
    for h in 1..=blocks {
        let fee = 1_000u64 + u64::from(h % 9_001);
        let (signed, next_spend) = spend.sign_self_transfer(fee);
        spend = next_spend;
        st = apply_legacy_block(&st, h, std::slice::from_ref(&signed.tx));
        model_treasury = treasury_after_block(model_treasury, u128::from(fee), 0, &emission);
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h} (fee {fee})"
        );
        assert!(st.treasury < u128::MAX);
    }
}

#[test]
fn sim_emission_params_validate() {
    assert!(validate_emission_params(&SIM_EMISSION).is_ok());
}

#[test]
fn debug_genesis_ring_size_is_sixteen() {
    let (_, spend) = genesis_with_funded_utxo(SIM_EMISSION, 1_000);
    assert_eq!(ring_size_for(&DEFAULT_CONSENSUS_PARAMS), 16);
    assert_eq!(spend.ring_decoys.len(), 15);
    assert_eq!(spend.input_spec().ring.p.len(), 16);
}

#[test]
fn emission_summation_matches_cumulative_over_100k_heights() {
    let p = DEFAULT_EMISSION_PARAMS;
    let max_h = 100_000u64;
    let mut running: u128 = 0;
    for h in 1..=max_h {
        running += u128::from(emission_at_height(h, &p));
        if h % 10_000 == 0 {
            assert_eq!(running, cumulative_emission(h, &p), "drift at height {h}");
        }
    }
    assert_eq!(running, cumulative_emission(max_h, &p));
}

/// Full million-height curve check (~1–2s locally). Run with `cargo test -- --ignored`.
#[test]
#[ignore = "long emission curve simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn emission_summation_matches_cumulative_over_1m_heights() {
    let p = DEFAULT_EMISSION_PARAMS;
    let max_h = 1_000_000u64;
    let mut running: u128 = 0;
    for h in 1..=max_h {
        running += u128::from(emission_at_height(h, &p));
        if h % 100_000 == 0 {
            assert_eq!(running, cumulative_emission(h, &p), "drift at height {h}");
        }
    }
    assert_eq!(running, cumulative_emission(max_h, &p));
}

#[test]
fn apply_block_advances_ten_thousand_empty_legacy_blocks() {
    let mut st = genesis_state(DEFAULT_EMISSION_PARAMS);
    for h in 1..=10_000u32 {
        st = apply_empty_legacy_block(&st, h);
        assert_eq!(st.height, Some(h));
        assert!(st.treasury < u128::MAX);
    }
}

/// Validator quorum + coinbase: CLSAG fees split between treasury and producer (**M5.0+**).
#[test]
fn treasury_ledger_matches_apply_block_over_validator_clsag_fee_blocks() {
    run_validator_fee_treasury_sim(16, SIM_EMISSION);
}

/// Validator quorum + coinbase: CLSAG fees over 96 blocks (**M5.35**).
#[test]
fn treasury_ledger_matches_apply_block_over_ninety_six_validator_clsag_fee_blocks() {
    run_validator_fee_treasury_sim(96, SIM_EMISSION);
}

/// Production path: BLS finality, coinbase with storage-reward term, fee credit + proof drain.
#[test]
fn treasury_ledger_matches_apply_block_over_validator_mixed_fee_and_proof_blocks() {
    run_validator_mixed_fee_and_proof_sim(12, SIM_EMISSION);
}

/// Validator quorum + coinbase + CLSAG fee + SPoRA proof over 64 blocks (**M5.34**, **B-03**).
#[test]
fn treasury_ledger_matches_apply_block_over_sixty_four_validator_mixed_blocks() {
    run_validator_mixed_fee_and_proof_sim(64, SIM_EMISSION);
}

/// CLSAG self-transfers in legacy mode credit `fee · fee_to_treasury_bps / 10_000`
/// to the permanence treasury each block (**M5.1**).
#[test]
fn treasury_ledger_matches_apply_block_over_clsag_fee_blocks() {
    run_fee_treasury_sim(128, SIM_EMISSION);
}

#[test]
#[ignore = "long CLSAG fee treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_apply_block_over_two_thousand_clsag_fee_blocks() {
    run_fee_treasury_sim(2_048, SIM_EMISSION);
}

/// Each block: one CLSAG self-transfer (treasury credit) + one SPoRA proof (treasury drain).
#[test]
fn treasury_ledger_matches_apply_block_over_mixed_fee_and_proof_blocks() {
    run_mixed_fee_and_proof_sim(48, SIM_EMISSION);
}

/// Legacy mixed CLSAG fee + SPoRA proof treasury ledger over 384 blocks (**M5.39**).
#[test]
fn treasury_ledger_matches_apply_block_over_three_hundred_eighty_four_mixed_blocks() {
    run_mixed_fee_and_proof_sim(384, SIM_EMISSION);
}

/// Storage-proof rewards drain an empty treasury via coinbase backstop; treasury never underflows.
#[test]
fn treasury_ledger_matches_apply_block_over_storage_proof_blocks() {
    let storage = StorageFixture::sample_4k();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![storage.built.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: SIM_EMISSION,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let mut st = apply_genesis(&g, &cfg).expect("genesis");
    let mut model_treasury = 0u128;

    for h in 1..=512u32 {
        let slot = h;
        let ts = u64::from(h) * 1_000;
        let prev = *st.tip_id().expect("tip after genesis");
        let proof = build_test_storage_proof(
            &storage.built.commit,
            &prev,
            slot,
            &storage.payload,
            &storage.built.tree,
        );
        let unsealed =
            build_unsealed_header(&st, &[], &[], &[], std::slice::from_ref(&proof), slot, ts);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proof],
        );
        st = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => state,
            ApplyOutcome::Err { errors, .. } => panic!("height {h}: {errors:?}"),
        };
        model_treasury = treasury_after_block(model_treasury, 0, 1, &SIM_EMISSION);
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h}"
        );
    }
}

/// Liveness slash + CLSAG fee + SPoRA proof in one block; treasury ledger stays non-negative (**M5.9**).
fn run_liveness_slash_mixed_treasury_sim(emission: EmissionParams) {
    struct StorageFixture {
        payload: Vec<u8>,
        built: BuiltCommitment,
    }
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let storage = StorageFixture { payload, built };

    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let initial = 50_000_000_000u64;
    let (mut st, mut spend_state) = genesis_validator_with_funded_utxo(
        emission,
        initial,
        &fixture,
        vec![storage.built.commit.clone()],
        DEFAULT_ENDOWMENT_PARAMS,
        None,
    );
    let mut model_treasury = 0u128;
    let voters = [0u32, 2];
    let liveness_forfeit = 10_000u128;

    for h in 1..=4u32 {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend_state.sign_self_transfer(fee);
        spend_state = next_spend;
        let fee_sum = u128::from(fee);
        let proofs = if h == 3 { 1u128 } else { 0 };
        let storage_proofs = if h == 3 {
            let prev = *st.tip_id().expect("tip");
            vec![build_test_storage_proof(
                &storage.built.commit,
                &prev,
                h,
                &storage.payload,
                &storage.built.tree,
            )]
        } else {
            Vec::new()
        };
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &storage_proofs,
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        if h == 3 {
            st.validator_stats[1].consecutive_missed = 2;
        }
        st = apply_validator_block_with_voters(
            &fixture,
            &[],
            &voters,
            &st,
            h,
            txs,
            storage_proofs,
            Vec::new(),
            Vec::new(),
        );
        if h == 3 {
            model_treasury = treasury_after_liveness_block(
                model_treasury,
                liveness_forfeit,
                fee_sum,
                1,
                &emission,
            );
        } else {
            model_treasury = treasury_after_block(model_treasury, fee_sum, proofs, &emission);
        }
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h}"
        );
        assert!(st.treasury < u128::MAX, "treasury must not overflow");
        if h == 3 {
            assert_eq!(st.validators[1].stake, 990_000);
        }
    }
}

#[test]
fn treasury_ledger_matches_liveness_slash_plus_fee_and_proof_blocks() {
    run_liveness_slash_mixed_treasury_sim(SIM_EMISSION);
}

/// Alternating bond / liveness / fee / proof inflows over many blocks (**M5.11**, **M5.31**, **M5.32**).
fn run_combined_inflow_treasury_sim(blocks: u32, emission: EmissionParams, initial_treasury: u128) {
    struct StorageFixture {
        payload: Vec<u8>,
        built: BuiltCommitment,
    }
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let storage = StorageFixture { payload, built };

    let fixture = ValidatorFixture::liveness_absentee_long_sim();
    let (mut st, mut spend_state) = genesis_validator_with_funded_utxo(
        emission,
        50_000_000_000,
        &fixture,
        vec![storage.built.commit.clone()],
        DEFAULT_ENDOWMENT_PARAMS,
        Some(mfn_consensus::DEFAULT_BONDING_PARAMS),
    );
    st.treasury = initial_treasury;
    let mut model_treasury = initial_treasury;
    let bond_stake = u128::from(mfn_consensus::DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let mut bond_seed = 50u8;
    let mut bond_validator_secrets: Vec<ValidatorSecrets> = Vec::new();

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend_state.sign_self_transfer(fee);
        spend_state = next_spend;
        let fee_sum = u128::from(fee);
        let with_bond = h == 8;
        let with_proof = h % 4 == 0;
        let with_liveness = h == 12;
        let proofs = if with_proof { 1u128 } else { 0 };
        let storage_proofs = if with_proof {
            let prev = *st.tip_id().expect("tip");
            vec![build_test_storage_proof(
                &storage.built.commit,
                &prev,
                h,
                &storage.payload,
                &storage.built.tree,
            )]
        } else {
            Vec::new()
        };
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &storage_proofs,
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        let bond_ops = if with_bond {
            bond_seed = bond_seed.wrapping_add(1);
            let new_index = st.validators.len() as u32;
            bond_validator_secrets.push(validator_secrets_from_bond_seed(bond_seed, new_index));
            vec![register_op_for_sim(bond_seed)]
        } else {
            Vec::new()
        };
        if with_liveness {
            st.validator_stats[1].consecutive_missed =
                fixture.params.liveness_max_consecutive_missed - 1;
        }
        let voters = active_voter_indices_for_treasury_sim(
            &st,
            &fixture,
            &bond_validator_secrets,
            with_liveness,
        );
        st = apply_validator_block_with_voters(
            &fixture,
            &bond_validator_secrets,
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
        let treasury_before_block = model_treasury;
        model_treasury = treasury_after_combined_inflow_block(
            model_treasury,
            bond_credit,
            liveness_credit,
            fee_sum,
            proofs,
            &emission,
        );
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h}"
        );
        assert!(st.treasury < u128::MAX);
        if with_liveness {
            assert_eq!(st.validators[1].stake, 990_000);
        }
        if with_proof {
            let treasury_fee = fee_sum * u128::from(emission.fee_to_treasury_bps) / 10_000;
            let pending_before_drain = treasury_before_block
                .saturating_add(bond_credit)
                .saturating_add(liveness_credit)
                .saturating_add(treasury_fee);
            let storage_reward = u128::from(emission.storage_proof_reward) * proofs;
            let from_treasury = pending_before_drain.min(storage_reward);
            let backstop = storage_reward - from_treasury;
            if backstop > 0 {
                let producer_fee = fee_sum - treasury_fee;
                let expected_cb = u128::from(emission_at_height(u64::from(h), &emission))
                    + producer_fee
                    + storage_reward;
                let cb_total =
                    producer_coinbase_amount(u64::from(h), &emission, fee_sum, proofs as usize, 0);
                assert_eq!(
                    u128::from(cb_total),
                    expected_cb,
                    "coinbase must pay full storage reward; backstop {backstop} at height {h}"
                );
            }
        }
    }
}

/// Bond/liveness/fee/PPB-proof inflows over many blocks without equivocation (**M5.28**–**M5.33**).
fn run_combined_inflow_ppb_treasury_sim(
    blocks: u32,
    emission: EmissionParams,
    initial_treasury: u128,
) {
    struct StorageFixture {
        payload: Vec<u8>,
        built: BuiltCommitment,
    }
    let payload: Vec<u8> = vec![0u8; 1 << 20];
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        SIM_PPB_ENDOWMENT.min_replication,
        None,
    )
    .expect("commitment");
    let storage = StorageFixture { payload, built };
    let commit_hash = storage_commitment_hash(&storage.built.commit);

    let fixture = ValidatorFixture::liveness_absentee_long_sim();
    let (mut st, mut spend_state) = genesis_validator_with_funded_utxo(
        emission,
        50_000_000_000,
        &fixture,
        vec![storage.built.commit.clone()],
        SIM_PPB_ENDOWMENT,
        Some(mfn_consensus::DEFAULT_BONDING_PARAMS),
    );
    st.treasury = initial_treasury;
    let mut model_treasury = initial_treasury;
    let bond_stake = u128::from(mfn_consensus::DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let mut bond_seed = 80u8;
    let mut bond_validator_secrets: Vec<ValidatorSecrets> = Vec::new();

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend_state.sign_self_transfer(fee);
        spend_state = next_spend;
        let fee_sum = u128::from(fee);
        let with_bond = h == 8;
        let with_proof = h % 4 == 0;
        let with_liveness = h == 12;
        let proofs = if with_proof { 1u128 } else { 0 };
        let ppb_bonus = if with_proof {
            let payout =
                seed_ppb_pending_and_expected_payout(&mut st, &commit_hash, h, &SIM_PPB_ENDOWMENT);
            assert!(payout > 0, "seeded PPB must cross integer payout boundary");
            payout
        } else {
            0
        };
        let storage_proofs = if with_proof {
            let prev = *st.tip_id().expect("tip");
            let proof = build_test_storage_proof(
                &storage.built.commit,
                &prev,
                h,
                &storage.payload,
                &storage.built.tree,
            );
            let bonus = storage_proof_coinbase_bonus(
                std::slice::from_ref(&proof),
                &st.storage,
                h,
                &SIM_PPB_ENDOWMENT,
            );
            assert_eq!(bonus, ppb_bonus, "PPB bonus must match accrual payout");
            vec![proof]
        } else {
            Vec::new()
        };
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &storage_proofs,
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        let bond_ops = if with_bond {
            bond_seed = bond_seed.wrapping_add(1);
            let new_index = st.validators.len() as u32;
            bond_validator_secrets.push(validator_secrets_from_bond_seed(bond_seed, new_index));
            vec![register_op_for_sim(bond_seed)]
        } else {
            Vec::new()
        };
        if with_liveness {
            st.validator_stats[1].consecutive_missed =
                fixture.params.liveness_max_consecutive_missed - 1;
        }
        let voters = active_voter_indices_for_treasury_sim(
            &st,
            &fixture,
            &bond_validator_secrets,
            with_liveness,
        );
        st = apply_validator_block_with_voters(
            &fixture,
            &bond_validator_secrets,
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
        let treasury_before_block = model_treasury;
        model_treasury = treasury_after_combined_inflow_block_with_ppb_bonus(
            model_treasury,
            bond_credit,
            liveness_credit,
            fee_sum,
            proofs,
            ppb_bonus,
            &emission,
        );
        assert_eq!(
            st.treasury, model_treasury,
            "PPB combined inflow treasury mismatch at height {h}"
        );
        assert!(st.treasury < u128::MAX);
        if with_liveness {
            assert_eq!(st.validators[1].stake, 990_000);
        }
        if with_proof {
            let treasury_fee = fee_sum * u128::from(emission.fee_to_treasury_bps) / 10_000;
            let pending_before_drain = treasury_before_block
                .saturating_add(bond_credit)
                .saturating_add(liveness_credit)
                .saturating_add(treasury_fee);
            let storage_reward = u128::from(emission.storage_proof_reward) * proofs + ppb_bonus;
            let from_treasury = pending_before_drain.min(storage_reward);
            let backstop = storage_reward - from_treasury;
            if backstop > 0 {
                let producer_fee = fee_sum - treasury_fee;
                let expected_cb = u128::from(emission_at_height(u64::from(h), &emission))
                    + producer_fee
                    + storage_reward;
                let cb_total =
                    producer_coinbase_amount(u64::from(h), &emission, fee_sum, proofs as usize, 0);
                assert_eq!(
                    u128::from(cb_total),
                    expected_cb,
                    "coinbase must pay full PPB-augmented storage reward; backstop {backstop} at height {h}"
                );
            }
        }
    }
}

fn register_op_for_sim(seed: u8) -> mfn_consensus::BondOp {
    use mfn_consensus::{sign_register, BondOp, DEFAULT_BONDING_PARAMS};
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

fn validator_secrets_from_bond_seed(seed: u8, validator_index: u32) -> ValidatorSecrets {
    let bls = bls_keygen_from_seed(&[seed.wrapping_add(1); 32]);
    let vrf = vrf_keygen_from_seed(&[seed.wrapping_add(101); 32]).expect("vrf");
    ValidatorSecrets {
        index: validator_index,
        vrf,
        bls,
    }
}

fn validator_secrets_for_index<'a>(
    fixture: &'a ValidatorFixture,
    bond_secrets: &'a [ValidatorSecrets],
    index: u32,
) -> &'a ValidatorSecrets {
    if index < fixture.secrets.len() as u32 {
        &fixture.secrets[index as usize]
    } else {
        &bond_secrets[(index as usize) - fixture.secrets.len()]
    }
}

/// All staked validators vote except on intentional absentee blocks (**M5.22**).
fn active_voter_indices_for_treasury_sim(
    st: &ChainState,
    fixture: &ValidatorFixture,
    bond_secrets: &[ValidatorSecrets],
    intentional_absentee_block: bool,
) -> Vec<u32> {
    if intentional_absentee_block {
        vec![0, 2]
    } else {
        st.validators
            .iter()
            .enumerate()
            .filter(|(i, v)| {
                v.stake > 0
                    && (*i < fixture.secrets.len()
                        || *i - fixture.secrets.len() < bond_secrets.len())
            })
            .map(|(i, _)| i as u32)
            .collect()
    }
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

#[test]
fn treasury_ledger_matches_combined_inflow_blocks() {
    run_combined_inflow_treasury_sim(16, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_sixty_four_combined_inflow_blocks() {
    run_combined_inflow_treasury_sim(64, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_two_hundred_fifty_six_combined_inflow_blocks() {
    run_combined_inflow_treasury_sim(256, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_five_hundred_twelve_combined_inflow_blocks() {
    run_combined_inflow_treasury_sim(512, SIM_EMISSION, 0);
}

/// Partial treasury prefund, no equivocation: proof blocks drain treasury first; backstop on shortfall (**M5.31**).
#[test]
fn treasury_ledger_matches_prefunded_combined_inflow_blocks() {
    run_combined_inflow_treasury_sim(32, SIM_EMISSION, 10);
}

#[test]
fn treasury_ledger_matches_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(16, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow PPB treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_sixty_four_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(64, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow PPB treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_one_hundred_twenty_eight_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(128, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow PPB treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_two_hundred_fifty_six_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(256, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long combined inflow PPB treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_five_hundred_twelve_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(512, SIM_EMISSION, 0);
}

/// Partial treasury prefund with PPB proof drain, no equivocation: treasury first, backstop on shortfall (**M5.29**).
#[test]
fn treasury_ledger_matches_prefunded_combined_inflow_ppb_blocks() {
    run_combined_inflow_ppb_treasury_sim(32, SIM_EMISSION, 10);
}

/// Bond/liveness/fee/proof inflows with terminal equivocation slash (**M5.13**, **M5.16**).
fn run_equivocation_combined_inflow_treasury_sim(
    blocks: u32,
    emission: EmissionParams,
    initial_treasury: u128,
) {
    struct StorageFixture {
        payload: Vec<u8>,
        built: BuiltCommitment,
    }
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let storage = StorageFixture { payload, built };

    let fixture = ValidatorFixture::liveness_absentee_long_sim();
    let (mut st, mut spend_state) = genesis_validator_with_funded_utxo(
        emission,
        50_000_000_000,
        &fixture,
        vec![storage.built.commit.clone()],
        DEFAULT_ENDOWMENT_PARAMS,
        Some(mfn_consensus::DEFAULT_BONDING_PARAMS),
    );
    st.treasury = initial_treasury;
    let mut model_treasury = initial_treasury;
    const EQUIVOCATION_IDX: u32 = 2;
    let bond_stake = u128::from(mfn_consensus::DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let mut bond_seed = 60u8;
    let mut bond_validator_secrets: Vec<ValidatorSecrets> = Vec::new();
    let liveness_h = blocks / 2;

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend_state.sign_self_transfer(fee);
        spend_state = next_spend;
        let fee_sum = u128::from(fee);
        let with_bond = h == 8;
        let with_proof = h % 4 == 0;
        let with_liveness = h == liveness_h;
        let with_equivocation = h == blocks;
        let proofs = if with_proof { 1u128 } else { 0 };
        let equivocation_credit = if with_equivocation {
            u128::from(st.validators[EQUIVOCATION_IDX as usize].stake)
        } else {
            0
        };
        let storage_proofs = if with_proof {
            let prev = *st.tip_id().expect("tip");
            vec![build_test_storage_proof(
                &storage.built.commit,
                &prev,
                h,
                &storage.payload,
                &storage.built.tree,
            )]
        } else {
            Vec::new()
        };
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &storage_proofs,
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        let bond_ops = if with_bond {
            bond_seed = bond_seed.wrapping_add(1);
            let new_index = st.validators.len() as u32;
            bond_validator_secrets.push(validator_secrets_from_bond_seed(bond_seed, new_index));
            vec![register_op_for_sim(bond_seed)]
        } else {
            Vec::new()
        };
        let slashings = if with_equivocation {
            vec![equivocation_evidence(
                h,
                h,
                EQUIVOCATION_IDX,
                &fixture.secrets[EQUIVOCATION_IDX as usize].bls.sk,
            )]
        } else {
            Vec::new()
        };
        if h > liveness_h {
            st.validator_stats[1].consecutive_missed = 0;
        }
        if with_liveness {
            st.validator_stats[1].consecutive_missed =
                fixture.params.liveness_max_consecutive_missed - 1;
        }
        let voters = active_voter_indices_for_treasury_sim(
            &st,
            &fixture,
            &bond_validator_secrets,
            with_liveness,
        );
        st = apply_validator_block_with_voters(
            &fixture,
            &bond_validator_secrets,
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
        let treasury_before_block = model_treasury;
        model_treasury = treasury_after_equivocation_combined_inflow_block(
            model_treasury,
            equivocation_credit,
            bond_credit,
            liveness_credit,
            fee_sum,
            proofs,
            &emission,
        );
        assert_eq!(
            st.treasury, model_treasury,
            "treasury mismatch at height {h}"
        );
        assert!(st.treasury < u128::MAX);
        if with_liveness {
            assert_eq!(st.validators[1].stake, 990_000);
        }
        if with_equivocation {
            assert_eq!(
                st.validators[EQUIVOCATION_IDX as usize].stake, 0,
                "equivocation must zero slashed validator stake"
            );
        }
        if with_proof {
            let treasury_fee = fee_sum * u128::from(emission.fee_to_treasury_bps) / 10_000;
            let pending_before_drain = treasury_before_block
                .saturating_add(equivocation_credit)
                .saturating_add(bond_credit)
                .saturating_add(liveness_credit)
                .saturating_add(treasury_fee);
            let storage_reward = u128::from(emission.storage_proof_reward) * proofs;
            let from_treasury = pending_before_drain.min(storage_reward);
            let backstop = storage_reward - from_treasury;
            if backstop > 0 {
                let producer_fee = fee_sum - treasury_fee;
                let expected_cb = u128::from(emission_at_height(u64::from(h), &emission))
                    + producer_fee
                    + storage_reward;
                let cb_total =
                    producer_coinbase_amount(u64::from(h), &emission, fee_sum, proofs as usize, 0);
                assert_eq!(
                    u128::from(cb_total),
                    expected_cb,
                    "coinbase must pay full storage reward; backstop {backstop} at height {h}"
                );
            }
        }
    }
}

/// Equivocation combined inflow with PPB-augmented proof treasury drain (**M5.23**).
fn run_equivocation_combined_inflow_ppb_treasury_sim(
    blocks: u32,
    emission: EmissionParams,
    initial_treasury: u128,
) {
    struct StorageFixture {
        payload: Vec<u8>,
        built: BuiltCommitment,
    }
    let payload: Vec<u8> = vec![0u8; 1 << 20];
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        SIM_PPB_ENDOWMENT.min_replication,
        None,
    )
    .expect("commitment");
    let storage = StorageFixture { payload, built };
    let commit_hash = storage_commitment_hash(&storage.built.commit);

    let fixture = ValidatorFixture::liveness_absentee_long_sim();
    let (mut st, mut spend_state) = genesis_validator_with_funded_utxo(
        emission,
        50_000_000_000,
        &fixture,
        vec![storage.built.commit.clone()],
        SIM_PPB_ENDOWMENT,
        Some(mfn_consensus::DEFAULT_BONDING_PARAMS),
    );
    st.treasury = initial_treasury;
    let mut model_treasury = initial_treasury;
    const EQUIVOCATION_IDX: u32 = 2;
    let bond_stake = u128::from(mfn_consensus::DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let mut bond_seed = 70u8;
    let mut bond_validator_secrets: Vec<ValidatorSecrets> = Vec::new();
    let liveness_h = blocks / 2;

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend_state.sign_self_transfer(fee);
        spend_state = next_spend;
        let fee_sum = u128::from(fee);
        let with_bond = h == 8;
        let with_proof = h % 4 == 0;
        let with_liveness = h == liveness_h;
        let with_equivocation = h == blocks;
        let proofs = if with_proof { 1u128 } else { 0 };
        let equivocation_credit = if with_equivocation {
            u128::from(st.validators[EQUIVOCATION_IDX as usize].stake)
        } else {
            0
        };
        let ppb_bonus = if with_proof {
            let payout =
                seed_ppb_pending_and_expected_payout(&mut st, &commit_hash, h, &SIM_PPB_ENDOWMENT);
            assert!(payout > 0, "seeded PPB must cross integer payout boundary");
            payout
        } else {
            0
        };
        let storage_proofs = if with_proof {
            let prev = *st.tip_id().expect("tip");
            let proof = build_test_storage_proof(
                &storage.built.commit,
                &prev,
                h,
                &storage.payload,
                &storage.built.tree,
            );
            let bonus = storage_proof_coinbase_bonus(
                std::slice::from_ref(&proof),
                &st.storage,
                h,
                &SIM_PPB_ENDOWMENT,
            );
            assert_eq!(bonus, ppb_bonus, "PPB bonus must match accrual payout");
            vec![proof]
        } else {
            Vec::new()
        };
        let coinbase = build_validator_coinbase(
            u64::from(h),
            &emission,
            fee_sum,
            &fixture.payout,
            &st,
            h,
            &storage_proofs,
        );
        assert_producer_coinbase_decryptable(&coinbase, &fixture, u64::from(h), &emission, fee_sum);
        let txs = vec![coinbase, signed.tx];
        let bond_ops = if with_bond {
            bond_seed = bond_seed.wrapping_add(1);
            let new_index = st.validators.len() as u32;
            bond_validator_secrets.push(validator_secrets_from_bond_seed(bond_seed, new_index));
            vec![register_op_for_sim(bond_seed)]
        } else {
            Vec::new()
        };
        let slashings = if with_equivocation {
            vec![equivocation_evidence(
                h,
                h,
                EQUIVOCATION_IDX,
                &fixture.secrets[EQUIVOCATION_IDX as usize].bls.sk,
            )]
        } else {
            Vec::new()
        };
        if h > liveness_h {
            st.validator_stats[1].consecutive_missed = 0;
        }
        if with_liveness {
            st.validator_stats[1].consecutive_missed =
                fixture.params.liveness_max_consecutive_missed - 1;
        }
        let voters = active_voter_indices_for_treasury_sim(
            &st,
            &fixture,
            &bond_validator_secrets,
            with_liveness,
        );
        st = apply_validator_block_with_voters(
            &fixture,
            &bond_validator_secrets,
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
        let treasury_before_block = model_treasury;
        model_treasury = treasury_after_equivocation_combined_inflow_block_with_ppb_bonus(
            model_treasury,
            equivocation_credit,
            bond_credit,
            liveness_credit,
            fee_sum,
            proofs,
            ppb_bonus,
            &emission,
        );
        assert_eq!(
            st.treasury, model_treasury,
            "PPB treasury mismatch at height {h}"
        );
        assert!(st.treasury < u128::MAX);
        if with_liveness {
            assert_eq!(st.validators[1].stake, 990_000);
        }
        if with_equivocation {
            assert_eq!(
                st.validators[EQUIVOCATION_IDX as usize].stake, 0,
                "equivocation must zero slashed validator stake"
            );
        }
        if with_proof {
            let treasury_fee = fee_sum * u128::from(emission.fee_to_treasury_bps) / 10_000;
            let pending_before_drain = treasury_before_block
                .saturating_add(equivocation_credit)
                .saturating_add(bond_credit)
                .saturating_add(liveness_credit)
                .saturating_add(treasury_fee);
            let storage_reward = u128::from(emission.storage_proof_reward) * proofs + ppb_bonus;
            let from_treasury = pending_before_drain.min(storage_reward);
            let backstop = storage_reward - from_treasury;
            if backstop > 0 {
                let producer_fee = fee_sum - treasury_fee;
                let expected_cb = u128::from(emission_at_height(u64::from(h), &emission))
                    + producer_fee
                    + storage_reward;
                let cb_total =
                    producer_coinbase_amount(u64::from(h), &emission, fee_sum, proofs as usize, 0);
                assert_eq!(
                    u128::from(cb_total),
                    expected_cb,
                    "coinbase must pay full PPB-augmented storage reward; backstop {backstop} at height {h}"
                );
            }
        }
    }
}

#[test]
fn treasury_ledger_matches_equivocation_combined_inflow_blocks() {
    run_equivocation_combined_inflow_treasury_sim(32, SIM_EMISSION, 0);
}

#[test]
fn treasury_ledger_matches_sixty_four_equivocation_combined_inflow_blocks() {
    run_equivocation_combined_inflow_treasury_sim(64, SIM_EMISSION, 0);
}

/// Partial treasury prefund: proof blocks drain treasury first; emission backstop fills shortfall (**M5.19**).
#[test]
fn treasury_ledger_matches_prefunded_equivocation_combined_inflow_blocks() {
    run_equivocation_combined_inflow_treasury_sim(32, SIM_EMISSION, 10);
}

#[test]
fn treasury_ledger_matches_equivocation_combined_inflow_ppb_blocks() {
    run_equivocation_combined_inflow_ppb_treasury_sim(32, SIM_EMISSION, 0);
}

/// Partial treasury prefund with PPB proof drain: treasury first, backstop on shortfall (**M5.24**).
#[test]
fn treasury_ledger_matches_prefunded_equivocation_combined_inflow_ppb_blocks() {
    run_equivocation_combined_inflow_ppb_treasury_sim(32, SIM_EMISSION, 10);
}

#[test]
#[ignore = "long equivocation PPB combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_sixty_four_equivocation_combined_inflow_ppb_blocks() {
    run_equivocation_combined_inflow_ppb_treasury_sim(64, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long equivocation PPB combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_one_hundred_twenty_eight_equivocation_combined_inflow_ppb_blocks() {
    run_equivocation_combined_inflow_ppb_treasury_sim(128, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long equivocation combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_one_hundred_twenty_eight_equivocation_combined_inflow_blocks() {
    run_equivocation_combined_inflow_treasury_sim(128, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long equivocation combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_five_hundred_twelve_equivocation_combined_inflow_blocks() {
    run_equivocation_combined_inflow_treasury_sim(512, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long equivocation PPB combined inflow treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_five_hundred_twelve_equivocation_combined_inflow_ppb_blocks() {
    run_equivocation_combined_inflow_ppb_treasury_sim(512, SIM_EMISSION, 0);
}

#[test]
#[ignore = "long apply_block simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn apply_block_hundred_thousand_empty_legacy_blocks() {
    let mut st = genesis_state(SIM_EMISSION);
    for h in 1..=100_000u32 {
        st = apply_empty_legacy_block(&st, h);
    }
    assert_eq!(st.height, Some(100_000));
}
