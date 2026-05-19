//! Long-horizon emission / treasury simulations (**M5.0**, **M5.0+**, **M5.1**, **M5.1+**).
//!
//! Fast curve checks run in default CI; million-block and deep `apply_block`
//! harnesses are `#[ignore]` (see `scripts/ci-ignored.sh` pattern / nightly).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    apply_block, apply_genesis, build_coinbase, build_genesis, build_unsealed_header, cast_vote,
    cumulative_emission, emission_at_height, encode_finality_proof, finalize, header_signing_hash,
    seal_block, sign_transaction, try_produce_slot, validate_emission_params, ApplyOutcome,
    ChainState, ConsensusParams, EmissionParams, FinalityProof, GenesisConfig, GenesisOutput,
    InputSpec, OutputSpec, PayoutAddress, SignedTransaction, SlotContext, TransactionWire,
    Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_CONSENSUS_PARAMS,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    build_storage_commitment, build_storage_proof, BuiltCommitment, DEFAULT_ENDOWMENT_PARAMS,
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

/// Coinbase amount `apply_block` expects (subsidy + producer fee share + storage rewards).
fn expected_coinbase_amount(
    height: u32,
    fee_sum: u128,
    storage_proofs: u128,
    params: &EmissionParams,
) -> u64 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let producer_fee = fee_sum - treasury_fee;
    let storage_reward_total = params.storage_proof_reward as u128 * storage_proofs;
    let subsidy = u128::from(emission_at_height(u64::from(height), params));
    let total = subsidy
        .saturating_add(producer_fee)
        .saturating_add(storage_reward_total);
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// Three-validator quorum harness (BLS finality + coinbase payout).
struct ValidatorFixture {
    validators: Vec<Validator>,
    secrets: Vec<ValidatorSecrets>,
    payout: PayoutAddress,
    params: ConsensusParams,
    total_stake: u64,
}

impl ValidatorFixture {
    fn three_validators() -> Self {
        let mk = |i: u32, stake: u64| -> (Validator, ValidatorSecrets) {
            let vrf = vrf_keygen_from_seed(&[i.wrapping_add(1); 32]).expect("vrf");
            let bls = bls_keygen_from_seed(&[i.wrapping_add(101); 32]);
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
            (val, secrets)
        };
        let (v0, s0) = mk(0, 100);
        let (v1, s1) = mk(1, 100);
        let (v2, s2) = mk(2, 100);
        let validators = vec![v0.clone(), v1, v2];
        let secrets = vec![s0, s1, s2];
        let payout = PayoutAddress {
            view_pub: v0.payout.as_ref().unwrap().view_pub,
            spend_pub: v0.payout.as_ref().unwrap().spend_pub,
        };
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

fn genesis_validator_with_funded_utxo(
    emission: EmissionParams,
    spend_value: u64,
    fixture: &ValidatorFixture,
) -> (ChainState, SpendState) {
    let spend_priv = random_scalar();
    let blinding = random_scalar();
    let spend = SpendState::genesis(spend_priv, blinding, spend_value);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: spend.one_time_addr,
            amount: spend.commitment(),
        }],
        initial_storage: Vec::new(),
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: emission,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
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

/// Validator-mode blocks: BLS finality, coinbase pays subsidy + producer fee share; treasury
/// credits the permanence pool from the fee split (**M5.0+**).
fn run_validator_fee_treasury_sim(blocks: u32, emission: EmissionParams) {
    let fixture = ValidatorFixture::three_validators();
    let initial = 50_000_000_000u64;
    let (mut st, mut spend) = genesis_validator_with_funded_utxo(emission, initial, &fixture);
    let mut model_treasury = 0u128;

    for h in 1..=blocks {
        let fee = 2_500u64 + u64::from(h % 4_501);
        let (signed, next_spend) = spend.sign_self_transfer(fee);
        spend = next_spend;
        let fee_sum = u128::from(fee);
        let cb_amount = expected_coinbase_amount(h, fee_sum, 0, &emission);
        let coinbase = build_coinbase(u64::from(h), cb_amount, &fixture.payout).expect("coinbase");
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

/// Spendable UTXO the simulator chains block-to-block via `OutputSpec::Raw` change.
struct SpendState {
    spend_priv: Scalar,
    blinding: Scalar,
    value: u64,
    one_time_addr: EdwardsPoint,
}

impl SpendState {
    fn genesis(spend_priv: Scalar, blinding: Scalar, value: u64) -> Self {
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
        };
        (signed, next)
    }
}

fn genesis_with_funded_utxo(emission: EmissionParams, value: u64) -> (ChainState, SpendState) {
    let spend_priv = random_scalar();
    let blinding = random_scalar();
    let spend = SpendState::genesis(spend_priv, blinding, value);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: spend.one_time_addr,
            amount: spend.commitment(),
        }],
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
    let spend = SpendState::genesis(spend_priv, blinding, spend_value);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: spend.one_time_addr,
            amount: spend.commitment(),
        }],
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
        let proof = build_storage_proof(
            &storage.built.commit,
            &prev,
            h,
            &storage.payload,
            &storage.built.tree,
        )
        .expect("proof");
        st = apply_legacy_block_mixed(&st, h, std::slice::from_ref(&signed.tx), &proof);
        model_treasury = treasury_after_block(model_treasury, u128::from(fee), 1, &emission);
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

#[test]
#[ignore = "long validator CLSAG fee treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn treasury_ledger_matches_apply_block_over_ninety_six_validator_clsag_fee_blocks() {
    run_validator_fee_treasury_sim(96, SIM_EMISSION);
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

#[test]
#[ignore = "long mixed fee+proof treasury simulation; run with cargo test -p mfn-consensus -- --ignored"]
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
        let proof = build_storage_proof(
            &storage.built.commit,
            &prev,
            slot,
            &storage.payload,
            &storage.built.tree,
        )
        .expect("proof");
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

#[test]
#[ignore = "long apply_block simulation; run with cargo test -p mfn-consensus -- --ignored"]
fn apply_block_hundred_thousand_empty_legacy_blocks() {
    let mut st = genesis_state(SIM_EMISSION);
    for h in 1..=100_000u32 {
        st = apply_empty_legacy_block(&st, h);
    }
    assert_eq!(st.height, Some(100_000));
}
