//! Producer revenue and treasury settlement invariants (**M5.7**, **M5.7+**).
//!
//! Locks the economics from [`docs/ECONOMICS.md`]: coinbase pays
//! `emission(height) + producer fee share (+ storage rewards + PPB bonus)`;
//! fees split 90/10 treasury/producer by default; storage rewards drain treasury
//! first; emission backstop covers only the treasury shortfall; validator bond
//! burns credit treasury before fee settlement in the closed loop.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    apply_block, apply_genesis, build_coinbase, build_genesis, build_unsealed_header, cast_vote,
    emission_at_height, encode_finality_proof, finalize, header_signing_hash,
    producer_coinbase_amount, seal_block, sign_register, sign_transaction,
    storage_proof_coinbase_bonus, try_produce_slot, ApplyOutcome, BlockError, BondOp, ChainState,
    ConsensusParams, EmissionParams, FinalityProof, GenesisConfig, GenesisOutput, InputSpec,
    OutputSpec, PayoutAddress, SignedTransaction, SlotContext, TransactionWire, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    accrue_proof_reward, build_storage_commitment, build_storage_proof, storage_commitment_hash,
    AccrueArgs, BuiltCommitment, EndowmentParams, DEFAULT_ENDOWMENT_PARAMS, PPB,
};

/// Compact schedule for fast `apply_block` loops.
const TEST_EMISSION: EmissionParams = EmissionParams {
    initial_reward: 1_000,
    halving_period: 64,
    halving_count: 4,
    tail_emission: 50,
    storage_proof_reward: 25,
    fee_to_treasury_bps: 9000,
};

fn fee_split(fee: u128, bps: u16) -> (u128, u128) {
    let treasury = fee * u128::from(bps) / 10_000;
    (treasury, fee - treasury)
}

/// Treasury balance after `apply_block` settlement (fees in, storage drain out).
fn treasury_after_settlement(
    treasury: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let storage_reward = u128::from(params.storage_proof_reward) * accepted_proofs;
    let mut pending = treasury.saturating_add(treasury_fee);
    let from_treasury = pending.min(storage_reward);
    pending -= from_treasury;
    pending
}

/// Bond burns credit treasury before fee settlement; mirrors `apply_block` ordering.
fn treasury_after_block(
    treasury: u128,
    bond_burn: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement(
        treasury.saturating_add(bond_burn),
        fee_sum,
        accepted_proofs,
        params,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StateSnap {
    height: Option<u32>,
    treasury: u128,
    block_ids_len: usize,
    tip: Option<[u8; 32]>,
    utxo_len: usize,
}

fn snap(st: &ChainState) -> StateSnap {
    StateSnap {
        height: st.height,
        treasury: st.treasury,
        block_ids_len: st.block_ids.len(),
        tip: st.tip_id().copied(),
        utxo_len: st.utxo.len(),
    }
}

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
            (val, secrets)
        };
        let (v0, s0) = mk(0, 100);
        let (v1, s1) = mk(1, 100);
        let (v2, s2) = mk(2, 100);
        let producer_wallet = stealth_gen();
        let payout = PayoutAddress {
            view_pub: producer_wallet.view_pub,
            spend_pub: producer_wallet.spend_pub,
        };
        let mut validators = vec![v0, v1, v2];
        validators[0].payout = Some(ValidatorPayout {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        });
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6667,
            ..ConsensusParams::default()
        };
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            secrets: vec![s0, s1, s2],
            payout,
            params,
            total_stake,
        }
    }
}

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

fn genesis_validator_with_funded_utxo(
    emission: EmissionParams,
    spend_value: u64,
    fixture: &ValidatorFixture,
    storage: Option<&StorageFixture>,
    endowment_params: EndowmentParams,
    enable_bonding: bool,
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
        initial_storage: storage
            .map(|s| vec![s.built.commit.clone()])
            .unwrap_or_default(),
        validators: fixture.validators.clone(),
        params: fixture.params,
        emission_params: emission,
        endowment_params,
        bonding_params: if enable_bonding {
            Some(DEFAULT_BONDING_PARAMS)
        } else {
            None
        },
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).expect("genesis");
    (st, spend)
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

fn apply_validator_block(
    fixture: &ValidatorFixture,
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
    bond_ops: Vec<BondOp>,
    slot: u32,
) -> ApplyOutcome {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &txs, &bond_ops, &[], &storage_proofs, slot, ts);
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
        bond_ops,
        encode_finality_proof(&fin),
        Vec::new(),
        storage_proofs,
    );
    apply_block(st, &blk)
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

// ---- Invariant tests -------------------------------------------------------

#[test]
fn default_fee_split_is_ninety_ten() {
    assert_eq!(DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps, 9000);
    let fee = 10_000u128;
    let (treasury, producer) = fee_split(fee, DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps);
    assert_eq!(treasury, 9_000);
    assert_eq!(producer, 1_000);
    assert_eq!(treasury + producer, fee);
}

#[test]
fn producer_coinbase_amount_is_emission_plus_producer_fee_share() {
    let height = 1u64;
    let fee = 50_000u128;
    let amount = producer_coinbase_amount(height, &TEST_EMISSION, fee, 0, 0);
    let (treasury_fee, producer_fee) = fee_split(fee, TEST_EMISSION.fee_to_treasury_bps);
    let _ = treasury_fee;
    let subsidy = u128::from(emission_at_height(height, &TEST_EMISSION));
    assert_eq!(
        u128::from(amount),
        subsidy + producer_fee,
        "coinbase = emission + producer fee share (no storage proofs)"
    );
}

#[test]
fn producer_coinbase_amount_includes_full_storage_rewards() {
    let height = 3u64;
    let fee = 7_777u128;
    let proofs = 2usize;
    let bonus = 13u128;
    let amount = producer_coinbase_amount(height, &TEST_EMISSION, fee, proofs, bonus);
    let (_, producer_fee) = fee_split(fee, TEST_EMISSION.fee_to_treasury_bps);
    let storage_total = u128::from(TEST_EMISSION.storage_proof_reward) * proofs as u128 + bonus;
    let subsidy = u128::from(emission_at_height(height, &TEST_EMISSION));
    assert_eq!(
        u128::from(amount),
        subsidy + producer_fee + storage_total,
        "coinbase includes emission, producer fee share, and all storage rewards"
    );
}

#[test]
fn fee_only_block_credits_treasury_ninety_percent() {
    let initial = 50_000_000_000u64;
    let (mut st, spend) = {
        let spend_priv = random_scalar();
        let blinding = random_scalar();
        let spend = SpendState::genesis(spend_priv, blinding, initial);
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![GenesisOutput {
                one_time_addr: spend.one_time_addr,
                amount: spend.commitment(),
            }],
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: TEST_EMISSION,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).expect("genesis");
        (st, spend)
    };

    let fee = 10_000u64;
    let (signed, _next_spend) = spend.sign_self_transfer(fee);
    let before = st.treasury;
    st = apply_legacy_block(&st, 1, std::slice::from_ref(&signed.tx));

    let (treasury_share, _) = fee_split(u128::from(fee), TEST_EMISSION.fee_to_treasury_bps);
    assert_eq!(st.treasury, before + treasury_share);
    assert_eq!(
        st.treasury,
        treasury_after_settlement(before, u128::from(fee), 0, &TEST_EMISSION)
    );
}

#[test]
fn storage_reward_drains_prefunded_treasury_first() {
    let fixture = ValidatorFixture::three_validators();
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        DEFAULT_ENDOWMENT_PARAMS,
        false,
    );

    // Block 1: fee inflow prefunds treasury (90%).
    let fee = 10_000u64;
    let (signed, _next_spend) = spend.sign_self_transfer(fee);
    let cb1 = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    let coinbase1 = build_coinbase(1, cb1, &fixture.payout).expect("coinbase");
    let txs1 = vec![coinbase1, signed.tx];
    st = match apply_validator_block(&fixture, &st, 1, txs1, Vec::new(), Vec::new(), 1) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 1: {errors:?}"),
    };
    let prefunded = st.treasury;
    let (treasury_fee, _) = fee_split(u128::from(fee), TEST_EMISSION.fee_to_treasury_bps);
    assert_eq!(prefunded, treasury_fee);
    assert!(prefunded >= u128::from(TEST_EMISSION.storage_proof_reward));

    // Block 2: storage proof drains treasury before any backstop.
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        2,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let cb2 = producer_coinbase_amount(2, &TEST_EMISSION, 0, 1, 0);
    let coinbase2 = build_coinbase(2, cb2, &fixture.payout).expect("coinbase");
    let txs2 = vec![coinbase2];
    st = match apply_validator_block(&fixture, &st, 2, txs2, vec![proof], Vec::new(), 2) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 2: {errors:?}"),
    };

    let expected_treasury = treasury_after_settlement(prefunded, 0, 1, &TEST_EMISSION);
    assert_eq!(st.treasury, expected_treasury);
    assert_eq!(
        st.treasury,
        prefunded - u128::from(TEST_EMISSION.storage_proof_reward),
        "treasury must cover storage reward before backstop mints"
    );

    let subsidy = u128::from(emission_at_height(2, &TEST_EMISSION));
    let storage_reward = u128::from(TEST_EMISSION.storage_proof_reward);
    assert_eq!(
        u128::from(cb2),
        subsidy + storage_reward,
        "coinbase still pays full storage reward to producer"
    );
}

#[test]
fn emission_backstop_only_when_treasury_short() {
    let fixture = ValidatorFixture::three_validators();
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, _) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        DEFAULT_ENDOWMENT_PARAMS,
        false,
    );

    // Empty treasury: entire storage reward is backstop-minted via coinbase.
    assert_eq!(st.treasury, 0);
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let cb_amount = producer_coinbase_amount(1, &TEST_EMISSION, 0, 1, 0);
    let coinbase = build_coinbase(1, cb_amount, &fixture.payout).expect("coinbase");
    st = match apply_validator_block(&fixture, &st, 1, vec![coinbase], vec![proof], Vec::new(), 1) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 1: {errors:?}"),
    };
    assert_eq!(
        st.treasury, 0,
        "treasury stays empty when backstop covers drain"
    );
    let subsidy = u128::from(emission_at_height(1, &TEST_EMISSION));
    let storage_reward = u128::from(TEST_EMISSION.storage_proof_reward);
    assert_eq!(
        u128::from(cb_amount),
        subsidy + storage_reward,
        "backstop appears in coinbase, not as negative treasury"
    );

    // Partial treasury: only the shortfall is backstop-minted.
    st.treasury = 10;
    let prev2 = *st.tip_id().expect("tip");
    let proof2 = build_storage_proof(
        &storage.built.commit,
        &prev2,
        2,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let cb2 = producer_coinbase_amount(2, &TEST_EMISSION, 0, 1, 0);
    let coinbase2 = build_coinbase(2, cb2, &fixture.payout).expect("coinbase");
    st = match apply_validator_block(
        &fixture,
        &st,
        2,
        vec![coinbase2],
        vec![proof2],
        Vec::new(),
        2,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 2: {errors:?}"),
    };
    assert_eq!(st.treasury, 0, "treasury drained to zero, never negative");
    let backstop = storage_reward - 10;
    let subsidy2 = u128::from(emission_at_height(2, &TEST_EMISSION));
    assert_eq!(
        u128::from(cb2),
        subsidy2 + storage_reward,
        "coinbase pays full storage reward; backstop portion = {backstop}"
    );
}

#[test]
fn invalid_coinbase_amount_rejected_without_state_change() {
    let fixture = ValidatorFixture::three_validators();
    let initial = 50_000_000_000u64;
    let (st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        None,
        DEFAULT_ENDOWMENT_PARAMS,
        false,
    );
    let before = snap(&st);

    let fee = 5_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let correct = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    // Underpay: subsidy only, omitting producer fee share.
    let wrong = emission_at_height(1, &TEST_EMISSION);
    assert_ne!(wrong, correct);
    let bad_coinbase = build_coinbase(1, wrong, &fixture.payout).expect("coinbase");
    let txs = vec![bad_coinbase, signed.tx];

    match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), Vec::new(), 1) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::CoinbaseInvalid(_))),
                "expected CoinbaseInvalid, got {errors:?}"
            );
            assert_eq!(snap(&st), before, "state must be unchanged on reject");
        }
        ApplyOutcome::Ok { .. } => panic!("underpaid coinbase must reject"),
    }
}

#[test]
fn overpaid_coinbase_amount_rejected_without_state_change() {
    let fixture = ValidatorFixture::three_validators();
    let initial = 50_000_000_000u64;
    let (st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        None,
        DEFAULT_ENDOWMENT_PARAMS,
        false,
    );
    let before = snap(&st);

    let fee = 5_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let correct = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    let wrong = correct + 1;
    assert_ne!(wrong, correct);
    let bad_coinbase = build_coinbase(1, wrong, &fixture.payout).expect("coinbase");
    let txs = vec![bad_coinbase, signed.tx];

    match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), Vec::new(), 1) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::CoinbaseInvalid(_))),
                "expected CoinbaseInvalid, got {errors:?}"
            );
            assert_eq!(snap(&st), before, "state must be unchanged on reject");
        }
        ApplyOutcome::Ok { .. } => panic!("overpaid coinbase must reject"),
    }
}

#[test]
fn bond_burn_and_fee_inflow_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::three_validators();
    let initial = 50_000_000_000u64;
    let (st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        None,
        DEFAULT_ENDOWMENT_PARAMS,
        true,
    );
    assert_eq!(st.treasury, 0);

    let bond = register_op(99);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let fee = 12_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let st = match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), vec![bond], 1) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("bond+fee block: {errors:?}"),
    };
    let expected = treasury_after_block(0, bond_stake, u128::from(fee), 0, &TEST_EMISSION);
    assert_eq!(
        st.treasury, expected,
        "bond burn must credit treasury before fee settlement in the same block"
    );
    assert_eq!(st.validators.len(), 4);
}

#[test]
fn ppb_bonus_increases_validator_coinbase_and_treasury_drain() {
    let fixture = ValidatorFixture::three_validators();
    let ep = EndowmentParams {
        real_yield_ppb: 40_000_000, // 4% > 2% inflation buffer
        ..DEFAULT_ENDOWMENT_PARAMS
    };
    let payload: Vec<u8> = vec![0u8; 1 << 20];
    let built = build_storage_commitment(&payload, 1_000, Some(4096), ep.min_replication, None)
        .expect("commitment");
    let storage = StorageFixture { payload, built };
    let initial = 50_000_000_000u64;
    let (mut st, _) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        ep,
        false,
    );
    st.treasury = 100_000_000;
    let treasury_before = st.treasury;
    let commit_hash = storage_commitment_hash(&storage.built.commit);
    if let Some(entry) = st.storage.get_mut(&commit_hash) {
        // Seed pending PPB so the next proof crosses an integer payout boundary.
        entry.pending_yield_ppb = PPB - 1;
    }
    let slot = 1u32;
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        slot,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let accrual = accrue_proof_reward(AccrueArgs {
        size_bytes: storage.built.commit.size_bytes,
        replication: storage.built.commit.replication,
        pending_ppb: PPB - 1,
        last_proven_slot: 0,
        current_slot: u64::from(slot),
        params: &ep,
    })
    .expect("accrue");
    assert!(
        accrual.payout > 0,
        "PPB accrual must produce integer payout for coinbase bonus test"
    );
    let bonus = storage_proof_coinbase_bonus(std::slice::from_ref(&proof), &st.storage, slot, &ep);
    assert_eq!(bonus, accrual.payout);
    let cb_amount = producer_coinbase_amount(1, &TEST_EMISSION, 0, 1, bonus);
    let coinbase = build_coinbase(1, cb_amount, &fixture.payout).expect("coinbase");
    st = match apply_validator_block(
        &fixture,
        &st,
        1,
        vec![coinbase],
        vec![proof],
        Vec::new(),
        slot,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("ppb block: {errors:?}"),
    };
    let storage_reward_total = u128::from(TEST_EMISSION.storage_proof_reward) + accrual.payout;
    let expected_treasury =
        treasury_before.saturating_sub(treasury_before.min(storage_reward_total));
    assert_eq!(st.treasury, expected_treasury);
    let subsidy = u128::from(emission_at_height(1, &TEST_EMISSION));
    assert_eq!(
        u128::from(cb_amount),
        subsidy + storage_reward_total,
        "coinbase must include flat proof reward plus PPB bonus"
    );
}
