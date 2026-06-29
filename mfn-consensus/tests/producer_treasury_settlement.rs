//! Producer revenue and treasury settlement invariants (**M5.7**–**M5.13**, **M5.18**).
//!
//! Locks the economics from [`docs/ECONOMICS.md`]: coinbase pays
//! `emission(height) + producer fee share (+ storage rewards + PPB bonus)`;
//! fees split 90/10 treasury/producer by default; storage rewards drain treasury
//! first; emission backstop covers only the treasury shortfall; validator bond
//! burns and slash forfeits credit treasury before fee settlement in the closed loop.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_bls::{bls_keygen_from_seed, bls_sign, BlsSecretKey};
use mfn_consensus::{
    apply_block, apply_genesis, build_coinbase, build_genesis, build_unsealed_header, cast_vote,
    emission_at_height, encode_finality_proof, finalize, header_signing_hash,
    producer_coinbase_amount, seal_block, sign_register, sign_transaction,
    storage_proof_coinbase_bonus, try_produce_slot, ApplyOutcome, BlockError, BondOp, ChainState,
    ConsensusParams, EmissionParams, FinalityProof, GenesisConfig, GenesisOutput, InputSpec,
    OutputSpec, PayoutAddress, SignedTransaction, SlashEvidence, SlotContext, TransactionWire,
    Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS,
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

/// Equivocation slash credits treasury before fee settlement and proof drain.
fn treasury_after_slash_block(
    treasury: u128,
    slash_credit: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement(
        treasury.saturating_add(slash_credit),
        fee_sum,
        accepted_proofs,
        params,
    )
}

/// Liveness slash credits treasury before fee settlement and proof drain.
fn treasury_after_liveness_block(
    treasury: u128,
    liveness_credit: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement(
        treasury.saturating_add(liveness_credit),
        fee_sum,
        accepted_proofs,
        params,
    )
}

/// Bond burn and liveness slash both credit treasury before fee settlement and proof drain.
fn treasury_after_bond_and_liveness_block(
    treasury: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement(
        treasury
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        accepted_proofs,
        params,
    )
}

/// Equivocation, liveness, and bond burns all credit treasury before settlement.
fn treasury_after_equivocation_bond_liveness_block(
    treasury: u128,
    equivocation_credit: u128,
    liveness_credit: u128,
    bond_burn: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement(
        treasury
            .saturating_add(equivocation_credit)
            .saturating_add(liveness_credit)
            .saturating_add(bond_burn),
        fee_sum,
        accepted_proofs,
        params,
    )
}

/// Settlement when storage payout includes a PPB integer bonus beyond the flat proof reward.
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

/// Bond burn and liveness slash credit treasury before fee + PPB-augmented proof drain.
fn treasury_after_bond_and_liveness_block_with_ppb_bonus(
    treasury: u128,
    bond_burn: u128,
    liveness_credit: u128,
    fee_sum: u128,
    accepted_proofs: u128,
    ppb_bonus: u128,
    params: &EmissionParams,
) -> u128 {
    treasury_after_settlement_with_ppb_bonus(
        treasury
            .saturating_add(bond_burn)
            .saturating_add(liveness_credit),
        fee_sum,
        accepted_proofs,
        ppb_bonus,
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

    /// High stakes + low liveness threshold for treasury slash composition tests.
    fn liveness_absentee_three_validators() -> Self {
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
        let (v0, s0) = mk(0, 1_000_000);
        let (v1, s1) = mk(1, 1_000_000);
        let (v2, s2) = mk(2, 1_000_000);
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
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 3,
            liveness_slash_bps: 100,
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

/// Validator quorum block apply helper (BLS finality + optional bond/slash body).
#[allow(clippy::too_many_arguments)]
fn apply_validator_block(
    fixture: &ValidatorFixture,
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
    bond_ops: Vec<BondOp>,
    slashings: Vec<SlashEvidence>,
    slot: u32,
) -> ApplyOutcome {
    let ts = u64::from(height) * 1_000;
    let unsealed =
        build_unsealed_header(st, &txs, &bond_ops, &slashings, &storage_proofs, slot, ts);
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
        slashings,
        storage_proofs,
    );
    apply_block(st, &blk)
}

fn signing_stake_for_voters(fixture: &ValidatorFixture, voter_indices: &[u32]) -> u64 {
    voter_indices
        .iter()
        .map(|&i| fixture.validators[i as usize].stake)
        .sum()
}

/// Validator block where only `voter_indices` cast finality votes (liveness miss for others).
#[allow(clippy::too_many_arguments)]
fn apply_validator_block_with_voters(
    fixture: &ValidatorFixture,
    voter_indices: &[u32],
    st: &ChainState,
    height: u32,
    txs: Vec<TransactionWire>,
    storage_proofs: Vec<mfn_storage::StorageProof>,
    bond_ops: Vec<BondOp>,
    slashings: Vec<SlashEvidence>,
    slot: u32,
) -> ApplyOutcome {
    let ts = u64::from(height) * 1_000;
    let unsealed =
        build_unsealed_header(st, &txs, &bond_ops, &slashings, &storage_proofs, slot, ts);
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
                fixture.total_stake,
                fixture.params.expected_proposers_per_slot,
            )
            .expect("vote")
        })
        .collect();
    let agg = finalize(&header_hash, &votes, fixture.validators.len()).expect("finalize");
    let signing_stake = signing_stake_for_voters(fixture, voter_indices);
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
    st = match apply_validator_block(
        &fixture,
        &st,
        1,
        txs1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        1,
    ) {
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
    st = match apply_validator_block(
        &fixture,
        &st,
        2,
        txs2,
        vec![proof],
        Vec::new(),
        Vec::new(),
        2,
    ) {
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
    st = match apply_validator_block(
        &fixture,
        &st,
        1,
        vec![coinbase],
        vec![proof],
        Vec::new(),
        Vec::new(),
        1,
    ) {
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

    match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), Vec::new(), Vec::new(), 1) {
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

    match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), Vec::new(), Vec::new(), 1) {
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
    let st =
        match apply_validator_block(&fixture, &st, 1, txs, Vec::new(), vec![bond], Vec::new(), 1) {
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
#[test]
fn equivocation_slash_fee_and_storage_proof_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::three_validators();
    let slash_idx = 1u32;
    let slash_stake = u128::from(fixture.validators[slash_idx as usize].stake);
    let slash = equivocation_evidence(1, 1, slash_idx, &fixture.secrets[slash_idx as usize].bls.sk);
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        DEFAULT_ENDOWMENT_PARAMS,
        false,
    );
    assert_eq!(st.treasury, 0);

    let fee = 8_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let bonus = storage_proof_coinbase_bonus(
        std::slice::from_ref(&proof),
        &st.storage,
        1,
        &DEFAULT_ENDOWMENT_PARAMS,
    );
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 1, bonus);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let st = match apply_validator_block(
        &fixture,
        &st,
        1,
        txs,
        vec![proof],
        Vec::new(),
        vec![slash],
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("slash+fee+proof block: {errors:?}"),
    };
    let expected = treasury_after_slash_block(0, slash_stake, u128::from(fee), 1, &TEST_EMISSION);
    assert_eq!(
        st.treasury, expected,
        "slash credit, fee inflow, and storage drain compose in treasury ledger"
    );
    assert_eq!(
        st.validators[slash_idx as usize].stake, 0,
        "equivocation must zero slashed validator stake"
    );
}

#[test]
fn ppb_pending_carryover_pays_on_second_proof_block() {
    let fixture = ValidatorFixture::three_validators();
    let ep = EndowmentParams {
        real_yield_ppb: 40_000_000,
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
    st.treasury = 1_000_000;
    let commit_hash = storage_commitment_hash(&storage.built.commit);

    let slot1 = 1u32;
    let probe = accrue_proof_reward(AccrueArgs {
        size_bytes: storage.built.commit.size_bytes,
        replication: storage.built.commit.replication,
        pending_ppb: 0,
        last_proven_slot: 0,
        current_slot: u64::from(slot1),
        params: &ep,
    })
    .expect("probe accrual");
    assert_eq!(
        probe.payout, 0,
        "one slot of yield must not cross PPB payout boundary alone"
    );
    let incoming = probe.new_pending_ppb;
    assert!(incoming > 0 && incoming < PPB);
    let seed_pending = PPB - incoming - 1;
    st.storage.get_mut(&commit_hash).unwrap().pending_yield_ppb = seed_pending;

    let accrual1 = accrue_proof_reward(AccrueArgs {
        size_bytes: storage.built.commit.size_bytes,
        replication: storage.built.commit.replication,
        pending_ppb: seed_pending,
        last_proven_slot: 0,
        current_slot: u64::from(slot1),
        params: &ep,
    })
    .expect("accrue block 1");
    assert_eq!(
        accrual1.payout, 0,
        "seeded pending must defer payout to block 2"
    );
    assert_eq!(accrual1.new_pending_ppb, PPB - 1);

    let prev = *st.tip_id().expect("tip");
    let proof1 = build_storage_proof(
        &storage.built.commit,
        &prev,
        slot1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof1");
    let cb1 = producer_coinbase_amount(1, &TEST_EMISSION, 0, 1, 0);
    let coinbase1 = build_coinbase(1, cb1, &fixture.payout).expect("coinbase1");
    st = match apply_validator_block(
        &fixture,
        &st,
        1,
        vec![coinbase1],
        vec![proof1],
        Vec::new(),
        Vec::new(),
        slot1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 1: {errors:?}"),
    };
    assert_eq!(st.storage[&commit_hash].pending_yield_ppb, PPB - 1);

    let slot2 = 2u32;
    let accrual2 = accrue_proof_reward(AccrueArgs {
        size_bytes: storage.built.commit.size_bytes,
        replication: storage.built.commit.replication,
        pending_ppb: PPB - 1,
        last_proven_slot: u64::from(slot1),
        current_slot: u64::from(slot2),
        params: &ep,
    })
    .expect("accrue block 2");
    assert!(
        accrual2.payout > 0,
        "second proof must pay integer units from carried PPB"
    );

    let treasury_before_b2 = st.treasury;
    let prev2 = *st.tip_id().expect("tip");
    let proof2 = build_storage_proof(
        &storage.built.commit,
        &prev2,
        slot2,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof2");
    let bonus2 =
        storage_proof_coinbase_bonus(std::slice::from_ref(&proof2), &st.storage, slot2, &ep);
    assert_eq!(bonus2, accrual2.payout);
    let cb2 = producer_coinbase_amount(2, &TEST_EMISSION, 0, 1, bonus2);
    let coinbase2 = build_coinbase(2, cb2, &fixture.payout).expect("coinbase2");
    st = match apply_validator_block(
        &fixture,
        &st,
        2,
        vec![coinbase2],
        vec![proof2],
        Vec::new(),
        Vec::new(),
        slot2,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block 2: {errors:?}"),
    };
    let storage_reward_total = u128::from(TEST_EMISSION.storage_proof_reward) + accrual2.payout;
    let expected_treasury =
        treasury_before_b2.saturating_sub(treasury_before_b2.min(storage_reward_total));
    assert_eq!(st.treasury, expected_treasury);
    let subsidy2 = u128::from(emission_at_height(2, &TEST_EMISSION));
    assert_eq!(
        u128::from(cb2),
        subsidy2 + storage_reward_total,
        "coinbase on carry-over block includes flat reward plus PPB payout"
    );
}

#[test]
fn liveness_slash_fee_and_storage_proof_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let absentee_idx = 1u32;
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
    assert_eq!(st.treasury, 0);
    // Two prior misses; validator 1 absent again on this block → liveness slash.
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;

    let liveness_forfeit = 10_000u128;
    let fee = 8_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let bonus = storage_proof_coinbase_bonus(
        std::slice::from_ref(&proof),
        &st.storage,
        1,
        &DEFAULT_ENDOWMENT_PARAMS,
    );
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 1, bonus);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    // Validators 0 and 2 sign; validator 1 misses → slash on threshold block.
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        vec![proof],
        Vec::new(),
        Vec::new(),
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("liveness+fee+proof block: {errors:?}"),
    };
    let expected =
        treasury_after_liveness_block(0, liveness_forfeit, u128::from(fee), 1, &TEST_EMISSION);
    assert_eq!(
        st.treasury, expected,
        "liveness slash, fee inflow, and storage drain compose in treasury ledger"
    );
    assert_eq!(
        st.validators[absentee_idx as usize].stake, 990_000,
        "liveness slash must reduce absentee stake by 1%"
    );
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}

#[test]
fn bond_burn_liveness_slash_and_fee_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let absentee_idx = 1u32;
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        None,
        DEFAULT_ENDOWMENT_PARAMS,
        true,
    );
    assert_eq!(st.treasury, 0);
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;

    let bond = register_op(77);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let fee = 8_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        Vec::new(),
        vec![bond],
        Vec::new(),
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("bond+liveness+fee block: {errors:?}"),
    };
    let expected = treasury_after_bond_and_liveness_block(
        0,
        bond_stake,
        liveness_forfeit,
        u128::from(fee),
        0,
        &TEST_EMISSION,
    );
    assert_eq!(
        st.treasury, expected,
        "bond burn, liveness slash, and fee inflow compose in treasury ledger"
    );
    assert_eq!(
        st.validators.len(),
        4,
        "bond register must append validator"
    );
    assert_eq!(st.validators[absentee_idx as usize].stake, 990_000);
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}

#[test]
fn bond_liveness_slash_fee_and_storage_proof_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let absentee_idx = 1u32;
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        DEFAULT_ENDOWMENT_PARAMS,
        true,
    );
    assert_eq!(st.treasury, 0);
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;

    let bond = register_op(88);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let fee = 8_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let bonus = storage_proof_coinbase_bonus(
        std::slice::from_ref(&proof),
        &st.storage,
        1,
        &DEFAULT_ENDOWMENT_PARAMS,
    );
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 1, bonus);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        vec![proof],
        vec![bond],
        Vec::new(),
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("full inflow stack block: {errors:?}"),
    };
    let expected = treasury_after_bond_and_liveness_block(
        0,
        bond_stake,
        liveness_forfeit,
        u128::from(fee),
        1,
        &TEST_EMISSION,
    );
    assert_eq!(
        st.treasury, expected,
        "bond, liveness slash, fee, and storage drain compose in treasury ledger"
    );
    assert_eq!(st.validators.len(), 4);
    assert_eq!(st.validators[absentee_idx as usize].stake, 990_000);
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}

#[test]
fn equivocation_bond_and_liveness_slash_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let equivocation_idx = 2u32;
    let absentee_idx = 1u32;
    let equivocation_stake = u128::from(fixture.validators[equivocation_idx as usize].stake);
    let slash = equivocation_evidence(
        1,
        1,
        equivocation_idx,
        &fixture.secrets[equivocation_idx as usize].bls.sk,
    );
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        None,
        DEFAULT_ENDOWMENT_PARAMS,
        true,
    );
    assert_eq!(st.treasury, 0);
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;

    let bond = register_op(55);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let fee = 6_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 0, 0);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    // Validators 0 and 2 sign; validator 1 misses → liveness slash; validator 2 equivocates.
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        Vec::new(),
        vec![bond],
        vec![slash],
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("equivocation+bond+liveness block: {errors:?}"),
    };
    let expected = treasury_after_equivocation_bond_liveness_block(
        0,
        equivocation_stake,
        liveness_forfeit,
        bond_stake,
        u128::from(fee),
        0,
        &TEST_EMISSION,
    );
    assert_eq!(
        st.treasury, expected,
        "equivocation, bond burn, liveness slash, and fee compose in treasury ledger"
    );
    assert_eq!(
        st.validators[equivocation_idx as usize].stake, 0,
        "equivocation must zero slashed validator stake"
    );
    assert_eq!(st.validators[absentee_idx as usize].stake, 990_000);
    assert_eq!(st.validators.len(), 4);
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}

#[test]
fn equivocation_bond_liveness_fee_and_storage_proof_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let equivocation_idx = 2u32;
    let absentee_idx = 1u32;
    let equivocation_stake = u128::from(fixture.validators[equivocation_idx as usize].stake);
    let slash = equivocation_evidence(
        1,
        1,
        equivocation_idx,
        &fixture.secrets[equivocation_idx as usize].bls.sk,
    );
    let storage = StorageFixture::sample_4k();
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        DEFAULT_ENDOWMENT_PARAMS,
        true,
    );
    assert_eq!(st.treasury, 0);
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;

    let bond = register_op(99);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let fee = 10_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
    let prev = *st.tip_id().expect("tip");
    let proof = build_storage_proof(
        &storage.built.commit,
        &prev,
        1,
        &storage.payload,
        &storage.built.tree,
    )
    .expect("proof");
    let bonus = storage_proof_coinbase_bonus(
        std::slice::from_ref(&proof),
        &st.storage,
        1,
        &DEFAULT_ENDOWMENT_PARAMS,
    );
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 1, bonus);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        vec![proof],
        vec![bond],
        vec![slash],
        1,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => {
            panic!("full five-path inflow/outflow block: {errors:?}")
        }
    };
    let expected = treasury_after_equivocation_bond_liveness_block(
        0,
        equivocation_stake,
        liveness_forfeit,
        bond_stake,
        u128::from(fee),
        1,
        &TEST_EMISSION,
    );
    assert_eq!(
        st.treasury, expected,
        "equivocation, bond, liveness, fee, and storage drain compose in treasury ledger"
    );
    assert_eq!(
        st.validators[equivocation_idx as usize].stake, 0,
        "equivocation must zero slashed validator stake"
    );
    assert_eq!(st.validators[absentee_idx as usize].stake, 990_000);
    assert_eq!(st.validators.len(), 4);
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}

/// Bond, liveness slash, fee, and PPB-augmented storage proof compose in treasury ledger (**M5.18**).
#[test]
fn bond_liveness_fee_ppb_storage_proof_compose_in_treasury_closed_loop() {
    let fixture = ValidatorFixture::liveness_absentee_three_validators();
    let absentee_idx = 1u32;
    let ep = EndowmentParams {
        real_yield_ppb: 40_000_000,
        ..DEFAULT_ENDOWMENT_PARAMS
    };
    let payload: Vec<u8> = vec![0u8; 1 << 20];
    let built = build_storage_commitment(&payload, 1_000, Some(4096), ep.min_replication, None)
        .expect("commitment");
    let storage = StorageFixture { payload, built };
    let initial = 50_000_000_000u64;
    let (mut st, spend) = genesis_validator_with_funded_utxo(
        TEST_EMISSION,
        initial,
        &fixture,
        Some(&storage),
        ep,
        true,
    );
    assert_eq!(st.treasury, 0);
    st.validator_stats[absentee_idx as usize].consecutive_missed = 2;
    st.treasury = 100_000_000;
    let treasury_before = st.treasury;

    let commit_hash = storage_commitment_hash(&storage.built.commit);
    st.storage.get_mut(&commit_hash).unwrap().pending_yield_ppb = PPB - 1;

    let bond = register_op(101);
    let bond_stake = u128::from(DEFAULT_BONDING_PARAMS.min_validator_stake);
    let liveness_forfeit = 10_000u128;
    let fee = 9_000u64;
    let (signed, _) = spend.sign_self_transfer(fee);
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
        "seeded PPB must cross integer payout boundary"
    );
    let bonus = storage_proof_coinbase_bonus(std::slice::from_ref(&proof), &st.storage, slot, &ep);
    assert_eq!(bonus, accrual.payout);
    let cb = producer_coinbase_amount(1, &TEST_EMISSION, u128::from(fee), 1, bonus);
    let coinbase = build_coinbase(1, cb, &fixture.payout).expect("coinbase");
    let txs = vec![coinbase, signed.tx];
    let voters = [0u32, 2];
    let st = match apply_validator_block_with_voters(
        &fixture,
        &voters,
        &st,
        1,
        txs,
        vec![proof],
        vec![bond],
        Vec::new(),
        slot,
    ) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("bond+liveness+fee+ppb proof block: {errors:?}"),
    };
    let expected = treasury_after_bond_and_liveness_block_with_ppb_bonus(
        treasury_before,
        bond_stake,
        liveness_forfeit,
        u128::from(fee),
        1,
        accrual.payout,
        &TEST_EMISSION,
    );
    assert_eq!(
        st.treasury, expected,
        "bond, liveness, fee, and PPB-augmented proof drain compose in treasury ledger"
    );
    let storage_reward_total = u128::from(TEST_EMISSION.storage_proof_reward) + accrual.payout;
    let subsidy = u128::from(emission_at_height(1, &TEST_EMISSION));
    let (_, producer_fee) = fee_split(u128::from(fee), TEST_EMISSION.fee_to_treasury_bps);
    assert_eq!(
        u128::from(cb),
        subsidy + producer_fee + storage_reward_total,
        "coinbase must include subsidy, producer fee share, flat proof reward, and PPB bonus"
    );
    assert_eq!(st.validators.len(), 4);
    assert_eq!(st.validators[absentee_idx as usize].stake, 990_000);
    assert_eq!(
        st.validator_stats[absentee_idx as usize].liveness_slashes,
        1
    );
}
