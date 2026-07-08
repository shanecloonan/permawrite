use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use mfn_consensus::consensus::{
    cast_vote, eligibility_threshold, encode_finality_proof, finalize, is_eligible, pick_winner,
    slot_seed, try_produce_slot, FinalityProof, ProducerProof, SlotContext, Validator,
    ValidatorSecrets,
};
use mfn_consensus::{
    apply_genesis, build_genesis, build_unsealed_header, header_signing_hash, seal_block, Block,
    BondOp, ChainState, ConsensusParams, GenesisConfig, SlashEvidence, ValidatorStats,
    DEFAULT_EMISSION_PARAMS, TEST_CONSENSUS_PARAMS,
};
use mfn_crypto::vrf::{vrf_keygen_from_seed, vrf_prove};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
pub struct Fixture {
    pub state: ChainState,
    pub secrets: Vec<ValidatorSecrets>,
    pub params: ConsensusParams,
}

pub fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
    let vrf = vrf_keygen_from_seed(&[(i.wrapping_add(1)) as u8; 32]).expect("vrf");
    let bls = bls_keygen_from_seed(&[(i.wrapping_add(101)) as u8; 32]);
    let val = Validator {
        index: i,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        stake,
        payout: None,
    };
    let secrets = ValidatorSecrets { index: i, vrf, bls };
    (val, secrets)
}

pub fn boot_three_validators(liveness_max_missed: u32) -> Fixture {
    boot_three_validators_cfg(
        liveness_max_missed,
        DEFAULT_BONDING_PARAMS.unbond_delay_heights,
    )
}

/// Algorand-style `F = 1` with a dust-stake validator whose eligibility
/// threshold is negligible — used to deterministically exercise `NotEligible`.
pub fn boot_three_validators_strict_eligibility(liveness_max_missed: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 1.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: liveness_max_missed,
        liveness_slash_bps: 100,
        ..TEST_CONSENSUS_PARAMS
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights: DEFAULT_BONDING_PARAMS.unbond_delay_heights,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

pub fn boot_three_validators_cfg(liveness_max_missed: u32, unbond_delay_heights: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: liveness_max_missed,
        liveness_slash_bps: 100,
        ..TEST_CONSENSUS_PARAMS
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

pub fn boot_three_validators_entry_churn_cfg(
    max_entry_churn_per_epoch: u32,
    slots_per_epoch: u32,
) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
        ..TEST_CONSENSUS_PARAMS
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        max_entry_churn_per_epoch,
        slots_per_epoch,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

/// Matches `boot_three_validators_entry_churn_cfg`'s lowered `min_validator_stake`.
pub const ENTRY_CHURN_REGISTER_STAKE: u64 = 100_000;

/// Four-validator chain with short unbond delay and a tight exit-churn cap.
pub fn boot_four_validators_exit_churn() -> Fixture {
    boot_four_validators_exit_churn_cfg(DEFAULT_BONDING_PARAMS.slots_per_epoch)
}

pub fn boot_four_validators_exit_churn_cfg(slots_per_epoch: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let (v3, s3) = mk_validator(3, 1_000_000);
    let validators = vec![v0, v1, v2, v3];
    let secrets = vec![s0, s1, s2, s3];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 5000,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
        ..TEST_CONSENSUS_PARAMS
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights: 1,
        max_exit_churn_per_epoch: 2,
        slots_per_epoch,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

pub fn register_op(stake: u64, seed: u8) -> BondOp {
    let vrf = vrf_keygen_from_seed(&[seed.wrapping_add(50); 32]).expect("vrf");
    let bls = bls_keygen_from_seed(&[seed.wrapping_add(150); 32]);
    BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &bls.pk, None, &bls.sk),
    }
}

/// Attach BLS finality; `voter_positions` lists indices into `st.validators`.
pub fn attach_finality(
    st: &ChainState,
    fx: &Fixture,
    mut unsealed: mfn_consensus::BlockHeader,
    voter_positions: &[usize],
) -> (mfn_consensus::BlockHeader, Vec<u8>) {
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;
    let base_slot = unsealed.slot;

    for bump in 0u32..=512 {
        unsealed.slot = base_slot.saturating_add(bump);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: unsealed.height,
            slot: unsealed.slot,
            prev_hash: unsealed.prev_hash,
        };

        let mut candidates: Vec<ProducerProof> = Vec::new();
        for (i, v) in st.validators.iter().enumerate().take(fx.secrets.len()) {
            if let Ok(Some(p)) =
                try_produce_slot(&ctx, &fx.secrets[i], v, total_stake, f, &header_hash)
            {
                candidates.push(p);
            }
        }
        let Some(producer_proof) = pick_winner(&candidates).cloned() else {
            continue;
        };
        let producer_validator = st
            .validators
            .iter()
            .find(|v| v.index == producer_proof.validator_index)
            .expect("producer in set");

        let mut votes = Vec::new();
        let mut signing_stake = 0u64;
        for &pos in voter_positions {
            let v = &st.validators[pos];
            let vote = cast_vote(
                &header_hash,
                &fx.secrets[pos],
                &ctx,
                &producer_proof,
                producer_validator,
                total_stake,
                f,
            )
            .expect("vote");
            signing_stake = signing_stake.saturating_add(v.stake);
            votes.push(vote);
        }
        let agg = finalize(&header_hash, &votes, st.validators.len()).expect("finalize");
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake,
        };
        return (unsealed, encode_finality_proof(&fin));
    }
    panic!("no VRF-eligible producer in 512 slot attempts");
}

pub fn seal_empty(
    fx: &Fixture,
    st: &ChainState,
    height: u32,
    bond_ops: Vec<BondOp>,
    slashings: Vec<SlashEvidence>,
    voter_positions: &[usize],
) -> Block {
    let unsealed = build_unsealed_header(
        st,
        &[],
        &bond_ops,
        &slashings,
        &[],
        height,
        u64::from(height) * 100,
    );
    let (unsealed, fin) = attach_finality(st, fx, unsealed, voter_positions);
    seal_block(unsealed, Vec::new(), bond_ops, fin, slashings, Vec::new())
}

pub fn all_voter_positions(st: &ChainState) -> Vec<usize> {
    (0..st.validators.len()).collect()
}

/// Genesis committee positions — only these validators have BLS secrets in
/// the fixture, so post-`Register` blocks must not iterate new indices.
pub fn incumbent_voter_positions(fx: &Fixture) -> Vec<usize> {
    (0..fx.secrets.len()).collect()
}

pub fn snapshot(st: &ChainState) -> (Option<u32>, usize, Vec<u64>, Vec<ValidatorStats>) {
    (
        st.height,
        st.block_ids.len(),
        st.validators.iter().map(|v| v.stake).collect(),
        st.validator_stats.clone(),
    )
}

pub fn ineligible_producer_at_ctx(
    fx: &Fixture,
    st: &ChainState,
    ctx: &SlotContext,
    header_hash: &[u8; 32],
) -> Option<ProducerProof> {
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;
    let seed = slot_seed(ctx);
    for (i, v) in st.validators.iter().enumerate().take(fx.secrets.len()) {
        let res = vrf_prove(&fx.secrets[i].vrf, &seed).ok()?;
        let threshold = eligibility_threshold(v.stake, total_stake, f);
        if !is_eligible(&res.output, threshold) {
            return Some(ProducerProof {
                validator_index: v.index,
                beta: res.output,
                vrf_proof: res.proof,
                producer_sig: bls_sign(header_hash, &fx.secrets[i].bls.sk),
            });
        }
    }
    None
}
