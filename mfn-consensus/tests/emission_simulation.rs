//! Long-horizon emission / treasury simulations (**M5.0**).
//!
//! Fast curve checks run in default CI; million-block and deep `apply_block`
//! harnesses are `#[ignore]` (see `scripts/ci-ignored.sh` pattern / nightly).

use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, build_unsealed_header, cumulative_emission,
    emission_at_height, seal_block, validate_emission_params, ApplyOutcome, ChainState,
    EmissionParams, GenesisConfig, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
};
use mfn_storage::build_storage_proof;
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

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

/// Step the same treasury arithmetic as `apply_block` (fee-less block, `proofs` accepted).
fn treasury_after_block(treasury: u128, proofs: u128, params: &EmissionParams) -> u128 {
    let storage_reward_total = params.storage_proof_reward as u128 * proofs;
    let mut pending = treasury;
    let from_treasury = pending.min(storage_reward_total);
    pending -= from_treasury;
    pending
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

/// Storage-proof rewards drain an empty treasury via coinbase backstop; treasury never underflows.
#[test]
fn treasury_ledger_matches_apply_block_over_storage_proof_blocks() {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
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
        let proof =
            build_storage_proof(&built.commit, &prev, slot, &payload, &built.tree).expect("proof");
        let unsealed = build_unsealed_header(&st, &[], &[], &[], &[proof.clone()], slot, ts);
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
        model_treasury = treasury_after_block(model_treasury, 1, &SIM_EMISSION);
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
