//! Property-based fuzzing of [`apply_block`] (**M5.2**, **M5.2+**).
//!
//! CI runs a bounded case count; deeper chains are `#[ignore]` (nightly).

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, build_unsealed_header, seal_block, sign_register,
    ApplyOutcome, BlockError, BondOp, ChainState, GenesisConfig, DEFAULT_BONDING_PARAMS,
    DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{
    build_storage_commitment, build_storage_proof, BuiltCommitment, DEFAULT_ENDOWMENT_PARAMS,
};
use proptest::prelude::*;

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

fn genesis_with_storage() -> StorageGenesis {
    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
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
    let blk = seal_block(
        unsealed,
        Vec::new(),
        bond_ops,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn apply_with_storage_proofs(
    st: &ChainState,
    height: u32,
    proofs: Vec<mfn_storage::StorageProof>,
) -> ChainState {
    let ts = u64::from(height) * 1_000;
    let unsealed = build_unsealed_header(st, &[], &[], &[], &proofs, height, ts);
    let blk = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs,
    );
    match apply_block(st, &blk) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("height {height}: {errors:?}"),
    }
}

fn apply_valid_proof_at(
    built: &BuiltCommitment,
    payload: &[u8],
    st: &ChainState,
    height: u32,
) -> ChainState {
    let prev = *st.tip_id().expect("tip");
    let proof =
        build_storage_proof(&built.commit, &prev, height, payload, &built.tree).expect("proof");
    apply_with_storage_proofs(st, height, vec![proof])
}

fn seal_empty(header: mfn_consensus::BlockHeader) -> mfn_consensus::Block {
    seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn next_height(st: &ChainState) -> u32 {
    st.height.map(|h| h + 1).unwrap_or(0)
}

fn apply_empty_at(st: &ChainState, height: u32, timestamp: u64) -> ChainState {
    let header = build_unsealed_header(st, &[], &[], &[], &[], height, timestamp);
    let blk = seal_empty(header);
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
        let blk = seal_empty(header);
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
        let blk = seal_empty(header);

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
