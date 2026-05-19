//! Property-based fuzzing of [`apply_block`] (**M5.2**).
//!
//! CI runs a bounded case count; deeper chains are `#[ignore]` (nightly).

use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, build_unsealed_header, seal_block, ApplyOutcome,
    BlockError, ChainState, GenesisConfig, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
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
}

fn snap(st: &ChainState) -> StateSnap {
    StateSnap {
        height: st.height,
        treasury: st.treasury,
        block_ids_len: st.block_ids.len(),
        tip: st.tip_id().copied(),
        utxo_len: st.utxo.len(),
        spent_key_images_len: st.spent_key_images.len(),
    }
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
