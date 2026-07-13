use crate::support::*;
use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::DEFAULT_BONDING_PARAMS;
use mfn_consensus::consensus::{
    decode_finality_proof, encode_finality_proof, validator_set_root, verify_finality_proof,
    ConsensusCheck, FinalityProof, ProducerProof, SlotContext,
};
use mfn_consensus::{
    apply_block, build_unsealed_header, decode_chain_checkpoint, encode_chain_checkpoint,
    header_signing_hash, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint,
    EquivocationEvidence, SlashEvidence, ValidatorStats,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::vrf_keygen_from_seed;

/// Bond epoch entry counters survive empty blocks until the epoch rolls.
#[test]
fn bond_epoch_entry_count_persists_across_empty_blocks() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let epoch0 = st.bond_epoch_id;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(ENTRY_CHURN_REGISTER_STAKE, 70)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("one register");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("empty block 2");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("empty block 3");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
    assert_eq!(st.validators.len(), 4);
}

/// Bond epoch exit counters survive empty blocks until the epoch rolls.
#[test]
fn bond_epoch_exit_count_persists_across_empty_blocks() {
    let fx = boot_four_validators_exit_churn_cfg(DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let mut st = fx.state.clone();
    let epoch0 = st.bond_epoch_id;
    let idx = st.validators[1].index;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![BondOp::Unbond {
                validator_index: idx,
                sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
            }],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond settlement");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
    assert_eq!(st.validators[1].stake, 0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("empty block 3");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("empty block 4");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
}

/// Bond epoch counters and validator set survive chain-checkpoint encode/decode.
#[test]
fn bond_epoch_counters_persist_in_chain_checkpoint_roundtrip() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let genesis_id = st.block_ids[0];

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(ENTRY_CHURN_REGISTER_STAKE, 80)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.validators.len(), 4);

    let cp = ChainCheckpoint {
        genesis_id,
        state: st.clone(),
    };
    let restored = decode_chain_checkpoint(&encode_chain_checkpoint(&cp)).expect("roundtrip");
    assert_eq!(restored.genesis_id, genesis_id);
    assert_eq!(restored.state.bond_epoch_id, st.bond_epoch_id);
    assert_eq!(
        restored.state.bond_epoch_entry_count,
        st.bond_epoch_entry_count
    );
    assert_eq!(
        restored.state.bond_epoch_exit_count,
        st.bond_epoch_exit_count
    );
    assert_eq!(restored.state.next_validator_index, st.next_validator_index);
    assert_eq!(restored.state.validators.len(), st.validators.len());
    assert_eq!(
        validator_set_root(&restored.state.validators),
        validator_set_root(&st.validators)
    );
}

/// Empty blocks at the epoch boundary roll `bond_epoch_id` and reset churn counters.
#[test]
fn bond_epoch_id_increments_at_epoch_boundary() {
    let fx = boot_three_validators_entry_churn_cfg(2, 4);
    let mut st = fx.state.clone();
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    assert_eq!(st.bond_epoch_id, 0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 50), register_op(stake, 51)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("two registers in epoch 0");
    assert_eq!(st.bond_epoch_entry_count, 2);
    assert_eq!(st.bond_epoch_id, 0);

    for height in 2..=3 {
        st = apply_block(
            &st,
            &seal_empty(
                &fx,
                &st,
                height,
                Vec::new(),
                Vec::new(),
                &incumbent_voter_positions(&fx),
            ),
        )
        .into_state()
        .expect("advance within epoch 0");
    }

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("first block of epoch 1");
    assert_eq!(st.bond_epoch_id, 1);
    assert_eq!(st.bond_epoch_entry_count, 0);
    assert_eq!(st.bond_epoch_exit_count, 0);
}

/// Liveness counters and slashed stake survive chain-checkpoint encode/decode.
#[test]
fn validator_stats_persist_in_chain_checkpoint_after_liveness_evolution() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;
    let genesis_id = st.block_ids[0];
    let voters_miss_v1 = [0usize, 2];

    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &voters_miss_v1),
    )
    .into_state()
    .expect("first miss");
    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &voters_miss_v1),
    )
    .into_state()
    .expect("liveness slash");
    assert_eq!(st.validator_stats[1].liveness_slashes, 1);
    assert_eq!(st.validator_stats[1].total_missed, 2);
    assert_eq!(st.validators[1].stake, 990_000);

    let cp = ChainCheckpoint {
        genesis_id,
        state: st.clone(),
    };
    let restored = decode_chain_checkpoint(&encode_chain_checkpoint(&cp)).expect("roundtrip");
    assert_eq!(restored.state.validator_stats, st.validator_stats);
    assert_eq!(restored.state.validators[1].stake, st.validators[1].stake);
}

/// Pending unbond queue survives chain-checkpoint encode/decode after an exit request.
#[test]
fn pending_unbonds_persist_in_chain_checkpoint_after_unbond_request() {
    let fx = boot_three_validators_cfg(64, 4);
    let mut st = fx.state.clone();
    let genesis_id = st.block_ids[0];
    let v1_idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
    };

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![unbond],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    assert_eq!(st.pending_unbonds.len(), 1);
    let unlock = st
        .pending_unbonds
        .get(&v1_idx)
        .expect("pending entry")
        .unlock_height;

    let cp = ChainCheckpoint {
        genesis_id,
        state: st.clone(),
    };
    let restored = decode_chain_checkpoint(&encode_chain_checkpoint(&cp)).expect("roundtrip");
    assert_eq!(restored.state.pending_unbonds, st.pending_unbonds);
    assert_eq!(
        restored
            .state
            .pending_unbonds
            .get(&v1_idx)
            .map(|p| p.unlock_height),
        Some(unlock)
    );
}

/// Zeroed stake and slash treasury credit survive chain-checkpoint encode/decode.
#[test]
fn equivocation_slash_persists_in_chain_checkpoint_roundtrip() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let genesis_id = st.block_ids[0];
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [55u8; 32];
    let h2 = [66u8; 32];
    let evidence = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    });
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            Vec::new(),
            vec![evidence],
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("equivocation slash");
    assert_eq!(post.validators[1].stake, 0);
    assert_eq!(post.treasury, 1_000_000);

    let cp = ChainCheckpoint {
        genesis_id,
        state: post.clone(),
    };
    let restored = decode_chain_checkpoint(&encode_chain_checkpoint(&cp)).expect("roundtrip");
    assert_eq!(restored.state.validators[1].stake, 0);
    assert_eq!(restored.state.treasury, post.treasury);
    assert_eq!(
        validator_set_root(&restored.state.validators),
        validator_set_root(&post.validators)
    );
}
