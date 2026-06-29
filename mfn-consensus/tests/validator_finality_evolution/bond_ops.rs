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
    header_signing_hash, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint, SlashEvidence,
    ValidatorStats,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::vrf_keygen_from_seed;

/// Requesting unbond enqueues exit but keeps stake and `validator_root`
/// stable until the delay elapses.
#[test]
fn unbond_request_preserves_validator_root_in_delay_window() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let root_genesis = validator_set_root(&st.validators);
    let v1_idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
    };

    let block1 = seal_empty(
        &fx,
        &st,
        1,
        vec![unbond],
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block1)
        .into_state()
        .expect("unbond request block");
    assert_eq!(st.validators[1].stake, 1_000_000);
    assert_eq!(
        validator_set_root(&st.validators),
        root_genesis,
        "request alone must not move validator_root"
    );

    let block2 = seal_empty(
        &fx,
        &st,
        2,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block2)
        .into_state()
        .expect("delay window block");
    assert_eq!(
        validator_set_root(&st.validators),
        root_genesis,
        "delay window keeps validator_root stable"
    );
}

/// Unbond settlement zeroes stake; the successor header commits the
/// post-settlement validator set root.
#[test]
fn validator_root_moves_on_unbond_settlement() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let root_genesis = validator_set_root(&st.validators);
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
    .expect("delay window");

    let block3 = seal_empty(
        &fx,
        &st,
        3,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block3)
        .into_state()
        .expect("unbond settlement");
    assert_eq!(st.validators[1].stake, 0);
    let root_after = validator_set_root(&st.validators);
    assert_ne!(
        root_genesis, root_after,
        "settlement must move validator_root"
    );

    let next = build_unsealed_header(&st, &[], &[], &[], &[], 4, 400);
    assert_eq!(
        next.validator_root, root_after,
        "successor header commits post-settlement set"
    );
}

/// Per-epoch exit churn caps defer settlement beyond the first N due unbonds.
#[test]
fn exit_churn_cap_defers_third_unbond_settlement() {
    let fx = boot_four_validators_exit_churn();
    let mut st = fx.state.clone();
    let i1 = st.validators[1].index;
    let i2 = st.validators[2].index;
    let i3 = st.validators[3].index;
    let unbonds = vec![
        BondOp::Unbond {
            validator_index: i1,
            sig: sign_unbond(i1, &fx.secrets[1].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i2,
            sig: sign_unbond(i2, &fx.secrets[2].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i3,
            sig: sign_unbond(i3, &fx.secrets[3].bls.sk),
        },
    ];

    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, unbonds, Vec::new(), &all_voter_positions(&st)),
    )
    .into_state()
    .expect("three unbond requests");
    assert_eq!(st.pending_unbonds.len(), 3);

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
    .expect("first settlement block");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert!(st.pending_unbonds.contains_key(&i3));
    assert_eq!(st.validators[1].stake, 0);
    assert_eq!(st.validators[2].stake, 0);
    assert_eq!(st.validators[3].stake, 1_000_000);
    assert_eq!(st.bond_epoch_exit_count, 2);
}

/// Exit-churn budget resets at the bond epoch boundary so deferred unbonds
/// can settle on the first block of the next epoch.
#[test]
fn exit_churn_cap_resets_at_epoch_boundary() {
    let fx = boot_four_validators_exit_churn_cfg(4);
    let mut st = fx.state.clone();
    let i1 = st.validators[1].index;
    let i2 = st.validators[2].index;
    let i3 = st.validators[3].index;
    let unbonds = vec![
        BondOp::Unbond {
            validator_index: i1,
            sig: sign_unbond(i1, &fx.secrets[1].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i2,
            sig: sign_unbond(i2, &fx.secrets[2].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i3,
            sig: sign_unbond(i3, &fx.secrets[3].bls.sk),
        },
    ];

    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, unbonds, Vec::new(), &all_voter_positions(&st)),
    )
    .into_state()
    .expect("unbond requests");
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
    .expect("cap settles first two");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert!(st.pending_unbonds.contains_key(&i3));

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
    .expect("same epoch still capped");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert_eq!(st.validators[3].stake, 1_000_000);

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
    .expect("new epoch settles deferred exit");
    assert!(!st.pending_unbonds.contains_key(&i3));
    assert_eq!(st.validators[3].stake, 0);
    assert_eq!(st.bond_epoch_exit_count, 1);
}

/// Per-epoch entry churn rejects a third `Register` in the same block.
#[test]
fn entry_churn_cap_rejects_third_register_without_state_change() {
    let fx = boot_three_validators_entry_churn_cfg(2, DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    let ops = vec![
        register_op(stake, 10),
        register_op(stake, 11),
        register_op(stake, 12),
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 2, .. })),
                "expected third register rejected, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("third register must exceed entry churn cap"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators.len(), 3);
}

/// Two `Register` ops within the entry cap apply atomically and move
/// `validator_root` for the successor header.
#[test]
fn entry_churn_cap_allows_two_registers_and_moves_validator_root() {
    let fx = boot_three_validators_entry_churn_cfg(2, DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let st = fx.state.clone();
    let pre_root = validator_set_root(&st.validators);
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    let ops = vec![register_op(stake, 20), register_op(stake, 21)];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    assert_eq!(block.header.validator_root, pre_root);

    let post = apply_block(&st, &block)
        .into_state()
        .expect("two registers within cap");
    assert_eq!(post.validators.len(), 5);
    assert_eq!(post.bond_epoch_entry_count, 2);
    let post_root = validator_set_root(&post.validators);
    assert_ne!(pre_root, post_root);

    let next = build_unsealed_header(&post, &[], &[], &[], &[], 2, 200);
    assert_eq!(next.validator_root, post_root);
}

/// Entry-churn budget resets at the bond epoch boundary.
#[test]
fn entry_churn_cap_resets_at_epoch_boundary() {
    let fx = boot_three_validators_entry_churn_cfg(2, 4);
    let mut st = fx.state.clone();
    let stake = ENTRY_CHURN_REGISTER_STAKE;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 30), register_op(stake, 31)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("first two registers");
    assert_eq!(st.validators.len(), 5);
    assert_eq!(st.bond_epoch_entry_count, 2);

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
    .expect("advance to height 2");
    assert_eq!(st.height, Some(2));

    let after_two = st.clone();
    let block3 = seal_empty(
        &fx,
        &st,
        3,
        vec![register_op(stake, 32)],
        Vec::new(),
        &incumbent_voter_positions(&fx),
    );
    match apply_block(&st, &block3) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })),
                "expected entry cap rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("third register same epoch must reject"),
    }
    assert_eq!(st.validators.len(), after_two.validators.len());

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
    .expect("advance to height 3 before epoch boundary");
    assert_eq!(st.height, Some(3));

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            vec![register_op(stake, 33), register_op(stake, 34)],
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("new epoch allows two more registers");
    assert_eq!(st.validators.len(), 7);
    assert_eq!(st.bond_epoch_entry_count, 2);
}

/// `Register` with a vrf_pk already in the active set rejects atomically.
#[test]
fn duplicate_vrf_register_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let dup_vrf = st.validators[0].vrf_pk;
    let bls = bls_keygen_from_seed(&[190u8; 32]);
    let dup_register = BondOp::Register {
        stake,
        vrf_pk: dup_vrf,
        bls_pk: bls.pk,
        payout: None,
        sig: sign_register(stake, &dup_vrf, &bls.pk, None, &bls.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![dup_register],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("duplicate vrf_pk")
                    )
                }),
                "expected duplicate vrf rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate vrf register must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Two `Unbond` ops for the same validator in one block reject atomically.
#[test]
fn duplicate_unbond_enqueue_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let idx = st.validators[1].index;
    let sig = sign_unbond(idx, &fx.secrets[1].bls.sk);
    let ops = vec![
        BondOp::Unbond {
            validator_index: idx,
            sig,
        },
        BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
        },
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("pending unbond")
                    )
                }),
                "expected duplicate unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate unbond enqueue must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert!(st.pending_unbonds.is_empty());
}

/// Stake below `min_validator_stake` rejects without mutating chain state.
#[test]
fn register_stake_below_minimum_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let below_min = st.bonding_params.min_validator_stake - 1;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![register_op(below_min, 41)],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("min_validator_stake")
                    )
                }),
                "expected stake minimum rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("sub-minimum register must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Same-block `Register` then `Unbond` of the new validator rejects atomically
/// because unbond resolves only against the pre-block validator set.
#[test]
fn same_block_register_then_unbond_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let reg = register_op(stake, 42);
    let new_index = st.next_validator_index;
    let bls = bls_keygen_from_seed(&[192u8; 32]);
    let unbond_new = BondOp::Unbond {
        validator_index: new_index,
        sig: sign_unbond(new_index, &bls.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![reg, unbond_new],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("unknown validator")
                    )
                }),
                "expected same-block register-then-unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("same-block register-then-unbond must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators.len(), 3);
}

/// Two `Register` ops sharing a vrf_pk in one block reject at the second op.
#[test]
fn same_block_duplicate_vrf_register_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = st.bonding_params.min_validator_stake;
    let vrf = vrf_keygen_from_seed(&[60u8; 32]).expect("vrf");
    let bls0 = bls_keygen_from_seed(&[161u8; 32]);
    let bls1 = bls_keygen_from_seed(&[162u8; 32]);
    let ops = vec![
        BondOp::Register {
            stake,
            vrf_pk: vrf.pk,
            bls_pk: bls0.pk,
            payout: None,
            sig: sign_register(stake, &vrf.pk, &bls0.pk, None, &bls0.sk),
        },
        BondOp::Register {
            stake,
            vrf_pk: vrf.pk,
            bls_pk: bls1.pk,
            payout: None,
            sig: sign_register(stake, &vrf.pk, &bls1.pk, None, &bls1.sk),
        },
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("duplicate vrf_pk")
                    )
                }),
                "expected same-block duplicate vrf rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("same-block duplicate vrf must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// `Unbond` of a settled zombie (`stake == 0`) rejects atomically.
#[test]
fn unbond_zombie_validator_rejects_without_state_change() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let v1_idx = st.validators[1].index;
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![BondOp::Unbond {
                validator_index: v1_idx,
                sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
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
    .expect("delay window");
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
    .expect("settlement");
    assert_eq!(st.validators[1].stake, 0);

    let before = snapshot(&st);
    let block = seal_empty(
        &fx,
        &st,
        4,
        vec![BondOp::Unbond {
            validator_index: v1_idx,
            sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("zombie")
                    )
                }),
                "expected zombie unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unbond of zombie must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Forged `Unbond` signature rejects without mutating chain state.
#[test]
fn forged_unbond_signature_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let idx = st.validators[1].index;
    let attacker = bls_keygen_from_seed(&[253u8; 32]);
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &attacker.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("unbond signature invalid")
                    )
                }),
                "expected forged unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("forged unbond must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert!(st.pending_unbonds.is_empty());
}

/// `Unbond` referencing an unknown validator index rejects atomically.
#[test]
fn unbond_unknown_validator_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let bls = bls_keygen_from_seed(&[254u8; 32]);
    let unknown = st.next_validator_index;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![BondOp::Unbond {
            validator_index: unknown,
            sig: sign_unbond(unknown, &bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("unknown validator")
                    )
                }),
                "expected unknown validator unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unbond of unknown validator must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Failed bond ops must not credit treasury — register burn is all-or-nothing.
#[test]
fn bond_rejection_leaves_treasury_unchanged() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let treasury_before = st.treasury;
    let attacker = bls_keygen_from_seed(&[240u8; 32]);
    let victim = bls_keygen_from_seed(&[241u8; 32]);
    let vrf = vrf_keygen_from_seed(&[242u8; 32]).expect("vrf");
    let stake = st.bonding_params.min_validator_stake;
    let bad_register = BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: victim.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &victim.pk, None, &attacker.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![bad_register],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { .. })),
                "expected bond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("forged register must reject"),
    }
    assert_eq!(st.treasury, treasury_before);
    assert_eq!(st.validators.len(), 3);
}

/// Second `Unbond` for a validator who already has a pending exit rejects.
#[test]
fn duplicate_unbond_after_pending_request_rejects_without_state_change() {
    let fx = boot_three_validators_cfg(64, 4);
    let mut st = fx.state.clone();
    let idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: idx,
        sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
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
    .expect("first unbond request");
    assert_eq!(st.pending_unbonds.len(), 1);

    let before = snapshot(&st);
    let treasury_before = st.treasury;
    let block2 = seal_empty(
        &fx,
        &st,
        2,
        vec![BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block2) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("pending unbond")
                    )
                }),
                "expected duplicate pending unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("second unbond while pending must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.treasury, treasury_before);
    assert_eq!(st.pending_unbonds.len(), 1);
}

/// Successful `Register` assigns `next_validator_index` monotonically.
#[test]
fn register_assigns_monotonic_validator_index() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.next_validator_index, 3);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![register_op(stake, 40)],
        Vec::new(),
        &all_voter_positions(&st),
    );
    let post = apply_block(&st, &block)
        .into_state()
        .expect("register block");
    assert_eq!(post.validators.len(), 4);
    assert_eq!(post.validators[3].index, 3);
    assert_eq!(post.next_validator_index, 4);
    assert_eq!(post.bond_epoch_entry_count, 1);
}

/// Successful `Register` extends `validator_stats` in lockstep with the set.
#[test]
fn register_extends_validator_stats() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.validator_stats.len(), 3);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 41)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(post.validators.len(), 4);
    assert_eq!(post.validator_stats.len(), 4);
    assert_eq!(post.validator_stats[3], ValidatorStats::default());
}

/// Successful `Register` burns bonded stake into the permanence treasury.
#[test]
fn register_success_credits_treasury() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.treasury, 0);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 42)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(post.treasury, u128::from(stake));
}

/// Unbond settlement removes the pending exit entry from chain state.
#[test]
fn unbond_settlement_clears_pending_unbond_in_validator_mode() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
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
    assert!(st.pending_unbonds.contains_key(&v1_idx));

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
    .expect("delay window");
    assert!(st.pending_unbonds.contains_key(&v1_idx));

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
    .expect("settlement");
    assert!(!st.pending_unbonds.contains_key(&v1_idx));
    assert_eq!(st.validators[1].stake, 0);
}
