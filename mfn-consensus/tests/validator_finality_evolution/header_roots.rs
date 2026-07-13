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

/// Header `bond_root` must match the body's bond-op list; tampering
/// rejects before any validator-set mutation.
#[test]
fn bond_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.bond_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondRootMismatch)),
                "expected bond_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered bond_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `slashing_root` must match the body's slashings list even when
/// the list carries valid equivocation evidence.
#[test]
fn slashing_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
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
    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![evidence],
        &all_voter_positions(&st),
    );
    assert_ne!(block.header.slashing_root, [0u8; 32]);
    block.header.slashing_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::SlashingRootMismatch)),
                "expected slashing_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered slashing_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `tx_root` must match the (empty) tx list on validator-mode blocks.
#[test]
fn tx_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.tx_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::TxRootMismatch)),
                "expected tx_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered tx_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `storage_proof_root` must match the (empty) proofs list.
#[test]
fn storage_proof_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    assert_eq!(block.header.storage_proof_root, [0u8; 32]);
    block.header.storage_proof_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)),
                "expected storage_proof_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered storage_proof_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `claims_root` must match the (empty) authorship-claims list.
#[test]
fn claims_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.claims_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::ClaimsRootMismatch)),
                "expected claims_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered claims_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `utxo_root` must match the projected post-block accumulator.
#[test]
fn utxo_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.utxo_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::UtxoRootMismatch)),
                "expected utxo_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered utxo_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `storage_root` must match newly-anchored commitments (empty ⇒ zero).
#[test]
fn storage_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    assert_eq!(block.header.storage_root, [0u8; 32]);
    block.header.storage_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageRootMismatch)),
                "expected storage_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered storage_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}
