use super::internal::*;
use super::*;
use crate::block::ValidatorStats;
use crate::consensus::{Validator, ValidatorPayout};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use mfn_bls::{bls_keygen_from_seed, encode_public_key};
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::utxo_tree::{append_utxo, empty_utxo_tree, utxo_leaf_hash};
use mfn_storage::{StorageCommitment, DEFAULT_CHUNK_SIZE};

fn fresh_state() -> ChainState {
    ChainState {
        height: None,
        utxo: HashMap::new(),
        spent_key_images: HashSet::new(),
        storage: HashMap::new(),
        storage_operators: BTreeMap::new(),
        claims: BTreeMap::new(),
        block_ids: Vec::new(),
        validators: Vec::new(),
        validator_stats: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        treasury: 0,
        utxo_tree: empty_utxo_tree(),
        bonding_params: DEFAULT_BONDING_PARAMS,
        bond_epoch_id: 0,
        bond_epoch_entry_count: 0,
        bond_epoch_exit_count: 0,
        next_validator_index: 0,
        pending_unbonds: BTreeMap::new(),
    }
}

fn point_for(seed: u64) -> EdwardsPoint {
    generator_g() * Scalar::from(seed)
}

fn commit_for(seed: u64) -> EdwardsPoint {
    generator_h() * Scalar::from(seed)
}

fn make_validator(index: u32, stake: u64, with_payout: bool) -> Validator {
    let bls = bls_keygen_from_seed(&[index as u8; 32]);
    let payout = if with_payout {
        Some(ValidatorPayout {
            view_pub: point_for(0xa000 + index as u64),
            spend_pub: point_for(0xb000 + index as u64),
        })
    } else {
        None
    };
    Validator {
        index,
        vrf_pk: point_for(0xc000 + index as u64),
        bls_pk: bls.pk,
        stake,
        payout,
    }
}

fn make_storage_commitment(seed: u8) -> StorageCommitment {
    StorageCommitment {
        data_root: [seed; 32],
        size_bytes: 1024 * (seed as u64 + 1),
        chunk_size: DEFAULT_CHUNK_SIZE as u32,
        num_chunks: 1 + seed as u32,
        replication: 3,
        endowment: commit_for(0xd000 + seed as u64),
    }
}

#[test]
fn pre_genesis_round_trip() {
    let s = fresh_state();
    let cp = ChainCheckpoint {
        genesis_id: [9u8; 32],
        state: s.clone(),
    };
    let bytes = encode_chain_checkpoint(&cp);
    let cp2 = decode_chain_checkpoint(&bytes).unwrap();
    assert_eq!(cp2.genesis_id, cp.genesis_id);
    assert_eq!(cp2.state.height, None);
    assert!(cp2.state.utxo.is_empty());
    assert!(cp2.state.spent_key_images.is_empty());
    assert!(cp2.state.storage.is_empty());
    assert!(cp2.state.claims.is_empty());
    assert!(cp2.state.validators.is_empty());
    // Re-encode must produce identical bytes.
    let bytes2 = encode_chain_checkpoint(&cp2);
    assert_eq!(bytes, bytes2);
}

fn rich_state() -> ChainState {
    let mut s = fresh_state();
    s.height = Some(7);
    s.block_ids = (0u8..8).map(|i| [i; 32]).collect();
    s.treasury = 12_345_678_901_234_567_890u128;
    s.validators.push(make_validator(0, 1_000_000, true));
    s.validators.push(make_validator(1, 2_000_000, false));
    s.validators.push(make_validator(2, 3_000_000, true));
    s.validator_stats.push(ValidatorStats {
        consecutive_missed: 0,
        total_signed: 7,
        total_missed: 0,
        liveness_slashes: 0,
    });
    s.validator_stats.push(ValidatorStats {
        consecutive_missed: 3,
        total_signed: 4,
        total_missed: 3,
        liveness_slashes: 1,
    });
    s.validator_stats.push(ValidatorStats {
        consecutive_missed: 0,
        total_signed: 5,
        total_missed: 2,
        liveness_slashes: 0,
    });
    s.pending_unbonds.insert(
        1,
        PendingUnbond {
            validator_index: 1,
            unlock_height: 100,
            stake_at_request: 2_000_000,
            request_height: 50,
        },
    );
    s.next_validator_index = 3;
    s.bond_epoch_id = 4;
    s.bond_epoch_entry_count = 1;
    s.bond_epoch_exit_count = 0;
    for i in 0u64..10 {
        let key_pt = point_for(0x1000 + i);
        let key = key_pt.compress().to_bytes();
        s.utxo.insert(
            key,
            UtxoEntry {
                commit: commit_for(0x2000 + i),
                height: i as u32,
            },
        );
    }
    for i in 0u64..5 {
        let ki = point_for(0x3000 + i).compress().to_bytes();
        s.spent_key_images.insert(ki);
    }
    for seed in 0u8..4 {
        let c = make_storage_commitment(seed);
        let key = mfn_storage::storage_commitment_hash(&c);
        s.storage.insert(
            key,
            StorageEntry {
                commit: c,
                last_proven_height: 100 + seed as u32,
                last_proven_slot: 1_000 + seed as u64,
                pending_yield_ppb: 1234 * (seed as u128 + 1),
            },
        );
    }
    // Populate the UTXO accumulator with the same leaves that match
    // the utxo entries (so utxo_tree_root is non-trivial).
    let mut t = empty_utxo_tree();
    for (i, (k, v)) in {
        let mut keys: Vec<&[u8; 32]> = s.utxo.keys().collect();
        keys.sort();
        keys.into_iter().map(|k| (k, &s.utxo[k]))
    }
    .enumerate()
    {
        let _ = i;
        let key_pt = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(k)
            .unwrap()
            .decompress()
            .unwrap();
        let leaf = utxo_leaf_hash(&key_pt, &v.commit, v.height);
        t = append_utxo(&t, leaf).unwrap();
    }
    s.utxo_tree = t;
    s
}

#[test]
fn rich_round_trip_preserves_every_field() {
    let s = rich_state();
    let cp = ChainCheckpoint {
        genesis_id: [0xab; 32],
        state: s.clone(),
    };
    let bytes = encode_chain_checkpoint(&cp);
    let cp2 = decode_chain_checkpoint(&bytes).unwrap();
    assert_eq!(cp2.genesis_id, cp.genesis_id);
    let r = &cp2.state;
    assert_eq!(r.height, s.height);
    assert_eq!(r.block_ids, s.block_ids);
    assert_eq!(r.treasury, s.treasury);
    assert_eq!(r.bond_epoch_id, s.bond_epoch_id);
    assert_eq!(r.bond_epoch_entry_count, s.bond_epoch_entry_count);
    assert_eq!(r.bond_epoch_exit_count, s.bond_epoch_exit_count);
    assert_eq!(r.next_validator_index, s.next_validator_index);
    assert_eq!(r.validators.len(), s.validators.len());
    for (a, b) in r.validators.iter().zip(s.validators.iter()) {
        assert_eq!(a.index, b.index);
        assert_eq!(a.stake, b.stake);
        assert_eq!(
            a.vrf_pk.compress().to_bytes(),
            b.vrf_pk.compress().to_bytes()
        );
        assert_eq!(encode_public_key(&a.bls_pk), encode_public_key(&b.bls_pk));
        assert_eq!(a.payout.is_some(), b.payout.is_some());
    }
    assert_eq!(r.validator_stats, s.validator_stats);
    assert_eq!(r.pending_unbonds, s.pending_unbonds);
    assert_eq!(r.utxo.len(), s.utxo.len());
    for (k, v) in &s.utxo {
        let rv = r.utxo.get(k).expect("utxo key preserved");
        assert_eq!(
            rv.commit.compress().to_bytes(),
            v.commit.compress().to_bytes()
        );
        assert_eq!(rv.height, v.height);
    }
    assert_eq!(r.spent_key_images, s.spent_key_images);
    assert_eq!(r.claims, s.claims);
    assert_eq!(r.storage.len(), s.storage.len());
    for (k, v) in &s.storage {
        let rv = r.storage.get(k).expect("storage key preserved");
        assert_eq!(
            mfn_storage::storage_commitment_hash(&rv.commit),
            mfn_storage::storage_commitment_hash(&v.commit)
        );
        assert_eq!(rv.last_proven_height, v.last_proven_height);
        assert_eq!(rv.last_proven_slot, v.last_proven_slot);
        assert_eq!(rv.pending_yield_ppb, v.pending_yield_ppb);
    }
    assert_eq!(
        mfn_crypto::utxo_tree_root(&r.utxo_tree),
        mfn_crypto::utxo_tree_root(&s.utxo_tree)
    );
    assert_eq!(r.params.quorum_stake_bps, s.params.quorum_stake_bps);
    assert_eq!(r.emission_params, s.emission_params);
    assert_eq!(r.endowment_params, s.endowment_params);
    assert_eq!(r.bonding_params, s.bonding_params);
    // Determinism: re-encode round 2 yields identical bytes.
    let bytes2 = encode_chain_checkpoint(&cp2);
    assert_eq!(bytes, bytes2, "encoder must be deterministic");
}

#[test]
fn encode_is_independent_of_hashmap_iteration_order() {
    let s_a = rich_state();
    // Build a "shuffled" duplicate by inserting in reverse — its
    // HashMap iteration order will differ, but the canonical sort
    // inside the encoder must produce identical bytes.
    let mut s_b = ChainState {
        height: s_a.height,
        utxo: HashMap::new(),
        spent_key_images: HashSet::new(),
        storage: HashMap::new(),
        storage_operators: BTreeMap::new(),
        claims: s_a.claims.clone(),
        block_ids: s_a.block_ids.clone(),
        validators: s_a.validators.clone(),
        validator_stats: s_a.validator_stats.clone(),
        params: s_a.params,
        emission_params: s_a.emission_params,
        endowment_params: s_a.endowment_params,
        treasury: s_a.treasury,
        utxo_tree: s_a.utxo_tree.clone(),
        bonding_params: s_a.bonding_params,
        bond_epoch_id: s_a.bond_epoch_id,
        bond_epoch_entry_count: s_a.bond_epoch_entry_count,
        bond_epoch_exit_count: s_a.bond_epoch_exit_count,
        next_validator_index: s_a.next_validator_index,
        pending_unbonds: s_a.pending_unbonds.clone(),
    };
    let mut utxo_pairs: Vec<_> = s_a.utxo.iter().collect();
    utxo_pairs.reverse();
    for (k, v) in utxo_pairs {
        s_b.utxo.insert(*k, v.clone());
    }
    let mut spent: Vec<_> = s_a.spent_key_images.iter().collect();
    spent.reverse();
    for k in spent {
        s_b.spent_key_images.insert(*k);
    }
    let mut storage: Vec<_> = s_a.storage.iter().collect();
    storage.reverse();
    for (k, v) in storage {
        s_b.storage.insert(*k, v.clone());
    }
    let cp_a = ChainCheckpoint {
        genesis_id: [7u8; 32],
        state: s_a,
    };
    let cp_b = ChainCheckpoint {
        genesis_id: [7u8; 32],
        state: s_b,
    };
    assert_eq!(
        encode_chain_checkpoint(&cp_a),
        encode_chain_checkpoint(&cp_b),
        "encoding must be independent of HashMap insertion order"
    );
}

#[test]
fn rejects_bad_magic() {
    let cp = ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: fresh_state(),
    };
    let mut bytes = encode_chain_checkpoint(&cp);
    bytes[0] ^= 0xff;
    // Flipping the magic changes the payload → integrity tag mismatch
    // triggers first. Recompute the tag so the magic check actually
    // fires.
    let plen = bytes.len() - 32;
    let new_tag = dhash(CHAIN_CHECKPOINT, &[&bytes[..plen]]);
    bytes[plen..].copy_from_slice(&new_tag);
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::BadMagic { .. }) => {}
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn rejects_unsupported_version() {
    let cp = ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: fresh_state(),
    };
    let mut bytes = encode_chain_checkpoint(&cp);
    // Bytes 4..8 are the version, big-endian. Flip to 9.
    bytes[4..8].copy_from_slice(&9u32.to_be_bytes());
    let plen = bytes.len() - 32;
    let new_tag = dhash(CHAIN_CHECKPOINT, &[&bytes[..plen]]);
    bytes[plen..].copy_from_slice(&new_tag);
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::UnsupportedVersion { got }) => assert_eq!(got, 9),
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn detects_payload_tamper() {
    let cp = ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: rich_state(),
    };
    let mut bytes = encode_chain_checkpoint(&cp);
    // Flip a payload byte but leave the trailing tag alone — the
    // recomputed tag will no longer match.
    let pos = bytes.len() / 2;
    bytes[pos] ^= 0xff;
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::IntegrityCheckFailed) => {}
        other => panic!("expected IntegrityCheckFailed, got {other:?}"),
    }
}

#[test]
fn detects_tag_tamper() {
    let cp = ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: fresh_state(),
    };
    let mut bytes = encode_chain_checkpoint(&cp);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::IntegrityCheckFailed) => {}
        other => panic!("expected IntegrityCheckFailed, got {other:?}"),
    }
}

#[test]
fn rejects_truncated_below_minimum() {
    let bytes = vec![0u8; 8];
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::Read(CheckpointReadError::Truncated { .. })) => {}
        other => panic!("expected Read(Truncated), got {other:?}"),
    }
}

#[test]
fn rejects_duplicate_validator_index() {
    // Manually craft a tiny payload with two validators sharing index 0.
    let mut w = Writer::new();
    w.push(&CHAIN_CHECKPOINT_MAGIC);
    w.u32(1); // v1 wire (no claims section)
    w.push(&[0u8; 32]); // genesis_id
    w.u8(0); // height_flag = pre-genesis
    w.varint(0); // block_ids
    encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
    encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
    encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
    encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS, 1);
    encode_u128(&mut w, 0);
    w.u64(0); // bond_epoch_id
    w.u32(0);
    w.u32(0);
    w.u32(100); // next_validator_index
    w.varint(2); // validators.len
    encode_validator(&mut w, &make_validator(7, 1, false));
    encode_validator(&mut w, &make_validator(7, 2, false));
    w.varint(2); // stats.len
    for _ in 0..2 {
        encode_validator_stats(&mut w, &ValidatorStats::default());
    }
    w.varint(0); // pending_unbonds
    w.varint(0); // utxo
    w.varint(0); // spent
    w.varint(0); // storage
    let tree = encode_utxo_tree_state(&empty_utxo_tree());
    w.varint(tree.len() as u64);
    w.push(&tree);
    let payload = w.into_bytes();
    let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
    let mut bytes = payload;
    bytes.extend_from_slice(&tag);
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::Read(CheckpointReadError::DuplicateValidatorIndex { index })) => {
            assert_eq!(index, 7);
        }
        other => panic!("expected Read(DuplicateValidatorIndex), got {other:?}"),
    }
}

#[test]
fn rejects_stats_validators_mismatch() {
    let mut w = Writer::new();
    w.push(&CHAIN_CHECKPOINT_MAGIC);
    w.u32(1); // v1 wire (no claims section)
    w.push(&[0u8; 32]);
    w.u8(0);
    w.varint(0);
    encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
    encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
    encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
    encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS, 1);
    encode_u128(&mut w, 0);
    w.u64(0);
    w.u32(0);
    w.u32(0);
    w.u32(100);
    w.varint(1);
    encode_validator(&mut w, &make_validator(0, 1, false));
    w.varint(2); // mismatch
    for _ in 0..2 {
        encode_validator_stats(&mut w, &ValidatorStats::default());
    }
    w.varint(0);
    w.varint(0);
    w.varint(0);
    w.varint(0);
    let tree = encode_utxo_tree_state(&empty_utxo_tree());
    w.varint(tree.len() as u64);
    w.push(&tree);
    let payload = w.into_bytes();
    let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
    let mut bytes = payload;
    bytes.extend_from_slice(&tag);
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::Read(CheckpointReadError::StatsLengthMismatch {
            validators,
            stats,
        })) => {
            assert_eq!(validators, 1);
            assert_eq!(stats, 2);
        }
        other => panic!("expected Read(StatsLengthMismatch), got {other:?}"),
    }
}

#[test]
fn rejects_next_index_at_or_below_max_assigned() {
    let mut w = Writer::new();
    w.push(&CHAIN_CHECKPOINT_MAGIC);
    w.u32(1); // v1 wire (no claims section)
    w.push(&[0u8; 32]);
    w.u8(0);
    w.varint(0);
    encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
    encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
    encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
    encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS, 1);
    encode_u128(&mut w, 0);
    w.u64(0);
    w.u32(0);
    w.u32(0);
    w.u32(5); // next_validator_index = 5
    w.varint(1);
    encode_validator(&mut w, &make_validator(5, 1, false));
    w.varint(1);
    encode_validator_stats(&mut w, &ValidatorStats::default());
    w.varint(0);
    w.varint(0);
    w.varint(0);
    w.varint(0);
    let tree = encode_utxo_tree_state(&empty_utxo_tree());
    w.varint(tree.len() as u64);
    w.push(&tree);
    let payload = w.into_bytes();
    let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
    let mut bytes = payload;
    bytes.extend_from_slice(&tag);
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::Read(CheckpointReadError::NextIndexBelowAssigned {
            next,
            max_assigned,
        })) => {
            assert_eq!(next, 5);
            assert_eq!(max_assigned, 5);
        }
        other => panic!("expected Read(NextIndexBelowAssigned), got {other:?}"),
    }
}

#[test]
fn rejects_trailing_bytes_after_tag() {
    let cp = ChainCheckpoint {
        genesis_id: [0u8; 32],
        state: fresh_state(),
    };
    let mut bytes = encode_chain_checkpoint(&cp);
    bytes.push(0u8);
    // After the integrity check, decoder reads the payload via the
    // inner reader and would see trailing bytes inside the payload.
    // But pushing a byte AFTER the tag changes the payload-vs-tag
    // split: now the "tag" is the last 32 bytes (which include
    // payload bytes + the appended byte), and the recomputed tag
    // won't match.  In that case `IntegrityCheckFailed` is the
    // expected behavior — the codec doesn't have a separate
    // "trailing-after-tag" path because every byte before the tag
    // is part of the integrity-checked payload by definition.
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::IntegrityCheckFailed) => {}
        other => panic!("expected IntegrityCheckFailed, got {other:?}"),
    }
}

#[test]
fn light_checkpoint_bytes_fail_chain_decode() {
    // Sanity check that the two checkpoint families are
    // domain-separated: feeding a (well-formed) byte stream that
    // happens to start with a different magic must fail the magic
    // check, not silently decode part of the way through.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MFLC"); // light magic
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]); // fake payload
                                         // 32-byte tag at the end so length >= MIN_LEN.
    bytes.extend_from_slice(&[0u8; 32]);
    // Integrity check fails first (the tag isn't a real
    // CHAIN_CHECKPOINT tag), which is the correct rejection mode.
    match decode_chain_checkpoint(&bytes) {
        Err(ChainCheckpointError::IntegrityCheckFailed) => {}
        other => panic!("expected IntegrityCheckFailed, got {other:?}"),
    }
}
