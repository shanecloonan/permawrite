//! Chain checkpoint decoder.

use super::internal::*;

use super::{ChainCheckpoint, ChainCheckpointError, CHAIN_CHECKPOINT_MAGIC};

/* ----------------------------------------------------------------------- *
 *  Decode                                                                   *
 * ----------------------------------------------------------------------- */

fn decode_emission_params(r: &mut Reader<'_>) -> Result<EmissionParams, ChainCheckpointError> {
    Ok(EmissionParams {
        initial_reward: read_u64(r, "emission_params.initial_reward")?,
        halving_period: read_u64(r, "emission_params.halving_period")?,
        halving_count: read_u32(r, "emission_params.halving_count")?,
        tail_emission: read_u64(r, "emission_params.tail_emission")?,
        storage_proof_reward: read_u64(r, "emission_params.storage_proof_reward")?,
        fee_to_treasury_bps: read_u16(r, "emission_params.fee_to_treasury_bps")?,
    })
}

fn decode_endowment_params(
    r: &mut Reader<'_>,
    checkpoint_version: u32,
) -> Result<EndowmentParams, ChainCheckpointError> {
    Ok(EndowmentParams {
        cost_per_byte_year_ppb: read_u64(r, "endowment_params.cost_per_byte_year_ppb")?,
        inflation_ppb: read_u64(r, "endowment_params.inflation_ppb")?,
        real_yield_ppb: read_u64(r, "endowment_params.real_yield_ppb")?,
        min_replication: read_u8(r, "endowment_params.min_replication")?,
        max_replication: read_u8(r, "endowment_params.max_replication")?,
        slots_per_year: read_u64(r, "endowment_params.slots_per_year")?,
        proof_reward_window_slots: read_u64(r, "endowment_params.proof_reward_window_slots")?,
        require_endowment_opening: if checkpoint_version >= 4 {
            read_u8(r, "endowment_params.require_endowment_opening")?
        } else {
            0
        },
    })
}

fn decode_utxo_entry(r: &mut Reader<'_>, index: usize) -> Result<UtxoEntry, ChainCheckpointError> {
    let commit = read_edwards_point(r, "utxo[i].commit").map_err(|e| match e {
        EdwardsReadError::Truncated { field, needed } => {
            ChainCheckpointError::Read(CheckpointReadError::Truncated { field, needed })
        }
        EdwardsReadError::InvalidPoint => ChainCheckpointError::InvalidUtxoCommit { index },
    })?;
    let height = read_u32(r, "utxo[i].height")?;
    Ok(UtxoEntry { commit, height })
}

fn decode_storage_entry(
    r: &mut Reader<'_>,
    index: usize,
) -> Result<StorageEntry, ChainCheckpointError> {
    // The inner storage-commitment codec enforces "no trailing bytes"
    // itself, so we hand it exactly the slice we framed on the encode
    // side and propagate any structural error verbatim.
    let commit_len = read_len(r, "storage[i].commit.len")?;
    let commit_slice = r
        .bytes(commit_len)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "storage[i].commit",
            needed: commit_len,
        })?;
    let commit = decode_storage_commitment(commit_slice)
        .map_err(|source| ChainCheckpointError::InvalidStorageCommitment { index, source })?;
    let last_proven_height = read_u32(r, "storage[i].last_proven_height")?;
    let last_proven_slot = read_u64(r, "storage[i].last_proven_slot")?;
    let pending_yield_ppb = read_u128(r, "storage[i].pending_yield_ppb")?;
    Ok(StorageEntry {
        commit,
        last_proven_height,
        last_proven_slot,
        pending_yield_ppb,
    })
}

fn decode_authorship_claim_record_v3(
    r: &mut Reader<'_>,
    index: usize,
    expected_data_root: &[u8; 32],
    expected_claim_pubkey: &[u8; 32],
) -> Result<AuthorshipClaimRecord, ChainCheckpointError> {
    let wire_len = read_len(r, "claims.record.wire.len")?;
    let wire = r
        .bytes(wire_len)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "claims.record.wire",
            needed: wire_len,
        })?;
    let claim = decode_authorship_claim(wire)
        .map_err(|e| ChainCheckpointError::AuthorshipClaimWire(format!("claims[{index}]: {e}")))?;
    if &claim.data_root != expected_data_root {
        return Err(ChainCheckpointError::ClaimsRecordKeyMismatch {
            outer: index,
            inner: 0,
        });
    }
    if claim.claim_pubkey.compress().as_bytes() != expected_claim_pubkey {
        return Err(ChainCheckpointError::ClaimsRecordKeyMismatch {
            outer: index,
            inner: 0,
        });
    }
    let tx_id = read_fixed(r, "claims.record.tx_id")?;
    let height = read_u32(r, "claims.record.height")?;
    let tx_index = read_u32(r, "claims.record.tx_index")?;
    let claim_index = read_u32(r, "claims.record.claim_index")?;
    Ok(AuthorshipClaimRecord {
        claim,
        tx_id,
        height,
        tx_index,
        claim_index,
    })
}

fn decode_authorship_claim_record_v2(
    r: &mut Reader<'_>,
    outer: usize,
    inner: usize,
    expected_data_root: &[u8; 32],
) -> Result<AuthorshipClaimRecord, ChainCheckpointError> {
    let wire_len = read_len(r, "claims.record.wire.len")?;
    let wire = r
        .bytes(wire_len)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "claims.record.wire",
            needed: wire_len,
        })?;
    let claim = decode_authorship_claim(wire).map_err(|e| {
        ChainCheckpointError::AuthorshipClaimWire(format!("claims[{outer}].records[{inner}]: {e}"))
    })?;
    if &claim.data_root != expected_data_root {
        return Err(ChainCheckpointError::ClaimsRecordKeyMismatch { outer, inner });
    }
    let tx_id = read_fixed(r, "claims.record.tx_id")?;
    let height = read_u32(r, "claims.record.height")?;
    let tx_index = read_u32(r, "claims.record.tx_index")?;
    let claim_index = read_u32(r, "claims.record.claim_index")?;
    Ok(AuthorshipClaimRecord {
        claim,
        tx_id,
        height,
        tx_index,
        claim_index,
    })
}

fn decode_claims_state_v3(
    r: &mut Reader<'_>,
) -> Result<BTreeMap<AuthorshipClaimKey, AuthorshipClaimRecord>, ChainCheckpointError> {
    let claims_n = read_len(r, "claims.len")?;
    let mut claims: BTreeMap<AuthorshipClaimKey, AuthorshipClaimRecord> = BTreeMap::new();
    let mut prev_key: Option<AuthorshipClaimKey> = None;
    for i in 0..claims_n {
        let data_root: [u8; 32] = read_fixed(r, "claims[i].data_root")?;
        let claim_pubkey: [u8; 32] = read_fixed(r, "claims[i].claim_pubkey")?;
        let key = (data_root, claim_pubkey);
        if let Some(prev) = prev_key {
            if key <= prev {
                return Err(ChainCheckpointError::ClaimsNotSorted { index: i });
            }
        }
        prev_key = Some(key);
        let rec = decode_authorship_claim_record_v3(r, i, &data_root, &claim_pubkey)?;
        claims.insert(key, rec);
    }
    Ok(claims)
}

fn decode_claims_state_v2(
    r: &mut Reader<'_>,
) -> Result<BTreeMap<AuthorshipClaimKey, AuthorshipClaimRecord>, ChainCheckpointError> {
    let claims_n = read_len(r, "claims.len")?;
    let mut claims: BTreeMap<AuthorshipClaimKey, AuthorshipClaimRecord> = BTreeMap::new();
    let mut prev_key: Option<[u8; 32]> = None;
    for i in 0..claims_n {
        let data_root: [u8; 32] = read_fixed(r, "claims[i].key")?;
        if let Some(prev) = prev_key {
            if data_root <= prev {
                return Err(ChainCheckpointError::ClaimsNotSorted { index: i });
            }
        }
        prev_key = Some(data_root);
        let rec_n = read_len(r, "claims[i].records.len")?;
        for j in 0..rec_n {
            let rec = decode_authorship_claim_record_v2(r, i, j, &data_root)?;
            let key = authorship_claim_key(&rec.claim);
            claims.insert(key, rec);
        }
    }
    // Legacy `claim_submitted` leaf set — skip on load (superseded by keyed map).
    let submitted_n = read_len(r, "claim_submitted.len")?;
    for _ in 0..submitted_n {
        let _: [u8; 32] = read_fixed(r, "claim_submitted[i]")?;
    }
    Ok(claims)
}

/// Decode a [`ChainCheckpoint`] from canonical bytes produced by
/// [`encode_chain_checkpoint`]. Strict on every invariant:
///
/// - magic + version must match;
/// - every length must fit `usize`;
/// - sorted-map fields must be **strictly ascending** (rejects duplicates);
/// - validator-stats length must equal validator length;
/// - `next_validator_index` must exceed every assigned validator index;
/// - trailing integrity tag must reproduce `dhash(CHAIN_CHECKPOINT, &[payload])`;
/// - no trailing bytes after the tag.
///
/// # Errors
///
/// See [`ChainCheckpointError`].
pub fn decode_chain_checkpoint(bytes: &[u8]) -> Result<ChainCheckpoint, ChainCheckpointError> {
    // Need at least magic + version + tag.
    const MIN_LEN: usize = 4 + 4 + 32;
    if bytes.len() < MIN_LEN {
        return Err(CheckpointReadError::Truncated {
            field: "magic+version+tag",
            needed: MIN_LEN.saturating_sub(bytes.len()),
        }
        .into());
    }
    let payload_len = bytes.len() - 32;
    let payload = &bytes[..payload_len];
    let tag_bytes = &bytes[payload_len..];
    let expected_tag = dhash(CHAIN_CHECKPOINT, &[payload]);
    if tag_bytes != expected_tag {
        return Err(ChainCheckpointError::IntegrityCheckFailed);
    }

    let mut r = Reader::new(payload);

    let magic: [u8; 4] = read_fixed(&mut r, "magic")?;
    if magic != CHAIN_CHECKPOINT_MAGIC {
        return Err(ChainCheckpointError::BadMagic { got: magic });
    }
    let version = read_u32(&mut r, "version")?;
    if version != 1 && version != 2 && version != 3 && version != 4 {
        return Err(ChainCheckpointError::UnsupportedVersion { got: version });
    }

    let genesis_id: [u8; 32] = read_fixed(&mut r, "genesis_id")?;

    let height_flag = read_u8(&mut r, "height_flag")?;
    let height = match height_flag {
        0 => None,
        1 => Some(read_u32(&mut r, "height")?),
        other => return Err(ChainCheckpointError::InvalidHeightFlag { flag: other }),
    };

    let block_ids_n = read_len(&mut r, "block_ids.len")?;
    let mut block_ids = Vec::with_capacity(block_ids_n);
    for _ in 0..block_ids_n {
        block_ids.push(read_fixed::<32>(&mut r, "block_ids[i]")?);
    }

    let params = decode_consensus_params(&mut r)?;
    let bonding_params = decode_bonding_params(&mut r)?;
    let emission_params = decode_emission_params(&mut r)?;
    let endowment_params = decode_endowment_params(&mut r, version)?;

    let treasury = read_u128(&mut r, "treasury")?;

    let bond_epoch_id = read_u64(&mut r, "bond_counters.bond_epoch_id")?;
    let bond_epoch_entry_count = read_u32(&mut r, "bond_counters.bond_epoch_entry_count")?;
    let bond_epoch_exit_count = read_u32(&mut r, "bond_counters.bond_epoch_exit_count")?;
    let next_validator_index = read_u32(&mut r, "bond_counters.next_validator_index")?;

    let validators_n = read_len(&mut r, "validators.len")?;
    let mut validators = Vec::with_capacity(validators_n);
    for i in 0..validators_n {
        validators.push(decode_validator(&mut r, i)?);
    }

    let stats_n = read_len(&mut r, "validator_stats.len")?;
    if stats_n != validators_n {
        return Err(CheckpointReadError::StatsLengthMismatch {
            validators: validators_n,
            stats: stats_n,
        }
        .into());
    }
    let mut validator_stats = Vec::with_capacity(stats_n);
    for _ in 0..stats_n {
        validator_stats.push(decode_validator_stats(&mut r)?);
    }

    let pending_n = read_len(&mut r, "pending_unbonds.len")?;
    let mut pending_unbonds: BTreeMap<u32, PendingUnbond> = BTreeMap::new();
    let mut prev_pidx: Option<u32> = None;
    for i in 0..pending_n {
        let p = decode_pending_unbond(&mut r)?;
        if let Some(prev) = prev_pidx {
            if p.validator_index <= prev {
                return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
            }
        }
        prev_pidx = Some(p.validator_index);
        if pending_unbonds.insert(p.validator_index, p).is_some() {
            return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
        }
    }

    // ---- UTXO map ----
    let utxo_n = read_len(&mut r, "utxo.len")?;
    let mut utxo: HashMap<[u8; 32], UtxoEntry> = HashMap::with_capacity(utxo_n);
    let mut prev_utxo_key: Option<[u8; 32]> = None;
    for i in 0..utxo_n {
        let key: [u8; 32] = read_fixed(&mut r, "utxo[i].key")?;
        if let Some(prev) = prev_utxo_key {
            if key <= prev {
                return Err(ChainCheckpointError::UtxoNotSorted { index: i });
            }
        }
        prev_utxo_key = Some(key);
        let entry = decode_utxo_entry(&mut r, i)?;
        utxo.insert(key, entry);
    }

    // ---- Spent key images ----
    let spent_n = read_len(&mut r, "spent_key_images.len")?;
    let mut spent_key_images: HashSet<[u8; 32]> = HashSet::with_capacity(spent_n);
    let mut prev_spent_key: Option<[u8; 32]> = None;
    for i in 0..spent_n {
        let key: [u8; 32] = read_fixed(&mut r, "spent_key_images[i]")?;
        if let Some(prev) = prev_spent_key {
            if key <= prev {
                return Err(ChainCheckpointError::SpentKeyImagesNotSorted { index: i });
            }
        }
        prev_spent_key = Some(key);
        spent_key_images.insert(key);
    }

    // ---- Storage map ----
    let storage_n = read_len(&mut r, "storage.len")?;
    let mut storage: HashMap<[u8; 32], StorageEntry> = HashMap::with_capacity(storage_n);
    let mut prev_storage_key: Option<[u8; 32]> = None;
    for i in 0..storage_n {
        let key: [u8; 32] = read_fixed(&mut r, "storage[i].key")?;
        if let Some(prev) = prev_storage_key {
            if key <= prev {
                return Err(ChainCheckpointError::StorageNotSorted { index: i });
            }
        }
        prev_storage_key = Some(key);
        let entry = decode_storage_entry(&mut r, i)?;
        storage.insert(key, entry);
    }

    let claims = match version {
        1 => BTreeMap::new(),
        2 => decode_claims_state_v2(&mut r)?,
        3 | 4 => decode_claims_state_v3(&mut r)?,
        _ => {
            return Err(ChainCheckpointError::UnsupportedVersion { got: version });
        }
    };

    // ---- UTXO accumulator ----
    let utxo_tree_n = read_len(&mut r, "utxo_tree.len")?;
    let utxo_tree_bytes = r
        .bytes(utxo_tree_n)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "utxo_tree",
            needed: utxo_tree_n,
        })?;
    let utxo_tree: UtxoTreeState = decode_utxo_tree_state(utxo_tree_bytes)
        .map_err(|source| ChainCheckpointError::InvalidUtxoTree { source })?;

    if !r.end() {
        return Err(ChainCheckpointError::TrailingBytes {
            remaining: r.remaining(),
        });
    }

    // Cross-validator invariants (duplicate-index + next-index) live
    // in the shared codec.
    check_validator_assignment(&validators, next_validator_index)?;

    let counters = BondEpochCounters {
        bond_epoch_id,
        bond_epoch_entry_count,
        bond_epoch_exit_count,
        next_validator_index,
    };

    // Silence "unused" warnings for the params defaults we don't need
    // here — they exist to document the genesis defaults that match the
    // codec. (Touching them keeps `cargo doc` cross-links honest.)
    let _ = DEFAULT_CONSENSUS_PARAMS;
    let _ = DEFAULT_BONDING_PARAMS;
    let _ = DEFAULT_EMISSION_PARAMS;
    let _ = DEFAULT_ENDOWMENT_PARAMS;

    let state = ChainState {
        height,
        utxo,
        spent_key_images,
        storage,
        claims,
        block_ids,
        validators,
        validator_stats,
        params,
        emission_params,
        endowment_params,
        treasury,
        utxo_tree,
        bonding_params,
        bond_epoch_id: counters.bond_epoch_id,
        bond_epoch_entry_count: counters.bond_epoch_entry_count,
        bond_epoch_exit_count: counters.bond_epoch_exit_count,
        next_validator_index: counters.next_validator_index,
        pending_unbonds,
    };

    Ok(ChainCheckpoint { genesis_id, state })
}
