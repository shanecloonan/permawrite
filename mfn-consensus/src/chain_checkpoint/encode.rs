//! Chain checkpoint encoder.

use super::internal::*;

use super::{ChainCheckpoint, CHAIN_CHECKPOINT_MAGIC, CHAIN_CHECKPOINT_VERSION};

/* ----------------------------------------------------------------------- *
 *  Encode                                                                   *
 * ----------------------------------------------------------------------- */

pub(crate) fn encode_emission_params(w: &mut Writer, p: &EmissionParams) {
    w.u64(p.initial_reward);
    w.u64(p.halving_period);
    w.u32(p.halving_count);
    w.u64(p.tail_emission);
    w.u64(p.storage_proof_reward);
    // u16 — emit as 2 BE bytes.
    w.push(&p.fee_to_treasury_bps.to_be_bytes());
}

pub(crate) fn encode_endowment_params(
    w: &mut Writer,
    p: &EndowmentParams,
    checkpoint_version: u32,
) {
    w.u64(p.cost_per_byte_year_ppb);
    w.u64(p.inflation_ppb);
    w.u64(p.real_yield_ppb);
    w.u8(p.min_replication);
    w.u8(p.max_replication);
    w.u64(p.slots_per_year);
    w.u64(p.proof_reward_window_slots);
    if checkpoint_version >= 4 {
        w.u8(p.require_endowment_opening);
    }
    if checkpoint_version >= 5 {
        w.u8(p.operator_salted_challenges);
    }
    if checkpoint_version >= 6 {
        w.u8(p.require_registered_operators);
    }
    if checkpoint_version >= 7 {
        w.u64(p.min_storage_operator_bond);
    }
    if checkpoint_version >= 8 {
        w.u8(p.operator_audit_missed_cap);
        w.u32(p.operator_slash_bps);
    }
}

pub(crate) fn encode_u128(w: &mut Writer, v: u128) {
    w.push(&v.to_be_bytes());
}

fn encode_utxo_entry(w: &mut Writer, e: &UtxoEntry) {
    w.push(&e.commit.compress().to_bytes());
    w.u32(e.height);
}

fn encode_storage_operator_entry(w: &mut Writer, e: &StorageOperatorEntry) {
    w.push(&e.operator_view_pub.compress().to_bytes());
    w.push(&e.operator_spend_pub.compress().to_bytes());
    w.u32(e.registration_height);
    w.u64(e.bond_amount);
}

fn encode_storage_entry(w: &mut Writer, e: &StorageEntry) {
    let commit_bytes = encode_storage_commitment(&e.commit);
    w.varint(commit_bytes.len() as u64);
    w.push(&commit_bytes);
    w.u32(e.last_proven_height);
    w.u64(e.last_proven_slot);
    encode_u128(w, e.pending_yield_ppb);
}

fn encode_authorship_claim_record(w: &mut Writer, rec: &AuthorshipClaimRecord) {
    let wire = encode_authorship_claim(&rec.claim)
        .expect("checkpoint only serializes consensus-valid authorship claims");
    w.varint(wire.len() as u64);
    w.push(&wire);
    w.push(&rec.tx_id);
    w.u32(rec.height);
    w.u32(rec.tx_index);
    w.u32(rec.claim_index);
}

fn encode_claims_state(w: &mut Writer, state: &ChainState) {
    w.varint(state.claims.len() as u64);
    for ((data_root, claim_pubkey), rec) in &state.claims {
        w.push(data_root);
        w.push(claim_pubkey);
        encode_authorship_claim_record(w, rec);
    }
}

/// Encode a [`ChainCheckpoint`] to its canonical bytes.
///
/// Always produces the same output for the same input — including the
/// final integrity tag. Length grows linearly in the unioned size of
/// `utxo`, `spent_key_images`, `storage`, `block_ids`, `validators`,
/// `validator_stats`, `pending_unbonds`, and the sparse `utxo_tree`.
#[must_use]
pub fn encode_chain_checkpoint(parts: &ChainCheckpoint) -> Vec<u8> {
    let mut w = Writer::new();

    // ---- Header ----
    w.push(&CHAIN_CHECKPOINT_MAGIC);
    w.u32(CHAIN_CHECKPOINT_VERSION);

    // ---- Identity ----
    w.push(&parts.genesis_id);

    // ---- Optional height ----
    match parts.state.height {
        None => {
            w.u8(0);
        }
        Some(h) => {
            w.u8(1);
            w.u32(h);
        }
    }

    // ---- Block-id chain ----
    w.varint(parts.state.block_ids.len() as u64);
    for id in &parts.state.block_ids {
        w.push(id);
    }

    // ---- Frozen params ----
    encode_consensus_params(&mut w, &parts.state.params);
    encode_bonding_params(&mut w, &parts.state.bonding_params);
    encode_emission_params(&mut w, &parts.state.emission_params);
    encode_endowment_params(
        &mut w,
        &parts.state.endowment_params,
        CHAIN_CHECKPOINT_VERSION,
    );

    // ---- Treasury ----
    encode_u128(&mut w, parts.state.treasury);

    // ---- Bond counters (flat on ChainState) ----
    w.u64(parts.state.bond_epoch_id);
    w.u32(parts.state.bond_epoch_entry_count);
    w.u32(parts.state.bond_epoch_exit_count);
    w.u32(parts.state.next_validator_index);

    // ---- Validators (preserved order — consensus root depends on it) ----
    w.varint(parts.state.validators.len() as u64);
    for v in &parts.state.validators {
        encode_validator(&mut w, v);
    }

    // ---- Validator stats (1:1 with validators) ----
    w.varint(parts.state.validator_stats.len() as u64);
    for s in &parts.state.validator_stats {
        encode_validator_stats(&mut w, s);
    }

    // ---- Pending unbonds (BTreeMap iterates ascending by key) ----
    w.varint(parts.state.pending_unbonds.len() as u64);
    for p in parts.state.pending_unbonds.values() {
        encode_pending_unbond(&mut w, p);
    }

    // ---- UTXO map (sorted by 32-byte key) ----
    let mut utxo_keys: Vec<&[u8; 32]> = parts.state.utxo.keys().collect();
    utxo_keys.sort();
    w.varint(utxo_keys.len() as u64);
    for k in utxo_keys {
        w.push(k);
        encode_utxo_entry(&mut w, &parts.state.utxo[k]);
    }

    // ---- Spent key images (sorted) ----
    let mut spent_keys: Vec<&[u8; 32]> = parts.state.spent_key_images.iter().collect();
    spent_keys.sort();
    w.varint(spent_keys.len() as u64);
    for k in spent_keys {
        w.push(k);
    }

    // ---- Storage map (sorted by data-root key) ----
    let mut storage_keys: Vec<&[u8; 32]> = parts.state.storage.keys().collect();
    storage_keys.sort();
    w.varint(storage_keys.len() as u64);
    for k in storage_keys {
        w.push(k);
        encode_storage_entry(&mut w, &parts.state.storage[k]);
    }

    if CHAIN_CHECKPOINT_VERSION >= 6 {
        let mut op_keys: Vec<&[u8; 32]> = parts.state.storage_operators.keys().collect();
        op_keys.sort();
        w.varint(op_keys.len() as u64);
        for k in op_keys {
            w.push(k);
            encode_storage_operator_entry(&mut w, &parts.state.storage_operators[k]);
        }
    }

    encode_claims_state(&mut w, &parts.state);

    // ---- UTXO accumulator (length-prefixed nested blob) ----
    let utxo_tree_bytes = encode_utxo_tree_state(&parts.state.utxo_tree);
    w.varint(utxo_tree_bytes.len() as u64);
    w.push(&utxo_tree_bytes);

    // ---- Trailing integrity tag ----
    let payload = w.into_bytes();
    let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
    let mut out = payload;
    out.extend_from_slice(&tag);
    out
}
