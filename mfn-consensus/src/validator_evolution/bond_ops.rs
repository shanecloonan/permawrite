//! Bond-op application phase.

#![allow(unused_imports)]

use super::internal::*;
use super::BondEpochCounters;

/* ----------------------------------------------------------------------- *
 *  Phase 3 — Bond ops                                                       *
 * ----------------------------------------------------------------------- */

/// A single bond-op rejection — the offending op's position plus a
/// human-readable reason.
///
/// Bond-op application is **atomic**: if any op in `block.bond_ops`
/// fails, the entire op list is rejected and the validator set / pending
/// unbonds / counters are left untouched. This matches the full-node
/// `apply_block`'s `BlockError::BondOpRejected` behaviour exactly.
#[derive(Debug)]
pub struct BondOpError {
    /// 0-indexed position in `block.bond_ops`.
    pub index: usize,
    /// Human-readable reason.
    pub message: String,
}

/// Apply this block's bond ops (Register/Unbond) atomically.
///
/// On success: mutates `validators` (extended with new entries from
/// `Register`), `validator_stats` (extended with defaults), `pending_unbonds`
/// (new entries from `Unbond`), and `counters`
/// (`bond_epoch_id` rolls if the epoch boundary crossed,
/// `bond_epoch_entry_count` increments per successful Register,
/// `next_validator_index` advances). Returns the total stake burned
/// (caller credits the treasury).
///
/// On failure: returns `BondOpError`; **no mutation occurs** — the
/// caller's pre-state is preserved. This atomicity mirrors
/// `apply_block`'s historical behaviour and is what the on-chain
/// invariant relies on (a bad bond-ops list rejects the entire block).
#[allow(clippy::too_many_arguments)]
pub fn apply_bond_ops_evolution(
    height: u32,
    counters: &mut BondEpochCounters,
    validators: &mut Vec<Validator>,
    validator_stats: &mut Vec<ValidatorStats>,
    pending_unbonds: &mut BTreeMap<u32, PendingUnbond>,
    bonding_params: &BondingParams,
    bond_ops: &[BondOp],
) -> Result<u128, BondOpError> {
    let slots = bonding_params.slots_per_epoch;
    let epoch_id = epoch_id_for_height(height, slots).map_err(|e| BondOpError {
        index: 0,
        message: format!("bond epoch id: {e}"),
    })?;

    // Working copy of counters — only committed on full success.
    let mut working_epoch_id = counters.bond_epoch_id;
    let mut working_entry_count = counters.bond_epoch_entry_count;
    let mut working_exit_count = counters.bond_epoch_exit_count;
    let mut working_next_index = counters.next_validator_index;
    if epoch_id != working_epoch_id {
        working_epoch_id = epoch_id;
        working_entry_count = 0;
        working_exit_count = 0;
    }

    // Stage new validators and pending unbonds; commit at the end.
    let mut seen_vrf: HashSet<[u8; 32]> = validators
        .iter()
        .map(|v| v.vrf_pk.compress().to_bytes())
        .collect();
    let mut staged_new_validators: Vec<Validator> = Vec::new();
    let mut burn_total: u128 = 0;
    let mut staged_unbonds: Vec<PendingUnbond> = Vec::new();
    let mut seen_unbond_indices: HashSet<u32> = pending_unbonds.keys().copied().collect();

    for (i, op) in bond_ops.iter().enumerate() {
        match op {
            BondOp::Register {
                stake,
                vrf_pk,
                bls_pk,
                payout,
                sig,
            } => {
                validate_stake(*stake, bonding_params).map_err(|e| BondOpError {
                    index: i,
                    message: e.to_string(),
                })?;
                if !verify_register_sig(*stake, vrf_pk, bls_pk, payout.as_ref(), sig) {
                    return Err(BondOpError {
                        index: i,
                        message: "register signature invalid".into(),
                    });
                }
                let vrf_b = vrf_pk.compress().to_bytes();
                if !seen_vrf.insert(vrf_b) {
                    return Err(BondOpError {
                        index: i,
                        message: "duplicate vrf_pk".into(),
                    });
                }
                working_entry_count = try_register_entry_churn(working_entry_count, bonding_params)
                    .map_err(|e| BondOpError {
                        index: i,
                        message: e.to_string(),
                    })?;
                let idx = working_next_index;
                working_next_index = working_next_index.saturating_add(1);
                staged_new_validators.push(Validator {
                    index: idx,
                    vrf_pk: *vrf_pk,
                    bls_pk: *bls_pk,
                    stake: *stake,
                    payout: *payout,
                });
                burn_total = burn_total.saturating_add(u128::from(*stake));
            }
            BondOp::Unbond {
                validator_index,
                sig,
            } => {
                // Resolve against the *combined* validator view: the
                // pre-state plus anything we just staged in this op
                // batch. (apply_block previously used &next.validators
                // which is the pre-block snapshot, so the original
                // behaviour disallows unbonding a validator that was
                // *registered* earlier in the same op list — a same-block
                // register-then-unbond. We preserve that.)
                let v = validators
                    .iter()
                    .find(|v| v.index == *validator_index)
                    .ok_or_else(|| BondOpError {
                        index: i,
                        message: format!("unknown validator {validator_index}"),
                    })?;
                if v.stake == 0 {
                    return Err(BondOpError {
                        index: i,
                        message: "validator already zombie (stake=0)".into(),
                    });
                }
                if !seen_unbond_indices.insert(*validator_index) {
                    return Err(BondOpError {
                        index: i,
                        message: "validator already has pending unbond".into(),
                    });
                }
                if !verify_unbond_sig(*validator_index, sig, &v.bls_pk) {
                    return Err(BondOpError {
                        index: i,
                        message: "unbond signature invalid".into(),
                    });
                }
                staged_unbonds.push(PendingUnbond {
                    validator_index: *validator_index,
                    unlock_height: unbond_unlock_height(height, bonding_params),
                    stake_at_request: v.stake,
                    request_height: height,
                });
            }
        }
    }

    // Atomic commit.
    let n_new = staged_new_validators.len();
    validators.extend(staged_new_validators);
    validator_stats.extend((0..n_new).map(|_| ValidatorStats::default()));
    for pu in staged_unbonds {
        pending_unbonds.insert(pu.validator_index, pu);
    }
    counters.bond_epoch_id = working_epoch_id;
    counters.bond_epoch_entry_count = working_entry_count;
    counters.bond_epoch_exit_count = working_exit_count;
    counters.next_validator_index = working_next_index;
    Ok(burn_total)
}
