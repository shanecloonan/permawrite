//! Unbond settlement phase.

#![allow(unused_imports)]

use super::internal::*;
use super::BondEpochCounters;

/* ----------------------------------------------------------------------- *
 *  Phase 4 — Unbond settlements                                             *
 * ----------------------------------------------------------------------- */

/// Apply this block's unbond settlements.
///
/// Walks `pending_unbonds` in sorted-by-index order. For each entry
/// whose `unlock_height <= height` AND that fits in the remaining
/// exit-churn budget for `counters.bond_epoch_id`:
///
/// - Increment `counters.bond_epoch_exit_count`.
/// - Zero the validator's stake in `validators`.
/// - Remove the entry from `pending_unbonds`.
///
/// Stops at the first entry that can't be admitted (churn full); the
/// remaining due entries are held over to the next block, exactly as
/// `apply_block` does.
pub fn apply_unbond_settlements(
    height: u32,
    counters: &mut BondEpochCounters,
    bonding_params: &BondingParams,
    validators: &mut [Validator],
    pending_unbonds: &mut BTreeMap<u32, PendingUnbond>,
) {
    let due: Vec<u32> = pending_unbonds
        .iter()
        .filter(|(_, pu)| pu.unlock_height <= height)
        .map(|(idx, _)| *idx)
        .collect();
    for validator_index in due {
        match try_register_exit_churn(counters.bond_epoch_exit_count, bonding_params) {
            Ok(next_count) => {
                counters.bond_epoch_exit_count = next_count;
            }
            Err(_) => break,
        }
        if let Some(pos) = validators.iter().position(|v| v.index == validator_index) {
            validators[pos].stake = 0;
        }
        pending_unbonds.remove(&validator_index);
    }
}
