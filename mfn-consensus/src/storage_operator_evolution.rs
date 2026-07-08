//! Storage-operator audit liveness evolution (B5 phase 5b).
//!
//! Mirrors validator liveness in [`crate::validator_evolution::liveness`]:
//! counters move only inside `apply_block` from verified SPoRA proofs, not
//! from gossip accusations. Slash execution is phase 5c.

use std::collections::{BTreeMap, HashMap, HashSet};

use mfn_storage::EndowmentParams;

use crate::block::{StorageEntry, StorageOperatorStats};

/// True when at least one on-chain commitment is stale under the anti-hoarding
/// window, so registered operators owe operator-salted proofs this block.
#[must_use]
pub fn storage_audit_challenge_active(
    storage: &HashMap<[u8; 32], StorageEntry>,
    current_slot: u64,
    params: &EndowmentParams,
) -> bool {
    if params.operator_audit_missed_cap == 0 || params.operator_salted_challenges == 0 {
        return false;
    }
    let window = params.proof_reward_window_slots;
    storage.values().any(|e| {
        e.commit.replication >= 1 && current_slot.saturating_sub(e.last_proven_slot) > window
    })
}

/// Update per-operator miss counters after storage proofs and operator ops.
///
/// When `challenge_active` is false, leaves `stats` unchanged. When true,
/// operators present in `proved_operators` reset their miss streak; all other
/// registered operators increment by one (saturating `u8`).
pub fn apply_storage_operator_audit_evolution(
    height: u32,
    challenge_active: bool,
    storage_operators: &BTreeMap<[u8; 32], crate::block::StorageOperatorEntry>,
    storage_operator_stats: &mut BTreeMap<[u8; 32], StorageOperatorStats>,
    proved_operators: &HashSet<[u8; 32]>,
) {
    if !challenge_active {
        return;
    }
    for id in storage_operators.keys() {
        let stats = storage_operator_stats
            .entry(*id)
            .or_insert_with(StorageOperatorStats::default);
        if proved_operators.contains(id) {
            stats.consecutive_missed_audits = 0;
        } else {
            stats.consecutive_missed_audits = stats.consecutive_missed_audits.saturating_add(1);
        }
        stats.last_audit_height = height;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};

    fn stale_storage(slot_gap: u64) -> HashMap<[u8; 32], StorageEntry> {
        let payload = b"audit-evolution-payload".to_vec();
        let built = build_storage_commitment(&payload, 1, Some(64), 3, None).unwrap();
        let hash = mfn_storage::storage_commitment_hash(&built.commit);
        let mut map = HashMap::new();
        map.insert(
            hash,
            StorageEntry {
                commit: built.commit,
                last_proven_height: 0,
                last_proven_slot: 0,
                pending_yield_ppb: 0,
            },
        );
        let _ = slot_gap;
        map
    }

    #[test]
    fn challenge_inactive_when_cap_zero() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 0;
        let storage = stale_storage(10_000);
        assert!(!storage_audit_challenge_active(&storage, 10_000, &params));
    }

    #[test]
    fn challenge_active_when_stale_commit_exists() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 3;
        params.proof_reward_window_slots = 100;
        let storage = stale_storage(0);
        assert!(storage_audit_challenge_active(&storage, 200, &params));
    }
}
