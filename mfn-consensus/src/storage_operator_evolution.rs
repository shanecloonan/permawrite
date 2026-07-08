//! Storage-operator audit liveness evolution (B5 phase 5b–5c).
//!
//! Mirrors validator liveness in [`crate::validator_evolution::liveness`]:
//! counters move only inside `apply_block` from verified SPoRA proofs, not
//! from gossip accusations.

use std::collections::{BTreeMap, HashMap, HashSet};

use mfn_storage::EndowmentParams;

use crate::block::{StorageEntry, StorageOperatorEntry, StorageOperatorStats};

/// Outcome of [`apply_storage_operator_audit_evolution`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StorageOperatorAuditOutcome {
    /// Bond forfeitures credited to the permanence treasury this block.
    pub slash_to_treasury: u128,
}

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

/// Update per-operator miss counters; slash bonded collateral when the streak
/// crosses `operator_audit_missed_cap` (B5 phase 5c).
///
/// When `challenge_active` is false, leaves state unchanged. When true,
/// operators in `proved_operators` reset their miss streak; others increment.
/// On slash: `bond_amount * operator_slash_bps / 10000` credits `treasury`, bond
/// is reduced, the miss counter resets, and operators with zero bond are
/// removed from the registry.
pub fn apply_storage_operator_audit_evolution(
    height: u32,
    challenge_active: bool,
    endowment_params: &EndowmentParams,
    storage_operators: &mut BTreeMap<[u8; 32], StorageOperatorEntry>,
    storage_operator_stats: &mut BTreeMap<[u8; 32], StorageOperatorStats>,
    proved_operators: &HashSet<[u8; 32]>,
    treasury: &mut u128,
) -> StorageOperatorAuditOutcome {
    if !challenge_active {
        return StorageOperatorAuditOutcome::default();
    }

    let cap = endowment_params.operator_audit_missed_cap;
    let slash_bps = endowment_params.operator_slash_bps.min(10_000);
    let slash_enabled = cap > 0 && slash_bps > 0;

    let operator_ids: Vec<[u8; 32]> = storage_operators.keys().copied().collect();
    let mut slash_to_treasury: u128 = 0;
    let mut deregister: Vec<[u8; 32]> = Vec::new();

    for id in operator_ids {
        let stats = storage_operator_stats.entry(id).or_default();

        if proved_operators.contains(&id) {
            stats.consecutive_missed_audits = 0;
        } else {
            stats.consecutive_missed_audits = stats.consecutive_missed_audits.saturating_add(1);

            if slash_enabled && stats.consecutive_missed_audits >= cap {
                if let Some(entry) = storage_operators.get_mut(&id) {
                    let old_bond = u128::from(entry.bond_amount);
                    if old_bond > 0 {
                        let forfeited = old_bond * u128::from(slash_bps) / 10_000;
                        let new_bond_u128 = old_bond.saturating_sub(forfeited);
                        entry.bond_amount = u64::try_from(new_bond_u128).unwrap_or(u64::MAX);
                        slash_to_treasury = slash_to_treasury.saturating_add(forfeited);
                        if entry.bond_amount == 0 {
                            deregister.push(id);
                        }
                    }
                }
                stats.consecutive_missed_audits = 0;
            }
        }
        stats.last_audit_height = height;
    }

    for id in deregister {
        storage_operators.remove(&id);
        storage_operator_stats.remove(&id);
    }

    *treasury = treasury.saturating_add(slash_to_treasury);

    StorageOperatorAuditOutcome { slash_to_treasury }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::point::generator_g;
    use mfn_storage::{
        build_storage_commitment, operator_identity_from_payout, DEFAULT_ENDOWMENT_PARAMS,
    };

    fn stale_storage() -> HashMap<[u8; 32], StorageEntry> {
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
        map
    }

    fn test_operator() -> ([u8; 32], StorageOperatorEntry) {
        let view = generator_g() * Scalar::from(3u64);
        let spend = generator_g() * Scalar::from(5u64);
        let id = operator_identity_from_payout(&view, &spend);
        (
            id,
            StorageOperatorEntry {
                operator_view_pub: view,
                operator_spend_pub: spend,
                registration_height: 0,
                bond_amount: 1_000_000,
            },
        )
    }

    #[test]
    fn challenge_inactive_when_cap_zero() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 0;
        let storage = stale_storage();
        assert!(!storage_audit_challenge_active(&storage, 10_000, &params));
    }

    #[test]
    fn challenge_active_when_stale_commit_exists() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 3;
        params.proof_reward_window_slots = 100;
        let storage = stale_storage();
        assert!(storage_audit_challenge_active(&storage, 200, &params));
    }

    #[test]
    fn slash_on_cap_miss_credits_treasury_and_reduces_bond() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 2;
        params.operator_slash_bps = 1_000;
        let (id, entry) = test_operator();
        let mut operators = BTreeMap::from([(id, entry)]);
        let mut stats = BTreeMap::new();
        let mut treasury = 0u128;
        let proved = HashSet::new();

        let o1 = apply_storage_operator_audit_evolution(
            1,
            true,
            &params,
            &mut operators,
            &mut stats,
            &proved,
            &mut treasury,
        );
        assert_eq!(o1.slash_to_treasury, 0);
        assert_eq!(stats[&id].consecutive_missed_audits, 1);

        let o2 = apply_storage_operator_audit_evolution(
            2,
            true,
            &params,
            &mut operators,
            &mut stats,
            &proved,
            &mut treasury,
        );
        assert_eq!(o2.slash_to_treasury, 100_000);
        assert_eq!(treasury, 100_000);
        assert_eq!(operators[&id].bond_amount, 900_000);
        assert_eq!(stats[&id].consecutive_missed_audits, 0);
    }

    #[test]
    fn full_slash_deregisters_operator() {
        let mut params = DEFAULT_ENDOWMENT_PARAMS;
        params.operator_salted_challenges = 1;
        params.operator_audit_missed_cap = 1;
        params.operator_slash_bps = 10_000;
        let (id, entry) = test_operator();
        let mut operators = BTreeMap::from([(id, entry)]);
        let mut stats = BTreeMap::new();
        let mut treasury = 0u128;

        let o = apply_storage_operator_audit_evolution(
            1,
            true,
            &params,
            &mut operators,
            &mut stats,
            &HashSet::new(),
            &mut treasury,
        );
        assert_eq!(o.slash_to_treasury, 1_000_000);
        assert!(!operators.contains_key(&id));
        assert!(!stats.contains_key(&id));
    }
}
