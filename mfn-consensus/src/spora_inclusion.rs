//! F-A SPoRA lottery inclusion (**B-44**).
//!
//! Path A pays proofs in body order. The F-A parameter bundle (drip on,
//! subsidy 1000 bps, backstop-sized prize, PM1 bond floor, fee split still
//! 9000) pays the lottery winners from [`rank_spora_lottery`] instead.
//! The seed is the prior block id and the window start, not the producer VRF.

use std::collections::{BTreeMap, BTreeSet};

use mfn_storage::{
    rank_spora_lottery, recommended_backstop_proof_reward, recommended_min_storage_operator_bond,
    spora_lottery_operator_score, spora_lottery_window_seed, EndowmentParams,
};

use crate::emission::{EmissionParams, DEFAULT_EMISSION_PARAMS};

/// One verified proof that may be paid.
#[derive(Clone, Copy, Debug)]
pub struct LotteryCandidate {
    /// Storage commitment the proof covers.
    pub commit_hash: [u8; 32],
    /// Operator identity from the proof payout keys.
    pub operator_id: [u8; 32],
    /// How many distinct operators this commitment pays (`replication`).
    pub max_winners: usize,
}

/// `true` only for the F-A economics bundle.
///
/// Path A fails every conjunct (drip 0, subsidy 0, 0.1 MFN prize, bond 0).
/// A partial fork that sets drip alone does not arm the lottery.
#[must_use]
pub fn fa_spora_lottery_armed(emission: &EmissionParams, endowment: &EndowmentParams) -> bool {
    let Ok(prize) = recommended_backstop_proof_reward(endowment) else {
        return false;
    };
    let Ok(bond) = recommended_min_storage_operator_bond(endowment) else {
        return false;
    };
    endowment.deflation_funded_drip == 1
        && emission.subsidy_to_treasury_bps == 1000
        && emission.fee_to_treasury_bps == DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps
        && emission.storage_proof_reward == prize
        && endowment.min_storage_operator_bond == bond
}

/// First slot of the proof window that contains `slot`.
#[must_use]
pub fn lottery_window_start(slot: u64, window_slots: u64) -> u64 {
    let window_slots = window_slots.max(1);
    slot - slot % window_slots
}

/// `(commit, operator)` pairs that are paid. Input order does not matter.
#[must_use]
pub fn lottery_winner_keys(
    prior_block_id: &[u8; 32],
    slot: u64,
    window_slots: u64,
    candidates: &[LotteryCandidate],
) -> BTreeSet<([u8; 32], [u8; 32])> {
    let seed = spora_lottery_window_seed(prior_block_id, lottery_window_start(slot, window_slots));
    let mut by_commit: BTreeMap<[u8; 32], (usize, Vec<[u8; 32]>)> = BTreeMap::new();
    for candidate in candidates {
        let entry = by_commit
            .entry(candidate.commit_hash)
            .or_insert((candidate.max_winners, Vec::new()));
        entry.0 = entry.0.min(candidate.max_winners);
        entry.1.push(candidate.operator_id);
    }
    let mut paid = BTreeSet::new();
    for (commit, (max_winners, operators)) in by_commit {
        for operator_id in rank_spora_lottery(&seed, &operators, max_winners) {
            paid.insert((commit, operator_id));
        }
    }
    paid
}

/// Sort key so a producer can lay proofs out in lottery order.
///
/// Lower score wins. The operator id breaks ties. Callers that are not on
/// the F-A bundle should not reorder.
#[must_use]
pub fn lottery_operator_score(
    prior_block_id: &[u8; 32],
    slot: u64,
    window_slots: u64,
    operator_id: &[u8; 32],
) -> [u8; 32] {
    let seed = spora_lottery_window_seed(prior_block_id, lottery_window_start(slot, window_slots));
    spora_lottery_operator_score(&seed, operator_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn fa_endowment() -> EndowmentParams {
        let bond = recommended_min_storage_operator_bond(&DEFAULT_ENDOWMENT_PARAMS).unwrap();
        EndowmentParams {
            deflation_funded_drip: 1,
            min_storage_operator_bond: bond,
            ..DEFAULT_ENDOWMENT_PARAMS
        }
    }

    fn fa_emission() -> EmissionParams {
        let prize = recommended_backstop_proof_reward(&fa_endowment()).unwrap();
        EmissionParams {
            storage_proof_reward: prize,
            subsidy_to_treasury_bps: 1000,
            ..DEFAULT_EMISSION_PARAMS
        }
    }

    #[test]
    fn b44_path_a_is_not_armed_and_fa_bundle_is() {
        assert!(!fa_spora_lottery_armed(
            &DEFAULT_EMISSION_PARAMS,
            &DEFAULT_ENDOWMENT_PARAMS
        ));
        assert!(fa_spora_lottery_armed(&fa_emission(), &fa_endowment()));
        let mut drip_only = DEFAULT_ENDOWMENT_PARAMS;
        drip_only.deflation_funded_drip = 1;
        assert!(!fa_spora_lottery_armed(
            &DEFAULT_EMISSION_PARAMS,
            &drip_only
        ));
    }

    #[test]
    fn b44_winner_is_independent_of_candidate_order() {
        let commit = [9u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        let prior = [4u8; 32];
        let forward = [
            LotteryCandidate {
                commit_hash: commit,
                operator_id: a,
                max_winners: 1,
            },
            LotteryCandidate {
                commit_hash: commit,
                operator_id: b,
                max_winners: 1,
            },
        ];
        let reverse = [forward[1], forward[0]];
        let won_forward = lottery_winner_keys(&prior, 100, 7_200, &forward);
        let won_reverse = lottery_winner_keys(&prior, 100, 7_200, &reverse);
        assert_eq!(won_forward, won_reverse);
        assert_eq!(won_forward.len(), 1);
        let other_seed = lottery_winner_keys(&[5u8; 32], 100, 7_200, &forward);
        assert_eq!(other_seed.len(), 1);
    }
}
