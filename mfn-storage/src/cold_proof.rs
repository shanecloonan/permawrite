//! Per-commitment cold-data proof cadence (**B-314** / **PM19** helper).
//!
//! Path A B5 `storage_audit_challenge_active` is **global**: if *any*
//! commitment is older than one proof window, *every* registered operator
//! owes a proof this block. Proving a hot file resets the operator miss
//! streak while cold files can stay unproven.
//!
//! This module names the missing **per-commitment** obligation: how long
//! since the last proof is too long, given file age, and how a later bounty
//! should escalate. Not read by `apply_block`.

use crate::endowment::EndowmentParams;

/// Age at which the recommended interval has grown from the hot window to
/// [`RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS`] (one default year).
pub const RECOMMENDED_COLD_AGE_SLOTS: u64 = 2_629_800;

/// Longest allowed gap between proofs of one commitment (~30 days at
/// 12-second slots = 30 × 7_200). Cold files stay on a deadline; frequency
/// never drops to zero.
pub const RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS: u64 = 216_000;

/// 1.0× payout in basis points (no missed windows).
pub const RECOMMENDED_COLD_BOUNTY_BASE_BPS: u16 = 10_000;

/// Extra bounty per missed interval (`+10%` each window).
pub const RECOMMENDED_COLD_BOUNTY_STEP_BPS: u16 = 1_000;

/// Cap at 2.0× so a dormant file cannot unbounded-inflate the prize.
pub const RECOMMENDED_COLD_BOUNTY_CAP_BPS: u16 = 20_000;

/// Minimum slots between required proofs of one commitment.
///
/// - Age 0: the endowment `proof_reward_window_slots` (Path A: 7_200).
/// - Age ≥ [`RECOMMENDED_COLD_AGE_SLOTS`]:
///   [`RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS`] (or the hot window if
///   larger).
/// - In between: linear interpolation (integer division).
///
/// A never-proven file should pass `age_slots = 0` so the first proof is
/// due on the hot window, not the 30-day cap.
#[must_use]
pub fn recommended_min_proof_interval_slots(age_slots: u64, params: &EndowmentParams) -> u64 {
    let hot = params.proof_reward_window_slots.max(1);
    let cold = RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS.max(hot);
    if age_slots == 0 || RECOMMENDED_COLD_AGE_SLOTS == 0 {
        return hot;
    }
    if age_slots >= RECOMMENDED_COLD_AGE_SLOTS {
        return cold;
    }
    let span = cold.saturating_sub(hot);
    hot.saturating_add(span.saturating_mul(age_slots) / RECOMMENDED_COLD_AGE_SLOTS)
}

/// `true` when `elapsed` since last proof meets or exceeds the age-scaled
/// interval. `current_slot < last_proven_slot` is not overdue (clock skew).
#[must_use]
pub fn cold_proof_overdue(
    last_proven_slot: u64,
    current_slot: u64,
    age_slots: u64,
    params: &EndowmentParams,
) -> bool {
    if current_slot < last_proven_slot {
        return false;
    }
    let elapsed = current_slot - last_proven_slot;
    elapsed >= recommended_min_proof_interval_slots(age_slots, params)
}

/// Whole intervals missed since last proof (`elapsed / interval`).
#[must_use]
pub fn missed_proof_windows(
    last_proven_slot: u64,
    current_slot: u64,
    age_slots: u64,
    params: &EndowmentParams,
) -> u64 {
    if current_slot < last_proven_slot {
        return 0;
    }
    let interval = recommended_min_proof_interval_slots(age_slots, params);
    if interval == 0 {
        return 0;
    }
    (current_slot - last_proven_slot) / interval
}

/// PM19 bounty multiplier in bps. `10_000` = 1.0×; saturates at
/// [`RECOMMENDED_COLD_BOUNTY_CAP_BPS`].
#[must_use]
pub fn recommended_cold_reward_multiplier_bps(missed_windows: u64) -> u16 {
    let extra = missed_windows.saturating_mul(u64::from(RECOMMENDED_COLD_BOUNTY_STEP_BPS));
    let extra_u16 = u16::try_from(extra.min(u64::from(u16::MAX))).unwrap_or(u16::MAX);
    RECOMMENDED_COLD_BOUNTY_BASE_BPS
        .saturating_add(extra_u16)
        .min(RECOMMENDED_COLD_BOUNTY_CAP_BPS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_ENDOWMENT_PARAMS;

    fn p() -> EndowmentParams {
        DEFAULT_ENDOWMENT_PARAMS
    }

    #[test]
    fn b314_hot_interval_matches_default_proof_window() {
        assert_eq!(p().proof_reward_window_slots, 7_200);
        assert_eq!(recommended_min_proof_interval_slots(0, &p()), 7_200);
        assert_eq!(RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS, 30 * 7_200);
        assert_eq!(RECOMMENDED_COLD_AGE_SLOTS, p().slots_per_year);
    }

    #[test]
    fn b314_interval_grows_with_age_but_never_zero() {
        let young = recommended_min_proof_interval_slots(0, &p());
        let mid = recommended_min_proof_interval_slots(RECOMMENDED_COLD_AGE_SLOTS / 2, &p());
        let old = recommended_min_proof_interval_slots(RECOMMENDED_COLD_AGE_SLOTS, &p());
        let older = recommended_min_proof_interval_slots(RECOMMENDED_COLD_AGE_SLOTS * 10, &p());
        assert!(young > 0);
        assert!(mid > young);
        assert_eq!(old, RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS);
        assert_eq!(older, old);
        assert!(old >= young);
    }

    #[test]
    fn b314_overdue_at_interval_boundary() {
        let interval = recommended_min_proof_interval_slots(0, &p());
        assert!(!cold_proof_overdue(100, 100 + interval - 1, 0, &p()));
        assert!(cold_proof_overdue(100, 100 + interval, 0, &p()));
        assert!(!cold_proof_overdue(500, 400, 0, &p()));
    }

    #[test]
    fn b314_year_old_file_is_not_exempt() {
        let age = RECOMMENDED_COLD_AGE_SLOTS;
        let interval = recommended_min_proof_interval_slots(age, &p());
        assert_eq!(interval, RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS);
        assert!(cold_proof_overdue(0, interval, age, &p()));
        assert!(!cold_proof_overdue(0, interval - 1, age, &p()));
    }

    #[test]
    fn b314_bounty_escalates_then_caps() {
        assert_eq!(recommended_cold_reward_multiplier_bps(0), 10_000);
        assert_eq!(recommended_cold_reward_multiplier_bps(1), 11_000);
        assert_eq!(recommended_cold_reward_multiplier_bps(10), 20_000);
        assert_eq!(recommended_cold_reward_multiplier_bps(u64::MAX), 20_000);
    }

    #[test]
    fn b314_missed_windows_floor_division() {
        let interval = recommended_min_proof_interval_slots(0, &p());
        assert_eq!(
            missed_proof_windows(0, interval * 2 + (interval - 1), 0, &p()),
            2
        );
        assert_eq!(missed_proof_windows(10, 10, 0, &p()), 0);
    }
}
