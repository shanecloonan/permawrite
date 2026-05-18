//! Liveness slashing phase.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Phase 2 — Liveness slashing                                              *
 * ----------------------------------------------------------------------- */

/// Outcome of [`apply_liveness_evolution`].
#[derive(Debug, Default)]
pub struct LivenessOutcome {
    /// Total stake forfeited across all liveness slashings this block.
    /// Caller credits this to the permanence treasury (same sink as
    /// equivocation slashing and bond burns).
    pub liveness_burn_total: u128,
}

/// Apply per-block liveness tracking + auto-slashing.
///
/// Walks the verified finality `bitmap`:
///
/// - Validator's bit set → reset `consecutive_missed`, increment
///   `total_signed`.
/// - Validator's bit clear → increment `consecutive_missed` and
///   `total_missed`; if `consecutive_missed >=
///   params.liveness_max_consecutive_missed`, multiplicatively
///   reduce stake by `params.liveness_slash_bps`, increment
///   `liveness_slashes`, and reset `consecutive_missed`.
///
/// Zero-stake validators (already slashed by equivocation) are
/// skipped — they're zombies until validator rotation reaps them.
///
/// Resizes `validator_stats` to match `validators.len()` if they're
/// misaligned (e.g. after a previous version of the chain produced
/// a state without stats).
pub fn apply_liveness_evolution(
    validators: &mut [Validator],
    validator_stats: &mut Vec<ValidatorStats>,
    bitmap: &[u8],
    params: &ConsensusParams,
) -> LivenessOutcome {
    if validator_stats.len() != validators.len() {
        validator_stats.resize(validators.len(), ValidatorStats::default());
    }
    let mut burn_total: u128 = 0;
    let max_missed = params.liveness_max_consecutive_missed;
    let slash_bps = u128::from(params.liveness_slash_bps);
    for (i, v) in validators.iter_mut().enumerate() {
        if v.stake == 0 {
            continue;
        }
        let byte = i >> 3;
        let bit = i & 7;
        let signed = byte < bitmap.len() && (bitmap[byte] & (1u8 << bit)) != 0;
        let stats = &mut validator_stats[i];
        if signed {
            stats.consecutive_missed = 0;
            stats.total_signed = stats.total_signed.saturating_add(1);
        } else {
            stats.consecutive_missed = stats.consecutive_missed.saturating_add(1);
            stats.total_missed = stats.total_missed.saturating_add(1);
            if max_missed > 0 && stats.consecutive_missed >= max_missed {
                let bps = slash_bps.min(10_000);
                let old_stake = u128::from(v.stake);
                let new_stake_u128 = old_stake * (10_000 - bps) / 10_000;
                let forfeited = old_stake - new_stake_u128;
                v.stake = u64::try_from(new_stake_u128).unwrap_or(u64::MAX);
                burn_total = burn_total.saturating_add(forfeited);
                stats.liveness_slashes = stats.liveness_slashes.saturating_add(1);
                stats.consecutive_missed = 0;
            }
        }
    }
    LivenessOutcome {
        liveness_burn_total: burn_total,
    }
}
