//! Equivocation slashing phase.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Phase 1 — Equivocation slashing                                          *
 * ----------------------------------------------------------------------- */

/// Outcome of [`apply_equivocation_slashings`].
#[derive(Debug, Default)]
pub struct EquivocationOutcome {
    /// Total stake forfeited across all valid slashings this block.
    /// Caller credits this to the permanence treasury.
    pub forfeited_total: u128,
    /// Per-slash errors in the order they appeared in `slashings`.
    /// Each error means the corresponding slashing was *not* applied;
    /// any subsequent valid slashings were applied normally.
    pub errors: Vec<EquivocationError>,
}

/// Reason a single piece of slashing evidence could not be applied.
#[derive(Debug)]
pub enum EquivocationError {
    /// A previous evidence in the same block already slashed this
    /// `voter_index`. The chain rejects duplicates so liveness +
    /// equivocation slashing don't double-zero an already-zero stake.
    Duplicate {
        /// Position in the block's `slashings` vector.
        index: usize,
        /// `voter_index` that was already slashed earlier in the block.
        voter_index: u32,
    },
    /// Evidence did not pass [`verify_evidence`] (signatures invalid,
    /// hashes match, etc.).
    Invalid {
        /// Position in the block's `slashings` vector.
        index: usize,
        /// Specific evidence-check failure.
        reason: EvidenceCheck,
    },
}

/// Apply equivocation slashings to `validators`.
///
/// For each piece of evidence:
///
/// 1. Canonicalize via [`canonicalize`] so swapping the
///    `(hash_a, sig_a) / (hash_b, sig_b)` pair cannot forge a
///    different slashing leaf.
/// 2. Reject duplicates within the block (`Duplicate` error).
/// 3. Run [`verify_evidence`] against `validators` (`Invalid` error
///    on failure).
/// 4. On success, zero the offending validator's stake.
///
/// Returns the total forfeited stake (caller credits the treasury)
/// and per-slash errors in input order.
pub fn apply_equivocation_slashings(
    validators: &mut [Validator],
    slashings: &[SlashEvidence],
) -> EquivocationOutcome {
    let mut out = EquivocationOutcome::default();
    let mut slashed_this_block: HashSet<u32> = HashSet::new();
    for (si, ev_raw) in slashings.iter().enumerate() {
        let ev = canonicalize(ev_raw);
        if !slashed_this_block.insert(ev.voter_index) {
            out.errors.push(EquivocationError::Duplicate {
                index: si,
                voter_index: ev.voter_index,
            });
            continue;
        }
        match verify_evidence(&ev, validators) {
            EvidenceCheck::Valid => {
                let idx = ev.voter_index as usize;
                if idx < validators.len() {
                    out.forfeited_total = out
                        .forfeited_total
                        .saturating_add(u128::from(validators[idx].stake));
                    validators[idx].stake = 0;
                }
            }
            other => out.errors.push(EquivocationError::Invalid {
                index: si,
                reason: other,
            }),
        }
    }
    out
}
