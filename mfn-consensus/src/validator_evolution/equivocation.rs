//! Equivocation + invalid-block slashing phase.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Phase 1 — Slash evidence application                                     *
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
    /// validator index. The chain rejects duplicates so liveness +
    /// equivocation slashing don't double-zero an already-zero stake.
    Duplicate {
        /// Position in the block's `slashings` vector.
        index: usize,
        /// Validator index that was already slashed earlier in the block.
        voter_index: u32,
    },
    /// Evidence did not pass verification (signatures invalid,
    /// fraud proof invalid, etc.).
    Invalid {
        /// Position in the block's `slashings` vector.
        index: usize,
        /// Specific evidence-check failure.
        reason: crate::slashing::SlashRejectReason,
    },
}

/// Apply slash evidence to `validators`.
///
/// Handles equivocation (BLS pair) and invalid-block (interactive fraud)
/// variants. Returns forfeited stake (caller credits treasury) and per-slash
/// errors in input order.
#[cfg(feature = "bls")]
pub fn apply_equivocation_slashings(
    validators: &mut [Validator],
    slashings: &[SlashEvidence],
    emission_params: &crate::emission::EmissionParams,
    applying_block_height: u32,
    header_version: u32,
) -> EquivocationOutcome {
    let mut out = EquivocationOutcome::default();
    let mut slashed_this_block: HashSet<u32> = HashSet::new();
    for (si, ev_raw) in slashings.iter().enumerate() {
        let ev = canonicalize(ev_raw);
        let offender = ev.offender_index();
        if !slashed_this_block.insert(offender) {
            out.errors.push(EquivocationError::Duplicate {
                index: si,
                voter_index: offender,
            });
            continue;
        }
        match verify_slash_evidence(
            &ev,
            validators,
            emission_params,
            applying_block_height,
            header_version,
        ) {
            Ok(()) => {
                let idx = offender as usize;
                if idx < validators.len() {
                    out.forfeited_total = out
                        .forfeited_total
                        .saturating_add(u128::from(validators[idx].stake));
                    validators[idx].stake = 0;
                }
            }
            Err(reason) => out
                .errors
                .push(EquivocationError::Invalid { index: si, reason }),
        }
    }
    out
}

#[cfg(not(feature = "bls"))]
pub fn apply_equivocation_slashings(
    validators: &mut [Validator],
    slashings: &[SlashEvidence],
    _emission_params: &crate::emission::EmissionParams,
    _applying_block_height: u32,
    _header_version: u32,
) -> EquivocationOutcome {
    let mut out = EquivocationOutcome::default();
    let mut slashed_this_block: HashSet<u32> = HashSet::new();
    for (si, ev_raw) in slashings.iter().enumerate() {
        let SlashEvidence::Equivocation(ev) = canonicalize(ev_raw) else {
            out.errors.push(EquivocationError::Invalid {
                index: si,
                reason: crate::slashing::SlashRejectReason::InvalidBlock(
                    crate::slashing::InvalidBlockEvidenceCheck::LegacyHeaderVersion,
                ),
            });
            continue;
        };
        if !slashed_this_block.insert(ev.voter_index) {
            out.errors.push(EquivocationError::Duplicate {
                index: si,
                voter_index: ev.voter_index,
            });
            continue;
        }
        match verify_equivocation_evidence(&ev, validators) {
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
                reason: crate::slashing::SlashRejectReason::Equivocation(other),
            }),
        }
    }
    out
}
