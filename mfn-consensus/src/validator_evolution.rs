//! Per-block validator-set evolution (M2.0.8).
//!
//! Pure helper functions for the four phases that mutate the active
//! validator set during [`crate::block::apply_block`]:
//!
//! 1. **Equivocation slashing** — `block.slashings` zero offending
//!    validators' stake.
//! 2. **Liveness slashing** — the finality bitmap drives per-validator
//!    participation tracking; chronic absenteeism is multiplicatively
//!    slashed.
//! 3. **Bond ops** — `BondOp::Register` adds new validators and burns
//!    their stake to the permanence treasury; `BondOp::Unbond` enqueues
//!    a pending exit.
//! 4. **Unbond settlements** — exits whose `unlock_height` has arrived
//!    and that fit in the epoch's exit-churn budget zero the
//!    departing validator's stake.
//!
//! These functions are the **single source of truth** for the chain's
//! validator-set evolution: both [`crate::block::apply_block`] (the
//! full-node state-transition function) and [`mfn-light`](https://docs.rs/mfn-light)
//! (the light client's chain follower) call them. Keeping the logic
//! in one place means a light client and a full node *cannot drift* —
//! every byte of `next.validators`, `next.validator_stats`,
//! `next.pending_unbonds`, and the bond-epoch counters is determined
//! by the same four functions applied to the same inputs.
//!
//! ## Why the light client needs this
//!
//! After M2.0.5 + M2.0.7 a light client can prove the cryptographic
//! authenticity of a `(header, body)` pair. But to follow a chain
//! across more than one rotation it must also evolve its trusted
//! validator set: the *next* block's header commits to
//! `validator_root_after_this_block`, so without evolving its set
//! the light client will start failing `verify_header` with
//! `ValidatorRootMismatch` the first time the chain rotates.
//!
//! ## Determinism contract
//!
//! Each function is a pure mutation: same inputs ⇒ same byte-for-byte
//! mutation. No IO, no allocation beyond `Vec`/`BTreeMap` growth, no
//! random state. The signature ordering of slashings / bond ops in
//! the block is the canonicalized chain order (matches the Merkle
//! root order from M2.0 / M2.0.1).

use std::collections::{BTreeMap, HashSet};

use crate::block::{BlockHeader, ConsensusParams, PendingUnbond, ValidatorStats};
use crate::bond_wire::{verify_register_sig, verify_unbond_sig, BondOp};
use crate::bonding::{
    epoch_id_for_height, try_register_entry_churn, try_register_exit_churn, unbond_unlock_height,
    validate_stake, BondingParams,
};
use crate::consensus::Validator;
use crate::slashing::{canonicalize, verify_evidence, EvidenceCheck, SlashEvidence};

/* ----------------------------------------------------------------------- *
 *  Shared state: BondEpochCounters                                          *
 * ----------------------------------------------------------------------- */

/// Aggregate counters needed by the bond-ops + unbond-settlement
/// phases.
///
/// These mirror the corresponding fields of
/// [`crate::block::ChainState`] one-for-one. They're surfaced as a
/// separate struct so external callers (e.g. light clients) can
/// thread them through the evolution functions without depending on
/// the full `ChainState` layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondEpochCounters {
    /// Epoch id derived from current height + `slots_per_epoch`.
    /// Bumps when the height crosses an epoch boundary; resets the
    /// per-epoch churn counters.
    pub bond_epoch_id: u64,
    /// Successful `BondOp::Register` applications so far in
    /// `bond_epoch_id`. Subject to `max_entries_per_epoch`.
    pub bond_epoch_entry_count: u32,
    /// Settled unbonds so far in `bond_epoch_id`. Subject to
    /// `max_exits_per_epoch`.
    pub bond_epoch_exit_count: u32,
    /// Next `Validator::index` to be assigned to a newly-bonded validator.
    /// Monotonically increasing — never reused across the chain's
    /// lifetime.
    pub next_validator_index: u32,
}

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

/* ----------------------------------------------------------------------- *
 *  Bitmap extractor                                                         *
 * ----------------------------------------------------------------------- */

/// Extract the finality bitmap from a [`BlockHeader`]'s `producer_proof`.
///
/// Returns `None` for genesis-style headers (empty `producer_proof`)
/// and for headers whose `producer_proof` fails to decode (light
/// clients should normally have already caught this through
/// [`crate::verify_header`]).
///
/// Light clients use this to drive [`apply_liveness_evolution`]
/// without having to decode the finality proof themselves.
#[must_use]
pub fn finality_bitmap_from_header(header: &BlockHeader) -> Option<Vec<u8>> {
    if header.producer_proof.is_empty() {
        return None;
    }
    crate::consensus::decode_finality_proof(&header.producer_proof)
        .ok()
        .map(|fp| fp.finality.bitmap)
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                               *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bonding::DEFAULT_BONDING_PARAMS;
    use crate::consensus::{ValidatorPayout, ValidatorSecrets};
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::stealth::stealth_gen;
    use mfn_crypto::vrf::vrf_keygen_from_seed;

    fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
        let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
        let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
        let payout_wallet = stealth_gen();
        let payout = ValidatorPayout {
            view_pub: payout_wallet.view_pub,
            spend_pub: payout_wallet.spend_pub,
        };
        let val = Validator {
            index: i,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake,
            payout: Some(payout),
        };
        let secrets = ValidatorSecrets {
            index: i,
            vrf,
            bls: bls.clone(),
        };
        (val, secrets)
    }

    fn default_params() -> ConsensusParams {
        ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 3,
            liveness_slash_bps: 100,
        }
    }

    /// Equivocation slashing with an empty input list is a no-op.
    #[test]
    fn equivocation_empty_input_is_noop() {
        let (v0, _) = mk_validator(0, 1_000);
        let mut validators = vec![v0];
        let out = apply_equivocation_slashings(&mut validators, &[]);
        assert_eq!(out.forfeited_total, 0);
        assert!(out.errors.is_empty());
        assert_eq!(validators[0].stake, 1_000);
    }

    /// Liveness slashing: a validator that misses ≥ threshold blocks
    /// gets its stake reduced; total_signed / total_missed track.
    #[test]
    fn liveness_clears_consecutive_missed_on_signed_bit() {
        let (mut v0, _) = mk_validator(0, 10_000);
        v0.stake = 10_000;
        let mut validators = vec![v0];
        let mut stats = vec![ValidatorStats::default()];
        let mut params = default_params();
        params.liveness_max_consecutive_missed = 2;
        params.liveness_slash_bps = 100;

        // Miss twice → slash applied at miss #2 (>=threshold).
        let bitmap_miss = vec![0u8];
        let out1 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_miss, &params);
        assert_eq!(out1.liveness_burn_total, 0);
        let out2 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_miss, &params);
        assert!(out2.liveness_burn_total > 0);
        assert_eq!(stats[0].liveness_slashes, 1);
        assert_eq!(stats[0].consecutive_missed, 0, "resets after slash");

        // Now a signed block clears the counter without further slash.
        let bitmap_signed = vec![1u8];
        let out3 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_signed, &params);
        assert_eq!(out3.liveness_burn_total, 0);
        assert_eq!(stats[0].consecutive_missed, 0);
        assert_eq!(stats[0].total_signed, 1);
    }

    /// Zero-stake validators are skipped (liveness doesn't touch zombies).
    #[test]
    fn liveness_skips_zero_stake_validators() {
        let (mut v0, _) = mk_validator(0, 0);
        v0.stake = 0;
        let mut validators = vec![v0];
        let mut stats = vec![ValidatorStats::default()];
        let params = default_params();
        let bitmap = vec![0u8];
        let out = apply_liveness_evolution(&mut validators, &mut stats, &bitmap, &params);
        assert_eq!(out.liveness_burn_total, 0);
        assert_eq!(stats[0].consecutive_missed, 0, "untouched");
        assert_eq!(stats[0].total_missed, 0);
    }

    /// Liveness automatically resizes the stats array to match
    /// validators if they're misaligned.
    #[test]
    fn liveness_resizes_stats_when_misaligned() {
        let (v0, _) = mk_validator(0, 10_000);
        let (v1, _) = mk_validator(1, 10_000);
        let mut validators = vec![v0, v1];
        // Stats has only 1 entry but we have 2 validators.
        let mut stats = vec![ValidatorStats::default()];
        let params = default_params();
        let bitmap = vec![0b11u8];
        apply_liveness_evolution(&mut validators, &mut stats, &bitmap, &params);
        assert_eq!(stats.len(), 2, "stats grew to match validators");
        assert_eq!(stats[0].total_signed, 1);
        assert_eq!(stats[1].total_signed, 1);
    }

    /// Empty bond-ops list is a no-op (no mutation, no error).
    #[test]
    fn bond_ops_empty_is_noop() {
        let (v0, _) = mk_validator(0, 1_000_000);
        let mut validators = vec![v0];
        let mut stats = vec![ValidatorStats::default()];
        let mut pending = BTreeMap::new();
        let mut counters = BondEpochCounters {
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index: 1,
        };
        let pre_counters = counters;
        let burn = apply_bond_ops_evolution(
            10,
            &mut counters,
            &mut validators,
            &mut stats,
            &mut pending,
            &DEFAULT_BONDING_PARAMS,
            &[],
        )
        .expect("empty ok");
        assert_eq!(burn, 0);
        assert_eq!(validators.len(), 1);
        assert_eq!(stats.len(), 1);
        assert!(pending.is_empty());
        // Epoch id is recomputed from height — at height 10 with default
        // slots_per_epoch (which is large), epoch is still 0.
        assert_eq!(counters.bond_epoch_id, pre_counters.bond_epoch_id);
        assert_eq!(
            counters.next_validator_index,
            pre_counters.next_validator_index
        );
    }

    /// Unbond settlements: empty pending list is a no-op.
    #[test]
    fn unbond_settlements_empty_pending_is_noop() {
        let (v0, _) = mk_validator(0, 1_000_000);
        let mut validators = vec![v0];
        let mut pending = BTreeMap::new();
        let mut counters = BondEpochCounters {
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index: 1,
        };
        apply_unbond_settlements(
            100,
            &mut counters,
            &DEFAULT_BONDING_PARAMS,
            &mut validators,
            &mut pending,
        );
        assert_eq!(validators[0].stake, 1_000_000);
        assert_eq!(counters.bond_epoch_exit_count, 0);
    }

    /// Unbond settlements: a pending unbond whose unlock_height has
    /// arrived zeros the validator's stake.
    #[test]
    fn unbond_settlements_zeros_validator_at_unlock_height() {
        let (mut v0, _) = mk_validator(0, 1_000_000);
        v0.stake = 1_000_000;
        let mut validators = vec![v0];
        let mut pending = BTreeMap::new();
        pending.insert(
            0,
            PendingUnbond {
                validator_index: 0,
                unlock_height: 50,
                stake_at_request: 1_000_000,
                request_height: 10,
            },
        );
        let mut counters = BondEpochCounters {
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index: 1,
        };
        // Before unlock: nothing happens.
        apply_unbond_settlements(
            49,
            &mut counters,
            &DEFAULT_BONDING_PARAMS,
            &mut validators,
            &mut pending,
        );
        assert_eq!(validators[0].stake, 1_000_000);
        assert_eq!(pending.len(), 1);

        // At unlock: settles.
        apply_unbond_settlements(
            50,
            &mut counters,
            &DEFAULT_BONDING_PARAMS,
            &mut validators,
            &mut pending,
        );
        assert_eq!(validators[0].stake, 0);
        assert!(pending.is_empty());
        assert_eq!(counters.bond_epoch_exit_count, 1);
    }

    /// Bitmap extraction: empty producer_proof → None.
    #[test]
    fn bitmap_extract_empty_proof_returns_none() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            height: 0,
            slot: 0,
            timestamp: 0,
            tx_root: [0u8; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        };
        assert!(finality_bitmap_from_header(&header).is_none());
    }
}
