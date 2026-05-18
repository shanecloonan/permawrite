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

mod bitmap;
mod bond_ops;
mod equivocation;
mod internal;
mod liveness;
mod unbond;

#[cfg(test)]
mod tests;

pub use bitmap::finality_bitmap_from_header;
pub use bond_ops::{apply_bond_ops_evolution, BondOpError};
pub use equivocation::{apply_equivocation_slashings, EquivocationError, EquivocationOutcome};
pub use liveness::{apply_liveness_evolution, LivenessOutcome};
pub use unbond::apply_unbond_settlements;
