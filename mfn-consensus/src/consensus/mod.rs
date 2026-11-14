//! Consensus types and (with `bls` feature) production/finality engine.

pub mod lock_rule;
pub mod types;

pub use lock_rule::{
    lock_on_polka, lock_rule_active, may_vote_locked, second_finalization_conflicts, HeightLock,
    Polka, HEADER_VERSION_LOCK_RULE,
};
pub use types::{
    validator_leaf_bytes, validator_leaf_hash, validator_set_root, Validator, ValidatorPayout,
};

#[cfg(feature = "bls")]
mod engine;

#[cfg(feature = "bls")]
pub use engine::*;
