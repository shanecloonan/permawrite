//! Header verification result and error types.

#![allow(unused_imports)]

use super::internal::*;

use crate::consensus::{ConsensusCheck, ConsensusDecodeError};

/* ----------------------------------------------------------------------- *
 *  Result                                                                  *
 * ----------------------------------------------------------------------- */

/// Successful verification of a header. Carries enough info for a
/// light client to (a) confirm which validator produced the block,
/// and (b) understand how much stake voted.
///
/// `quorum_reached` is always `true` for a successful verification —
/// it's exposed as a field so callers writing their own
/// quorum-stricter policies (e.g. "I require 90% stake even though
/// the chain only requires 2/3") can compare `signing_stake` to
/// `total_stake` directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderCheck {
    /// Validator index of the block producer (as recorded in the
    /// `producer_proof`'s VRF half).
    pub producer_index: u32,
    /// Sum of stake of validators whose bit is set in the
    /// finality bitmap.
    pub signing_stake: u64,
    /// Sum of stake of *all* validators in the trusted set.
    pub total_stake: u64,
    /// Minimum signing stake required to clear quorum at
    /// `params.quorum_stake_bps`. Always `signing_stake >= quorum_required`
    /// for a successful verification (this is *what* was verified).
    pub quorum_required: u64,
    /// Number of validators in the trusted set.
    pub validator_count: usize,
    /// Always `true` for a successful verification; exposed so
    /// stricter callers can pattern-match without redoing the math.
    pub quorum_reached: bool,
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Failure modes of [`verify_header`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeaderVerifyError {
    /// `header.validator_root` does not equal
    /// `validator_set_root(trusted_validators)`. The trust anchor
    /// the caller provided doesn't match the set the producer
    /// claimed to commit to — either the caller's set is wrong, or
    /// the header is for a different chain.
    #[error("validator_root mismatch: header committed a different validator set than the caller's trusted set")]
    ValidatorRootMismatch,

    /// Header has an empty `producer_proof`, but the trusted set is
    /// non-empty. This only happens for the genesis block (which is
    /// the trust anchor, not light-verifiable in the normal sense).
    /// Light clients should bootstrap from a `GenesisConfig`, not
    /// try to "verify" the genesis header.
    #[error("genesis-style header (empty producer_proof) cannot be light-verified")]
    GenesisHeader,

    /// `header.producer_proof` failed to decode. The header is
    /// malformed.
    #[error("producer_proof decode failed: {0}")]
    ProducerProofDecode(String),

    /// One of the cryptographic / structural finality checks failed.
    /// See [`ConsensusCheck`] for the specific reason.
    #[error("finality proof rejected: {0:?}")]
    FinalityRejected(ConsensusCheck),

    /// `trusted_validators` was empty. A light client *must* be
    /// bootstrapped with a non-empty trusted set; verifying a header
    /// against an empty set is structurally meaningless.
    #[error(
        "trusted validator set is empty — light client must be bootstrapped with a non-empty set"
    )]
    EmptyTrustedSet,
}

impl From<ConsensusDecodeError> for HeaderVerifyError {
    fn from(e: ConsensusDecodeError) -> Self {
        HeaderVerifyError::ProducerProofDecode(format!("{e}"))
    }
}
