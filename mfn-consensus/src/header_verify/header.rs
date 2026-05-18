//! Stateless block header verification.

#![allow(unused_imports)]

use super::internal::*;

use super::types::{HeaderCheck, HeaderVerifyError};

/* ----------------------------------------------------------------------- *
 *  Verify                                                                  *
 * ----------------------------------------------------------------------- */

/// Verify a [`BlockHeader`] against a trusted *pre-block* validator
/// set.
///
/// "Pre-block" is the same convention `apply_block` uses for
/// `validator_root`: the set that was in force at the moment the
/// producer signed the header. Any rotation / slashing / unbond
/// settlement applied *by* this block moves the *next* header's
/// `validator_root`, and is the caller's responsibility to apply
/// before verifying the next header (typically by replaying
/// `block.bond_ops`, `block.slashings`, and any pending-unbond
/// settlements against their own trusted-validators bookkeeping).
///
/// # Checks performed (in order)
///
/// 1. **Trusted set non-empty.** Empty set → [`HeaderVerifyError::EmptyTrustedSet`].
/// 2. **Validator-root match.** `validator_set_root(trusted) ==
///    header.validator_root` (the trust anchor). Mismatch →
///    [`HeaderVerifyError::ValidatorRootMismatch`].
/// 3. **Producer-proof present.** Genesis-style headers (empty
///    `producer_proof`) → [`HeaderVerifyError::GenesisHeader`].
/// 4. **Producer-proof decode.** Malformed bytes →
///    [`HeaderVerifyError::ProducerProofDecode`].
/// 5. **Full [`verify_finality_proof`].** This covers producer VRF +
///    ed25519 + slot eligibility, BLS aggregate over the header
///    signing hash, signing-stake-bitmap consistency, and quorum
///    threshold. Any failure → [`HeaderVerifyError::FinalityRejected`].
///
/// # Determinism
///
/// Pure function. No IO, no allocation beyond what `verify_finality_proof`
/// requires, no clock. Calling this with the same `(header,
/// trusted_validators, params)` returns byte-for-byte the same
/// result.
///
/// # Errors
///
/// See variants of [`HeaderVerifyError`].
pub fn verify_header(
    header: &BlockHeader,
    trusted_validators: &[Validator],
    params: &ConsensusParams,
) -> Result<HeaderCheck, HeaderVerifyError> {
    // (1) Trusted-set non-empty.
    if trusted_validators.is_empty() {
        return Err(HeaderVerifyError::EmptyTrustedSet);
    }

    // (2) Validator-root match.
    let computed_root = validator_set_root(trusted_validators);
    if computed_root != header.validator_root {
        return Err(HeaderVerifyError::ValidatorRootMismatch);
    }

    // (3) Producer-proof present.
    if header.producer_proof.is_empty() {
        return Err(HeaderVerifyError::GenesisHeader);
    }

    // (4) Producer-proof decode.
    let fin = decode_finality_proof(&header.producer_proof)?;

    // (5) Full finality verification.
    let ctx = SlotContext {
        height: header.height,
        slot: header.slot,
        prev_hash: header.prev_hash,
    };
    let header_hash = header_signing_hash(header);
    let check = verify_finality_proof(
        &ctx,
        &fin,
        trusted_validators,
        params.expected_proposers_per_slot,
        params.quorum_stake_bps,
        &header_hash,
    );
    if !check.is_ok() {
        return Err(HeaderVerifyError::FinalityRejected(check));
    }

    // Compute quorum stats for the caller.
    let total_stake: u64 = trusted_validators.iter().map(|v| v.stake).sum();
    let quorum_required =
        (u128::from(total_stake) * u128::from(params.quorum_stake_bps)).div_ceil(10_000u128) as u64;

    Ok(HeaderCheck {
        producer_index: fin.producer.validator_index,
        signing_stake: fin.signing_stake,
        total_stake,
        quorum_required,
        validator_count: trusted_validators.len(),
        quorum_reached: true,
    })
}
