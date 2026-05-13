//! Shared sub-encoders used by both checkpoint codecs (M2.0.16).
//!
//! The two checkpoint families — [`mfn_light::checkpoint`] (M2.0.9)
//! and [`crate::chain_checkpoint`] (M2.0.15) — both serialise the
//! same per-field building blocks: a [`Validator`], a [`ValidatorStats`],
//! a [`PendingUnbond`], a [`ConsensusParams`], a [`BondingParams`].
//! Before M2.0.16 each family carried its own private copy of these
//! encoders + matching decoders; the bytes were identical by
//! convention but maintained twice, with no compiler-enforced
//! invariant that they would stay in sync.
//!
//! This module lifts those building blocks into a **single public
//! source of truth** that both codecs consume. The wire layout is
//! unchanged byte-for-byte from M2.0.9 / M2.0.15 — every existing
//! `LightCheckpoint` / `ChainCheckpoint` binary on disk continues to
//! decode without modification, and every newly-produced byte stream
//! matches the corresponding pre-M2.0.16 codec exactly.
//!
//! ## Public surface
//!
//! - **Encoders** ([`encode_validator`], [`encode_validator_stats`],
//!   [`encode_pending_unbond`], [`encode_consensus_params`],
//!   [`encode_bonding_params`]) write the canonical wire bytes for
//!   each per-field building block. Infallible; pure write.
//! - **Decoders** ([`decode_validator`], [`decode_validator_stats`],
//!   [`decode_pending_unbond`], [`decode_consensus_params`],
//!   [`decode_bonding_params`]) read the bytes back. All four return
//!   `Result<T, CheckpointReadError>` so the **same** typed error set
//!   surfaces in both checkpoint families.
//! - **Helpers** ([`read_fixed`], [`read_u8`], [`read_u16`],
//!   [`read_u32`], [`read_u64`], [`read_u128`], [`read_varint`],
//!   [`read_len`], [`read_edwards_point`]) are the small primitives
//!   the higher-level codecs build on; exposing them publicly means
//!   the wrapper modules can chain their own per-field assertions
//!   (sort order, length mismatches, integrity-tag checks) without
//!   re-implementing the reader plumbing.
//!
//! ## Error mapping in wrapper codecs
//!
//! Both [`mfn_light::LightCheckpointError`] and
//! [`crate::ChainCheckpointError`] carry a single
//! `Read(CheckpointReadError)` variant + `#[from]`. The mapping is
//! lossless: every variant of [`CheckpointReadError`] surfaces
//! verbatim through the wrapper error, so callers that match on a
//! specific failure mode (e.g. `Read(InvalidBlsPublicKey { index, .. })`)
//! see the same `index` they would have seen pre-M2.0.16.

use std::collections::HashSet;

use mfn_bls::{decode_public_key, encode_public_key, BlsError, BlsPublicKey};
use mfn_crypto::codec::{Reader, Writer};

use crate::block::{ConsensusParams, PendingUnbond, ValidatorStats};
use crate::bonding::BondingParams;
use crate::consensus::{Validator, ValidatorPayout};

/// Errors produced by the per-field checkpoint decoders.
///
/// Shared between the light-client checkpoint codec
/// ([`mfn_light::checkpoint`]) and the full-node chain-state
/// checkpoint codec ([`crate::chain_checkpoint`]). Both higher-level
/// codecs carry this enum verbatim as a `Read(CheckpointReadError)`
/// variant on their own error types.
///
/// Each variant identifies a specific byte-level failure with enough
/// context (the field that failed, the value or index that violated
/// an invariant) for the caller to log or render an actionable
/// message.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointReadError {
    /// The buffer ran out before the expected number of bytes were
    /// available at `field`.
    #[error("checkpoint truncated at field `{field}`: needed {needed} more byte(s)")]
    Truncated {
        /// Symbolic name of the field that was being read when
        /// truncation hit.
        field: &'static str,
        /// Bytes still required.
        needed: usize,
    },

    /// A length-prefix varint overflowed `u64`.
    #[error("checkpoint varint overflow at field `{field}`")]
    VarintOverflow {
        /// Field whose length was being read.
        field: &'static str,
    },

    /// A `u64` length did not fit `usize` on this platform.
    #[error("checkpoint length {got} at field `{field}` exceeds usize")]
    LengthOverflow {
        /// The raw `u64` length read.
        got: u64,
        /// Field whose length was being read.
        field: &'static str,
    },

    /// A validator's `vrf_pk` failed Edwards-point decompression.
    #[error("validator #{index}: invalid vrf_pk (decompression failed)")]
    InvalidVrfPublicKey {
        /// Position of the offending validator in the validator list.
        index: usize,
    },

    /// A validator's `bls_pk` failed G1 decode.
    #[error("validator #{index}: invalid bls_pk: {source}")]
    InvalidBlsPublicKey {
        /// Position of the offending validator in the validator list.
        index: usize,
        /// The underlying BLS decode error.
        #[source]
        source: BlsError,
    },

    /// A validator-payout `view_pub` failed Edwards-point decompression.
    #[error("validator #{index}: invalid payout view_pub")]
    InvalidPayoutViewPub {
        /// Position of the offending validator in the validator list.
        index: usize,
    },

    /// A validator-payout `spend_pub` failed Edwards-point decompression.
    #[error("validator #{index}: invalid payout spend_pub")]
    InvalidPayoutSpendPub {
        /// Position of the offending validator in the validator list.
        index: usize,
    },

    /// A validator-payout-presence flag byte was not 0 or 1.
    #[error("validator #{index}: invalid payout_flag {flag} (must be 0 or 1)")]
    InvalidPayoutFlag {
        /// Position of the offending validator in the validator list.
        index: usize,
        /// Raw flag byte.
        flag: u8,
    },

    /// Per-validator stats length did not match the validator count
    /// — the STF invariant the codec preserves.
    #[error("validator_stats length {stats} does not match validators length {validators}")]
    StatsLengthMismatch {
        /// Decoded validator count.
        validators: usize,
        /// Decoded stats count.
        stats: usize,
    },

    /// Two validators sharing the same `index` appeared in the
    /// payload — the STF treats `Validator::index` as a primary key.
    #[error("duplicate validator index {index}")]
    DuplicateValidatorIndex {
        /// The repeated index.
        index: u32,
    },

    /// Pending unbonds were not strictly ascending by
    /// `validator_index`.
    #[error(
        "pending_unbonds not strictly sorted ascending by validator_index at position {index}"
    )]
    PendingUnbondsNotSorted {
        /// Position in the `pending_unbonds` list.
        index: usize,
    },

    /// `next_validator_index <= max(validator.index)` — the on-chain
    /// invariant "`next_validator_index` always points one past the
    /// highest assigned index" was violated.
    #[error("next_validator_index {next} \u{2264} max assigned index {max_assigned}")]
    NextIndexBelowAssigned {
        /// The encoded counter value.
        next: u32,
        /// The maximum `index` actually present in the payload.
        max_assigned: u32,
    },
}

/* ----------------------------------------------------------------------- *
 *  Helpers                                                                  *
 * ----------------------------------------------------------------------- */

/// Read `N` bytes into a fixed-size array, surfacing truncation with
/// the symbolic `field` name.
pub fn read_fixed<const N: usize>(
    r: &mut Reader<'_>,
    field: &'static str,
) -> Result<[u8; N], CheckpointReadError> {
    let slice = r
        .bytes(N)
        .map_err(|_| CheckpointReadError::Truncated { field, needed: N })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Read a 1-byte unsigned integer.
pub fn read_u8(r: &mut Reader<'_>, field: &'static str) -> Result<u8, CheckpointReadError> {
    r.u8()
        .map_err(|_| CheckpointReadError::Truncated { field, needed: 1 })
}

/// Read a 2-byte big-endian unsigned integer.
pub fn read_u16(r: &mut Reader<'_>, field: &'static str) -> Result<u16, CheckpointReadError> {
    let b: [u8; 2] = read_fixed(r, field)?;
    Ok(u16::from_be_bytes(b))
}

/// Read a 4-byte big-endian unsigned integer.
pub fn read_u32(r: &mut Reader<'_>, field: &'static str) -> Result<u32, CheckpointReadError> {
    r.u32()
        .map_err(|_| CheckpointReadError::Truncated { field, needed: 4 })
}

/// Read an 8-byte big-endian unsigned integer.
pub fn read_u64(r: &mut Reader<'_>, field: &'static str) -> Result<u64, CheckpointReadError> {
    r.u64()
        .map_err(|_| CheckpointReadError::Truncated { field, needed: 8 })
}

/// Read a 16-byte big-endian unsigned integer.
pub fn read_u128(r: &mut Reader<'_>, field: &'static str) -> Result<u128, CheckpointReadError> {
    let b: [u8; 16] = read_fixed(r, field)?;
    Ok(u128::from_be_bytes(b))
}

/// Read a variable-length unsigned integer.
pub fn read_varint(r: &mut Reader<'_>, field: &'static str) -> Result<u64, CheckpointReadError> {
    r.varint()
        .map_err(|_| CheckpointReadError::VarintOverflow { field })
}

/// Read a varint length and narrow to `usize`, with both overflow
/// modes surfacing distinctly.
pub fn read_len(r: &mut Reader<'_>, field: &'static str) -> Result<usize, CheckpointReadError> {
    let raw = read_varint(r, field)?;
    usize::try_from(raw).map_err(|_| CheckpointReadError::LengthOverflow { got: raw, field })
}

/// Distinguish a truncation-on-point-read from a structural
/// "32 bytes present but the encoding is invalid" failure.
pub enum EdwardsReadError {
    /// Reader ran out of bytes before all 32 could be consumed.
    Truncated {
        /// Field that was being read.
        field: &'static str,
        /// Bytes still required.
        needed: usize,
    },
    /// 32 bytes were read but did not decompress to a valid Edwards
    /// point.
    InvalidPoint,
}

/// Read 32 bytes and decompress as an ed25519 Edwards point.
pub fn read_edwards_point(
    r: &mut Reader<'_>,
    field: &'static str,
) -> Result<curve25519_dalek::edwards::EdwardsPoint, EdwardsReadError> {
    match r.point() {
        Ok(p) => Ok(p),
        Err(mfn_crypto::CryptoError::ShortBuffer { needed }) => {
            Err(EdwardsReadError::Truncated { field, needed })
        }
        Err(_) => Err(EdwardsReadError::InvalidPoint),
    }
}

/* ----------------------------------------------------------------------- *
 *  Validator                                                                *
 * ----------------------------------------------------------------------- */

/// Wire encode a single [`Validator`].
///
/// Layout:
/// `index (u32) | stake (u64) | vrf_pk [32] | bls_pk [48] | payout_flag (u8) [ | view_pub [32] | spend_pub [32] ]`.
pub fn encode_validator(w: &mut Writer, v: &Validator) {
    w.u32(v.index);
    w.u64(v.stake);
    w.push(&v.vrf_pk.compress().to_bytes());
    w.push(&encode_public_key(&v.bls_pk));
    match &v.payout {
        None => {
            w.u8(0);
        }
        Some(p) => {
            w.u8(1);
            w.push(&p.view_pub.compress().to_bytes());
            w.push(&p.spend_pub.compress().to_bytes());
        }
    }
}

/// Wire decode a single [`Validator`].
///
/// `index` is the validator's position in the encoded list, used only
/// for diagnostic error reporting (it has no effect on the decoded
/// value).
pub fn decode_validator(
    r: &mut Reader<'_>,
    index: usize,
) -> Result<Validator, CheckpointReadError> {
    let v_index = read_u32(r, "validators[i].index")?;
    let stake = read_u64(r, "validators[i].stake")?;

    let vrf_pk = read_edwards_point(r, "validators[i].vrf_pk").map_err(|e| match e {
        EdwardsReadError::Truncated { field, needed } => {
            CheckpointReadError::Truncated { field, needed }
        }
        EdwardsReadError::InvalidPoint => CheckpointReadError::InvalidVrfPublicKey { index },
    })?;

    let bls_pk_bytes: [u8; 48] = read_fixed(r, "validators[i].bls_pk")?;
    let bls_pk: BlsPublicKey = decode_public_key(&bls_pk_bytes)
        .map_err(|source| CheckpointReadError::InvalidBlsPublicKey { index, source })?;

    let flag = read_u8(r, "validators[i].payout_flag")?;
    let payout = match flag {
        0 => None,
        1 => {
            let view_pub =
                read_edwards_point(r, "validators[i].payout.view_pub").map_err(|e| match e {
                    EdwardsReadError::Truncated { field, needed } => {
                        CheckpointReadError::Truncated { field, needed }
                    }
                    EdwardsReadError::InvalidPoint => {
                        CheckpointReadError::InvalidPayoutViewPub { index }
                    }
                })?;
            let spend_pub =
                read_edwards_point(r, "validators[i].payout.spend_pub").map_err(|e| match e {
                    EdwardsReadError::Truncated { field, needed } => {
                        CheckpointReadError::Truncated { field, needed }
                    }
                    EdwardsReadError::InvalidPoint => {
                        CheckpointReadError::InvalidPayoutSpendPub { index }
                    }
                })?;
            Some(ValidatorPayout {
                view_pub,
                spend_pub,
            })
        }
        other => return Err(CheckpointReadError::InvalidPayoutFlag { index, flag: other }),
    };

    Ok(Validator {
        index: v_index,
        vrf_pk,
        bls_pk,
        stake,
        payout,
    })
}

/* ----------------------------------------------------------------------- *
 *  ValidatorStats                                                           *
 * ----------------------------------------------------------------------- */

/// Wire encode a single [`ValidatorStats`].
///
/// Layout:
/// `consecutive_missed (u32) | total_signed (u64) | total_missed (u64) | liveness_slashes (u32)`.
pub fn encode_validator_stats(w: &mut Writer, s: &ValidatorStats) {
    w.u32(s.consecutive_missed);
    w.u64(s.total_signed);
    w.u64(s.total_missed);
    w.u32(s.liveness_slashes);
}

/// Wire decode a single [`ValidatorStats`].
pub fn decode_validator_stats(r: &mut Reader<'_>) -> Result<ValidatorStats, CheckpointReadError> {
    Ok(ValidatorStats {
        consecutive_missed: read_u32(r, "validator_stats[i].consecutive_missed")?,
        total_signed: read_u64(r, "validator_stats[i].total_signed")?,
        total_missed: read_u64(r, "validator_stats[i].total_missed")?,
        liveness_slashes: read_u32(r, "validator_stats[i].liveness_slashes")?,
    })
}

/* ----------------------------------------------------------------------- *
 *  PendingUnbond                                                            *
 * ----------------------------------------------------------------------- */

/// Wire encode a single [`PendingUnbond`].
///
/// Layout:
/// `validator_index (u32) | unlock_height (u32) | stake_at_request (u64) | request_height (u32)`.
pub fn encode_pending_unbond(w: &mut Writer, p: &PendingUnbond) {
    w.u32(p.validator_index);
    w.u32(p.unlock_height);
    w.u64(p.stake_at_request);
    w.u32(p.request_height);
}

/// Wire decode a single [`PendingUnbond`].
pub fn decode_pending_unbond(r: &mut Reader<'_>) -> Result<PendingUnbond, CheckpointReadError> {
    Ok(PendingUnbond {
        validator_index: read_u32(r, "pending_unbonds[i].validator_index")?,
        unlock_height: read_u32(r, "pending_unbonds[i].unlock_height")?,
        stake_at_request: read_u64(r, "pending_unbonds[i].stake_at_request")?,
        request_height: read_u32(r, "pending_unbonds[i].request_height")?,
    })
}

/* ----------------------------------------------------------------------- *
 *  ConsensusParams                                                          *
 * ----------------------------------------------------------------------- */

/// Wire encode a [`ConsensusParams`].
///
/// `expected_proposers_per_slot` (an `f64`) is round-tripped via
/// `f64::to_bits()` → `u64` big-endian; cross-platform exact for
/// every value (NaN payloads + sub-normals + infinities included).
pub fn encode_consensus_params(w: &mut Writer, p: &ConsensusParams) {
    w.u64(p.expected_proposers_per_slot.to_bits());
    w.u32(p.quorum_stake_bps);
    w.u32(p.liveness_max_consecutive_missed);
    w.u32(p.liveness_slash_bps);
}

/// Wire decode a [`ConsensusParams`].
pub fn decode_consensus_params(r: &mut Reader<'_>) -> Result<ConsensusParams, CheckpointReadError> {
    Ok(ConsensusParams {
        expected_proposers_per_slot: f64::from_bits(read_u64(
            r,
            "params.expected_proposers_per_slot",
        )?),
        quorum_stake_bps: read_u32(r, "params.quorum_stake_bps")?,
        liveness_max_consecutive_missed: read_u32(r, "params.liveness_max_consecutive_missed")?,
        liveness_slash_bps: read_u32(r, "params.liveness_slash_bps")?,
    })
}

/* ----------------------------------------------------------------------- *
 *  BondingParams                                                            *
 * ----------------------------------------------------------------------- */

/// Wire encode a [`BondingParams`].
pub fn encode_bonding_params(w: &mut Writer, p: &BondingParams) {
    w.u64(p.min_validator_stake);
    w.u32(p.unbond_delay_heights);
    w.u32(p.max_entry_churn_per_epoch);
    w.u32(p.max_exit_churn_per_epoch);
    w.u32(p.slots_per_epoch);
}

/// Wire decode a [`BondingParams`].
pub fn decode_bonding_params(r: &mut Reader<'_>) -> Result<BondingParams, CheckpointReadError> {
    Ok(BondingParams {
        min_validator_stake: read_u64(r, "bonding_params.min_validator_stake")?,
        unbond_delay_heights: read_u32(r, "bonding_params.unbond_delay_heights")?,
        max_entry_churn_per_epoch: read_u32(r, "bonding_params.max_entry_churn_per_epoch")?,
        max_exit_churn_per_epoch: read_u32(r, "bonding_params.max_exit_churn_per_epoch")?,
        slots_per_epoch: read_u32(r, "bonding_params.slots_per_epoch")?,
    })
}

/* ----------------------------------------------------------------------- *
 *  Validator-list assignment-invariant check                                *
 * ----------------------------------------------------------------------- */

/// Verify the cross-validator invariants that BOTH checkpoint codecs
/// enforce post-decode:
///
/// - **Duplicate-index detection.** Every `Validator::index` must be
///   unique (the STF treats it as a primary key).
/// - **`next_validator_index` ≥ max assigned index + 1.** When at
///   least one validator is present, the encoded
///   `next_validator_index` must strictly exceed the largest assigned
///   index — otherwise the next bond op would collide with an
///   existing validator.
///
/// Returns the largest assigned `index` (or `None` when the list is
/// empty), so callers can chain context-specific assertions.
pub fn check_validator_assignment(
    validators: &[Validator],
    next_validator_index: u32,
) -> Result<Option<u32>, CheckpointReadError> {
    let mut seen: HashSet<u32> = HashSet::with_capacity(validators.len());
    let mut max_assigned: Option<u32> = None;
    for v in validators {
        if !seen.insert(v.index) {
            return Err(CheckpointReadError::DuplicateValidatorIndex { index: v.index });
        }
        max_assigned = Some(max_assigned.map_or(v.index, |m| m.max(v.index)));
    }
    if let Some(max_idx) = max_assigned {
        if next_validator_index <= max_idx {
            return Err(CheckpointReadError::NextIndexBelowAssigned {
                next: next_validator_index,
                max_assigned: max_idx,
            });
        }
    }
    Ok(max_assigned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::DEFAULT_CONSENSUS_PARAMS;
    use crate::bonding::DEFAULT_BONDING_PARAMS;
    use curve25519_dalek::scalar::Scalar;
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;

    fn point_for(seed: u64) -> curve25519_dalek::edwards::EdwardsPoint {
        generator_g() * Scalar::from(seed)
    }

    fn make_validator(index: u32, stake: u64, with_payout: bool) -> Validator {
        let bls = bls_keygen_from_seed(&[index as u8; 32]);
        Validator {
            index,
            vrf_pk: point_for(0x1000 + index as u64),
            bls_pk: bls.pk,
            stake,
            payout: if with_payout {
                Some(ValidatorPayout {
                    view_pub: point_for(0x2000 + index as u64),
                    spend_pub: point_for(0x3000 + index as u64),
                })
            } else {
                None
            },
        }
    }

    fn round_trip<T>(encode: impl Fn(&mut Writer, &T), decode: impl Fn(&mut Reader<'_>) -> T, v: &T)
    where
        T: PartialEq + std::fmt::Debug,
    {
        let mut w = Writer::new();
        encode(&mut w, v);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let back = decode(&mut r);
        assert!(r.end(), "decoder must consume exactly the encoded bytes");
        assert_eq!(&back, v);
    }

    #[test]
    fn validator_round_trip_with_and_without_payout() {
        for with_payout in [false, true] {
            let v = make_validator(7, 1_234_567, with_payout);
            let mut w = Writer::new();
            encode_validator(&mut w, &v);
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            let back = decode_validator(&mut r, 0).unwrap();
            assert!(r.end());
            assert_eq!(back.index, v.index);
            assert_eq!(back.stake, v.stake);
            assert_eq!(
                back.vrf_pk.compress().to_bytes(),
                v.vrf_pk.compress().to_bytes()
            );
            assert_eq!(
                encode_public_key(&back.bls_pk),
                encode_public_key(&v.bls_pk)
            );
            assert_eq!(back.payout.is_some(), v.payout.is_some());
        }
    }

    #[test]
    fn validator_stats_round_trip() {
        round_trip(
            encode_validator_stats,
            |r| decode_validator_stats(r).unwrap(),
            &ValidatorStats {
                consecutive_missed: 3,
                total_signed: 42,
                total_missed: 7,
                liveness_slashes: 1,
            },
        );
    }

    #[test]
    fn pending_unbond_round_trip() {
        round_trip(
            encode_pending_unbond,
            |r| decode_pending_unbond(r).unwrap(),
            &PendingUnbond {
                validator_index: 5,
                unlock_height: 1_000_000,
                stake_at_request: 2_000_000,
                request_height: 500_000,
            },
        );
    }

    #[test]
    fn consensus_params_round_trip_preserves_f64_bits() {
        // Pin a non-trivial f64 to ensure `to_bits` / `from_bits`
        // round-trips bit-exact.
        let p = ConsensusParams {
            expected_proposers_per_slot: 1.5_f64.next_up(),
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 100,
        };
        let mut w = Writer::new();
        encode_consensus_params(&mut w, &p);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let back = decode_consensus_params(&mut r).unwrap();
        assert!(r.end());
        assert_eq!(
            back.expected_proposers_per_slot.to_bits(),
            p.expected_proposers_per_slot.to_bits()
        );
        assert_eq!(back.quorum_stake_bps, p.quorum_stake_bps);
    }

    #[test]
    fn bonding_params_round_trip() {
        round_trip(
            encode_bonding_params,
            |r| decode_bonding_params(r).unwrap(),
            &DEFAULT_BONDING_PARAMS,
        );
    }

    #[test]
    fn validator_decoder_rejects_invalid_payout_flag() {
        // Hand-craft a payload whose payout flag is neither 0 nor 1.
        let mut w = Writer::new();
        encode_validator(&mut w, &make_validator(0, 1, false));
        let mut bytes = w.into_bytes();
        // The payout flag is the last byte of a no-payout encoding.
        let last = bytes.len() - 1;
        bytes[last] = 99;
        let mut r = Reader::new(&bytes);
        match decode_validator(&mut r, 0) {
            Err(CheckpointReadError::InvalidPayoutFlag { index: 0, flag: 99 }) => {}
            other => panic!("expected InvalidPayoutFlag, got {other:?}"),
        }
    }

    #[test]
    fn validator_decoder_rejects_truncation_at_every_field() {
        let v = make_validator(0, 1_000, true);
        let mut w = Writer::new();
        encode_validator(&mut w, &v);
        let bytes = w.into_bytes();
        for cut in 0..bytes.len() {
            let mut r = Reader::new(&bytes[..cut]);
            assert!(
                decode_validator(&mut r, 0).is_err(),
                "must reject cut at {cut}"
            );
        }
    }

    #[test]
    fn validator_assignment_check_accepts_well_formed_lists() {
        let vs = vec![make_validator(0, 1, false), make_validator(1, 1, false)];
        let max = check_validator_assignment(&vs, 2).unwrap();
        assert_eq!(max, Some(1));
    }

    #[test]
    fn validator_assignment_check_rejects_duplicate_indices() {
        let vs = vec![make_validator(7, 1, false), make_validator(7, 2, false)];
        match check_validator_assignment(&vs, 100) {
            Err(CheckpointReadError::DuplicateValidatorIndex { index: 7 }) => {}
            other => panic!("expected DuplicateValidatorIndex, got {other:?}"),
        }
    }

    #[test]
    fn validator_assignment_check_rejects_next_index_at_or_below_max() {
        let vs = vec![make_validator(5, 1, false)];
        match check_validator_assignment(&vs, 5) {
            Err(CheckpointReadError::NextIndexBelowAssigned {
                next: 5,
                max_assigned: 5,
            }) => {}
            other => panic!("expected NextIndexBelowAssigned, got {other:?}"),
        }
    }

    #[test]
    fn empty_validator_list_accepts_any_next_index() {
        // No validators → no assignment constraint to violate.
        assert!(check_validator_assignment(&[], 0).unwrap().is_none());
        assert!(check_validator_assignment(&[], u32::MAX).unwrap().is_none());
    }

    #[test]
    fn consensus_params_default_round_trips_byte_identical() {
        // Insulate against future drift of the default value.
        let mut w = Writer::new();
        encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let back = decode_consensus_params(&mut r).unwrap();
        let mut w2 = Writer::new();
        encode_consensus_params(&mut w2, &back);
        assert_eq!(bytes, w2.into_bytes());
    }
}
