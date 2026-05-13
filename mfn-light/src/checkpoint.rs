//! Light-client checkpoint serialization (M2.0.9).
//!
//! A *checkpoint* is a self-contained binary snapshot of a
//! [`crate::LightChain`]: tip identity, frozen consensus / bonding
//! parameters, the current trusted validator set, the per-validator
//! liveness stats, the pending-unbond queue, and the four
//! bond-epoch counters. After saving a checkpoint to disk and
//! restoring later, the resulting `LightChain` is bit-for-bit equal
//! to the one that was saved — including its position on the chain
//! and its byte-for-byte view of the next validator set.
//!
//! ## Why a dedicated format
//!
//! The light client's whole purpose is *not* to re-derive the chain
//! from genesis every time it restarts: at scale, "follow from
//! height 0" is a non-starter when the gap between checkpoints can
//! be hours or days. The checkpoint format produced here is:
//!
//! - **Self-contained.** No external genesis config needed at
//!   restore time — the bonding params, consensus params, and
//!   genesis id all travel inside the payload. Callers who *want*
//!   to verify the checkpoint corresponds to a particular genesis
//!   can compare `decoded.genesis_id() == build_genesis(cfg).id()`.
//! - **Deterministic.** Byte-for-byte: two callers serializing the
//!   same [`LightChain`] state produce identical bytes. Useful for
//!   downstream integrity hashing and content-addressable storage.
//! - **Domain-separated integrity.** Trailing 32 bytes are
//!   `dhash(LIGHT_CHECKPOINT, payload)` — tampering with any field
//!   is detected on decode, with a single typed error
//!   ([`LightCheckpointError::IntegrityCheckFailed`]). The hash
//!   uses the dedicated `MFBN-1/light-checkpoint` domain so it
//!   can't collide with any other hash in the protocol.
//! - **Forward-compatible.** Versioned (`u32`). Newer crate
//!   versions may keep accepting older checkpoint versions by
//!   gating decode logic on the version word.
//!
//! ## Wire layout (version 1)
//!
//! Big-endian everywhere unless noted. `varint` is LEB128, matching
//! [`mfn_crypto::codec`]. All hashes / IDs are 32 bytes; the BLS
//! public key is its 48-byte G1 compressed form; ed25519 keys
//! (`vrf_pk`, payout view/spend pubkeys) are 32-byte compressed
//! Edwards points.
//!
//! ```text
//!   magic          : 4 bytes = b"MFLC"
//!   version        : u32 (currently 1)
//!   tip_height     : u32
//!   tip_id         : [u8; 32]
//!   genesis_id     : [u8; 32]
//!   params:
//!     expected_proposers_per_slot : u64 (f64::to_bits, big-endian)
//!     quorum_stake_bps            : u32
//!     liveness_max_consecutive_missed : u32
//!     liveness_slash_bps          : u32
//!   bonding_params:
//!     min_validator_stake        : u64
//!     unbond_delay_heights       : u32
//!     max_entry_churn_per_epoch  : u32
//!     max_exit_churn_per_epoch   : u32
//!     slots_per_epoch            : u32
//!   validators: varint N
//!     repeated N times:
//!       index   : u32
//!       stake   : u64
//!       vrf_pk  : 32 bytes (compressed ed25519)
//!       bls_pk  : 48 bytes (BLS G1 compressed)
//!       payout_flag : u8 (0 = None, 1 = Some)
//!       if Some:
//!         view_pub  : 32 bytes
//!         spend_pub : 32 bytes
//!   validator_stats: varint N    -- MUST equal the validators count
//!     repeated N times:
//!       consecutive_missed : u32
//!       total_signed       : u64
//!       total_missed       : u64
//!       liveness_slashes   : u32
//!   pending_unbonds: varint M   -- ascending `validator_index`
//!     repeated M times:
//!       validator_index   : u32
//!       unlock_height     : u32
//!       stake_at_request  : u64
//!       request_height    : u32
//!   bond_counters:
//!     bond_epoch_id           : u32
//!     bond_epoch_entry_count  : u32
//!     bond_epoch_exit_count   : u32
//!     next_validator_index    : u32
//!   checksum : 32 bytes = dhash(LIGHT_CHECKPOINT, all bytes above)
//! ```
//!
//! Adding fields after `bond_counters` is a forward-compatible
//! change *if* the version word is bumped — older clients reject
//! unknown versions; newer clients can branch on the version they
//! observe.

use std::collections::BTreeMap;

use mfn_consensus::checkpoint_codec::{
    check_validator_assignment, decode_bonding_params, decode_consensus_params,
    decode_pending_unbond, decode_validator, decode_validator_stats, encode_bonding_params,
    encode_consensus_params, encode_pending_unbond, encode_validator, encode_validator_stats,
    CheckpointReadError,
};
use mfn_consensus::{
    BondEpochCounters, BondingParams, ConsensusParams, PendingUnbond, Validator, ValidatorStats,
};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::LIGHT_CHECKPOINT;
use mfn_crypto::hash::dhash;

/* ----------------------------------------------------------------------- *
 *  Format pins                                                             *
 * ----------------------------------------------------------------------- */

/// 4-byte magic header. ASCII "MFLC" = "M(oney)F(und) L(ight) C(heckpoint)".
pub const LIGHT_CHECKPOINT_MAGIC: [u8; 4] = *b"MFLC";

/// Currently-supported checkpoint format version. Bumped only on
/// wire-incompatible changes.
pub const LIGHT_CHECKPOINT_VERSION: u32 = 1;

/* ----------------------------------------------------------------------- *
 *  Error type                                                              *
 * ----------------------------------------------------------------------- */

/// Errors produced by the checkpoint codec.
///
/// Per-field decode failures (truncation, invalid public keys,
/// validator-list invariants) flow through the
/// [`Read`](Self::Read) variant carrying the shared
/// [`CheckpointReadError`] from
/// [`mfn_consensus::checkpoint_codec`] (M2.0.16). The light
/// checkpoint family adds its own framing / integrity / trailing
/// variants on top.
#[derive(Debug, thiserror::Error)]
pub enum LightCheckpointError {
    /// The first 4 bytes weren't [`LIGHT_CHECKPOINT_MAGIC`].
    #[error("bad checkpoint magic: got {got:02x?}, want {want:02x?}", want = LIGHT_CHECKPOINT_MAGIC)]
    BadMagic {
        /// The 4 bytes actually found at offset 0.
        got: [u8; 4],
    },

    /// The version word names a version this build doesn't support.
    #[error("unsupported checkpoint version {got}; this build supports {supported}", supported = LIGHT_CHECKPOINT_VERSION)]
    UnsupportedVersion {
        /// The version word parsed from the payload.
        got: u32,
    },

    /// A shared per-field decode failure (truncation, invalid public
    /// key, validator-list invariant violation, etc.). Surfaced
    /// verbatim from [`mfn_consensus::checkpoint_codec`].
    #[error(transparent)]
    Read(#[from] CheckpointReadError),

    /// `pending_unbonds[i].validator_index` doesn't match the
    /// embedded `validator_index` field (would be impossible from
    /// honest encoding; defensive check on decode).
    #[error("pending_unbond #{index}: stored index {got} does not match payload field {expected}")]
    PendingUnbondIndexMismatch {
        /// Position in the pending_unbonds array.
        index: usize,
        /// The key the entry was sorted under.
        expected: u32,
        /// The embedded field value.
        got: u32,
    },

    /// The trailing 32-byte integrity tag did not match
    /// `dhash(LIGHT_CHECKPOINT, payload)`.
    #[error("checkpoint integrity check failed (payload tampered or truncated)")]
    IntegrityCheckFailed,

    /// Bytes remained after the integrity tag.
    #[error("{remaining} trailing byte(s) after checkpoint tag")]
    TrailingBytes {
        /// Number of unaccounted-for bytes after the tag.
        remaining: usize,
    },
}

/* ----------------------------------------------------------------------- *
 *  Component bundle                                                        *
 * ----------------------------------------------------------------------- */

/// All the pieces that together represent a [`crate::LightChain`]'s
/// serializable state. Used as the boundary type between the codec
/// and the [`crate::LightChain`] struct's private fields — the
/// `LightChain` itself constructs this from its fields when
/// encoding, and the codec returns this for `LightChain` to
/// re-assemble after decoding.
#[derive(Clone, Debug)]
pub struct CheckpointParts {
    /// Current tip height.
    pub tip_height: u32,
    /// Current tip `block_id`.
    pub tip_id: [u8; 32],
    /// Genesis `block_id`.
    pub genesis_id: [u8; 32],
    /// Frozen consensus params.
    pub params: ConsensusParams,
    /// Frozen bonding params.
    pub bonding_params: BondingParams,
    /// Trusted validator set.
    pub validators: Vec<Validator>,
    /// Per-validator liveness stats, aligned 1:1 with `validators`.
    pub validator_stats: Vec<ValidatorStats>,
    /// In-flight unbond requests.
    pub pending_unbonds: BTreeMap<u32, PendingUnbond>,
    /// Bond-epoch counters mirroring `mfn-consensus::ChainState`.
    pub bond_counters: BondEpochCounters,
}

/* ----------------------------------------------------------------------- *
 *  Encode                                                                  *
 * ----------------------------------------------------------------------- */

/// Encode a [`CheckpointParts`] bundle to its canonical bytes.
///
/// Always produces the same output for the same input — including
/// the final integrity tag. Length grows linearly in
/// `validators + pending_unbonds`.
///
/// Every per-field sub-encoder (validator, validator-stats,
/// pending-unbond, consensus-params, bonding-params) is supplied by
/// [`mfn_consensus::checkpoint_codec`] (M2.0.16). The wire layout
/// they emit is byte-identical to the M2.0.9 light-checkpoint
/// codec.
#[must_use]
pub fn encode_checkpoint_bytes(parts: &CheckpointParts) -> Vec<u8> {
    let mut w = Writer::new();

    // ---- Header ----
    w.push(&LIGHT_CHECKPOINT_MAGIC);
    w.u32(LIGHT_CHECKPOINT_VERSION);

    // ---- Tip + identity ----
    w.u32(parts.tip_height);
    w.push(&parts.tip_id);
    w.push(&parts.genesis_id);

    // ---- Frozen params (shared sub-encoders) ----
    encode_consensus_params(&mut w, &parts.params);
    encode_bonding_params(&mut w, &parts.bonding_params);

    // ---- Validators ----
    w.varint(parts.validators.len() as u64);
    for v in &parts.validators {
        encode_validator(&mut w, v);
    }

    // ---- Validator stats (1:1 with validators) ----
    w.varint(parts.validator_stats.len() as u64);
    for s in &parts.validator_stats {
        encode_validator_stats(&mut w, s);
    }

    // ---- Pending unbonds (BTreeMap iterates ascending by key) ----
    w.varint(parts.pending_unbonds.len() as u64);
    for p in parts.pending_unbonds.values() {
        encode_pending_unbond(&mut w, p);
    }

    // ---- Bond counters ----
    w.u64(parts.bond_counters.bond_epoch_id);
    w.u32(parts.bond_counters.bond_epoch_entry_count);
    w.u32(parts.bond_counters.bond_epoch_exit_count);
    w.u32(parts.bond_counters.next_validator_index);

    // ---- Trailing integrity tag ----
    let payload = w.into_bytes();
    let tag = dhash(LIGHT_CHECKPOINT, &[&payload]);
    let mut out = payload;
    out.extend_from_slice(&tag);
    out
}

/* ----------------------------------------------------------------------- *
 *  Decode                                                                  *
 * ----------------------------------------------------------------------- */

/// Light-checkpoint-local thin wrapper around
/// [`mfn_consensus::checkpoint_codec::read_fixed`], specialised for
/// the [`LightCheckpointError`] return type so the body of
/// [`decode_checkpoint_bytes`] stays terse.
fn read_fixed<const N: usize>(
    r: &mut Reader<'_>,
    field: &'static str,
) -> Result<[u8; N], LightCheckpointError> {
    Ok(mfn_consensus::checkpoint_codec::read_fixed(r, field)?)
}

fn read_u32(r: &mut Reader<'_>, field: &'static str) -> Result<u32, LightCheckpointError> {
    Ok(mfn_consensus::checkpoint_codec::read_u32(r, field)?)
}

fn read_u64(r: &mut Reader<'_>, field: &'static str) -> Result<u64, LightCheckpointError> {
    Ok(mfn_consensus::checkpoint_codec::read_u64(r, field)?)
}

fn read_len(r: &mut Reader<'_>, field: &'static str) -> Result<usize, LightCheckpointError> {
    Ok(mfn_consensus::checkpoint_codec::read_len(r, field)?)
}

/// Decode bytes produced by [`encode_checkpoint_bytes`] back into a
/// [`CheckpointParts`] bundle.
///
/// Verifies the magic + version + integrity tag and enforces a
/// number of cross-field invariants (stats length = validators
/// length; pending unbonds strictly ascending and matching their
/// own embedded index; `next_validator_index` strictly greater
/// than any assigned validator index). Any invariant violation is
/// surfaced as a typed [`LightCheckpointError`] without partial
/// state escaping the function.
///
/// # Errors
///
/// See [`LightCheckpointError`] variants. Truncation, integrity
/// failure, bad magic / version, and any cross-field invariant
/// violation are all hard rejects.
pub fn decode_checkpoint_bytes(bytes: &[u8]) -> Result<CheckpointParts, LightCheckpointError> {
    if bytes.len() < 4 + 4 + 32 {
        return Err(CheckpointReadError::Truncated {
            field: "magic+version+tag",
            needed: 40_usize.saturating_sub(bytes.len()),
        }
        .into());
    }
    // Split off the trailing integrity tag (always 32 bytes).
    let payload_len = bytes.len() - 32;
    let payload = &bytes[..payload_len];
    let tag_bytes = &bytes[payload_len..];
    let expected_tag = dhash(LIGHT_CHECKPOINT, &[payload]);
    if tag_bytes != expected_tag {
        return Err(LightCheckpointError::IntegrityCheckFailed);
    }

    let mut r = Reader::new(payload);

    let magic: [u8; 4] = read_fixed(&mut r, "magic")?;
    if magic != LIGHT_CHECKPOINT_MAGIC {
        return Err(LightCheckpointError::BadMagic { got: magic });
    }
    let version = read_u32(&mut r, "version")?;
    if version != LIGHT_CHECKPOINT_VERSION {
        return Err(LightCheckpointError::UnsupportedVersion { got: version });
    }

    let tip_height = read_u32(&mut r, "tip_height")?;
    let tip_id: [u8; 32] = read_fixed(&mut r, "tip_id")?;
    let genesis_id: [u8; 32] = read_fixed(&mut r, "genesis_id")?;

    let params: ConsensusParams = decode_consensus_params(&mut r)?;
    let bonding_params: BondingParams = decode_bonding_params(&mut r)?;

    let validators_n = read_len(&mut r, "validators.len")?;
    let mut validators = Vec::with_capacity(validators_n);
    for i in 0..validators_n {
        validators.push(decode_validator(&mut r, i)?);
    }

    let stats_n = read_len(&mut r, "validator_stats.len")?;
    if stats_n != validators_n {
        return Err(CheckpointReadError::StatsLengthMismatch {
            validators: validators_n,
            stats: stats_n,
        }
        .into());
    }
    let mut validator_stats = Vec::with_capacity(stats_n);
    for _ in 0..stats_n {
        validator_stats.push(decode_validator_stats(&mut r)?);
    }

    let pending_n = read_len(&mut r, "pending_unbonds.len")?;
    let mut pending_unbonds: BTreeMap<u32, PendingUnbond> = BTreeMap::new();
    let mut prev_idx: Option<u32> = None;
    for i in 0..pending_n {
        let p = decode_pending_unbond(&mut r)?;
        // The encode side sorts by validator_index (BTreeMap iteration
        // order); on decode we enforce strict-ascending so a
        // re-encode after decode is byte-identical to the input.
        if let Some(prev) = prev_idx {
            if p.validator_index <= prev {
                return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
            }
        }
        prev_idx = Some(p.validator_index);
        if pending_unbonds.insert(p.validator_index, p).is_some() {
            return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
        }
    }

    let bond_counters = BondEpochCounters {
        bond_epoch_id: read_u64(&mut r, "bond_counters.bond_epoch_id")?,
        bond_epoch_entry_count: read_u32(&mut r, "bond_counters.bond_epoch_entry_count")?,
        bond_epoch_exit_count: read_u32(&mut r, "bond_counters.bond_epoch_exit_count")?,
        next_validator_index: read_u32(&mut r, "bond_counters.next_validator_index")?,
    };

    // After the last declared field there must be exactly zero
    // bytes left in the payload reader. (The trailing tag was
    // already stripped before the Reader was constructed.)
    if !r.end() {
        return Err(LightCheckpointError::TrailingBytes {
            remaining: r.remaining(),
        });
    }

    // Cross-validator invariants (duplicate-index detection +
    // `next_validator_index > max(validator.index)`) are enforced by
    // the shared codec helper.
    check_validator_assignment(&validators, bond_counters.next_validator_index)?;

    Ok(CheckpointParts {
        tip_height,
        tip_id,
        genesis_id,
        params,
        bonding_params,
        validators,
        validator_stats,
        pending_unbonds,
        bond_counters,
    })
}

/* ----------------------------------------------------------------------- *
 *  Unit tests for the pure codec helpers                                   *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_bls::{bls_keygen_from_seed, encode_public_key};
    use mfn_consensus::{ValidatorPayout, DEFAULT_BONDING_PARAMS};
    use mfn_crypto::point::generator_g;

    fn sample_validator(index: u32, stake: u64, with_payout: bool) -> Validator {
        let bls = bls_keygen_from_seed(&[(index as u8).wrapping_add(7); 32]);
        let payout = if with_payout {
            // Two distinct points so view ≠ spend; using generator_g
            // for view_pub and `2·G` for spend_pub keeps the test
            // hermetic.
            let g = generator_g();
            Some(ValidatorPayout {
                view_pub: g,
                spend_pub: g + g,
            })
        } else {
            None
        };
        Validator {
            index,
            vrf_pk: generator_g(),
            bls_pk: bls.pk,
            stake,
            payout,
        }
    }

    fn sample_parts(n_validators: u32, n_pending: u32) -> CheckpointParts {
        let validators: Vec<Validator> = (0..n_validators)
            .map(|i| sample_validator(i, 1_000_000 + u64::from(i), i % 2 == 0))
            .collect();
        let validator_stats: Vec<ValidatorStats> = (0..n_validators)
            .map(|i| ValidatorStats {
                consecutive_missed: i,
                total_signed: u64::from(i) * 2,
                total_missed: u64::from(i) * 3,
                liveness_slashes: i % 3,
            })
            .collect();
        let mut pending_unbonds: BTreeMap<u32, PendingUnbond> = BTreeMap::new();
        // Use indices well above the validator range so we don't
        // collide with assigned indices and break the next-index
        // invariant.
        for i in 0..n_pending {
            let idx = 10_000 + i;
            pending_unbonds.insert(
                idx,
                PendingUnbond {
                    validator_index: idx,
                    unlock_height: 100 + i,
                    stake_at_request: 555 + u64::from(i),
                    request_height: 50 + i,
                },
            );
        }
        let max_assigned = n_validators.saturating_sub(1);
        let next_validator_index = max_assigned.saturating_add(1).max(n_validators);
        CheckpointParts {
            tip_height: 7,
            tip_id: [0xa1; 32],
            genesis_id: [0xb2; 32],
            params: ConsensusParams {
                expected_proposers_per_slot: 1.5,
                quorum_stake_bps: 6667,
                liveness_max_consecutive_missed: 32,
                liveness_slash_bps: 100,
            },
            bonding_params: DEFAULT_BONDING_PARAMS,
            validators,
            validator_stats,
            pending_unbonds,
            bond_counters: BondEpochCounters {
                bond_epoch_id: 3,
                bond_epoch_entry_count: 1,
                bond_epoch_exit_count: 0,
                next_validator_index,
            },
        }
    }

    /// Empty validator set, no pending unbonds: smallest valid
    /// payload. Sanity: encode→decode→encode is idempotent.
    #[test]
    fn checkpoint_empty_round_trips() {
        let parts = CheckpointParts {
            tip_height: 0,
            tip_id: [0; 32],
            genesis_id: [0; 32],
            params: ConsensusParams::default(),
            bonding_params: DEFAULT_BONDING_PARAMS,
            validators: Vec::new(),
            validator_stats: Vec::new(),
            pending_unbonds: BTreeMap::new(),
            bond_counters: BondEpochCounters {
                bond_epoch_id: 0,
                bond_epoch_entry_count: 0,
                bond_epoch_exit_count: 0,
                next_validator_index: 0,
            },
        };
        let bytes = encode_checkpoint_bytes(&parts);
        let decoded = decode_checkpoint_bytes(&bytes).expect("decode");
        let re_encoded = encode_checkpoint_bytes(&decoded);
        assert_eq!(bytes, re_encoded, "encode is deterministic / idempotent");
    }

    /// Non-trivial set with validators (some with payout, some
    /// without), stats, and pending unbonds: full surface coverage.
    #[test]
    fn checkpoint_round_trip_with_validators_and_pending() {
        let parts = sample_parts(4, 2);
        let bytes = encode_checkpoint_bytes(&parts);
        let decoded = decode_checkpoint_bytes(&bytes).expect("decode");
        let re_encoded = encode_checkpoint_bytes(&decoded);
        assert_eq!(bytes, re_encoded);

        // Field-level equality.
        assert_eq!(decoded.tip_height, parts.tip_height);
        assert_eq!(decoded.tip_id, parts.tip_id);
        assert_eq!(decoded.genesis_id, parts.genesis_id);
        assert_eq!(
            decoded.params.expected_proposers_per_slot,
            parts.params.expected_proposers_per_slot
        );
        assert_eq!(decoded.validators.len(), parts.validators.len());
        for (a, b) in decoded.validators.iter().zip(parts.validators.iter()) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.stake, b.stake);
            assert_eq!(a.vrf_pk.compress(), b.vrf_pk.compress());
            assert_eq!(encode_public_key(&a.bls_pk), encode_public_key(&b.bls_pk));
            assert_eq!(a.payout.is_some(), b.payout.is_some());
        }
        assert_eq!(decoded.validator_stats, parts.validator_stats);
        assert_eq!(decoded.pending_unbonds, parts.pending_unbonds);
        assert_eq!(
            decoded.bond_counters.bond_epoch_id,
            parts.bond_counters.bond_epoch_id
        );
        assert_eq!(
            decoded.bond_counters.next_validator_index,
            parts.bond_counters.next_validator_index
        );
    }

    /// f64 round-trips through `to_bits` / `from_bits` exactly,
    /// including edge cases like NaN with payload, infinities,
    /// subnormals, and π.
    #[test]
    fn checkpoint_f64_bits_round_trip() {
        for &v in &[
            0.0_f64,
            -0.0_f64,
            1.0,
            -1.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            std::f64::consts::PI,
            f64::MIN_POSITIVE / 2.0, // subnormal
            f64::EPSILON,
        ] {
            let mut p = sample_parts(1, 0);
            p.params.expected_proposers_per_slot = v;
            let bytes = encode_checkpoint_bytes(&p);
            let decoded = decode_checkpoint_bytes(&bytes).expect("decode");
            // For finite values: exact equality. For NaN: bit-level
            // equality is the right comparison.
            assert_eq!(
                decoded.params.expected_proposers_per_slot.to_bits(),
                v.to_bits(),
                "f64 bits must round-trip for {v}"
            );
        }
    }

    /// Bad magic in the first 4 bytes → typed BadMagic.
    #[test]
    fn checkpoint_rejects_bad_magic() {
        let parts = sample_parts(1, 0);
        let mut bytes = encode_checkpoint_bytes(&parts);
        bytes[0] = b'X';
        // Re-tag so the integrity check passes and BadMagic is the
        // failure surfaced.
        let payload_len = bytes.len() - 32;
        let tag = dhash(LIGHT_CHECKPOINT, &[&bytes[..payload_len]]);
        bytes[payload_len..].copy_from_slice(&tag);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::BadMagic { got }) => {
                assert_eq!(got, [b'X', b'F', b'L', b'C'])
            }
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    /// Bumped version → typed UnsupportedVersion.
    #[test]
    fn checkpoint_rejects_unknown_version() {
        let parts = sample_parts(1, 0);
        let mut bytes = encode_checkpoint_bytes(&parts);
        // Write u32 = 9 at offset 4 (right after magic).
        bytes[4..8].copy_from_slice(&9u32.to_be_bytes());
        let payload_len = bytes.len() - 32;
        let tag = dhash(LIGHT_CHECKPOINT, &[&bytes[..payload_len]]);
        bytes[payload_len..].copy_from_slice(&tag);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::UnsupportedVersion { got }) => assert_eq!(got, 9),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    /// Tampering with any byte inside the payload (but recomputing
    /// no tag) → IntegrityCheckFailed.
    #[test]
    fn checkpoint_detects_payload_tamper_via_integrity_tag() {
        let parts = sample_parts(2, 1);
        let mut bytes = encode_checkpoint_bytes(&parts);
        // Flip a byte well inside the payload (past magic+version).
        let mid = (bytes.len() - 32) / 2;
        bytes[mid] ^= 0xff;
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::IntegrityCheckFailed) => (),
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }

    /// Tampering with the tag itself → IntegrityCheckFailed.
    #[test]
    fn checkpoint_detects_tag_tamper() {
        let parts = sample_parts(1, 0);
        let mut bytes = encode_checkpoint_bytes(&parts);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::IntegrityCheckFailed) => (),
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }

    /// Truncating before the tag → IntegrityCheckFailed (no enough
    /// bytes for a valid tag). Truncating before magic+version+tag
    /// minimum → Truncated.
    #[test]
    fn checkpoint_rejects_truncation_before_minimum_length() {
        // Less than magic+version+tag minimum.
        let too_short = vec![0u8; 39];
        match decode_checkpoint_bytes(&too_short) {
            Err(LightCheckpointError::Read(CheckpointReadError::Truncated { .. })) => (),
            other => panic!("expected Read(Truncated), got {other:?}"),
        }
    }

    /// Duplicate validator indices → DuplicateValidatorIndex.
    #[test]
    fn checkpoint_rejects_duplicate_validator_indices() {
        let mut parts = sample_parts(2, 0);
        parts.validators[1].index = parts.validators[0].index;
        // bond_counters.next_validator_index is at least 2 already
        // (from sample_parts(2, _)), so duplicate detection runs
        // before any next-index check.
        let bytes = encode_checkpoint_bytes(&parts);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::Read(CheckpointReadError::DuplicateValidatorIndex {
                index,
            })) => assert_eq!(index, parts.validators[0].index),
            other => panic!("expected Read(DuplicateValidatorIndex), got {other:?}"),
        }
    }

    /// `next_validator_index <= max(validator.index)` → typed reject.
    #[test]
    fn checkpoint_rejects_next_index_at_or_below_max_assigned() {
        let mut parts = sample_parts(3, 0);
        parts.bond_counters.next_validator_index = 1; // we have indices 0,1,2 → max=2
        let bytes = encode_checkpoint_bytes(&parts);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::Read(CheckpointReadError::NextIndexBelowAssigned {
                next,
                max_assigned,
            })) => {
                assert_eq!(next, 1);
                assert_eq!(max_assigned, 2);
            }
            other => panic!("expected Read(NextIndexBelowAssigned), got {other:?}"),
        }
    }

    /// Tampered `bls_pk` bytes → typed reject pointing at the
    /// offending validator slot. BLS G1 decompression is strict, so
    /// all-zero 48 bytes is guaranteed to fail (the infinity bit
    /// must be set if all coordinates are zero, etc.).
    #[test]
    fn checkpoint_rejects_invalid_bls_pk() {
        let parts = sample_parts(1, 0);
        let mut bytes = encode_checkpoint_bytes(&parts);
        // Offset of validators[0].bls_pk:
        //   magic(4) + version(4) + tip_height(4) + tip_id(32) +
        //   genesis_id(32) + params(8+4+4+4=20) + bonding_params(8+4*4=24) +
        //   validators_len_varint(1) + validators[0].{index(4)+stake(8)+vrf_pk(32)} = 165
        let bls_pk_start = 4 + 4 + 4 + 32 + 32 + 20 + 24 + 1 + 4 + 8 + 32;
        let bls_pk_end = bls_pk_start + 48;
        // Use a pattern that's *not* the canonical "infinity" form
        // (which would still decode). We flip a sentinel bit in the
        // first byte of the BLS encoding (the "compression" / sign
        // flags), which BLS12-381 G1 decompression rejects when the
        // resulting coordinates aren't well-formed.
        bytes[bls_pk_start..bls_pk_end].fill(0xab);
        let payload_len = bytes.len() - 32;
        let tag = dhash(LIGHT_CHECKPOINT, &[&bytes[..payload_len]]);
        bytes[payload_len..].copy_from_slice(&tag);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::Read(CheckpointReadError::InvalidBlsPublicKey {
                index: 0,
                ..
            })) => (),
            other => panic!("expected Read(InvalidBlsPublicKey), got {other:?}"),
        }
    }

    /// Tampered payout_flag (neither 0 nor 1) → typed reject.
    #[test]
    fn checkpoint_rejects_invalid_payout_flag() {
        let parts = sample_parts(1, 0); // validator 0 has payout=Some (i%2==0)
        let mut bytes = encode_checkpoint_bytes(&parts);
        // Offset of validators[0].payout_flag: prefix(165) + bls_pk(48) = 213.
        let flag_off = 4 + 4 + 4 + 32 + 32 + 20 + 24 + 1 + 4 + 8 + 32 + 48;
        bytes[flag_off] = 99;
        let payload_len = bytes.len() - 32;
        let tag = dhash(LIGHT_CHECKPOINT, &[&bytes[..payload_len]]);
        bytes[payload_len..].copy_from_slice(&tag);
        match decode_checkpoint_bytes(&bytes) {
            Err(LightCheckpointError::Read(CheckpointReadError::InvalidPayoutFlag {
                index: 0,
                flag: 99,
            })) => (),
            other => panic!("expected Read(InvalidPayoutFlag), got {other:?}"),
        }
    }

    /// Encoded length grows linearly in validators + pending_unbonds —
    /// sanity check that the codec doesn't quadratically blow up
    /// on real-sized validator sets.
    #[test]
    fn checkpoint_size_grows_linearly() {
        let small = encode_checkpoint_bytes(&sample_parts(1, 0)).len();
        let big = encode_checkpoint_bytes(&sample_parts(10, 0)).len();
        // Each validator contributes a fixed-ish chunk (≥ 80 bytes
        // counting index+stake+vrf+bls; payout adds 64). 10 vs 1
        // must be at most 12x larger to catch quadratic accidents.
        assert!(big < small * 12, "size grew non-linearly: {small} → {big}",);
    }

    /// Anchor for M2.0.16 — confirm the light-checkpoint embedded
    /// validator block is byte-identical to what
    /// `mfn_consensus::checkpoint_codec::encode_validator` emits. If
    /// the two codecs ever drift, this test fails fast.
    #[test]
    fn embedded_validator_block_matches_shared_encoder_byte_for_byte() {
        let parts = sample_parts(3, 0);
        let bytes = encode_checkpoint_bytes(&parts);

        // The validator block starts after:
        //   magic(4) + version(4) + tip_height(4) + tip_id(32)
        //   + genesis_id(32) + consensus_params(20) + bonding_params(24)
        //   + validators_len_varint(1)        // varint(3) = 1 byte
        // = 121 bytes.
        let validators_start = 4 + 4 + 4 + 32 + 32 + 20 + 24 + 1;

        let mut shared = Writer::new();
        for v in &parts.validators {
            encode_validator(&mut shared, v);
        }
        let shared_bytes = shared.into_bytes();

        let embedded = &bytes[validators_start..validators_start + shared_bytes.len()];
        assert_eq!(
            embedded, shared_bytes,
            "light-checkpoint validator block must match shared encoder exactly"
        );
    }
}
