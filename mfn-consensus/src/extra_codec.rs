//! Structured `TransactionWire.extra` payloads (M2.2.x).
//!
//! Legacy transactions use arbitrary opaque `extra` bytes. When `extra`
//! begins with the **`MFEX`** magic, the remainder is a versioned container
//! whose v1 body is a concatenation of zero or more self-delimiting
//! **`MFCL`** authorship claim frames (see [`mfn_crypto::authorship`]).
//!
//! **MFEX v2** appends zero or more **`MFEO`** endowment-opening frames
//! after the MFCL section (B-11). Each opening binds the Pedersen point in
//! `StorageCommitment.endowment` to a revealed `(value, blinding)` pair.
//!
//! **`MFEX`** is the only normative structured-`extra` envelope; future tagged
//! inner payloads extend this container without forking claim parsing.

use curve25519_dalek::scalar::Scalar;
use mfn_crypto::authorship::{
    decode_authorship_claim, mfcl_frame_wire_len, AuthorshipClaim, AuthorshipClaimDecodeError,
    MAX_CLAIMS_PER_TX, MFCL_MAGIC, MFCL_V2_MIN_WIRE_LEN,
};
use mfn_crypto::scalar::{bytes_to_scalar, scalar_to_bytes};
use thiserror::Error;

/// Magic for structured multi-payload `extra` (M2.2.x).
pub const MFEX_MAGIC: &[u8; 4] = b"MFEX";

/// MFEX v1 — MFCL claims only.
pub const MFEX_VERSION: u8 = 1;

/// MFEX v2 — MFCL claims + optional MFEO endowment openings (B-11).
pub const MFEX_VERSION_V2: u8 = 2;

/// Magic for Pedersen endowment opening reveal (B-11).
pub const MFEO_MAGIC: &[u8; 4] = b"MFEO";

/// Supported `MFEO` frame version.
pub const MFEO_VERSION: u8 = 1;

/// Wire length of an `MFEO` v1 frame: magic(4) + version(1) + value(8) + blinding(32).
pub const MFEO_V1_WIRE_LEN: usize = 4 + 1 + 8 + 32;

/// Pedersen opening for `StorageCommitment.endowment` (B-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndowmentOpening {
    /// Opened endowment amount (base units).
    pub value: u64,
    /// Pedersen blinding scalar.
    pub blinding: Scalar,
}

/// Fully parsed MFEX container (claims + optional openings).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParsedMfexExtra {
    /// Verified-parse authorship claims (signature check is separate).
    pub claims: Vec<AuthorshipClaim>,
    /// Endowment openings in wire order (one per new storage anchor when mandated).
    pub endowment_openings: Vec<EndowmentOpening>,
}

/// Errors from [`parse_mfex_authorship_claims`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtraClaimsParseError {
    /// `extra` starts with `MFEX` but is shorter than `MFEX` + version.
    #[error("truncated MFEX header: need {need_at_least} bytes, got {got}")]
    Truncated {
        /// Minimum bytes required.
        need_at_least: usize,
        /// Bytes available.
        got: usize,
    },
    /// Unknown `MFEX` version.
    #[error("unknown MFEX version {0}")]
    UnknownMfexVersion(u8),
    /// Expected an `MFCL` frame at the current offset.
    #[error("expected MFCL frame at offset {offset}")]
    ExpectedMfcl {
        /// Byte offset into `extra`.
        offset: usize,
    },
    /// More than [`MAX_CLAIMS_PER_TX`] claims in one `extra`.
    #[error("too many authorship claims: max {max}, got {got}")]
    TooManyClaims {
        /// [`MAX_CLAIMS_PER_TX`].
        max: usize,
        /// Parsed count before rejection.
        got: usize,
    },
    /// [`decode_authorship_claim`] failed on a slice.
    #[error("MFCL decode at offset {offset}: {source}")]
    MfclDecode {
        /// Byte offset into `extra`.
        offset: usize,
        /// Underlying decode error.
        source: AuthorshipClaimDecodeError,
    },
    /// Expected an `MFEO` frame at the current offset.
    #[error("expected MFEO frame at offset {offset}")]
    ExpectedMfeo {
        /// Byte offset into `extra`.
        offset: usize,
    },
    /// `MFEO` blinding scalar is not canonical.
    #[error("MFEO blinding not canonical at offset {offset}")]
    MfeoBlindingNotCanonical {
        /// Byte offset into `extra`.
        offset: usize,
    },
    /// Too many endowment openings in one `extra`.
    #[error("too many endowment openings: max {max}, got {got}")]
    TooManyEndowmentOpenings {
        /// Maximum openings per tx.
        max: usize,
        /// Parsed count before rejection.
        got: usize,
    },
}

/// Maximum endowment openings per transaction (`extra` wire limit).
pub const MAX_ENDOWMENT_OPENINGS_PER_TX: usize = 8;

fn parse_mfcl_claims_at(
    extra: &[u8],
    ver: u8,
    start: usize,
) -> Result<(Vec<AuthorshipClaim>, usize), ExtraClaimsParseError> {
    let mut i = start;
    let mut out = Vec::new();
    while i < extra.len() {
        if extra[i..].starts_with(MFEO_MAGIC) {
            if ver == MFEX_VERSION {
                return Err(ExtraClaimsParseError::ExpectedMfcl { offset: i });
            }
            break;
        }
        if i + MFCL_V2_MIN_WIRE_LEN > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + MFCL_V2_MIN_WIRE_LEN,
                got: extra.len(),
            });
        }
        if extra[i..i + 4] != MFCL_MAGIC[..] {
            return Err(ExtraClaimsParseError::ExpectedMfcl { offset: i });
        }
        let frame_len =
            mfcl_frame_wire_len(&extra[i..]).map_err(|e| ExtraClaimsParseError::MfclDecode {
                offset: i,
                source: e,
            })?;
        if i + frame_len > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + frame_len,
                got: extra.len(),
            });
        }
        let frame = &extra[i..i + frame_len];
        let claim =
            decode_authorship_claim(frame).map_err(|e| ExtraClaimsParseError::MfclDecode {
                offset: i,
                source: e,
            })?;
        out.push(claim);
        if out.len() > MAX_CLAIMS_PER_TX {
            return Err(ExtraClaimsParseError::TooManyClaims {
                max: MAX_CLAIMS_PER_TX,
                got: out.len(),
            });
        }
        i += frame_len;
    }
    Ok((out, i))
}

fn parse_mfeo_openings_at(
    extra: &[u8],
    start: usize,
) -> Result<Vec<EndowmentOpening>, ExtraClaimsParseError> {
    let mut i = start;
    let mut out = Vec::new();
    while i < extra.len() {
        if i + MFEO_V1_WIRE_LEN > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + MFEO_V1_WIRE_LEN,
                got: extra.len(),
            });
        }
        if !extra[i..].starts_with(MFEO_MAGIC) {
            return Err(ExtraClaimsParseError::ExpectedMfeo { offset: i });
        }
        if extra[i + 4] != MFEO_VERSION {
            return Err(ExtraClaimsParseError::UnknownMfexVersion(extra[i + 4]));
        }
        let value = u64::from_be_bytes(
            extra[i + 5..i + 13]
                .try_into()
                .expect("8-byte endowment value"),
        );
        let blinding_bytes: [u8; 32] = extra[i + 13..i + 45].try_into().expect("32-byte blinding");
        let blinding = bytes_to_scalar(&blinding_bytes);
        out.push(EndowmentOpening { value, blinding });
        if out.len() > MAX_ENDOWMENT_OPENINGS_PER_TX {
            return Err(ExtraClaimsParseError::TooManyEndowmentOpenings {
                max: MAX_ENDOWMENT_OPENINGS_PER_TX,
                got: out.len(),
            });
        }
        i += MFEO_V1_WIRE_LEN;
    }
    Ok(out)
}

/// Encode one `MFEO` v1 opening frame.
pub fn encode_mfeo_opening(value: u64, blinding: &Scalar) -> Vec<u8> {
    let mut out = Vec::with_capacity(MFEO_V1_WIRE_LEN);
    out.extend_from_slice(MFEO_MAGIC);
    out.push(MFEO_VERSION);
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&scalar_to_bytes(blinding));
    out
}

/// Parse the full MFEX container (claims + optional openings).
pub fn parse_mfex_extra(extra: &[u8]) -> Result<ParsedMfexExtra, ExtraClaimsParseError> {
    if extra.len() < 5 {
        if extra.starts_with(MFEX_MAGIC) {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: 5,
                got: extra.len(),
            });
        }
        return Ok(ParsedMfexExtra::default());
    }
    if !extra.starts_with(MFEX_MAGIC) {
        return Ok(ParsedMfexExtra::default());
    }
    let ver = extra[4];
    if ver != MFEX_VERSION && ver != MFEX_VERSION_V2 {
        return Err(ExtraClaimsParseError::UnknownMfexVersion(ver));
    }
    let (claims, after_claims) = parse_mfcl_claims_at(extra, ver, 5)?;
    let endowment_openings = if ver == MFEX_VERSION_V2 {
        parse_mfeo_openings_at(extra, after_claims)?
    } else {
        if after_claims < extra.len() {
            return Err(ExtraClaimsParseError::ExpectedMfcl {
                offset: after_claims,
            });
        }
        Vec::new()
    };
    Ok(ParsedMfexExtra {
        claims,
        endowment_openings,
    })
}

/// If `extra` begins with [`MFEX_MAGIC`], parse v1 as a concatenation of
/// `MFCL` claim frames. Otherwise returns an empty list (opaque legacy `extra`).
pub fn parse_mfex_authorship_claims(
    extra: &[u8],
) -> Result<Vec<AuthorshipClaim>, ExtraClaimsParseError> {
    Ok(parse_mfex_extra(extra)?.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::authorship::{
        build_signed_claim_version, encode_authorship_claim, MFCL_WIRE_VERSION_V2,
        UNBOUND_COMMIT_HASH,
    };
    use mfn_crypto::schnorr::schnorr_keygen;

    fn mfex_wrap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(MFEX_MAGIC);
        e.push(MFEX_VERSION);
        for f in frames {
            e.extend_from_slice(f);
        }
        e
    }

    #[test]
    fn legacy_opaque_extra_yields_empty_claims() {
        assert!(parse_mfex_authorship_claims(b"hello-memo")
            .unwrap()
            .is_empty());
        assert!(parse_mfex_authorship_claims(&[]).unwrap().is_empty());
    }

    #[test]
    fn mfex_empty_body_round_trip() {
        let extra = mfex_wrap(&[]);
        assert!(parse_mfex_authorship_claims(&extra).unwrap().is_empty());
    }

    #[test]
    fn mfex_one_claim_round_trip() {
        let kp = schnorr_keygen();
        let data_root = [3u8; 32];
        let claim = build_signed_claim_version(
            MFCL_WIRE_VERSION_V2,
            data_root,
            UNBOUND_COMMIT_HASH,
            b"hi",
            &kp,
            &mut rand_core::OsRng,
        )
        .expect("sign");
        let frame = encode_authorship_claim(&claim).expect("enc");
        let extra = mfex_wrap(&[frame]);
        let got = parse_mfex_authorship_claims(&extra).expect("parse");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], claim);
    }

    #[test]
    fn mfex_unknown_version_errors() {
        let mut b = vec![0u8; 5];
        b[0..4].copy_from_slice(MFEX_MAGIC);
        b[4] = 99;
        assert_eq!(
            parse_mfex_authorship_claims(&b),
            Err(ExtraClaimsParseError::UnknownMfexVersion(99))
        );
    }

    #[test]
    fn mfex_v2_endowment_opening_round_trip() {
        use curve25519_dalek::scalar::Scalar;
        let blinding = Scalar::from(42u64);
        let opening = EndowmentOpening {
            value: 1_234,
            blinding,
        };
        let mut extra = Vec::new();
        extra.extend_from_slice(MFEX_MAGIC);
        extra.push(MFEX_VERSION_V2);
        extra.extend_from_slice(&encode_mfeo_opening(opening.value, &opening.blinding));
        let parsed = parse_mfex_extra(&extra).expect("parse");
        assert!(parsed.claims.is_empty());
        assert_eq!(parsed.endowment_openings.len(), 1);
        assert_eq!(parsed.endowment_openings[0].value, 1_234);
        assert_eq!(parsed.endowment_openings[0].blinding, blinding);
    }
}
