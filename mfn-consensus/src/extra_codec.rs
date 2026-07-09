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
//! **MFEX v3** appends zero or more **`MFER`** endowment range-proof frames
//! (B-11 phase 2). Each proof shows the surplus over `required_endowment`
//! is non-negative without revealing the opened amount.
//!
//! **`MFEX`** is the only normative structured-`extra` envelope; future tagged
//! inner payloads extend this container without forking claim parsing.

use curve25519_dalek::scalar::Scalar;
use mfn_crypto::authorship::{
    decode_authorship_claim, mfcl_frame_wire_len, AuthorshipClaim, AuthorshipClaimDecodeError,
    MAX_CLAIMS_PER_TX, MFCL_MAGIC, MFCL_V2_MIN_WIRE_LEN,
};
use mfn_crypto::bulletproofs::encode_bulletproof;
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::scalar::{bytes_to_scalar, scalar_to_bytes};
use mfn_crypto::BulletproofRange;
use thiserror::Error;

/// Magic for structured multi-payload `extra` (M2.2.x).
pub const MFEX_MAGIC: &[u8; 4] = b"MFEX";

/// MFEX v1 — MFCL claims only.
pub const MFEX_VERSION: u8 = 1;

/// MFEX v2 — MFCL claims + optional MFEO endowment openings (B-11).
pub const MFEX_VERSION_V2: u8 = 2;

/// MFEX v3 — MFCL claims + optional MFER endowment range proofs (B-11 phase 2).
pub const MFEX_VERSION_V3: u8 = 3;

/// Magic for Pedersen endowment opening reveal (B-11).
pub const MFEO_MAGIC: &[u8; 4] = b"MFEO";

/// Supported `MFEO` frame version.
pub const MFEO_VERSION: u8 = 1;

/// Wire length of an `MFEO` v1 frame: magic(4) + version(1) + value(8) + blinding(32).
pub const MFEO_V1_WIRE_LEN: usize = 4 + 1 + 8 + 32;

/// Magic for Pedersen endowment surplus range proof (B-11 phase 2).
pub const MFER_MAGIC: &[u8; 4] = b"MFER";

/// Supported `MFER` frame version.
pub const MFER_VERSION: u8 = 1;

/// Minimum `MFER` header: magic(4) + version(1) + empty varint(1).
pub const MFER_V1_HEADER_LEN: usize = 6;

/// Pedersen opening for `StorageCommitment.endowment` (B-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndowmentOpening {
    /// Opened endowment amount (base units).
    pub value: u64,
    /// Pedersen blinding scalar.
    pub blinding: Scalar,
}

/// Canonical-encoded Bulletproof bytes for an endowment surplus proof (B-11 phase 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndowmentRangeProofWire {
    /// [`encode_bulletproof`] body (commitment `V` is carried out-of-band).
    pub proof_bytes: Vec<u8>,
}

/// Fully parsed MFEX container (claims + optional openings / range proofs).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParsedMfexExtra {
    /// Verified-parse authorship claims (signature check is separate).
    pub claims: Vec<AuthorshipClaim>,
    /// Endowment openings in wire order (one per new storage anchor when mandated).
    pub endowment_openings: Vec<EndowmentOpening>,
    /// Endowment range proofs in wire order (MFEX v3 / B-11 phase 2).
    pub endowment_range_proofs: Vec<EndowmentRangeProofWire>,
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
    /// Expected an `MFER` frame at the current offset.
    #[error("expected MFER frame at offset {offset}")]
    ExpectedMfer {
        /// Byte offset into `extra`.
        offset: usize,
    },
    /// Unknown `MFER` frame version.
    #[error("unknown MFER version {0}")]
    UnknownMferVersion(u8),
    /// Too many endowment range proofs in one `extra`.
    #[error("too many endowment range proofs: max {max}, got {got}")]
    TooManyEndowmentRangeProofs {
        /// Maximum proofs per tx.
        max: usize,
        /// Parsed count before rejection.
        got: usize,
    },
    /// `MFER` proof blob exceeds the protocol size cap.
    #[error("MFER proof too large: max {max} bytes, got {got}")]
    MferProofTooLarge {
        /// Maximum encoded proof bytes.
        max: usize,
        /// Declared length.
        got: usize,
    },
}

/// Maximum endowment openings per transaction (`extra` wire limit).
pub const MAX_ENDOWMENT_OPENINGS_PER_TX: usize = 8;

/// Maximum endowment range proofs per transaction (`extra` wire limit).
pub const MAX_ENDOWMENT_RANGE_PROOFS_PER_TX: usize = 8;

/// Encoded Bulletproof size cap for `MFER` frames (`N = 64` + slack).
pub const MAX_MFER_PROOF_BYTES: usize = 896;

fn parse_mfcl_claims_at(
    extra: &[u8],
    ver: u8,
    start: usize,
) -> Result<(Vec<AuthorshipClaim>, usize), ExtraClaimsParseError> {
    let mut i = start;
    let mut out = Vec::new();
    while i < extra.len() {
        if extra[i..].starts_with(MFEO_MAGIC) || extra[i..].starts_with(MFER_MAGIC) {
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

/// Encode one `MFER` v1 range-proof frame.
pub fn encode_mfer_range_proof(proof: &BulletproofRange) -> Vec<u8> {
    let proof_bytes = encode_bulletproof(proof);
    let mut out = Vec::with_capacity(MFER_V1_HEADER_LEN + proof_bytes.len());
    out.extend_from_slice(MFER_MAGIC);
    out.push(MFER_VERSION);
    let mut w = Writer::new();
    w.varint(u64::try_from(proof_bytes.len()).expect("proof fits u64"));
    out.extend_from_slice(&w.into_bytes());
    out.extend_from_slice(&proof_bytes);
    out
}

fn parse_mfer_range_proofs_at(
    extra: &[u8],
    start: usize,
) -> Result<Vec<EndowmentRangeProofWire>, ExtraClaimsParseError> {
    let mut i = start;
    let mut out = Vec::new();
    while i < extra.len() {
        if i + MFER_V1_HEADER_LEN > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + MFER_V1_HEADER_LEN,
                got: extra.len(),
            });
        }
        if !extra[i..].starts_with(MFER_MAGIC) {
            return Err(ExtraClaimsParseError::ExpectedMfer { offset: i });
        }
        if extra[i + 4] != MFER_VERSION {
            return Err(ExtraClaimsParseError::UnknownMferVersion(extra[i + 4]));
        }
        i += 5;
        let slice = &extra[i..];
        let mut r = Reader::new(slice);
        let len = r.varint().map_err(|_| ExtraClaimsParseError::Truncated {
            need_at_least: i + 1,
            got: extra.len(),
        })? as usize;
        if len > MAX_MFER_PROOF_BYTES {
            return Err(ExtraClaimsParseError::MferProofTooLarge {
                max: MAX_MFER_PROOF_BYTES,
                got: len,
            });
        }
        let proof_bytes = r.bytes(len).map_err(|_| ExtraClaimsParseError::Truncated {
            need_at_least: i + len,
            got: extra.len(),
        })?;
        out.push(EndowmentRangeProofWire {
            proof_bytes: proof_bytes.to_vec(),
        });
        if out.len() > MAX_ENDOWMENT_RANGE_PROOFS_PER_TX {
            return Err(ExtraClaimsParseError::TooManyEndowmentRangeProofs {
                max: MAX_ENDOWMENT_RANGE_PROOFS_PER_TX,
                got: out.len(),
            });
        }
        i += slice.len() - r.remaining();
    }
    Ok(out)
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
    if ver != MFEX_VERSION && ver != MFEX_VERSION_V2 && ver != MFEX_VERSION_V3 {
        return Err(ExtraClaimsParseError::UnknownMfexVersion(ver));
    }
    let (claims, after_claims) = parse_mfcl_claims_at(extra, ver, 5)?;
    let (endowment_openings, endowment_range_proofs) = match ver {
        MFEX_VERSION_V2 => (parse_mfeo_openings_at(extra, after_claims)?, Vec::new()),
        MFEX_VERSION_V3 => (Vec::new(), parse_mfer_range_proofs_at(extra, after_claims)?),
        MFEX_VERSION => {
            if after_claims < extra.len() {
                return Err(ExtraClaimsParseError::ExpectedMfcl {
                    offset: after_claims,
                });
            }
            (Vec::new(), Vec::new())
        }
        _ => unreachable!("version filtered above"),
    };
    Ok(ParsedMfexExtra {
        claims,
        endowment_openings,
        endowment_range_proofs,
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
        assert!(parsed.endowment_range_proofs.is_empty());
    }

    #[test]
    fn mfex_v3_endowment_range_proof_round_trip() {
        use mfn_crypto::bulletproofs::bp_prove;
        use mfn_crypto::scalar::random_scalar;
        let blinding = random_scalar();
        let proof = bp_prove(500, &blinding, 64).expect("prove").proof;
        let mut extra = Vec::new();
        extra.extend_from_slice(MFEX_MAGIC);
        extra.push(MFEX_VERSION_V3);
        extra.extend_from_slice(&encode_mfer_range_proof(&proof));
        let parsed = parse_mfex_extra(&extra).expect("parse");
        assert!(parsed.claims.is_empty());
        assert!(parsed.endowment_openings.is_empty());
        assert_eq!(parsed.endowment_range_proofs.len(), 1);
        assert_eq!(
            parsed.endowment_range_proofs[0].proof_bytes,
            encode_bulletproof(&proof)
        );
    }
}
