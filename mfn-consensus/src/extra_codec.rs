//! Structured `TransactionWire.extra` payloads (M2.2.x).
//!
//! Legacy transactions use arbitrary opaque `extra` bytes. When `extra`
//! begins with the **`MFEX`** magic, the remainder is a versioned container
//! whose v1 body is a concatenation of zero or more self-delimiting
//! **`MFCL`** authorship claim frames (see [`mfn_crypto::authorship`]).

use mfn_crypto::authorship::{
    decode_authorship_claim, AuthorshipClaim, AuthorshipClaimDecodeError, MFCL_HEADER_LEN,
    MFCL_MAGIC, MFCL_MIN_WIRE_LEN, MAX_CLAIMS_PER_TX,
};
use thiserror::Error;

/// Magic for structured multi-payload `extra` (M2.2.x).
pub const MFEX_MAGIC: &[u8; 4] = b"MFEX";

/// Supported `MFEX` container version (only byte after magic).
pub const MFEX_VERSION: u8 = 1;

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
}

/// If `extra` begins with [`MFEX_MAGIC`], parse v1 as a concatenation of
/// `MFCL` claim frames. Otherwise returns an empty list (opaque legacy `extra`).
pub fn parse_mfex_authorship_claims(extra: &[u8]) -> Result<Vec<AuthorshipClaim>, ExtraClaimsParseError> {
    if extra.len() < 5 {
        if extra.starts_with(MFEX_MAGIC) {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: 5,
                got: extra.len(),
            });
        }
        return Ok(Vec::new());
    }
    if !extra.starts_with(MFEX_MAGIC) {
        return Ok(Vec::new());
    }
    let ver = extra[4];
    if ver != MFEX_VERSION {
        return Err(ExtraClaimsParseError::UnknownMfexVersion(ver));
    }
    let mut i = 5usize;
    let mut out = Vec::new();
    while i < extra.len() {
        if i + MFCL_MIN_WIRE_LEN > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + MFCL_MIN_WIRE_LEN,
                got: extra.len(),
            });
        }
        if extra[i..i + 4] != MFCL_MAGIC[..] {
            return Err(ExtraClaimsParseError::ExpectedMfcl { offset: i });
        }
        let msg_len = extra[i + 69] as usize;
        if msg_len > mfn_crypto::authorship::MAX_CLAIM_MESSAGE_LEN {
            return Err(ExtraClaimsParseError::MfclDecode {
                offset: i,
                source: AuthorshipClaimDecodeError::MessageTooLong {
                    got: msg_len,
                    max: mfn_crypto::authorship::MAX_CLAIM_MESSAGE_LEN,
                },
            });
        }
        let frame_len = MFCL_HEADER_LEN + msg_len + 64;
        if i + frame_len > extra.len() {
            return Err(ExtraClaimsParseError::Truncated {
                need_at_least: i + frame_len,
                got: extra.len(),
            });
        }
        let frame = &extra[i..i + frame_len];
        let claim = decode_authorship_claim(frame).map_err(|e| ExtraClaimsParseError::MfclDecode {
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
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::authorship::{
        encode_authorship_claim, sign_claim_with, AuthorshipClaim, MFCL_WIRE_VERSION,
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
        assert!(parse_mfex_authorship_claims(b"hello-memo").unwrap().is_empty());
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
        let msg = b"hi";
        let sig =
            sign_claim_with(&data_root, &kp.pub_key, msg, &kp, &mut rand_core::OsRng).expect("sign");
        let claim = AuthorshipClaim {
            wire_version: MFCL_WIRE_VERSION,
            data_root,
            claim_pubkey: kp.pub_key,
            message: msg.to_vec(),
            sig,
        };
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
}
