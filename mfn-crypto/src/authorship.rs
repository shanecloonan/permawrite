//! Optional authorship claims (M2.2.x).
//!
//! A claim binds a **claiming** Schnorr public key and a short user message to
//! a storage **data_root** (32-byte Merkle root of chunk hashes) using a domain-separated digest and
//! the protocol's raw Schnorr construction ([`crate::schnorr`]). This is
//! intentionally **not** ring-signed: the pubkey is public by design.
//!
//! See [`docs/AUTHORSHIP.md`](../../docs/AUTHORSHIP.md) for the full protocol.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use thiserror::Error;

use crate::domain::AUTHORSHIP_CLAIM_DIGEST;
use crate::hash::dhash;
use crate::schnorr::{
    decode_schnorr_signature, encode_schnorr_signature, schnorr_sign_with, schnorr_verify,
    SchnorrKeypair, SchnorrSignature, SCHNORR_SIGNATURE_BYTES,
};
use crate::{CryptoError, Result};

/// Maximum UTF-8 / opaque message length for a single claim (bytes).
pub const MAX_CLAIM_MESSAGE_LEN: usize = 128;

/// Maximum number of well-formed `MFCL` claim blobs allowed per transaction
/// `extra` field (consensus-enforced when wired in `mfn-consensus`).
pub const MAX_CLAIMS_PER_TX: usize = 4;

/// Magic prefix for one authorship claim on the wire (`MFCL`).
pub const MFCL_MAGIC: &[u8; 4] = b"MFCL";

/// Current [`AuthorshipClaim::wire_version`] / `MFCL` payload version byte.
pub const MFCL_WIRE_VERSION: u8 = 1;

/// `MFCL` ‖ `version` ‖ `data_root` ‖ `claim_pubkey` ‖ `message_len` (fixed header).
pub const MFCL_HEADER_LEN: usize = 4 + 1 + 32 + 32 + 1;

/// Minimum `MFCL` frame size (empty message + signature).
pub const MFCL_MIN_WIRE_LEN: usize = MFCL_HEADER_LEN + SCHNORR_SIGNATURE_BYTES;

/// Maximum `MFCL` frame size (`message` = [`MAX_CLAIM_MESSAGE_LEN`]).
pub const MFCL_MAX_WIRE_LEN: usize =
    MFCL_HEADER_LEN + MAX_CLAIM_MESSAGE_LEN + SCHNORR_SIGNATURE_BYTES;

/// One decoded authorship claim (`MFCL` wire). Signature is **not** verified by [`decode_authorship_claim`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorshipClaim {
    /// Wire version (must be [`MFCL_WIRE_VERSION`] for consensus v1).
    pub wire_version: u8,
    /// Content-addressed storage root this claim refers to.
    pub data_root: [u8; 32],
    /// Public key whose owner signed [`Self::sig`].
    pub claim_pubkey: EdwardsPoint,
    /// Opaque user message (≤ [`MAX_CLAIM_MESSAGE_LEN`] bytes).
    pub message: Vec<u8>,
    /// Schnorr signature over [`claim_digest`](crate::authorship::claim_digest).
    pub sig: SchnorrSignature,
}

/// Errors from [`decode_authorship_claim`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorshipClaimDecodeError {
    /// Buffer shorter than the smallest valid `MFCL` frame.
    #[error("truncated claim wire: need at least {need_at_least} bytes, got {got}")]
    Truncated {
        /// Minimum bytes required for the fields parsed so far (or overall minimum).
        need_at_least: usize,
        /// Bytes available.
        got: usize,
    },
    /// First four bytes were not `MFCL`.
    #[error("expected MFCL magic")]
    WrongMagic,
    /// Unsupported `version` byte after `MFCL`.
    #[error("unknown MFCL wire version {0}")]
    UnknownVersion(u8),
    /// `message_len` exceeds [`MAX_CLAIM_MESSAGE_LEN`].
    #[error("message length {got} exceeds max {max}")]
    MessageTooLong {
        /// Length byte on wire.
        got: usize,
        /// [`MAX_CLAIM_MESSAGE_LEN`].
        max: usize,
    },
    /// `claim_pubkey` bytes are not a valid compressed Edwards point.
    #[error("invalid claim_pubkey encoding")]
    InvalidClaimPubkey,
    /// Trailing bytes after a well-formed `MFCL` frame (decoder is strict / self-delimiting).
    #[error("{remaining} trailing byte(s) after MFCL frame")]
    TrailingBytes {
        /// Extra bytes after the signature.
        remaining: usize,
    },
    /// [`decode_schnorr_signature`] failed on the final 64 bytes.
    #[error("invalid Schnorr signature encoding")]
    InvalidSchnorrEncoding,
}

/// Encode [`AuthorshipClaim`] as canonical `MFCL` bytes (version must be [`MFCL_WIRE_VERSION`]).
pub fn encode_authorship_claim(claim: &AuthorshipClaim) -> Result<Vec<u8>> {
    if claim.wire_version != MFCL_WIRE_VERSION {
        return Err(CryptoError::AuthorshipClaimBadWireVersion(
            claim.wire_version,
        ));
    }
    if claim.message.len() > MAX_CLAIM_MESSAGE_LEN {
        return Err(CryptoError::InvalidLength {
            expected: MAX_CLAIM_MESSAGE_LEN,
            got: claim.message.len(),
        });
    }
    let mut out =
        Vec::with_capacity(MFCL_HEADER_LEN + claim.message.len() + SCHNORR_SIGNATURE_BYTES);
    out.extend_from_slice(MFCL_MAGIC);
    out.push(claim.wire_version);
    out.extend_from_slice(&claim.data_root);
    out.extend_from_slice(&claim.claim_pubkey.compress().to_bytes());
    out.push(claim.message.len() as u8);
    out.extend_from_slice(&claim.message);
    out.extend_from_slice(&encode_schnorr_signature(&claim.sig));
    debug_assert_eq!(
        out.len(),
        MFCL_HEADER_LEN + claim.message.len() + SCHNORR_SIGNATURE_BYTES
    );
    Ok(out)
}

/// Decode a single strict `MFCL` frame from `buf` (no trailing bytes allowed).
pub fn decode_authorship_claim(
    buf: &[u8],
) -> core::result::Result<AuthorshipClaim, AuthorshipClaimDecodeError> {
    if buf.len() < MFCL_MIN_WIRE_LEN {
        return Err(AuthorshipClaimDecodeError::Truncated {
            need_at_least: MFCL_MIN_WIRE_LEN,
            got: buf.len(),
        });
    }
    if buf[..4] != MFCL_MAGIC[..] {
        return Err(AuthorshipClaimDecodeError::WrongMagic);
    }
    let wire_version = buf[4];
    if wire_version != MFCL_WIRE_VERSION {
        return Err(AuthorshipClaimDecodeError::UnknownVersion(wire_version));
    }
    let mut data_root = [0u8; 32];
    data_root.copy_from_slice(&buf[5..37]);
    let mut pk_b = [0u8; 32];
    pk_b.copy_from_slice(&buf[37..69]);
    let claim_pubkey = CompressedEdwardsY(pk_b)
        .decompress()
        .ok_or(AuthorshipClaimDecodeError::InvalidClaimPubkey)?;
    let msg_len = buf[69] as usize;
    if msg_len > MAX_CLAIM_MESSAGE_LEN {
        return Err(AuthorshipClaimDecodeError::MessageTooLong {
            got: msg_len,
            max: MAX_CLAIM_MESSAGE_LEN,
        });
    }
    let total = MFCL_HEADER_LEN + msg_len + SCHNORR_SIGNATURE_BYTES;
    if buf.len() < total {
        return Err(AuthorshipClaimDecodeError::Truncated {
            need_at_least: total,
            got: buf.len(),
        });
    }
    if buf.len() > total {
        return Err(AuthorshipClaimDecodeError::TrailingBytes {
            remaining: buf.len() - total,
        });
    }
    let msg = buf[70..70 + msg_len].to_vec();
    let sig_slice: &[u8; SCHNORR_SIGNATURE_BYTES] =
        buf[70 + msg_len..]
            .try_into()
            .map_err(|_| AuthorshipClaimDecodeError::Truncated {
                need_at_least: total,
                got: buf.len(),
            })?;
    let sig = decode_schnorr_signature(sig_slice)
        .map_err(|_| AuthorshipClaimDecodeError::InvalidSchnorrEncoding)?;
    Ok(AuthorshipClaim {
        wire_version,
        data_root,
        claim_pubkey,
        message: msg,
        sig,
    })
}

/// Domain-separated digest signed by [`sign_claim`] / verified by [`verify_claim`].
///
/// ```text
/// dhash(AUTHORSHIP_CLAIM_DIGEST, [
///     data_root,            // 32
///     claim_pubkey_bytes,   // 32 compressed
///     [message_len as u8],
///     message,
/// ])
/// ```
pub fn claim_digest(
    data_root: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
) -> Result<[u8; 32]> {
    if message.len() > MAX_CLAIM_MESSAGE_LEN {
        return Err(CryptoError::InvalidLength {
            expected: MAX_CLAIM_MESSAGE_LEN,
            got: message.len(),
        });
    }
    let pk = claim_pubkey.compress().to_bytes();
    let len_b = [message.len() as u8];
    Ok(dhash(
        AUTHORSHIP_CLAIM_DIGEST,
        &[
            data_root.as_slice(),
            pk.as_slice(),
            len_b.as_slice(),
            message,
        ],
    ))
}

/// Sign a claim digest with the claiming keypair (must match `claim_pubkey`).
pub fn sign_claim(
    data_root: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
    kp: &SchnorrKeypair,
) -> Result<SchnorrSignature> {
    if kp.pub_key != *claim_pubkey {
        return Err(CryptoError::ClaimSigningKeyMismatch);
    }
    let digest = claim_digest(data_root, claim_pubkey, message)?;
    Ok(schnorr_sign_with(&digest, kp, &mut rand_core::OsRng))
}

/// Sign with a deterministic RNG (tests only).
pub fn sign_claim_with<R: rand_core::CryptoRngCore + ?Sized>(
    data_root: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
    kp: &SchnorrKeypair,
    rng: &mut R,
) -> Result<SchnorrSignature> {
    if kp.pub_key != *claim_pubkey {
        return Err(CryptoError::ClaimSigningKeyMismatch);
    }
    let digest = claim_digest(data_root, claim_pubkey, message)?;
    Ok(schnorr_sign_with(&digest, kp, rng))
}

/// Verify a claim signature against `data_root`, `claim_pubkey`, and `message`.
pub fn verify_claim(
    data_root: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
    sig: &SchnorrSignature,
) -> Result<bool> {
    let digest = claim_digest(data_root, claim_pubkey, message)?;
    Ok(schnorr_verify(&digest, sig, claim_pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::schnorr_keygen;

    #[test]
    fn claim_digest_golden_vector() {
        use crate::point::generator_g;
        use crate::scalar::bytes_to_scalar;
        let mut sk = [0u8; 32];
        sk[0] = 9;
        let priv_key = bytes_to_scalar(&sk);
        let pub_key = generator_g() * priv_key;
        let data_root = [0u8; 32];
        let d = claim_digest(&data_root, &pub_key, &[]).expect("digest");
        assert_eq!(
            hex::encode(d),
            "81b2fb31ec05b1ddee5488b3e4d999b7809f02a16f58e006de503fd7c01980df"
        );
    }

    #[test]
    fn claim_digest_deterministic_and_32_bytes() {
        let data_root = [0x42u8; 32];
        let kp = schnorr_keygen();
        let msg = b"permawrite";
        let d1 = claim_digest(&data_root, &kp.pub_key, msg).expect("digest");
        let d2 = claim_digest(&data_root, &kp.pub_key, msg).expect("digest");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn claim_digest_changes_with_message() {
        let data_root = [1u8; 32];
        let kp = schnorr_keygen();
        let a = claim_digest(&data_root, &kp.pub_key, b"a").expect("d");
        let b = claim_digest(&data_root, &kp.pub_key, b"b").expect("d");
        assert_ne!(a, b);
    }

    #[test]
    fn sign_verify_round_trip() {
        let data_root = [1u8; 32];
        let kp = schnorr_keygen();
        let msg = b"hello-permaweb";
        let sig = sign_claim_with(&data_root, &kp.pub_key, msg, &kp, &mut rand_core::OsRng)
            .expect("sign");
        assert!(verify_claim(&data_root, &kp.pub_key, msg, &sig).expect("verify"));
    }

    #[test]
    fn wrong_message_fails() {
        let data_root = [2u8; 32];
        let kp = schnorr_keygen();
        let sig = sign_claim_with(&data_root, &kp.pub_key, b"a", &kp, &mut rand_core::OsRng)
            .expect("sign");
        assert!(!verify_claim(&data_root, &kp.pub_key, b"b", &sig).expect("verify"));
    }

    #[test]
    fn wrong_pubkey_fails() {
        let data_root = [3u8; 32];
        let kp = schnorr_keygen();
        let other = schnorr_keygen();
        let sig = sign_claim_with(&data_root, &kp.pub_key, b"x", &kp, &mut rand_core::OsRng)
            .expect("sign");
        assert!(!verify_claim(&data_root, &other.pub_key, b"x", &sig).expect("verify"));
    }

    #[test]
    fn message_too_long_rejected() {
        let data_root = [4u8; 32];
        let kp = schnorr_keygen();
        let long = vec![0u8; MAX_CLAIM_MESSAGE_LEN + 1];
        assert!(claim_digest(&data_root, &kp.pub_key, &long).is_err());
    }

    #[test]
    fn mismatched_keypair_rejected_on_sign() {
        let data_root = [5u8; 32];
        let kp = schnorr_keygen();
        let other = schnorr_keygen();
        let err = sign_claim_with(&data_root, &other.pub_key, b"m", &kp, &mut rand_core::OsRng)
            .expect_err("expect mismatch");
        match err {
            CryptoError::ClaimSigningKeyMismatch => {}
            e => panic!("unexpected err: {e:?}"),
        }
    }

    #[test]
    fn mfcl_wire_len_bounds() {
        assert_eq!(MFCL_MIN_WIRE_LEN, 134);
        assert_eq!(MFCL_MAX_WIRE_LEN, 262);
    }

    #[test]
    fn encode_decode_authorship_claim_round_trip() {
        let kp = schnorr_keygen();
        let data_root = [0x11u8; 32];
        let msg = b"byline";
        let sig = sign_claim_with(&data_root, &kp.pub_key, msg, &kp, &mut rand_core::OsRng)
            .expect("sign");
        let claim = AuthorshipClaim {
            wire_version: MFCL_WIRE_VERSION,
            data_root,
            claim_pubkey: kp.pub_key,
            message: msg.to_vec(),
            sig,
        };
        let wire = encode_authorship_claim(&claim).expect("encode");
        assert_eq!(
            wire.len(),
            MFCL_HEADER_LEN + msg.len() + SCHNORR_SIGNATURE_BYTES
        );
        let got = decode_authorship_claim(&wire).expect("decode");
        assert_eq!(got, claim);
        assert!(
            verify_claim(&got.data_root, &got.claim_pubkey, &got.message, &got.sig).expect("v")
        );
    }

    #[test]
    fn encode_decode_empty_message_is_min_wire() {
        let kp = schnorr_keygen();
        let data_root = [0u8; 32];
        let sig = sign_claim_with(&data_root, &kp.pub_key, &[], &kp, &mut rand_core::OsRng)
            .expect("sign");
        let claim = AuthorshipClaim {
            wire_version: MFCL_WIRE_VERSION,
            data_root,
            claim_pubkey: kp.pub_key,
            message: Vec::new(),
            sig,
        };
        let wire = encode_authorship_claim(&claim).expect("encode");
        assert_eq!(wire.len(), MFCL_MIN_WIRE_LEN);
        assert_eq!(decode_authorship_claim(&wire).expect("decode"), claim);
    }

    #[test]
    fn decode_wrong_magic() {
        let mut b = vec![0u8; MFCL_MIN_WIRE_LEN];
        b[0..4].copy_from_slice(b"XXXX");
        assert_eq!(
            decode_authorship_claim(&b),
            Err(AuthorshipClaimDecodeError::WrongMagic)
        );
    }

    #[test]
    fn decode_unknown_version() {
        let mut b = vec![0u8; MFCL_MIN_WIRE_LEN];
        b[0..4].copy_from_slice(MFCL_MAGIC);
        b[4] = 99;
        assert_eq!(
            decode_authorship_claim(&b),
            Err(AuthorshipClaimDecodeError::UnknownVersion(99))
        );
    }

    #[test]
    fn decode_trailing_bytes_rejected() {
        let kp = schnorr_keygen();
        let data_root = [7u8; 32];
        let sig = sign_claim_with(&data_root, &kp.pub_key, b"x", &kp, &mut rand_core::OsRng)
            .expect("sign");
        let claim = AuthorshipClaim {
            wire_version: MFCL_WIRE_VERSION,
            data_root,
            claim_pubkey: kp.pub_key,
            message: b"x".to_vec(),
            sig,
        };
        let mut wire = encode_authorship_claim(&claim).expect("encode");
        wire.push(0);
        assert_eq!(
            decode_authorship_claim(&wire),
            Err(AuthorshipClaimDecodeError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn encode_rejects_bad_wire_version() {
        let kp = schnorr_keygen();
        let claim = AuthorshipClaim {
            wire_version: 2,
            data_root: [1u8; 32],
            claim_pubkey: kp.pub_key,
            message: vec![],
            sig: sign_claim_with(&[1u8; 32], &kp.pub_key, &[], &kp, &mut rand_core::OsRng)
                .expect("s"),
        };
        assert!(matches!(
            encode_authorship_claim(&claim),
            Err(CryptoError::AuthorshipClaimBadWireVersion(2))
        ));
    }
}
