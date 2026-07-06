//! Optional authorship claims (M2.2.x).
//!
//! A claim binds a **claiming** Schnorr public key and a short user message to
//! a storage **data_root** (32-byte Merkle root of chunk hashes) using a domain-separated digest and
//! the protocol's raw Schnorr construction ([`crate::schnorr`]). This is
//! intentionally **not** ring-signed: the pubkey is public by design.
//!
//! MFCL wire **v2** adds an optional-on-wire `commit_hash`: all-zero means an
//! unbound bulletin-board attestation (v1 semantics); non-zero requires the
//! chain to anchor that storage commitment with a matching `data_root`.
//!
//! See [`docs/AUTHORSHIP.md`](../../docs/AUTHORSHIP.md) for the full protocol.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use thiserror::Error;

use crate::domain::{AUTHORSHIP_CLAIM_DIGEST, AUTHORSHIP_CLAIM_DIGEST_V2};
use crate::hash::{dhash, hash_to_scalar};
use crate::point::generator_g;
use crate::schnorr::{
    decode_schnorr_signature, encode_schnorr_signature, schnorr_sign_with, schnorr_verify,
    SchnorrKeypair, SchnorrSignature, SCHNORR_SIGNATURE_BYTES,
};
use crate::{CryptoError, Result};

/// Domain tag for [`derive_claiming_keypair`] — the **only** sanctioned
/// seed → claiming-key path (F5:P10).
///
/// This tag is deliberately disjoint from every financial-key derivation
/// domain (`MFW_SEED_VIEW_V1`, `MFW_SEED_SPEND_V1`,
/// `MFN-1/stealth-wallet/*`), so a claiming key derived from a wallet
/// seed is computationally independent of the wallet's view/spend keys:
/// publishing the claim pubkey can never link back to financial activity,
/// and reusing the financial seed for claims is structurally impossible
/// rather than merely discouraged (`AUTHORSHIP.md`).
pub const CLAIMING_KEY_DERIVE_TAG: &[u8] = b"MFW_SEED_CLAIM_V1";

/// Derive the canonical **claiming** Schnorr keypair from a 32-byte
/// wallet seed (F5:P10).
///
/// Hash-derives the private scalar under [`CLAIMING_KEY_DERIVE_TAG`],
/// with the standard zero → one pathological-recovery rule so the
/// function is total. All reference frontends (wallet, CLI, WASM) must
/// funnel through this function; deriving a claiming key from view/spend
/// material directly is a firewall violation.
#[must_use]
pub fn derive_claiming_keypair(seed: &[u8; 32]) -> SchnorrKeypair {
    let s = hash_to_scalar(&[CLAIMING_KEY_DERIVE_TAG, seed]);
    let priv_key = if s == curve25519_dalek::scalar::Scalar::ZERO {
        curve25519_dalek::scalar::Scalar::ONE
    } else {
        s
    };
    SchnorrKeypair {
        priv_key,
        pub_key: generator_g() * priv_key,
    }
}

/// Maximum opaque message length for a single claim (bytes).
pub const MAX_CLAIM_MESSAGE_LEN: usize = 256;

/// Maximum number of well-formed `MFCL` claim blobs allowed per transaction
/// `extra` field (consensus-enforced when wired in `mfn-consensus`).
pub const MAX_CLAIMS_PER_TX: usize = 4;

/// Magic prefix for one authorship claim on the wire (`MFCL`).
pub const MFCL_MAGIC: &[u8; 4] = b"MFCL";

/// MFCL wire version 1 (no `commit_hash` field).
pub const MFCL_WIRE_VERSION_V1: u8 = 1;

/// MFCL wire version 2 (`commit_hash` present; all-zero = unbound).
pub const MFCL_WIRE_VERSION_V2: u8 = 2;

/// Default wire version for newly encoded claims ([`MFCL_WIRE_VERSION_V2`]).
pub const MFCL_WIRE_VERSION: u8 = MFCL_WIRE_VERSION_V2;

/// `commit_hash` sentinel: claim is not bound to a specific on-chain upload.
pub const UNBOUND_COMMIT_HASH: [u8; 32] = [0u8; 32];

/// MFCL v1 fixed header: magic ‖ version ‖ `data_root` ‖ `claim_pubkey` ‖ `message_len`.
pub const MFCL_V1_HEADER_LEN: usize = 4 + 1 + 32 + 32 + 1;

/// MFCL v2 fixed header: v1 fields plus `commit_hash`.
pub const MFCL_V2_HEADER_LEN: usize = MFCL_V1_HEADER_LEN + 32;

/// Legacy alias (v1 header length).
pub const MFCL_HEADER_LEN: usize = MFCL_V1_HEADER_LEN;

/// Minimum MFCL v1 frame size (empty message + signature).
pub const MFCL_V1_MIN_WIRE_LEN: usize = MFCL_V1_HEADER_LEN + SCHNORR_SIGNATURE_BYTES;

/// Minimum MFCL v2 frame size (empty message + signature).
pub const MFCL_V2_MIN_WIRE_LEN: usize = MFCL_V2_HEADER_LEN + SCHNORR_SIGNATURE_BYTES;

/// Smallest valid frame (v1).
pub const MFCL_MIN_WIRE_LEN: usize = MFCL_V1_MIN_WIRE_LEN;

/// Maximum MFCL v1 frame size.
pub const MFCL_V1_MAX_WIRE_LEN: usize =
    MFCL_V1_HEADER_LEN + MAX_CLAIM_MESSAGE_LEN + SCHNORR_SIGNATURE_BYTES;

/// Maximum MFCL v2 frame size.
pub const MFCL_V2_MAX_WIRE_LEN: usize =
    MFCL_V2_HEADER_LEN + MAX_CLAIM_MESSAGE_LEN + SCHNORR_SIGNATURE_BYTES;

/// Legacy alias (v1 max).
pub const MFCL_MAX_WIRE_LEN: usize = MFCL_V1_MAX_WIRE_LEN;

/// One decoded authorship claim (`MFCL` wire). Signature is **not** verified by [`decode_authorship_claim`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorshipClaim {
    /// Wire version ([`MFCL_WIRE_VERSION_V1`] or [`MFCL_WIRE_VERSION_V2`]).
    pub wire_version: u8,
    /// Content-addressed storage root this claim refers to.
    pub data_root: [u8; 32],
    /// Storage commitment hash binding (v2 only on wire; zero for v1 / unbound v2).
    pub commit_hash: [u8; 32],
    /// Public key whose owner signed [`Self::sig`].
    pub claim_pubkey: EdwardsPoint,
    /// Opaque user message (≤ [`MAX_CLAIM_MESSAGE_LEN`] bytes).
    pub message: Vec<u8>,
    /// Schnorr signature over [`claim_digest_for`](crate::authorship::claim_digest_for).
    pub sig: SchnorrSignature,
}

/// Errors from [`decode_authorship_claim`] / [`mfcl_frame_wire_len`].
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
    /// v1 wire must not carry a non-zero `commit_hash` when re-encoded (internal).
    #[error("MFCL v1 cannot encode non-zero commit_hash")]
    V1CommitHashNonZero,
}

fn mfcl_header_len(wire_version: u8) -> core::result::Result<usize, AuthorshipClaimDecodeError> {
    match wire_version {
        MFCL_WIRE_VERSION_V1 => Ok(MFCL_V1_HEADER_LEN),
        MFCL_WIRE_VERSION_V2 => Ok(MFCL_V2_HEADER_LEN),
        v => Err(AuthorshipClaimDecodeError::UnknownVersion(v)),
    }
}

/// Total byte length of one `MFCL` frame starting at `buf[0]` (magic must be `MFCL`).
pub fn mfcl_frame_wire_len(buf: &[u8]) -> core::result::Result<usize, AuthorshipClaimDecodeError> {
    if buf.len() < 5 {
        return Err(AuthorshipClaimDecodeError::Truncated {
            need_at_least: 5,
            got: buf.len(),
        });
    }
    if buf[..4] != MFCL_MAGIC[..] {
        return Err(AuthorshipClaimDecodeError::WrongMagic);
    }
    let wire_version = buf[4];
    let header_len = mfcl_header_len(wire_version)?;
    if buf.len() < header_len {
        return Err(AuthorshipClaimDecodeError::Truncated {
            need_at_least: header_len,
            got: buf.len(),
        });
    }
    let msg_len_off = match wire_version {
        MFCL_WIRE_VERSION_V1 => 69,
        MFCL_WIRE_VERSION_V2 => 101,
        v => return Err(AuthorshipClaimDecodeError::UnknownVersion(v)),
    };
    let msg_len = buf[msg_len_off] as usize;
    if msg_len > MAX_CLAIM_MESSAGE_LEN {
        return Err(AuthorshipClaimDecodeError::MessageTooLong {
            got: msg_len,
            max: MAX_CLAIM_MESSAGE_LEN,
        });
    }
    Ok(header_len + msg_len + SCHNORR_SIGNATURE_BYTES)
}

/// Encode [`AuthorshipClaim`] as canonical `MFCL` bytes.
pub fn encode_authorship_claim(claim: &AuthorshipClaim) -> Result<Vec<u8>> {
    if claim.message.len() > MAX_CLAIM_MESSAGE_LEN {
        return Err(CryptoError::InvalidLength {
            expected: MAX_CLAIM_MESSAGE_LEN,
            got: claim.message.len(),
        });
    }
    match claim.wire_version {
        MFCL_WIRE_VERSION_V1 => {
            if claim.commit_hash != UNBOUND_COMMIT_HASH {
                return Err(CryptoError::AuthorshipClaimBadWireVersion(
                    claim.wire_version,
                ));
            }
            let mut out = Vec::with_capacity(
                MFCL_V1_HEADER_LEN + claim.message.len() + SCHNORR_SIGNATURE_BYTES,
            );
            out.extend_from_slice(MFCL_MAGIC);
            out.push(MFCL_WIRE_VERSION_V1);
            out.extend_from_slice(&claim.data_root);
            out.extend_from_slice(&claim.claim_pubkey.compress().to_bytes());
            out.push(claim.message.len() as u8);
            out.extend_from_slice(&claim.message);
            out.extend_from_slice(&encode_schnorr_signature(&claim.sig));
            Ok(out)
        }
        MFCL_WIRE_VERSION_V2 => {
            let mut out = Vec::with_capacity(
                MFCL_V2_HEADER_LEN + claim.message.len() + SCHNORR_SIGNATURE_BYTES,
            );
            out.extend_from_slice(MFCL_MAGIC);
            out.push(MFCL_WIRE_VERSION_V2);
            out.extend_from_slice(&claim.data_root);
            out.extend_from_slice(&claim.commit_hash);
            out.extend_from_slice(&claim.claim_pubkey.compress().to_bytes());
            out.push(claim.message.len() as u8);
            out.extend_from_slice(&claim.message);
            out.extend_from_slice(&encode_schnorr_signature(&claim.sig));
            Ok(out)
        }
        v => Err(CryptoError::AuthorshipClaimBadWireVersion(v)),
    }
}

/// Decode a single strict `MFCL` frame from `buf` (no trailing bytes allowed).
pub fn decode_authorship_claim(
    buf: &[u8],
) -> core::result::Result<AuthorshipClaim, AuthorshipClaimDecodeError> {
    let total = mfcl_frame_wire_len(buf)?;
    if buf.len() > total {
        return Err(AuthorshipClaimDecodeError::TrailingBytes {
            remaining: buf.len() - total,
        });
    }
    let wire_version = buf[4];
    let mut data_root = [0u8; 32];
    data_root.copy_from_slice(&buf[5..37]);
    let (commit_hash, pk_off) = match wire_version {
        MFCL_WIRE_VERSION_V1 => ([0u8; 32], 37),
        MFCL_WIRE_VERSION_V2 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[37..69]);
            (h, 69)
        }
        v => return Err(AuthorshipClaimDecodeError::UnknownVersion(v)),
    };
    let mut pk_b = [0u8; 32];
    pk_b.copy_from_slice(&buf[pk_off..pk_off + 32]);
    let claim_pubkey = CompressedEdwardsY(pk_b)
        .decompress()
        .ok_or(AuthorshipClaimDecodeError::InvalidClaimPubkey)?;
    let msg_len_off = pk_off + 32;
    let msg_len = buf[msg_len_off] as usize;
    let msg = buf[msg_len_off + 1..msg_len_off + 1 + msg_len].to_vec();
    let sig_off = msg_len_off + 1 + msg_len;
    let sig_slice: &[u8; SCHNORR_SIGNATURE_BYTES] = buf[sig_off..sig_off + SCHNORR_SIGNATURE_BYTES]
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
        commit_hash,
        claim_pubkey,
        message: msg,
        sig,
    })
}

/// Domain-separated digest for the fields in `claim` (version-aware).
pub fn claim_digest_for(claim: &AuthorshipClaim) -> Result<[u8; 32]> {
    claim_digest(
        claim.wire_version,
        &claim.data_root,
        &claim.commit_hash,
        &claim.claim_pubkey,
        &claim.message,
    )
}

/// Domain-separated digest signed by [`sign_claim`] / verified by [`verify_claim`].
pub fn claim_digest(
    wire_version: u8,
    data_root: &[u8; 32],
    commit_hash: &[u8; 32],
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
    match wire_version {
        MFCL_WIRE_VERSION_V1 => {
            if *commit_hash != UNBOUND_COMMIT_HASH {
                return Err(CryptoError::AuthorshipClaimBadWireVersion(wire_version));
            }
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
        MFCL_WIRE_VERSION_V2 => Ok(dhash(
            AUTHORSHIP_CLAIM_DIGEST_V2,
            &[
                data_root.as_slice(),
                commit_hash.as_slice(),
                pk.as_slice(),
                len_b.as_slice(),
                message,
            ],
        )),
        v => Err(CryptoError::AuthorshipClaimBadWireVersion(v)),
    }
}

/// Build and sign a claim (default wire version v2).
pub fn build_signed_claim(
    data_root: [u8; 32],
    commit_hash: [u8; 32],
    message: &[u8],
    kp: &SchnorrKeypair,
) -> Result<AuthorshipClaim> {
    build_signed_claim_version(
        MFCL_WIRE_VERSION_V2,
        data_root,
        commit_hash,
        message,
        kp,
        &mut rand_core::OsRng,
    )
}

/// Build and sign with explicit wire version (tests / legacy v1).
pub fn build_signed_claim_version<R: rand_core::CryptoRngCore + ?Sized>(
    wire_version: u8,
    data_root: [u8; 32],
    commit_hash: [u8; 32],
    message: &[u8],
    kp: &SchnorrKeypair,
    rng: &mut R,
) -> Result<AuthorshipClaim> {
    let claim_pubkey = kp.pub_key;
    let sig = sign_claim_with(
        wire_version,
        &data_root,
        &commit_hash,
        &claim_pubkey,
        message,
        kp,
        rng,
    )?;
    Ok(AuthorshipClaim {
        wire_version,
        data_root,
        commit_hash,
        claim_pubkey,
        message: message.to_vec(),
        sig,
    })
}

/// Sign a claim digest with the claiming keypair (must match `claim_pubkey`).
pub fn sign_claim(
    wire_version: u8,
    data_root: &[u8; 32],
    commit_hash: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
    kp: &SchnorrKeypair,
) -> Result<SchnorrSignature> {
    sign_claim_with(
        wire_version,
        data_root,
        commit_hash,
        claim_pubkey,
        message,
        kp,
        &mut rand_core::OsRng,
    )
}

/// Sign with a deterministic RNG (tests only).
pub fn sign_claim_with<R: rand_core::CryptoRngCore + ?Sized>(
    wire_version: u8,
    data_root: &[u8; 32],
    commit_hash: &[u8; 32],
    claim_pubkey: &EdwardsPoint,
    message: &[u8],
    kp: &SchnorrKeypair,
    rng: &mut R,
) -> Result<SchnorrSignature> {
    if kp.pub_key != *claim_pubkey {
        return Err(CryptoError::ClaimSigningKeyMismatch);
    }
    let digest = claim_digest(wire_version, data_root, commit_hash, claim_pubkey, message)?;
    Ok(schnorr_sign_with(&digest, kp, rng))
}

/// Verify a claim signature.
pub fn verify_claim(claim: &AuthorshipClaim) -> Result<bool> {
    let digest = claim_digest(
        claim.wire_version,
        &claim.data_root,
        &claim.commit_hash,
        &claim.claim_pubkey,
        &claim.message,
    )?;
    Ok(schnorr_verify(&digest, &claim.sig, &claim.claim_pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::schnorr_keygen;

    #[test]
    fn claim_digest_v1_golden_vector() {
        use crate::point::generator_g;
        use crate::scalar::bytes_to_scalar;
        let mut sk = [0u8; 32];
        sk[0] = 9;
        let priv_key = bytes_to_scalar(&sk);
        let pub_key = generator_g() * priv_key;
        let data_root = [0u8; 32];
        let d = claim_digest(
            MFCL_WIRE_VERSION_V1,
            &data_root,
            &UNBOUND_COMMIT_HASH,
            &pub_key,
            &[],
        )
        .expect("digest");
        assert_eq!(
            hex::encode(d),
            "81b2fb31ec05b1ddee5488b3e4d999b7809f02a16f58e006de503fd7c01980df"
        );
    }

    #[test]
    fn claim_digest_v2_differs_with_commit_hash() {
        let data_root = [1u8; 32];
        let kp = schnorr_keygen();
        let a = claim_digest(
            MFCL_WIRE_VERSION_V2,
            &data_root,
            &UNBOUND_COMMIT_HASH,
            &kp.pub_key,
            b"x",
        )
        .expect("d");
        let h = [2u8; 32];
        let b = claim_digest(MFCL_WIRE_VERSION_V2, &data_root, &h, &kp.pub_key, b"x").expect("d");
        assert_ne!(a, b);
    }

    #[test]
    fn sign_verify_round_trip_v2() {
        let data_root = [1u8; 32];
        let kp = schnorr_keygen();
        let claim = build_signed_claim_version(
            MFCL_WIRE_VERSION_V2,
            data_root,
            UNBOUND_COMMIT_HASH,
            b"hello-permaweb",
            &kp,
            &mut rand_core::OsRng,
        )
        .expect("build");
        assert!(verify_claim(&claim).expect("verify"));
    }

    #[test]
    fn wrong_message_fails() {
        let data_root = [2u8; 32];
        let kp = schnorr_keygen();
        let mut claim = build_signed_claim_version(
            MFCL_WIRE_VERSION_V2,
            data_root,
            UNBOUND_COMMIT_HASH,
            b"a",
            &kp,
            &mut rand_core::OsRng,
        )
        .expect("build");
        claim.message = b"b".to_vec();
        assert!(!verify_claim(&claim).expect("verify"));
    }

    #[test]
    fn mfcl_v2_wire_len_bounds() {
        assert_eq!(MFCL_V2_MIN_WIRE_LEN, 166);
        assert_eq!(MFCL_V2_MAX_WIRE_LEN, 422);
    }

    #[test]
    fn encode_decode_v1_round_trip() {
        let kp = schnorr_keygen();
        let data_root = [0x11u8; 32];
        let claim = build_signed_claim_version(
            MFCL_WIRE_VERSION_V1,
            data_root,
            UNBOUND_COMMIT_HASH,
            b"byline",
            &kp,
            &mut rand_core::OsRng,
        )
        .expect("build");
        let wire = encode_authorship_claim(&claim).expect("encode");
        assert_eq!(wire.len(), MFCL_V1_HEADER_LEN + 6 + SCHNORR_SIGNATURE_BYTES);
        let got = decode_authorship_claim(&wire).expect("decode");
        assert_eq!(got, claim);
        assert!(verify_claim(&got).expect("v"));
    }

    #[test]
    fn encode_decode_v2_round_trip() {
        let kp = schnorr_keygen();
        let data_root = [0x11u8; 32];
        let commit_hash = [0x22u8; 32];
        let claim = build_signed_claim_version(
            MFCL_WIRE_VERSION_V2,
            data_root,
            commit_hash,
            b"byline",
            &kp,
            &mut rand_core::OsRng,
        )
        .expect("build");
        let wire = encode_authorship_claim(&claim).expect("encode");
        let got = decode_authorship_claim(&wire).expect("decode");
        assert_eq!(got, claim);
        assert!(verify_claim(&got).expect("v"));
    }

    #[test]
    fn mfcl_frame_wire_len_matches_decode() {
        let kp = schnorr_keygen();
        let claim = build_signed_claim([3u8; 32], [4u8; 32], b"z", &kp).expect("build");
        let wire = encode_authorship_claim(&claim).expect("enc");
        assert_eq!(mfcl_frame_wire_len(&wire).expect("len"), wire.len());
    }

    #[test]
    fn claiming_key_domain_is_disjoint_from_stealth_seed_domains() {
        // F5:P10 — the same 32-byte seed must yield a claiming key that
        // is independent of every financial key derived from it. If any
        // derivation tag ever collapses into another, the claim pubkey
        // (public by design) would link to spendable material.
        use crate::stealth::stealth_wallet_from_seed;
        for byte in [0u8, 1, 7, 42, 0xff] {
            let seed = [byte; 32];
            let claim = derive_claiming_keypair(&seed);
            let stealth = stealth_wallet_from_seed(&seed);
            assert_ne!(
                claim.pub_key.compress(),
                stealth.view_pub.compress(),
                "claiming key equals view key for seed byte {byte}"
            );
            assert_ne!(
                claim.pub_key.compress(),
                stealth.spend_pub.compress(),
                "claiming key equals spend key for seed byte {byte}"
            );
        }
    }

    #[test]
    fn derive_claiming_keypair_is_deterministic_and_seed_sensitive() {
        let a = derive_claiming_keypair(&[7u8; 32]);
        let b = derive_claiming_keypair(&[7u8; 32]);
        let c = derive_claiming_keypair(&[8u8; 32]);
        assert_eq!(a.pub_key.compress(), b.pub_key.compress());
        assert_ne!(a.pub_key.compress(), c.pub_key.compress());
        assert_eq!(generator_g() * a.priv_key, a.pub_key);
    }

    #[test]
    fn decode_unknown_version() {
        let mut b = vec![0u8; MFCL_V2_MIN_WIRE_LEN];
        b[0..4].copy_from_slice(MFCL_MAGIC);
        b[4] = 99;
        assert_eq!(
            decode_authorship_claim(&b),
            Err(AuthorshipClaimDecodeError::UnknownVersion(99))
        );
    }
}
