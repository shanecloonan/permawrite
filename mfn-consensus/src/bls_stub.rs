//! Wire-compatible BLS types without `bls12_381_plus` (for `wasm32-unknown-unknown`).
#![allow(dead_code)]
//!
//! Used when the `bls` feature is disabled: block/tx codecs and wallet scan/sign
//! can decode BLS-shaped fields; cryptographic verify/sign is not available.

use core::fmt;

/// Compressed G1 public key bytes (48).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlsPublicKey(pub [u8; 48]);

/// Opaque secret key placeholder (not used on WASM).
#[derive(Clone, ZeroizeOnDrop)]
pub struct BlsSecretKey([u8; 32]);

use zeroize::ZeroizeOnDrop;

/// Compressed G2 signature bytes (96).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlsSignature(pub [u8; 96]);

/// Keypair placeholder for tests gated behind `bls`.
#[derive(Clone)]
pub struct BlsKeypair {
    /// Public key.
    pub pk: BlsPublicKey,
    /// Secret key.
    pub sk: BlsSecretKey,
}

/// Compressed signature size on the wire.
pub const BLS_SIGNATURE_BYTES: usize = 96;
/// Compressed public key size on the wire.
pub const BLS_PUBLIC_KEY_BYTES: usize = 48;

/// Stub BLS error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlsError {
    /// Wrong byte length.
    #[error("invalid bls length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Point decompression (stub never succeeds for invalid points).
    #[error("invalid bls point")]
    InvalidPoint,
}

/// Stub result type.
pub type BlsResult<T> = Result<T, BlsError>;

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPublicKey({})", hex::encode(self.0))
    }
}

impl fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlsSecretKey([redacted])")
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSignature({}…)", hex::encode(&self.0[..8]))
    }
}

/// Encode a public key to 48 bytes.
#[must_use]
pub fn encode_public_key(pk: &BlsPublicKey) -> [u8; 48] {
    pk.0
}

/// Decode 48-byte compressed public key (length check only).
pub fn decode_public_key(b: &[u8]) -> BlsResult<BlsPublicKey> {
    if b.len() != BLS_PUBLIC_KEY_BYTES {
        return Err(BlsError::InvalidLength {
            expected: BLS_PUBLIC_KEY_BYTES,
            got: b.len(),
        });
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(b);
    Ok(BlsPublicKey(out))
}

/// Encode a signature to 96 bytes.
#[must_use]
pub fn encode_signature(sig: &BlsSignature) -> [u8; 96] {
    sig.0
}

/// Decode 96-byte signature (length check only).
pub fn decode_signature(b: &[u8]) -> BlsResult<BlsSignature> {
    if b.len() != BLS_SIGNATURE_BYTES {
        return Err(BlsError::InvalidLength {
            expected: BLS_SIGNATURE_BYTES,
            got: b.len(),
        });
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(b);
    Ok(BlsSignature(out))
}

/// Stub sign (unavailable without `bls` feature).
pub fn bls_sign(_msg: &[u8], _sk: &BlsSecretKey) -> BlsSignature {
    BlsSignature([0u8; 96])
}

/// Stub verify (always false without real BLS).
#[must_use]
pub fn bls_verify(_sig: &BlsSignature, _msg: &[u8], _pk: &BlsPublicKey) -> bool {
    false
}

/// Stub keygen for compile-only call sites in tests.
pub fn bls_keygen_from_seed(_seed: &[u8; 32]) -> BlsKeypair {
    BlsKeypair {
        pk: BlsPublicKey([0u8; 48]),
        sk: BlsSecretKey([0u8; 32]),
    }
}

/// Committee vote placeholder (engine-only).
#[derive(Clone, Debug)]
pub struct CommitteeVote {
    /// Validator index.
    pub validator_index: u32,
    /// Signature bytes.
    pub signature: BlsSignature,
}

/// Committee aggregate placeholder.
#[derive(Clone, Debug)]
pub struct CommitteeAggregate {
    /// Participating validator bitmap.
    pub bitmap: Vec<u8>,
    /// Aggregated signature.
    pub signature: BlsSignature,
}

/// Stub aggregate (unavailable without `bls`).
pub fn aggregate_committee_votes(
    _votes: &[CommitteeVote],
    _n_validators: usize,
) -> BlsResult<CommitteeAggregate> {
    Err(BlsError::InvalidPoint)
}

/// Stub aggregate verify.
#[must_use]
pub fn verify_committee_aggregate(
    _agg: &CommitteeAggregate,
    _msg: &[u8],
    _validator_pks: &[BlsPublicKey],
) -> bool {
    false
}
