//! Slashable evidence — fault attribution at the consensus layer.
//!
//! Equivocation (two conflicting BLS signatures at the same slot) and,
//! from header v3 onward, invalid-block fraud proofs that zero producer
//! stake when a block body is provably wrong.
//!
//! From [`HEADER_VERSION_EQUIVOCATION_BIND`] (**B-330**) equivocation
//! evidence is the *bound* form: it carries both header signing preimages,
//! so the verifier can see that the two signatures were for one height and
//! one slot. Below that version the legacy form carries only the two signed
//! hashes and cannot tell two honest votes at different heights from a
//! double-sign.

use crate::block::{
    header_signing_fields, header_signing_hash_from_bytes, HEADER_VERSION,
    HEADER_VERSION_EQUIVOCATION_BIND, HEADER_VERSION_FRAUD_SLASH,
};
use crate::bls::{bls_verify, decode_signature, encode_signature, BlsSignature};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::SLASHING_LEAF;
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;

use crate::consensus::Validator;

/// Tagged slash wire marker (header v3+). Avoids ambiguity with legacy
/// equivocation blobs whose first byte is the low byte of `height`.
pub const SLASH_TAGGED_WIRE_MAGIC: u8 = 0xFE;

/// Kind tag: BLS equivocation (legacy body layout).
pub const SLASH_KIND_EQUIVOCATION: u8 = 0;
/// Kind tag: interactive fraud proof against a contested block producer.
pub const SLASH_KIND_INVALID_BLOCK: u8 = 1;
/// Kind tag: BLS equivocation with both header signing preimages (header
/// v8+, **B-330**).
pub const SLASH_KIND_BOUND_EQUIVOCATION: u8 = 2;

/// Largest header signing preimage a bound equivocation blob may carry.
///
/// A [`crate::block::header_signing_bytes`] preimage is 305 or 337 bytes
/// today. The cap keeps a hostile blob from making the decoder allocate
/// for a length it will reject anyway.
pub const MAX_EQUIVOCATION_PREIMAGE_BYTES: usize = 1024;

/// On-chain evidence of validator equivocation.
#[derive(Clone, Debug)]
pub struct EquivocationEvidence {
    /// Block height at which equivocation occurred.
    pub height: u32,
    /// Slot number within the epoch.
    pub slot: u32,
    /// Index of the offending validator in the canonical set.
    pub voter_index: u32,
    /// Hash of the first header the validator signed.
    pub header_hash_a: [u8; 32],
    /// Signature over `header_hash_a`.
    pub sig_a: BlsSignature,
    /// Hash of the second header (must differ from A).
    pub header_hash_b: [u8; 32],
    /// Signature over `header_hash_b`.
    pub sig_b: BlsSignature,
}

/// On-chain evidence of validator equivocation that binds height and slot
/// (header v8+, **B-330**).
///
/// Each preimage is the [`crate::block::header_signing_bytes`] of one header
/// the validator voted for. The verifier recomputes both signed hashes from
/// the preimages, so a signature here can only count against a header whose
/// height and slot the verifier can read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundEquivocationEvidence {
    /// Block height both votes were for.
    pub height: u32,
    /// Slot both votes were for.
    pub slot: u32,
    /// Index of the offending validator in the canonical set.
    pub voter_index: u32,
    /// Header signing preimage of the first header the validator signed.
    pub signing_a: Vec<u8>,
    /// Signature over `header_signing_hash_from_bytes(signing_a)`.
    pub sig_a: BlsSignature,
    /// Header signing preimage of the second header (must hash differently).
    pub signing_b: Vec<u8>,
    /// Signature over `header_signing_hash_from_bytes(signing_b)`.
    pub sig_b: BlsSignature,
}

impl BoundEquivocationEvidence {
    /// The committee-vote message the first signature is checked against.
    #[must_use]
    pub fn header_hash_a(&self) -> [u8; 32] {
        header_signing_hash_from_bytes(&self.signing_a)
    }

    /// The committee-vote message the second signature is checked against.
    #[must_use]
    pub fn header_hash_b(&self) -> [u8; 32] {
        header_signing_hash_from_bytes(&self.signing_b)
    }
}

/// On-chain evidence that a block producer included an invalid body.
#[derive(Clone, Debug)]
pub struct InvalidBlockEvidence {
    /// Height of the contested block.
    pub height: u32,
    /// `block_id` of the contested header.
    pub block_id: [u8; 32],
    /// Producer validator index from `producer_proof`.
    pub producer_index: u32,
    /// Canonical interactive fraud proof bytes (`verify_interactive_fraud_proof`).
    pub fraud_proof_wire: Vec<u8>,
}

/// Tagged slash evidence carried in `Block::slashings`.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SlashEvidence {
    /// Two conflicting BLS-signed headers at the same slot (legacy form;
    /// accepted below [`HEADER_VERSION_EQUIVOCATION_BIND`]).
    Equivocation(EquivocationEvidence),
    /// Valid interactive fraud proof against a producer (header v3+).
    InvalidBlock(InvalidBlockEvidence),
    /// Two conflicting BLS-signed headers whose preimages prove one height
    /// and slot (header v8+).
    BoundEquivocation(BoundEquivocationEvidence),
}

impl SlashEvidence {
    /// Validator index to slash (equivocation voter or contested producer).
    #[must_use]
    pub fn offender_index(&self) -> u32 {
        match self {
            Self::Equivocation(e) => e.voter_index,
            Self::InvalidBlock(e) => e.producer_index,
            Self::BoundEquivocation(e) => e.voter_index,
        }
    }
}

/* ----------------------------------------------------------------------- *
 *  Equivocation encoding (legacy + tagged inner body)                      *
 * ----------------------------------------------------------------------- */

/// Encode [`EquivocationEvidence`] to its canonical bytes (no kind tag).
pub fn encode_evidence(e: &EquivocationEvidence) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(e.height);
    w.u32(e.slot);
    w.u32(e.voter_index);
    w.push(&e.header_hash_a);
    w.push(&encode_signature(&e.sig_a));
    w.push(&e.header_hash_b);
    w.push(&encode_signature(&e.sig_b));
    w.into_bytes()
}

/// Encode [`BoundEquivocationEvidence`] to its canonical bytes (no kind tag).
pub fn encode_bound_evidence(e: &BoundEquivocationEvidence) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(e.height);
    w.u32(e.slot);
    w.u32(e.voter_index);
    w.blob(&e.signing_a);
    w.push(&encode_signature(&e.sig_a));
    w.blob(&e.signing_b);
    w.push(&encode_signature(&e.sig_b));
    w.into_bytes()
}

fn encode_invalid_block_evidence(e: &InvalidBlockEvidence) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(e.height);
    w.push(&e.block_id);
    w.u32(e.producer_index);
    w.blob(&e.fraud_proof_wire);
    w.into_bytes()
}

/// Encode slash evidence for a chain at `header_version`.
#[must_use]
pub fn encode_slash_evidence(e: &SlashEvidence, header_version: u32) -> Vec<u8> {
    if header_version < HEADER_VERSION_FRAUD_SLASH {
        match e {
            SlashEvidence::Equivocation(ev) => encode_evidence(ev),
            SlashEvidence::InvalidBlock(_) | SlashEvidence::BoundEquivocation(_) => {
                // Unreachable on honest producers; emit empty blob guard.
                Vec::new()
            }
        }
    } else {
        let mut w = Writer::new();
        w.u8(SLASH_TAGGED_WIRE_MAGIC);
        match e {
            SlashEvidence::Equivocation(ev) => {
                w.u8(SLASH_KIND_EQUIVOCATION);
                w.push(&encode_evidence(ev));
            }
            SlashEvidence::InvalidBlock(ev) => {
                w.u8(SLASH_KIND_INVALID_BLOCK);
                w.push(&encode_invalid_block_evidence(ev));
            }
            SlashEvidence::BoundEquivocation(ev) => {
                w.u8(SLASH_KIND_BOUND_EQUIVOCATION);
                w.push(&encode_bound_evidence(ev));
            }
        }
        w.into_bytes()
    }
}

/// Decoding errors for slash evidence.
#[derive(Debug, thiserror::Error)]
pub enum SlashDecodeError {
    /// Underlying buffer too short or malformed.
    #[error(transparent)]
    Codec(#[from] mfn_crypto::CryptoError),
    /// One of the BLS signatures failed to decode.
    #[error(transparent)]
    Bls(#[from] crate::bls::BlsError),
    /// Unknown kind tag on a tagged slash blob.
    #[error("unknown slash kind tag {0}")]
    UnknownSlashKind(u8),
    /// Invalid-block evidence on a pre-v3 header chain.
    #[error(
        "invalid-block slash evidence requires header version >= {HEADER_VERSION_FRAUD_SLASH}"
    )]
    InvalidBlockOnLegacyVersion,
    /// Bound equivocation evidence on a chain below
    /// [`HEADER_VERSION_EQUIVOCATION_BIND`].
    #[error(
        "bound equivocation evidence requires header version >= {HEADER_VERSION_EQUIVOCATION_BIND}"
    )]
    BoundEquivocationOnLegacyVersion,
    /// A header signing preimage declared more than
    /// [`MAX_EQUIVOCATION_PREIMAGE_BYTES`] bytes.
    #[error("equivocation preimage of {got} bytes exceeds {MAX_EQUIVOCATION_PREIMAGE_BYTES}")]
    PreimageTooLong {
        /// Declared preimage length.
        got: usize,
    },
}

/// Decode bytes produced by [`encode_evidence`] (equivocation only).
pub fn decode_evidence(bytes: &[u8]) -> Result<EquivocationEvidence, SlashDecodeError> {
    let mut r = Reader::new(bytes);
    let height = r.u32()?;
    let slot = r.u32()?;
    let voter_index = r.u32()?;
    let header_hash_a_raw = r.bytes(32)?;
    let mut header_hash_a = [0u8; 32];
    header_hash_a.copy_from_slice(header_hash_a_raw);
    let sig_a = decode_signature(r.bytes(96)?)?;
    let header_hash_b_raw = r.bytes(32)?;
    let mut header_hash_b = [0u8; 32];
    header_hash_b.copy_from_slice(header_hash_b_raw);
    let sig_b = decode_signature(r.bytes(96)?)?;
    if !r.end() {
        return Err(SlashDecodeError::Codec(
            mfn_crypto::CryptoError::TrailingBytes {
                remaining: r.remaining(),
            },
        ));
    }
    Ok(EquivocationEvidence {
        height,
        slot,
        voter_index,
        header_hash_a,
        sig_a,
        header_hash_b,
        sig_b,
    })
}

/// `Reader::blob` already refuses a length past the unread bytes (G-1), so
/// the only allocation here is bounded by the blob the caller handed in;
/// the cap then rejects anything longer than a header preimage can be.
fn read_preimage<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], SlashDecodeError> {
    let preimage = r.blob()?;
    if preimage.len() > MAX_EQUIVOCATION_PREIMAGE_BYTES {
        return Err(SlashDecodeError::PreimageTooLong {
            got: preimage.len(),
        });
    }
    Ok(preimage)
}

/// Decode bytes produced by [`encode_bound_evidence`].
pub fn decode_bound_evidence(bytes: &[u8]) -> Result<BoundEquivocationEvidence, SlashDecodeError> {
    let mut r = Reader::new(bytes);
    let height = r.u32()?;
    let slot = r.u32()?;
    let voter_index = r.u32()?;
    let signing_a = read_preimage(&mut r)?.to_vec();
    let sig_a = decode_signature(r.bytes(96)?)?;
    let signing_b = read_preimage(&mut r)?.to_vec();
    let sig_b = decode_signature(r.bytes(96)?)?;
    if !r.end() {
        return Err(SlashDecodeError::Codec(
            mfn_crypto::CryptoError::TrailingBytes {
                remaining: r.remaining(),
            },
        ));
    }
    Ok(BoundEquivocationEvidence {
        height,
        slot,
        voter_index,
        signing_a,
        sig_a,
        signing_b,
        sig_b,
    })
}

fn decode_invalid_block_evidence(bytes: &[u8]) -> Result<InvalidBlockEvidence, SlashDecodeError> {
    let mut r = Reader::new(bytes);
    let height = r.u32()?;
    let block_id_raw = r.bytes(32)?;
    let mut block_id = [0u8; 32];
    block_id.copy_from_slice(block_id_raw);
    let producer_index = r.u32()?;
    let fraud_proof_wire = r.blob()?.to_vec();
    if !r.end() {
        return Err(SlashDecodeError::Codec(
            mfn_crypto::CryptoError::TrailingBytes {
                remaining: r.remaining(),
            },
        ));
    }
    Ok(InvalidBlockEvidence {
        height,
        block_id,
        producer_index,
        fraud_proof_wire,
    })
}

/// Decode slash evidence for a chain at `header_version`.
pub fn decode_slash_evidence(
    bytes: &[u8],
    header_version: u32,
) -> Result<SlashEvidence, SlashDecodeError> {
    if header_version < HEADER_VERSION_FRAUD_SLASH {
        return decode_evidence(bytes).map(SlashEvidence::Equivocation);
    }
    if bytes.first() == Some(&SLASH_TAGGED_WIRE_MAGIC) {
        let mut r = Reader::new(bytes);
        let _magic = r.u8()?;
        let kind = r.u8()?;
        let body = r.bytes(r.remaining())?;
        return match kind {
            SLASH_KIND_EQUIVOCATION => decode_evidence(body).map(SlashEvidence::Equivocation),
            SLASH_KIND_INVALID_BLOCK => {
                decode_invalid_block_evidence(body).map(SlashEvidence::InvalidBlock)
            }
            SLASH_KIND_BOUND_EQUIVOCATION => {
                if header_version < HEADER_VERSION_EQUIVOCATION_BIND {
                    return Err(SlashDecodeError::BoundEquivocationOnLegacyVersion);
                }
                decode_bound_evidence(body).map(SlashEvidence::BoundEquivocation)
            }
            other => Err(SlashDecodeError::UnknownSlashKind(other)),
        };
    }
    decode_evidence(bytes).map(SlashEvidence::Equivocation)
}

/* ----------------------------------------------------------------------- *
 *  Canonicalization                                                        *
 * ----------------------------------------------------------------------- */

/// Lexicographic-order canonical form for equivocation evidence.
pub fn canonicalize_equivocation(e: &EquivocationEvidence) -> EquivocationEvidence {
    if e.header_hash_a < e.header_hash_b {
        e.clone()
    } else {
        EquivocationEvidence {
            height: e.height,
            slot: e.slot,
            voter_index: e.voter_index,
            header_hash_a: e.header_hash_b,
            sig_a: e.sig_b,
            header_hash_b: e.header_hash_a,
            sig_b: e.sig_a,
        }
    }
}

/// Lexicographic-order (by signed hash) canonical form for bound evidence.
pub fn canonicalize_bound_equivocation(e: &BoundEquivocationEvidence) -> BoundEquivocationEvidence {
    if e.header_hash_a() < e.header_hash_b() {
        e.clone()
    } else {
        BoundEquivocationEvidence {
            height: e.height,
            slot: e.slot,
            voter_index: e.voter_index,
            signing_a: e.signing_b.clone(),
            sig_a: e.sig_b,
            signing_b: e.signing_a.clone(),
            sig_b: e.sig_a,
        }
    }
}

/// Canonicalize slash evidence for Merkle leaf hashing.
#[must_use]
pub fn canonicalize(e: &SlashEvidence) -> SlashEvidence {
    match e {
        SlashEvidence::Equivocation(ev) => {
            SlashEvidence::Equivocation(canonicalize_equivocation(ev))
        }
        SlashEvidence::InvalidBlock(ev) => SlashEvidence::InvalidBlock(ev.clone()),
        SlashEvidence::BoundEquivocation(ev) => {
            SlashEvidence::BoundEquivocation(canonicalize_bound_equivocation(ev))
        }
    }
}

/* ----------------------------------------------------------------------- *
 *  Merkle commitment (M2.0.1)                                              *
 * ----------------------------------------------------------------------- */

fn slash_leaf_bytes(e: &SlashEvidence, header_version: u32) -> Vec<u8> {
    if header_version < HEADER_VERSION_FRAUD_SLASH {
        match e {
            SlashEvidence::Equivocation(ev) => encode_evidence(&canonicalize_equivocation(ev)),
            SlashEvidence::InvalidBlock(_) | SlashEvidence::BoundEquivocation(_) => Vec::new(),
        }
    } else {
        encode_slash_evidence(e, header_version)
    }
}

/// 32-byte Merkle leaf hash for a single piece of slash evidence.
#[must_use]
pub fn slashing_leaf_hash(e: &SlashEvidence) -> [u8; 32] {
    slashing_leaf_hash_for_version(e, HEADER_VERSION)
}

/// Version-aware Merkle leaf hash.
#[must_use]
pub fn slashing_leaf_hash_for_version(e: &SlashEvidence, header_version: u32) -> [u8; 32] {
    let canon = canonicalize(e);
    dhash(SLASHING_LEAF, &[&slash_leaf_bytes(&canon, header_version)])
}

/// Merkle root over slash evidence (legacy v1 encoding).
#[must_use]
pub fn slashing_merkle_root(evidence: &[SlashEvidence]) -> [u8; 32] {
    slashing_merkle_root_for_version(evidence, HEADER_VERSION)
}

/// Merkle root over slash evidence at `header_version`.
#[must_use]
pub fn slashing_merkle_root_for_version(
    evidence: &[SlashEvidence],
    header_version: u32,
) -> [u8; 32] {
    if evidence.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = evidence
        .iter()
        .map(|e| slashing_leaf_hash_for_version(e, header_version))
        .collect();
    merkle_root_or_zero(&leaves)
}

/* ----------------------------------------------------------------------- *
 *  Verification                                                            *
 * ----------------------------------------------------------------------- */

/// Result of [`verify_equivocation_evidence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceCheck {
    /// All checks passed; the validator is slashable.
    Valid,
    /// `voter_index` outside the validator slice.
    IndexOutOfRange,
    /// Both header hashes were identical (no equivocation).
    HeadersIdentical,
    /// Validator already has zero stake (cannot be slashed again).
    AlreadySlashed,
    /// `sig_a` did not verify against `header_hash_a` under the validator's
    /// BLS pubkey.
    SigAInvalid,
    /// `sig_b` did not verify against `header_hash_b` under the validator's
    /// BLS pubkey.
    SigBInvalid,
    /// Legacy (unbound) equivocation evidence on a chain at or above
    /// [`HEADER_VERSION_EQUIVOCATION_BIND`]. Height and slot are unproven.
    UnboundOnBindingVersion,
    /// Bound equivocation evidence on a chain below
    /// [`HEADER_VERSION_EQUIVOCATION_BIND`].
    BoundOnLegacyVersion,
    /// A header signing preimage was not a well-formed
    /// [`crate::block::header_signing_bytes`] encoding.
    PreimageMalformed,
    /// The two preimages do not both name the evidence's height and slot,
    /// so the votes may be honest votes at different heights.
    HeightSlotMismatch,
}

impl EvidenceCheck {
    /// `true` iff the evidence verifies.
    #[inline]
    pub fn is_valid(&self) -> bool {
        matches!(self, EvidenceCheck::Valid)
    }
}

/// Result of invalid-block slash verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidBlockEvidenceCheck {
    /// All checks passed.
    Valid,
    /// `producer_index` outside the validator slice.
    IndexOutOfRange,
    /// Producer already has zero stake.
    AlreadySlashed,
    /// Interactive fraud proof did not verify.
    FraudProofInvalid,
    /// Fraud proof contested block does not match evidence fields.
    ContestedMismatch,
    /// Producer index in evidence does not match fraud proof attachment.
    ProducerIndexMismatch,
    /// Cannot slash in the same block height as the contested block.
    SameHeightSlash,
    /// Invalid-block slash on a pre-v3 header chain.
    LegacyHeaderVersion,
}

/// Unified slash rejection reason for `apply_block` errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashRejectReason {
    /// Equivocation verifier failure.
    Equivocation(EvidenceCheck),
    /// Invalid-block verifier failure.
    InvalidBlock(InvalidBlockEvidenceCheck),
}

/// Verify equivocation evidence against the validator set.
pub fn verify_equivocation_evidence(
    evidence: &EquivocationEvidence,
    validators: &[Validator],
) -> EvidenceCheck {
    let idx = evidence.voter_index as usize;
    if idx >= validators.len() {
        return EvidenceCheck::IndexOutOfRange;
    }
    if evidence.header_hash_a == evidence.header_hash_b {
        return EvidenceCheck::HeadersIdentical;
    }
    let v = &validators[idx];
    if v.stake == 0 {
        return EvidenceCheck::AlreadySlashed;
    }
    if !bls_verify(&evidence.sig_a, &evidence.header_hash_a, &v.bls_pk) {
        return EvidenceCheck::SigAInvalid;
    }
    if !bls_verify(&evidence.sig_b, &evidence.header_hash_b, &v.bls_pk) {
        return EvidenceCheck::SigBInvalid;
    }
    EvidenceCheck::Valid
}

/// Back-compat alias.
pub fn verify_evidence(evidence: &EquivocationEvidence, validators: &[Validator]) -> EvidenceCheck {
    verify_equivocation_evidence(evidence, validators)
}

/// Verify bound equivocation evidence against the validator set (**B-330**).
///
/// Both preimages must parse as header signing bytes, both must carry the
/// evidence's `height` and `slot`, their hashes must differ, and each
/// signature must verify over its recomputed hash. Height and slot are
/// checked before the signatures so the error names the attribution gap,
/// not a signature, when a prover submits two honest votes.
pub fn verify_bound_equivocation_evidence(
    evidence: &BoundEquivocationEvidence,
    validators: &[Validator],
) -> EvidenceCheck {
    let idx = evidence.voter_index as usize;
    if idx >= validators.len() {
        return EvidenceCheck::IndexOutOfRange;
    }
    let (Some(fields_a), Some(fields_b)) = (
        header_signing_fields(&evidence.signing_a),
        header_signing_fields(&evidence.signing_b),
    ) else {
        return EvidenceCheck::PreimageMalformed;
    };
    if fields_a.height != evidence.height
        || fields_b.height != evidence.height
        || fields_a.slot != evidence.slot
        || fields_b.slot != evidence.slot
    {
        return EvidenceCheck::HeightSlotMismatch;
    }
    let hash_a = evidence.header_hash_a();
    let hash_b = evidence.header_hash_b();
    if hash_a == hash_b {
        return EvidenceCheck::HeadersIdentical;
    }
    let v = &validators[idx];
    if v.stake == 0 {
        return EvidenceCheck::AlreadySlashed;
    }
    if !bls_verify(&evidence.sig_a, &hash_a, &v.bls_pk) {
        return EvidenceCheck::SigAInvalid;
    }
    if !bls_verify(&evidence.sig_b, &hash_b, &v.bls_pk) {
        return EvidenceCheck::SigBInvalid;
    }
    EvidenceCheck::Valid
}

/// Verify either equivocation form for a chain at `header_version`.
///
/// At or above [`HEADER_VERSION_EQUIVOCATION_BIND`] only the bound form is
/// slashable; below it only the legacy form decodes, and a bound blob is
/// refused here as well in case one arrives through another path.
pub fn verify_equivocation_for_version(
    evidence: &SlashEvidence,
    validators: &[Validator],
    header_version: u32,
) -> Option<EvidenceCheck> {
    let binding = header_version >= HEADER_VERSION_EQUIVOCATION_BIND;
    match evidence {
        SlashEvidence::Equivocation(ev) => Some(if binding {
            EvidenceCheck::UnboundOnBindingVersion
        } else {
            verify_equivocation_evidence(ev, validators)
        }),
        SlashEvidence::BoundEquivocation(ev) => Some(if binding {
            verify_bound_equivocation_evidence(ev, validators)
        } else {
            EvidenceCheck::BoundOnLegacyVersion
        }),
        SlashEvidence::InvalidBlock(_) => None,
    }
}

/// Verify invalid-block slash evidence.
#[cfg(feature = "bls")]
pub fn verify_invalid_block_evidence(
    evidence: &InvalidBlockEvidence,
    validators: &[Validator],
    emission_params: &crate::emission::EmissionParams,
    subsidy_schedule: crate::emission::SubsidyBpsSchedule,
    applying_block_height: u32,
    header_version: u32,
) -> InvalidBlockEvidenceCheck {
    use crate::fraud_proof::{fraud_proof_contested_block, verify_interactive_fraud_proof};

    if header_version < HEADER_VERSION_FRAUD_SLASH {
        return InvalidBlockEvidenceCheck::LegacyHeaderVersion;
    }
    if evidence.height >= applying_block_height {
        return InvalidBlockEvidenceCheck::SameHeightSlash;
    }
    let idx = evidence.producer_index as usize;
    if idx >= validators.len() {
        return InvalidBlockEvidenceCheck::IndexOutOfRange;
    }
    if validators[idx].stake == 0 {
        return InvalidBlockEvidenceCheck::AlreadySlashed;
    }
    let contested_params = subsidy_schedule.effective(emission_params, evidence.height);
    if verify_interactive_fraud_proof(&evidence.fraud_proof_wire, &contested_params).is_err() {
        return InvalidBlockEvidenceCheck::FraudProofInvalid;
    }
    let Some((f_height, f_block_id, f_producer)) =
        fraud_proof_contested_block(&evidence.fraud_proof_wire)
    else {
        return InvalidBlockEvidenceCheck::ContestedMismatch;
    };
    if f_height != evidence.height
        || f_block_id != evidence.block_id
        || f_producer != Some(evidence.producer_index)
    {
        return InvalidBlockEvidenceCheck::ContestedMismatch;
    }
    InvalidBlockEvidenceCheck::Valid
}

/// Verify any slash evidence variant.
#[cfg(feature = "bls")]
pub fn verify_slash_evidence(
    evidence: &SlashEvidence,
    validators: &[Validator],
    emission_params: &crate::emission::EmissionParams,
    subsidy_schedule: crate::emission::SubsidyBpsSchedule,
    applying_block_height: u32,
    header_version: u32,
) -> Result<(), SlashRejectReason> {
    match evidence {
        SlashEvidence::Equivocation(_) | SlashEvidence::BoundEquivocation(_) => {
            let check = verify_equivocation_for_version(evidence, validators, header_version)
                .unwrap_or(EvidenceCheck::PreimageMalformed);
            if check.is_valid() {
                Ok(())
            } else {
                Err(SlashRejectReason::Equivocation(check))
            }
        }
        SlashEvidence::InvalidBlock(ev) => {
            let check = verify_invalid_block_evidence(
                ev,
                validators,
                emission_params,
                subsidy_schedule,
                applying_block_height,
                header_version,
            );
            if check == InvalidBlockEvidenceCheck::Valid {
                Ok(())
            } else {
                Err(SlashRejectReason::InvalidBlock(check))
            }
        }
    }
}

#[cfg(all(test, feature = "bls"))]
mod tests {
    use super::*;
    use crate::block::HEADER_VERSION_RETRIEVAL;
    use crate::consensus::Validator;
    use curve25519_dalek::scalar::Scalar;
    use mfn_bls::bls_keygen_from_seed;
    use mfn_bls::bls_sign;
    use mfn_crypto::point::generator_g;

    fn fresh_validator(index: u32, stake: u64) -> (Validator, mfn_bls::BlsKeypair) {
        let bls = bls_keygen_from_seed(&[index as u8; 32]);
        let vrf_pk = generator_g() * Scalar::from(u64::from(index) + 1);
        (
            Validator {
                index,
                vrf_pk,
                bls_pk: bls.pk,
                stake,
                payout: None,
            },
            bls,
        )
    }

    fn ev_for(
        idx: u32,
        sk: &mfn_bls::BlsSecretKey,
        a: [u8; 32],
        b: [u8; 32],
    ) -> EquivocationEvidence {
        EquivocationEvidence {
            height: 5,
            slot: 7,
            voter_index: idx,
            header_hash_a: a,
            sig_a: bls_sign(&a, sk),
            header_hash_b: b,
            sig_b: bls_sign(&b, sk),
        }
    }

    #[test]
    fn f5_1c_slash_drops_bond_registry_exit() {
        use std::collections::BTreeMap;

        use crate::block::PendingUnbond;
        use crate::emission::SubsidyBpsSchedule;
        use crate::validator_evolution::apply_equivocation_slashings;
        use crate::{DEFAULT_EMISSION_PARAMS, HEADER_VERSION};

        let (val, bls) = fresh_validator(0, 500);
        let mut pending = BTreeMap::new();
        pending.insert(
            0,
            PendingUnbond {
                validator_index: 0,
                unlock_height: 50,
                stake_at_request: 500,
                request_height: 1,
            },
        );
        let ev = SlashEvidence::Equivocation(ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]));
        let mut validators = vec![val];
        let out = apply_equivocation_slashings(
            &mut validators,
            &mut pending,
            &[ev],
            &DEFAULT_EMISSION_PARAMS,
            SubsidyBpsSchedule::default(),
            10,
            HEADER_VERSION,
        );
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(validators[0].stake, 0);
        assert_eq!(out.forfeited_total, 500);
        assert!(
            pending.is_empty(),
            "a slashed producer must leave the bond-registry exit set"
        );
    }

    #[test]
    fn valid_evidence_verifies() {
        let (val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        assert_eq!(
            verify_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::Valid
        );
    }

    #[test]
    fn rejects_index_out_of_range() {
        let (val, bls) = fresh_validator(0, 100);
        let mut ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        ev.voter_index = 99;
        assert_eq!(
            verify_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::IndexOutOfRange
        );
    }

    #[test]
    fn rejects_identical_headers() {
        let (val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [3u8; 32], [3u8; 32]);
        assert_eq!(
            verify_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::HeadersIdentical
        );
    }

    #[test]
    fn rejects_already_slashed() {
        let (mut val, bls) = fresh_validator(0, 100);
        val.stake = 0;
        let ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        assert_eq!(
            verify_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::AlreadySlashed
        );
    }

    #[test]
    fn rejects_wrong_signer() {
        let (val_0, _bls_0) = fresh_validator(0, 100);
        let (_val_1, bls_1) = fresh_validator(1, 50);
        let ev = ev_for(0, &bls_1.sk, [1u8; 32], [2u8; 32]);
        assert_eq!(
            verify_equivocation_evidence(&ev, &[val_0]),
            EvidenceCheck::SigAInvalid
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let (val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [4u8; 32], [5u8; 32]);
        let bytes = encode_evidence(&ev);
        let recovered = decode_evidence(&bytes).expect("decode");
        assert_eq!(recovered.height, ev.height);
        assert_eq!(recovered.slot, ev.slot);
        assert_eq!(recovered.voter_index, ev.voter_index);
        assert_eq!(recovered.header_hash_a, ev.header_hash_a);
        assert_eq!(recovered.header_hash_b, ev.header_hash_b);
        assert_eq!(
            verify_equivocation_evidence(&recovered, &[val]),
            EvidenceCheck::Valid
        );
    }

    #[test]
    fn tagged_slash_round_trip_v3() {
        let (val, bls) = fresh_validator(0, 100);
        let ev = SlashEvidence::Equivocation(ev_for(0, &bls.sk, [4u8; 32], [5u8; 32]));
        let bytes = encode_slash_evidence(&ev, HEADER_VERSION_FRAUD_SLASH);
        let recovered = decode_slash_evidence(&bytes, HEADER_VERSION_FRAUD_SLASH).expect("decode");
        assert_eq!(recovered.offender_index(), 0);
        match recovered {
            SlashEvidence::Equivocation(inner) => {
                assert_eq!(
                    verify_equivocation_evidence(&inner, &[val]),
                    EvidenceCheck::Valid
                );
            }
            other => panic!("expected equivocation, got {other:?}"),
        }
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let (_val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [9u8; 32], [1u8; 32]);
        let canon = canonicalize_equivocation(&ev);
        assert!(canon.header_hash_a < canon.header_hash_b);
        let canon2 = canonicalize_equivocation(&canon);
        assert_eq!(canon2.header_hash_a, canon.header_hash_a);
    }

    #[test]
    fn slashing_merkle_root_empty_is_zero_sentinel() {
        assert_eq!(slashing_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn slashing_leaf_is_reorder_stable() {
        let (_val, bls) = fresh_validator(0, 100);
        let ev_forward = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        let ev_reversed = EquivocationEvidence {
            height: ev_forward.height,
            slot: ev_forward.slot,
            voter_index: ev_forward.voter_index,
            header_hash_a: ev_forward.header_hash_b,
            sig_a: ev_forward.sig_b,
            header_hash_b: ev_forward.header_hash_a,
            sig_b: ev_forward.sig_a,
        };
        assert_eq!(
            slashing_leaf_hash(&SlashEvidence::Equivocation(ev_forward)),
            slashing_leaf_hash(&SlashEvidence::Equivocation(ev_reversed)),
        );
    }

    #[test]
    fn slashing_merkle_root_changes_with_addition() {
        let (_v0, b0) = fresh_validator(0, 100);
        let (_v1, b1) = fresh_validator(1, 100);
        let e0 = SlashEvidence::Equivocation(ev_for(0, &b0.sk, [1u8; 32], [2u8; 32]));
        let e1 = SlashEvidence::Equivocation(ev_for(1, &b1.sk, [3u8; 32], [4u8; 32]));
        let r_one = slashing_merkle_root(std::slice::from_ref(&e0));
        let r_two = slashing_merkle_root(&[e0, e1]);
        assert_ne!(r_one, r_two);
    }

    /// Protocol golden vector for the M2.0.1 slashing-root commitment.
    /// Protocol golden vector for the M2.0.1 slashing-root commitment.
    #[test]
    fn slashing_root_wire_matches_protocol_golden_vector() {
        let mut seed = [0u8; 48];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        let bls = bls_keygen_from_seed(&seed);

        let h_aa = [0xaau8; 32];
        let h_bb = [0xbbu8; 32];
        let e0 = EquivocationEvidence {
            height: 10,
            slot: 11,
            voter_index: 7,
            header_hash_a: h_aa,
            sig_a: bls_sign(&h_aa, &bls.sk),
            header_hash_b: h_bb,
            sig_b: bls_sign(&h_bb, &bls.sk),
        };

        let h_ee = [0xeeu8; 32];
        let h_cc = [0xccu8; 32];
        let e1 = EquivocationEvidence {
            height: 12,
            slot: 13,
            voter_index: 8,
            header_hash_a: h_ee,
            sig_a: bls_sign(&h_ee, &bls.sk),
            header_hash_b: h_cc,
            sig_b: bls_sign(&h_cc, &bls.sk),
        };

        let leaf0 = slashing_leaf_hash(&SlashEvidence::Equivocation(e0));
        let leaf1 = slashing_leaf_hash(&SlashEvidence::Equivocation(e1));
        let root = slashing_merkle_root(&[
            SlashEvidence::Equivocation(EquivocationEvidence {
                height: 10,
                slot: 11,
                voter_index: 7,
                header_hash_a: h_aa,
                sig_a: bls_sign(&h_aa, &bls.sk),
                header_hash_b: h_bb,
                sig_b: bls_sign(&h_bb, &bls.sk),
            }),
            SlashEvidence::Equivocation(EquivocationEvidence {
                height: 12,
                slot: 13,
                voter_index: 8,
                header_hash_a: h_ee,
                sig_a: bls_sign(&h_ee, &bls.sk),
                header_hash_b: h_cc,
                sig_b: bls_sign(&h_cc, &bls.sk),
            }),
        ]);

        assert_eq!(
            hex::encode(leaf0),
            "e58150a4f83124653f2d2ad1a54274fa5c3410dfaac3278df7c03d1db24141aa",
        );
        assert_eq!(
            hex::encode(leaf1),
            "d400dc0d29f652537d0fead9d400b2774fa6fde6c9f586067e5aab781a2a14d5",
        );
        assert_eq!(
            hex::encode(root),
            "24670a15fe826c64880104caf7ca5a86c48e7532a40e5271d1b40d0198206480",
        );
    }

    /* ---- B-330: bound equivocation evidence ------------------------------ */

    /// A header signing preimage at `version` for `height` / `slot`;
    /// `salt` makes two headers at one height hash differently.
    fn signing_preimage(version: u32, height: u32, slot: u32, salt: u8) -> Vec<u8> {
        use crate::block::{header_signing_bytes, BlockHeader};
        let h = BlockHeader {
            version,
            prev_hash: [7u8; 32],
            height,
            slot,
            timestamp: u64::from(height) * 100,
            tx_root: [salt; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            claims_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        };
        header_signing_bytes(&h)
    }

    fn bound_ev_for(
        idx: u32,
        sk: &mfn_bls::BlsSecretKey,
        height: u32,
        slot: u32,
        signing_a: Vec<u8>,
        signing_b: Vec<u8>,
    ) -> BoundEquivocationEvidence {
        let sig_a = bls_sign(&header_signing_hash_from_bytes(&signing_a), sk);
        let sig_b = bls_sign(&header_signing_hash_from_bytes(&signing_b), sk);
        BoundEquivocationEvidence {
            height,
            slot,
            voter_index: idx,
            signing_a,
            sig_a,
            signing_b,
            sig_b,
        }
    }

    #[test]
    fn b330_same_height_slot_double_sign_is_valid() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let ev = bound_ev_for(0, &bls.sk, 5, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::Valid
        );
    }

    #[test]
    fn b330_honest_votes_at_different_heights_are_not_equivocation() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 6, 8, 1);
        // Prover names height 5 / slot 7 and attaches a genuine vote from
        // the next height. Both signatures are real; the pair is not a
        // double-sign.
        let ev = bound_ev_for(0, &bls.sk, 5, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, std::slice::from_ref(&val)),
            EvidenceCheck::HeightSlotMismatch
        );
        // The same two votes still pass the legacy verifier, which is the
        // gap this unit closes behind the header gate.
        let legacy = EquivocationEvidence {
            height: 5,
            slot: 7,
            voter_index: 0,
            header_hash_a: ev.header_hash_a(),
            sig_a: ev.sig_a,
            header_hash_b: ev.header_hash_b(),
            sig_b: ev.sig_b,
        };
        assert_eq!(
            verify_equivocation_evidence(&legacy, &[val]),
            EvidenceCheck::Valid
        );
    }

    #[test]
    fn b330_same_height_different_slot_is_not_equivocation() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 8, 1);
        let ev = bound_ev_for(0, &bls.sk, 5, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::HeightSlotMismatch
        );
    }

    #[test]
    fn b330_evidence_fields_must_match_preimages() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let ev = bound_ev_for(0, &bls.sk, 9, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::HeightSlotMismatch
        );
    }

    #[test]
    fn b330_malformed_preimage_is_rejected_before_signatures() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let mut b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        b.push(0);
        let ev = bound_ev_for(0, &bls.sk, 5, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &[val]),
            EvidenceCheck::PreimageMalformed
        );
        // A bare 32-byte hash is not a preimage either.
        let ev2 = bound_ev_for(0, &bls.sk, 5, 7, vec![1u8; 32], vec![2u8; 32]);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev2, &[fresh_validator(0, 100).0]),
            EvidenceCheck::PreimageMalformed
        );
    }

    #[test]
    fn b330_identical_preimages_and_wrong_signer_still_rejected() {
        let (val, bls) = fresh_validator(0, 100);
        let (_v1, bls_1) = fresh_validator(1, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let same = bound_ev_for(0, &bls.sk, 5, 7, a.clone(), a.clone());
        assert_eq!(
            verify_bound_equivocation_evidence(&same, std::slice::from_ref(&val)),
            EvidenceCheck::HeadersIdentical
        );
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let forged = bound_ev_for(0, &bls_1.sk, 5, 7, a, b);
        assert_eq!(
            verify_bound_equivocation_evidence(&forged, &[val]),
            EvidenceCheck::SigAInvalid
        );
    }

    #[test]
    fn b330_version_gate_selects_the_form() {
        let (val, bls) = fresh_validator(0, 100);
        let legacy = SlashEvidence::Equivocation(ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]));
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let bound = SlashEvidence::BoundEquivocation(bound_ev_for(0, &bls.sk, 5, 7, a, b));
        let vals = [val];
        assert_eq!(
            verify_equivocation_for_version(&legacy, &vals, HEADER_VERSION),
            Some(EvidenceCheck::Valid)
        );
        assert_eq!(
            verify_equivocation_for_version(&legacy, &vals, HEADER_VERSION_EQUIVOCATION_BIND),
            Some(EvidenceCheck::UnboundOnBindingVersion)
        );
        assert_eq!(
            verify_equivocation_for_version(&bound, &vals, HEADER_VERSION_EQUIVOCATION_BIND),
            Some(EvidenceCheck::Valid)
        );
        assert_eq!(
            verify_equivocation_for_version(&bound, &vals, HEADER_VERSION_RETRIEVAL),
            Some(EvidenceCheck::BoundOnLegacyVersion)
        );
    }

    #[test]
    fn b330_bound_wire_round_trip_v8_and_refused_below() {
        let (val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let ev = SlashEvidence::BoundEquivocation(bound_ev_for(0, &bls.sk, 5, 7, a, b));
        let bytes = encode_slash_evidence(&ev, HEADER_VERSION_EQUIVOCATION_BIND);
        assert_eq!(bytes[0], SLASH_TAGGED_WIRE_MAGIC);
        assert_eq!(bytes[1], SLASH_KIND_BOUND_EQUIVOCATION);
        let back = decode_slash_evidence(&bytes, HEADER_VERSION_EQUIVOCATION_BIND).expect("decode");
        match &back {
            SlashEvidence::BoundEquivocation(inner) => {
                assert_eq!(inner.height, 5);
                assert_eq!(inner.slot, 7);
                assert_eq!(
                    verify_bound_equivocation_evidence(inner, &[val]),
                    EvidenceCheck::Valid
                );
            }
            other => panic!("expected bound equivocation, got {other:?}"),
        }
        assert_eq!(
            slashing_leaf_hash_for_version(&ev, HEADER_VERSION_EQUIVOCATION_BIND),
            slashing_leaf_hash_for_version(&back, HEADER_VERSION_EQUIVOCATION_BIND),
        );
        assert!(matches!(
            decode_slash_evidence(&bytes, HEADER_VERSION_RETRIEVAL),
            Err(SlashDecodeError::BoundEquivocationOnLegacyVersion)
        ));
    }

    #[test]
    fn b330_bound_leaf_is_reorder_stable() {
        let (_val, bls) = fresh_validator(0, 100);
        let a = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 1);
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let fwd = bound_ev_for(0, &bls.sk, 5, 7, a.clone(), b.clone());
        let rev = bound_ev_for(0, &bls.sk, 5, 7, b, a);
        assert_eq!(
            slashing_leaf_hash_for_version(
                &SlashEvidence::BoundEquivocation(fwd),
                HEADER_VERSION_EQUIVOCATION_BIND
            ),
            slashing_leaf_hash_for_version(
                &SlashEvidence::BoundEquivocation(rev),
                HEADER_VERSION_EQUIVOCATION_BIND
            ),
        );
    }

    #[test]
    fn b330_oversized_preimage_is_refused_at_decode() {
        let (_val, bls) = fresh_validator(0, 100);
        let a = vec![0u8; MAX_EQUIVOCATION_PREIMAGE_BYTES + 1];
        let b = signing_preimage(HEADER_VERSION_EQUIVOCATION_BIND, 5, 7, 2);
        let ev = SlashEvidence::BoundEquivocation(bound_ev_for(0, &bls.sk, 5, 7, a, b));
        let bytes = encode_slash_evidence(&ev, HEADER_VERSION_EQUIVOCATION_BIND);
        assert!(matches!(
            decode_slash_evidence(&bytes, HEADER_VERSION_EQUIVOCATION_BIND),
            Err(SlashDecodeError::PreimageTooLong { got }) if got == MAX_EQUIVOCATION_PREIMAGE_BYTES + 1
        ));
    }

    #[test]
    fn b330_legacy_v1_wire_and_golden_vector_unchanged() {
        // The v1 equivocation blob has no tag and no preimages; this unit
        // adds nothing to it (Path A root commitments are stable).
        let (_val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [4u8; 32], [5u8; 32]);
        let bytes = encode_slash_evidence(&SlashEvidence::Equivocation(ev.clone()), HEADER_VERSION);
        assert_eq!(bytes, encode_evidence(&ev));
        assert_eq!(bytes.len(), 4 + 4 + 4 + 32 + 96 + 32 + 96);
    }

    #[test]
    fn invalid_block_slash_evidence_roundtrip_and_verify_v3() {
        use crate::block::block_id;
        use crate::block::{
            apply_genesis, build_genesis, build_unsealed_header, seal_block, GenesisConfig,
            HEADER_VERSION_FRAUD_SLASH,
        };
        use crate::coinbase::{build_coinbase, PayoutAddress};
        use crate::emission::producer_portion_amount;
        use crate::fraud_proof::{
            encode_coinbase_amount_fraud_proof, CoinbaseAmountFraudProof,
            COINBASE_FRAUD_PROOF_VERSION,
        };
        use crate::{DEFAULT_EMISSION_PARAMS, TEST_CONSENSUS_PARAMS};
        use mfn_crypto::stealth::stealth_gen;
        use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

        let (val, _) = fresh_validator(0, 1_000_000);
        let w = stealth_gen();
        let payout = PayoutAddress {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        };
        let height = 1u64;
        let fee_sum = 0u128;
        let expected = producer_portion_amount(height, &DEFAULT_EMISSION_PARAMS, fee_sum);
        let wrong_cb = build_coinbase(height, expected.saturating_add(1), &payout).expect("cb");
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: vec![val.clone()],
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: HEADER_VERSION_FRAUD_SLASH,
        };
        let genesis = build_genesis(&cfg);
        let state = apply_genesis(&genesis, &cfg).expect("genesis");
        let header =
            build_unsealed_header(&state, std::slice::from_ref(&wrong_cb), &[], &[], &[], 1, 1);
        let block = seal_block(header, vec![wrong_cb], vec![], vec![], vec![], vec![]);
        let proof = CoinbaseAmountFraudProof {
            version: COINBASE_FRAUD_PROOF_VERSION,
            block: block.clone(),
            fee_sum,
            producer_payout: payout,
            accepted_settlements: Vec::new(),
        };
        let wire = encode_coinbase_amount_fraud_proof(&proof);
        let contested_id = block_id(&block.header);
        let ev = InvalidBlockEvidence {
            height: 1,
            block_id: contested_id,
            producer_index: 0,
            fraud_proof_wire: wire,
        };
        let bytes = encode_slash_evidence(
            &SlashEvidence::InvalidBlock(ev.clone()),
            HEADER_VERSION_FRAUD_SLASH,
        );
        let decoded = decode_slash_evidence(&bytes, HEADER_VERSION_FRAUD_SLASH).expect("decode");
        match decoded {
            SlashEvidence::InvalidBlock(inner) => {
                assert_eq!(inner.height, 1);
                assert_eq!(inner.block_id, contested_id);
            }
            other => panic!("expected invalid-block, got {other:?}"),
        }
        assert_eq!(
            verify_invalid_block_evidence(
                &ev,
                std::slice::from_ref(&val),
                &DEFAULT_EMISSION_PARAMS,
                crate::emission::SubsidyBpsSchedule::default(),
                1,
                HEADER_VERSION_FRAUD_SLASH,
            ),
            InvalidBlockEvidenceCheck::SameHeightSlash,
        );
        assert_eq!(
            verify_invalid_block_evidence(
                &ev,
                std::slice::from_ref(&val),
                &DEFAULT_EMISSION_PARAMS,
                crate::emission::SubsidyBpsSchedule::default(),
                2,
                HEADER_VERSION,
            ),
            InvalidBlockEvidenceCheck::LegacyHeaderVersion,
        );
    }
}
