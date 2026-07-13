//! Slashable evidence — fault attribution at the consensus layer.
//!
//! Equivocation (two conflicting BLS signatures at the same slot) and,
//! from header v3 onward, invalid-block fraud proofs that zero producer
//! stake when a block body is provably wrong.

use crate::block::{HEADER_VERSION, HEADER_VERSION_FRAUD_SLASH};
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
    /// Two conflicting BLS-signed headers at the same slot.
    Equivocation(EquivocationEvidence),
    /// Valid interactive fraud proof against a producer (header v3+).
    InvalidBlock(InvalidBlockEvidence),
}

impl SlashEvidence {
    /// Validator index to slash (equivocation voter or contested producer).
    #[must_use]
    pub fn offender_index(&self) -> u32 {
        match self {
            Self::Equivocation(e) => e.voter_index,
            Self::InvalidBlock(e) => e.producer_index,
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
            SlashEvidence::InvalidBlock(_) => {
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

/// Canonicalize slash evidence for Merkle leaf hashing.
#[must_use]
pub fn canonicalize(e: &SlashEvidence) -> SlashEvidence {
    match e {
        SlashEvidence::Equivocation(ev) => {
            SlashEvidence::Equivocation(canonicalize_equivocation(ev))
        }
        SlashEvidence::InvalidBlock(ev) => SlashEvidence::InvalidBlock(ev.clone()),
    }
}

/* ----------------------------------------------------------------------- *
 *  Merkle commitment (M2.0.1)                                              *
 * ----------------------------------------------------------------------- */

fn slash_leaf_bytes(e: &SlashEvidence, header_version: u32) -> Vec<u8> {
    if header_version < HEADER_VERSION_FRAUD_SLASH {
        match e {
            SlashEvidence::Equivocation(ev) => encode_evidence(&canonicalize_equivocation(ev)),
            SlashEvidence::InvalidBlock(_) => Vec::new(),
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

/// Verify invalid-block slash evidence.
#[cfg(feature = "bls")]
pub fn verify_invalid_block_evidence(
    evidence: &InvalidBlockEvidence,
    validators: &[Validator],
    emission_params: &crate::emission::EmissionParams,
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
    if verify_interactive_fraud_proof(&evidence.fraud_proof_wire, emission_params).is_err() {
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
    applying_block_height: u32,
    header_version: u32,
) -> Result<(), SlashRejectReason> {
    match evidence {
        SlashEvidence::Equivocation(ev) => {
            let check = verify_equivocation_evidence(ev, validators);
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
            SlashEvidence::InvalidBlock(_) => panic!("expected equivocation"),
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
            SlashEvidence::Equivocation(_) => panic!("expected invalid-block"),
        }
        assert_eq!(
            verify_invalid_block_evidence(
                &ev,
                std::slice::from_ref(&val),
                &DEFAULT_EMISSION_PARAMS,
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
                2,
                HEADER_VERSION,
            ),
            InvalidBlockEvidenceCheck::LegacyHeaderVersion,
        );
    }
}
