//! Slashable evidence — fault attribution at the consensus layer.
//!
//! Port of `cloonan-group/lib/network/slashing.ts`.
//!
//! When a validator BLS-signs two conflicting messages at the same slot
//! (e.g. votes for two different proposals at the same height) they are
//! **provably Byzantine** and must lose their stake. This module defines
//! the on-chain evidence object and its verifier.
//!
//! The same evidence shape covers a producer who signs two competing
//! unsealed headers — the producer signature is just a BLS signature over a
//! header hash, identical in form to a committee vote.
//!
//! ## Constraints (all required)
//!
//! - `header_hash_a != header_hash_b` (otherwise it's not equivocation)
//! - `bls_verify(sig_a, header_hash_a, validators[voter_index].bls_pk)`
//! - `bls_verify(sig_b, header_hash_b, validators[voter_index].bls_pk)`
//! - `validators[voter_index].stake > 0` (a zero-stake validator is already
//!   slashed and cannot be slashed twice)
//!
//! Anyone who observes both signatures (the gossip layer delivers both
//! proposals to honest nodes) can construct evidence and include it in the
//! next block. `apply_block` then zeroes the offender's stake.

use mfn_bls::{bls_verify, decode_signature, encode_signature, BlsSignature};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::SLASHING_LEAF;
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;

use crate::consensus::Validator;

/// On-chain evidence of validator equivocation.
#[derive(Clone, Debug)]
pub struct SlashEvidence {
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

/* ----------------------------------------------------------------------- *
 *  Encoding                                                                *
 * ----------------------------------------------------------------------- */

/// Encode a [`SlashEvidence`] to its canonical bytes.
pub fn encode_evidence(e: &SlashEvidence) -> Vec<u8> {
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

/// Decoding errors for [`SlashEvidence`].
#[derive(Debug, thiserror::Error)]
pub enum SlashDecodeError {
    /// Underlying buffer too short or malformed.
    #[error(transparent)]
    Codec(#[from] mfn_crypto::CryptoError),
    /// One of the BLS signatures failed to decode.
    #[error(transparent)]
    Bls(#[from] mfn_bls::BlsError),
}

/// Decode bytes produced by [`encode_evidence`].
pub fn decode_evidence(bytes: &[u8]) -> Result<SlashEvidence, SlashDecodeError> {
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
    Ok(SlashEvidence {
        height,
        slot,
        voter_index,
        header_hash_a,
        sig_a,
        header_hash_b,
        sig_b,
    })
}

/* ----------------------------------------------------------------------- *
 *  Canonicalization                                                        *
 * ----------------------------------------------------------------------- */

/// Lexicographic-order canonical form so two reorderings of the same
/// evidence hash to the same thing (enables dedup).
pub fn canonicalize(e: &SlashEvidence) -> SlashEvidence {
    if e.header_hash_a < e.header_hash_b {
        e.clone()
    } else {
        SlashEvidence {
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

/* ----------------------------------------------------------------------- *
 *  Merkle commitment (M2.0.1)                                              *
 * ----------------------------------------------------------------------- */

/// 32-byte Merkle leaf hash for a single piece of [`SlashEvidence`].
///
/// Canonicalizes first so two reorderings of the same equivocation
/// (same `(height, slot, voter_index)` with the header-hashes swapped)
/// yield the same leaf. Without canonicalization, an attacker could
/// flip the pair ordering to produce a different `slashing_root`
/// without changing the underlying slash semantics.
///
/// Domain-separated under [`SLASHING_LEAF`] so the leaf cannot be
/// reinterpreted as any other consensus message.
#[must_use]
pub fn slashing_leaf_hash(e: &SlashEvidence) -> [u8; 32] {
    let canon = canonicalize(e);
    dhash(SLASHING_LEAF, &[&encode_evidence(&canon)])
}

/// Merkle root over the block's slashings in their order-as-emitted by
/// the producer. Returns the 32-byte zero sentinel for an empty list
/// (matches every other consensus root).
///
/// **Why not sort?** Each leaf already canonicalizes the pair-order of
/// the BLS signatures internally, so the only ordering choice left is
/// across distinct pieces of evidence. Keeping the producer's emitted
/// order avoids forcing the block applier to re-sort just to verify
/// `header.slashing_root`, and the existing `apply_block` rejects
/// duplicate validator_indices anyway.
#[must_use]
pub fn slashing_merkle_root(evidence: &[SlashEvidence]) -> [u8; 32] {
    if evidence.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = evidence.iter().map(slashing_leaf_hash).collect();
    merkle_root_or_zero(&leaves)
}

/* ----------------------------------------------------------------------- *
 *  Verification                                                            *
 * ----------------------------------------------------------------------- */

/// Result of [`verify_evidence`].
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

/// Verify a piece of slashing evidence against the validator set.
///
/// Returns a structured [`EvidenceCheck`] describing the exact failure
/// mode; the block applier turns "valid" into a stake-zeroing state
/// transition.
pub fn verify_evidence(evidence: &SlashEvidence, validators: &[Validator]) -> EvidenceCheck {
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

#[cfg(test)]
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

    fn ev_for(idx: u32, sk: &mfn_bls::BlsSecretKey, a: [u8; 32], b: [u8; 32]) -> SlashEvidence {
        SlashEvidence {
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
        assert_eq!(verify_evidence(&ev, &[val]), EvidenceCheck::Valid);
    }

    #[test]
    fn rejects_index_out_of_range() {
        let (val, bls) = fresh_validator(0, 100);
        let mut ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        ev.voter_index = 99;
        assert_eq!(verify_evidence(&ev, &[val]), EvidenceCheck::IndexOutOfRange);
    }

    #[test]
    fn rejects_identical_headers() {
        let (val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [3u8; 32], [3u8; 32]);
        assert_eq!(
            verify_evidence(&ev, &[val]),
            EvidenceCheck::HeadersIdentical
        );
    }

    #[test]
    fn rejects_already_slashed() {
        let (mut val, bls) = fresh_validator(0, 100);
        val.stake = 0;
        let ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        assert_eq!(verify_evidence(&ev, &[val]), EvidenceCheck::AlreadySlashed);
    }

    #[test]
    fn rejects_wrong_signer() {
        let (val_0, _bls_0) = fresh_validator(0, 100);
        let (_val_1, bls_1) = fresh_validator(1, 50);
        // Sign with validator 1's BLS sk but claim it's validator 0.
        let ev = ev_for(0, &bls_1.sk, [1u8; 32], [2u8; 32]);
        assert_eq!(verify_evidence(&ev, &[val_0]), EvidenceCheck::SigAInvalid);
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
        // BLS sigs survive: re-verifying against the same key proves the
        // bytes round-tripped correctly.
        assert_eq!(verify_evidence(&recovered, &[val]), EvidenceCheck::Valid);
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let (_val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [9u8; 32], [1u8; 32]);
        let canon = canonicalize(&ev);
        // After canonicalization, header_a < header_b in lexicographic order.
        assert!(canon.header_hash_a < canon.header_hash_b);
        // And running it again is a no-op.
        let canon2 = canonicalize(&canon);
        assert_eq!(canon2.header_hash_a, canon.header_hash_a);
    }

    /* ------------------------------------------------------------- *
     *  Merkle commitment (M2.0.1)                                    *
     * ------------------------------------------------------------- */

    #[test]
    fn slashing_merkle_root_empty_is_zero_sentinel() {
        assert_eq!(slashing_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn slashing_leaf_is_reorder_stable() {
        // canonicalize() ensures the same equivocation hashes to the
        // same leaf regardless of which sig is presented as `a` vs
        // `b`. Verify that property is preserved through the leaf
        // hash itself.
        let (_val, bls) = fresh_validator(0, 100);
        let ev_forward = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        // Swap a/b.
        let ev_reversed = SlashEvidence {
            height: ev_forward.height,
            slot: ev_forward.slot,
            voter_index: ev_forward.voter_index,
            header_hash_a: ev_forward.header_hash_b,
            sig_a: ev_forward.sig_b,
            header_hash_b: ev_forward.header_hash_a,
            sig_b: ev_forward.sig_a,
        };
        assert_eq!(
            slashing_leaf_hash(&ev_forward),
            slashing_leaf_hash(&ev_reversed),
            "slashing leaf must be reorder-stable under pair-swap"
        );
    }

    #[test]
    fn slashing_leaf_changes_when_evidence_changes() {
        let (_val, bls) = fresh_validator(0, 100);
        let base = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        let h_base = slashing_leaf_hash(&base);

        let mut other_height = base.clone();
        other_height.height = base.height + 1;
        // Note: height differs but sigs are over the same hashes, so we
        // bypass verify (leaf-hash is a pure structural commitment).
        assert_ne!(h_base, slashing_leaf_hash(&other_height));

        let mut other_voter = base.clone();
        other_voter.voter_index = 99;
        assert_ne!(h_base, slashing_leaf_hash(&other_voter));
    }

    #[test]
    fn slashing_merkle_root_changes_with_addition() {
        let (_v0, b0) = fresh_validator(0, 100);
        let (_v1, b1) = fresh_validator(1, 100);
        let e0 = ev_for(0, &b0.sk, [1u8; 32], [2u8; 32]);
        let e1 = ev_for(1, &b1.sk, [3u8; 32], [4u8; 32]);
        let r_one = slashing_merkle_root(std::slice::from_ref(&e0));
        let r_two = slashing_merkle_root(&[e0, e1]);
        assert_ne!(r_one, r_two);
    }

    #[test]
    fn slashing_merkle_root_is_order_sensitive_across_evidence() {
        // Within a single piece of evidence, pair-swap is canonicalized
        // away. But across distinct evidence pieces, order matters —
        // we keep the producer's emitted order as the commitment.
        let (_v0, b0) = fresh_validator(0, 100);
        let (_v1, b1) = fresh_validator(1, 100);
        let e0 = ev_for(0, &b0.sk, [1u8; 32], [2u8; 32]);
        let e1 = ev_for(1, &b1.sk, [3u8; 32], [4u8; 32]);
        let r_a = slashing_merkle_root(&[e0.clone(), e1.clone()]);
        let r_b = slashing_merkle_root(&[e1, e0]);
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn slashing_leaf_is_domain_separated() {
        let (_val, bls) = fresh_validator(0, 100);
        let ev = ev_for(0, &bls.sk, [1u8; 32], [2u8; 32]);
        let leaf = slashing_leaf_hash(&ev);
        let canon = canonicalize(&ev);
        let other = mfn_crypto::hash::dhash(b"MFBN-1/not-a-slashing-leaf", &[&encode_evidence(&canon)]);
        assert_ne!(leaf, other);
    }

    /// TS-parity golden vector for the M2.0.1 slashing-root commitment.
    ///
    /// Pinned to the same `bls_keygen_from_seed([1..=48])` convention
    /// used by `BondOp::{Register, Unbond}` so a single TS smoke
    /// fixture can cover all three (`bond_root`-component + this).
    ///
    /// **Reference inputs:**
    /// - `bls_keypair` = `bls_keygen_from_seed([1, 2, …, 48])`
    /// - `e0`: height=10, slot=11, voter_index=7,
    ///   header_hash_a = [0xaa; 32], header_hash_b = [0xbb; 32]
    ///   (so the producer's emit order already matches canonical
    ///   form, exercising the no-swap branch).
    /// - `e1`: height=12, slot=13, voter_index=8,
    ///   header_hash_a = [0xee; 32], header_hash_b = [0xcc; 32]
    ///   (a > b, so canonicalize() will swap — exercises the swap
    ///   branch).
    /// - Root computed over `[e0, e1]` in emit order.
    #[test]
    fn slashing_root_wire_matches_cloonan_ts_smoke_reference() {
        let mut seed = [0u8; 48];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        let bls = bls_keygen_from_seed(&seed);

        let h_aa = [0xaau8; 32];
        let h_bb = [0xbbu8; 32];
        let e0 = SlashEvidence {
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
        let e1 = SlashEvidence {
            height: 12,
            slot: 13,
            voter_index: 8,
            header_hash_a: h_ee,
            sig_a: bls_sign(&h_ee, &bls.sk),
            header_hash_b: h_cc,
            sig_b: bls_sign(&h_cc, &bls.sk),
        };

        let leaf0 = slashing_leaf_hash(&e0);
        let leaf1 = slashing_leaf_hash(&e1);
        let root = slashing_merkle_root(&[e0, e1]);

        assert_eq!(
            hex::encode(leaf0),
            "e58150a4f83124653f2d2ad1a54274fa5c3410dfaac3278df7c03d1db24141aa",
            "slashing leaf for e0 drifted"
        );
        assert_eq!(
            hex::encode(leaf1),
            "d400dc0d29f652537d0fead9d400b2774fa6fde6c9f586067e5aab781a2a14d5",
            "slashing leaf for e1 (swap-branch) drifted"
        );
        assert_eq!(
            hex::encode(root),
            "24670a15fe826c64880104caf7ca5a86c48e7532a40e5271d1b40d0198206480",
            "slashing_merkle_root over [e0, e1] drifted"
        );
    }
}
