//! Build header v8 bound equivocation evidence from votes a node observes
//! (**B-332**).
//!
//! [`crate::slashing::BoundEquivocationEvidence`] (**B-330**) is the only
//! slashable equivocation form at
//! [`HEADER_VERSION_EQUIVOCATION_BIND`](crate::block::HEADER_VERSION_EQUIVOCATION_BIND)
//! and up, and it needs both header signing preimages. A node sees those
//! preimages when a proposal arrives and a committee vote is a BLS signature
//! over their hash, so the natural place to catch a double-sign is the vote
//! intake. This module is the pure part of that: it remembers one verified
//! vote per `(height, slot, voter)` and emits evidence the moment the same
//! voter signs a different header for the same pair.
//!
//! What it refuses to do:
//!
//! - **Record an unverified vote.** A forged "first vote" would otherwise let
//!   an attacker make an honest validator's real vote look like the second
//!   half of a double-sign. The evidence would still fail
//!   [`verify_bound_equivocation_evidence`], but the detector would have
//!   spent memory and reported a false positive to its caller.
//! - **Pair votes across heights or slots.** That is the gap B-330 closed in
//!   the verifier; the builder does not reopen it.
//! - **Grow without bound.** Entries are capped; a full detector evicts the
//!   lowest height first, and the caller prunes finalized heights.
//!
//! Wiring into the node's vote path (and staging the evidence into the next
//! block's `slashings`) is a separate unit.

use std::collections::BTreeMap;

use crate::block::{
    header_signing_fields, header_signing_hash_from_bytes, HEADER_VERSION_EQUIVOCATION_BIND,
};
use crate::bls::{bls_verify, BlsSignature};
use crate::consensus::Validator;
use crate::slashing::BoundEquivocationEvidence;

/// Default cap on remembered votes. Three committee votes per slot across a
/// few hundred unfinalized slots fits comfortably; a flood from one peer
/// cannot push it higher.
pub const DEFAULT_MAX_TRACKED_VOTES: usize = 4096;

/// Result of feeding one vote to [`EquivocationDetector::observe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// First verified vote from this voter for this `(height, slot)`;
    /// remembered.
    Recorded,
    /// Same voter, same `(height, slot)`, same header as before. Nothing to
    /// report (a re-broadcast is not a double-sign).
    Duplicate,
    /// Same voter, same `(height, slot)`, different header: the two signed
    /// preimages are returned as bound evidence. The pair is remembered so a
    /// third conflicting vote reports [`Observation::AlreadyReported`].
    Equivocation(Box<BoundEquivocationEvidence>),
    /// This voter was already reported for this `(height, slot)`; the first
    /// evidence stands and nothing new is emitted.
    AlreadyReported,
    /// `signing_bytes` is not a well-formed header signing preimage, or its
    /// header version is below [`HEADER_VERSION_EQUIVOCATION_BIND`] (where
    /// bound evidence does not exist).
    NotBindable,
    /// `voter_index` is outside the validator set.
    UnknownVoter,
    /// The signature does not verify over the preimage hash under the
    /// voter's BLS key. Not recorded.
    BadSignature,
    /// The detector is at its cap and this vote's height is lower than
    /// everything it holds, so it was not recorded.
    Full,
}

#[derive(Clone, Debug)]
struct SeenVote {
    hash: [u8; 32],
    signing_bytes: Vec<u8>,
    sig: BlsSignature,
    reported: bool,
}

/// Pure, bounded double-sign detector over header signing preimages.
#[derive(Clone, Debug)]
pub struct EquivocationDetector {
    /// `(height, slot, voter_index)` → first verified vote. Ordered by key so
    /// the lowest height is the first entry (eviction and prune order).
    seen: BTreeMap<(u32, u32, u32), SeenVote>,
    max_tracked: usize,
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TRACKED_VOTES)
    }
}

impl EquivocationDetector {
    /// A detector that remembers at most `max_tracked` votes (at least 1).
    #[must_use]
    pub fn new(max_tracked: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            max_tracked: max_tracked.max(1),
        }
    }

    /// Number of votes currently remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` when nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Lowest height with a remembered vote, if any.
    #[must_use]
    pub fn lowest_height(&self) -> Option<u32> {
        self.seen.keys().next().map(|(h, _, _)| *h)
    }

    /// Feed one observed committee vote.
    ///
    /// `signing_bytes` is the [`crate::block::header_signing_bytes`] of the
    /// header the vote is for and `sig` the voter's BLS signature over
    /// `header_signing_hash_from_bytes(signing_bytes)`. The signature is
    /// checked against `validators[voter_index]` before anything is stored.
    pub fn observe(
        &mut self,
        validators: &[Validator],
        voter_index: u32,
        signing_bytes: &[u8],
        sig: &BlsSignature,
    ) -> Observation {
        let Some(fields) = header_signing_fields(signing_bytes) else {
            return Observation::NotBindable;
        };
        if fields.version < HEADER_VERSION_EQUIVOCATION_BIND {
            return Observation::NotBindable;
        }
        let Some(voter) = validators.get(voter_index as usize) else {
            return Observation::UnknownVoter;
        };
        let hash = header_signing_hash_from_bytes(signing_bytes);
        if !bls_verify(sig, &hash, &voter.bls_pk) {
            return Observation::BadSignature;
        }

        let key = (fields.height, fields.slot, voter_index);
        if let Some(prev) = self.seen.get_mut(&key) {
            if prev.hash == hash {
                return Observation::Duplicate;
            }
            if prev.reported {
                return Observation::AlreadyReported;
            }
            prev.reported = true;
            return Observation::Equivocation(Box::new(BoundEquivocationEvidence {
                height: fields.height,
                slot: fields.slot,
                voter_index,
                signing_a: prev.signing_bytes.clone(),
                sig_a: prev.sig,
                signing_b: signing_bytes.to_vec(),
                sig_b: *sig,
            }));
        }

        if self.seen.len() >= self.max_tracked {
            // Evict the lowest height so a flood of old votes cannot push
            // out the slots still being voted on; refuse a vote that is
            // itself older than everything held.
            let Some(oldest) = self.seen.keys().next().copied() else {
                return Observation::Full;
            };
            if oldest.0 >= fields.height {
                return Observation::Full;
            }
            self.seen.remove(&oldest);
        }
        self.seen.insert(
            key,
            SeenVote {
                hash,
                signing_bytes: signing_bytes.to_vec(),
                sig: *sig,
                reported: false,
            },
        );
        Observation::Recorded
    }

    /// Forget every vote at a height below `height` (finalized heights
    /// cannot be double-signed any more as far as this node is concerned;
    /// the evidence for them, if any, was already emitted). Returns how
    /// many votes were dropped.
    pub fn prune_below(&mut self, height: u32) -> usize {
        let before = self.seen.len();
        self.seen = self.seen.split_off(&(height, 0, 0));
        before - self.seen.len()
    }
}

#[cfg(all(test, feature = "bls"))]
mod tests {
    use super::*;
    use crate::block::{header_signing_bytes, BlockHeader, HEADER_VERSION_RETRIEVAL};
    use crate::slashing::{verify_bound_equivocation_evidence, EvidenceCheck};
    use curve25519_dalek::scalar::Scalar;
    use mfn_bls::{bls_keygen_from_seed, bls_sign, BlsKeypair};
    use mfn_crypto::point::generator_g;

    fn validator(index: u32) -> (Validator, BlsKeypair) {
        let bls = bls_keygen_from_seed(&[index as u8 + 1; 32]);
        (
            Validator {
                index,
                vrf_pk: generator_g() * Scalar::from(u64::from(index) + 1),
                bls_pk: bls.pk,
                stake: 100,
                payout: None,
            },
            bls,
        )
    }

    fn preimage(version: u32, height: u32, slot: u32, salt: u8) -> Vec<u8> {
        header_signing_bytes(&BlockHeader {
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
        })
    }

    fn vote(bls: &BlsKeypair, signing: &[u8]) -> BlsSignature {
        bls_sign(&header_signing_hash_from_bytes(signing), &bls.sk)
    }

    const V8: u32 = HEADER_VERSION_EQUIVOCATION_BIND;

    #[test]
    fn b332_double_sign_at_one_height_slot_yields_valid_evidence() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let a = preimage(V8, 5, 7, 1);
        let b = preimage(V8, 5, 7, 2);
        assert_eq!(
            det.observe(&vals, 0, &a, &vote(&bls, &a)),
            Observation::Recorded
        );
        let Observation::Equivocation(ev) = det.observe(&vals, 0, &b, &vote(&bls, &b)) else {
            panic!("second header at the same height and slot is a double-sign");
        };
        assert_eq!((ev.height, ev.slot, ev.voter_index), (5, 7, 0));
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &vals),
            EvidenceCheck::Valid,
            "detector output must be what the verifier accepts"
        );
    }

    #[test]
    fn b332_honest_votes_at_different_heights_or_slots_are_not_evidence() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        for (h, s) in [(1u32, 1u32), (2, 2), (3, 3), (3, 4), (4, 4)] {
            let p = preimage(V8, h, s, 1);
            assert_eq!(
                det.observe(&vals, 0, &p, &vote(&bls, &p)),
                Observation::Recorded,
                "height {h} slot {s}"
            );
        }
        assert_eq!(det.len(), 5);
    }

    #[test]
    fn b332_rebroadcast_is_duplicate_not_equivocation() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let a = preimage(V8, 5, 7, 1);
        let s = vote(&bls, &a);
        assert_eq!(det.observe(&vals, 0, &a, &s), Observation::Recorded);
        assert_eq!(det.observe(&vals, 0, &a, &s), Observation::Duplicate);
        assert_eq!(det.len(), 1);
    }

    #[test]
    fn b332_forged_vote_is_not_recorded_so_it_cannot_frame_a_real_one() {
        let (val, bls) = validator(0);
        let (_other, other_bls) = validator(1);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let fake = preimage(V8, 5, 7, 9);
        // Signed by someone else's key but attributed to voter 0.
        assert_eq!(
            det.observe(&vals, 0, &fake, &vote(&other_bls, &fake)),
            Observation::BadSignature
        );
        assert!(det.is_empty());
        let real = preimage(V8, 5, 7, 1);
        assert_eq!(
            det.observe(&vals, 0, &real, &vote(&bls, &real)),
            Observation::Recorded,
            "the honest vote is a first vote, not a second"
        );
    }

    #[test]
    fn b332_unknown_voter_and_malformed_preimage_are_refused() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let a = preimage(V8, 5, 7, 1);
        assert_eq!(
            det.observe(&vals, 3, &a, &vote(&bls, &a)),
            Observation::UnknownVoter
        );
        let mut cut = a.clone();
        cut.pop();
        assert_eq!(
            det.observe(&vals, 0, &cut, &vote(&bls, &cut)),
            Observation::NotBindable
        );
        assert_eq!(
            det.observe(&vals, 0, &[1u8; 32], &vote(&bls, &[1u8; 32])),
            Observation::NotBindable
        );
        assert!(det.is_empty());
    }

    #[test]
    fn b332_pre_v8_votes_are_not_bindable() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let a = preimage(HEADER_VERSION_RETRIEVAL, 5, 7, 1);
        assert_eq!(
            det.observe(&vals, 0, &a, &vote(&bls, &a)),
            Observation::NotBindable
        );
        assert!(det.is_empty());
    }

    #[test]
    fn b332_third_conflicting_vote_is_already_reported() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        let a = preimage(V8, 5, 7, 1);
        let b = preimage(V8, 5, 7, 2);
        let c = preimage(V8, 5, 7, 3);
        det.observe(&vals, 0, &a, &vote(&bls, &a));
        assert!(matches!(
            det.observe(&vals, 0, &b, &vote(&bls, &b)),
            Observation::Equivocation(_)
        ));
        assert_eq!(
            det.observe(&vals, 0, &c, &vote(&bls, &c)),
            Observation::AlreadyReported
        );
        // Re-sending the recorded header is still a duplicate afterwards.
        assert_eq!(
            det.observe(&vals, 0, &a, &vote(&bls, &a)),
            Observation::Duplicate
        );
    }

    #[test]
    fn b332_two_voters_at_one_slot_are_independent() {
        let (v0, b0) = validator(0);
        let (v1, b1) = validator(1);
        let vals = [v0, v1];
        let mut det = EquivocationDetector::default();
        let a = preimage(V8, 5, 7, 1);
        let b = preimage(V8, 5, 7, 2);
        assert_eq!(
            det.observe(&vals, 0, &a, &vote(&b0, &a)),
            Observation::Recorded
        );
        // Voter 1 signing a different header than voter 0 is a split vote,
        // not an equivocation by either.
        assert_eq!(
            det.observe(&vals, 1, &b, &vote(&b1, &b)),
            Observation::Recorded
        );
        let Observation::Equivocation(ev) = det.observe(&vals, 1, &a, &vote(&b1, &a)) else {
            panic!("voter 1 then signing voter 0's header is its own double-sign");
        };
        assert_eq!(ev.voter_index, 1);
        assert_eq!(
            verify_bound_equivocation_evidence(&ev, &vals),
            EvidenceCheck::Valid
        );
    }

    #[test]
    fn b332_cap_evicts_lowest_height_and_refuses_older_votes() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::new(3);
        for h in 1..=3u32 {
            let p = preimage(V8, h, h, 1);
            assert_eq!(
                det.observe(&vals, 0, &p, &vote(&bls, &p)),
                Observation::Recorded
            );
        }
        assert_eq!(det.len(), 3);
        // A newer vote evicts height 1.
        let p4 = preimage(V8, 4, 4, 1);
        assert_eq!(
            det.observe(&vals, 0, &p4, &vote(&bls, &p4)),
            Observation::Recorded
        );
        assert_eq!(det.len(), 3);
        assert_eq!(det.lowest_height(), Some(2));
        // A vote older than everything held is refused, not recorded.
        let p1 = preimage(V8, 1, 1, 2);
        assert_eq!(
            det.observe(&vals, 0, &p1, &vote(&bls, &p1)),
            Observation::Full
        );
        assert_eq!(det.len(), 3);
        // Detection still works for a held height after eviction.
        let p4b = preimage(V8, 4, 4, 2);
        assert!(matches!(
            det.observe(&vals, 0, &p4b, &vote(&bls, &p4b)),
            Observation::Equivocation(_)
        ));
    }

    #[test]
    fn b332_prune_below_drops_finalized_heights_only() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::default();
        for h in 1..=6u32 {
            let p = preimage(V8, h, h, 1);
            det.observe(&vals, 0, &p, &vote(&bls, &p));
        }
        assert_eq!(det.prune_below(4), 3);
        assert_eq!(det.len(), 3);
        assert_eq!(det.lowest_height(), Some(4));
        assert_eq!(det.prune_below(4), 0);
        // Height 4 is still watched.
        let p4b = preimage(V8, 4, 4, 2);
        assert!(matches!(
            det.observe(&vals, 0, &p4b, &vote(&bls, &p4b)),
            Observation::Equivocation(_)
        ));
    }

    #[test]
    fn b332_zero_cap_is_clamped_to_one() {
        let (val, bls) = validator(0);
        let vals = [val];
        let mut det = EquivocationDetector::new(0);
        let p = preimage(V8, 1, 1, 1);
        assert_eq!(
            det.observe(&vals, 0, &p, &vote(&bls, &p)),
            Observation::Recorded
        );
        assert_eq!(det.len(), 1);
    }
}
