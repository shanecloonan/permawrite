//! Batch verification of independent proofs.
//!
//! A block holds many ring signatures and range proofs that do not depend
//! on each other. Checking them one after another leaves cores idle.
//! [`verify_batch`] splits the list across threads and writes the accept
//! bit back into the same position. Consensus is unchanged: a proof is
//! accepted only when the existing single-proof verifier accepts it.
//!
//! A worker that panics is a reject for every proof in its chunk. A panic
//! must not become an accept.

use std::thread;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_crypto::{
    bp_verify, clsag_verify, range_verify, verify_merkle_proof, BulletproofRange, ClsagRing,
    ClsagSignature, MerkleProof, RangeProof,
};

use crate::workload::{PreparedWorkload, CLSAG_WORKLOAD_MESSAGE};

/// Merkle inclusion of an already-hashed leaf.
#[derive(Clone)]
pub struct MerkleCheck {
    /// Leaf digest.
    pub leaf: [u8; 32],
    /// Sibling path.
    pub proof: MerkleProof,
    /// Expected root.
    pub root: [u8; 32],
}

/// One CLSAG.
#[derive(Clone)]
pub struct ClsagCheck {
    /// Signed message.
    pub message: Vec<u8>,
    /// Ring of spend keys and commitments.
    pub ring: ClsagRing,
    /// Pseudo-output commitment.
    pub pseudo: EdwardsPoint,
    /// Signature.
    pub signature: ClsagSignature,
}

/// Borromean range proof.
#[derive(Clone)]
pub struct RangeCheck {
    /// Commitment the proof claims to open.
    pub commitment: EdwardsPoint,
    /// Proof.
    pub proof: RangeProof,
}

/// One proof, owned so a worker can verify it without borrowing the caller.
///
/// Large curve objects are boxed so a `Vec` of mixed proofs stays small.
#[derive(Clone)]
pub enum BatchProof {
    /// Merkle inclusion.
    Merkle(Box<MerkleCheck>),
    /// CLSAG.
    Clsag(Box<ClsagCheck>),
    /// Borromean range proof.
    Range(Box<RangeCheck>),
    /// Bulletproof (the commitment sits inside the proof).
    Bulletproof(Box<BulletproofRange>),
}

/// Half-open index ranges that cover `0..len` exactly once.
#[must_use]
pub fn chunk_ranges(len: usize, workers: usize) -> Vec<(usize, usize)> {
    if len == 0 {
        return Vec::new();
    }
    let workers = workers.max(1).min(len);
    let base = len / workers;
    let extra = len % workers;
    let mut out = Vec::with_capacity(workers);
    let mut start = 0usize;
    for i in 0..workers {
        let size = base + usize::from(i < extra);
        let end = start + size;
        out.push((start, end));
        start = end;
    }
    out
}

fn worker_slots(requested: usize, jobs: usize) -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (requested, jobs);
        1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        if jobs <= 1 || requested <= 1 {
            1
        } else {
            requested.min(jobs)
        }
    }
}

/// Verify one proof with the consensus primitive for that kind.
#[must_use]
pub fn verify_one(item: &BatchProof) -> bool {
    match item {
        BatchProof::Merkle(item) => verify_merkle_proof(&item.leaf, &item.proof, &item.root),
        BatchProof::Clsag(item) => {
            clsag_verify(&item.message, &item.ring, &item.pseudo, &item.signature)
        }
        BatchProof::Range(item) => range_verify(&item.commitment, &item.proof),
        BatchProof::Bulletproof(proof) => bp_verify(proof),
    }
}

/// Verify `items` in order.
///
/// `workers` is a cap. `0` and `1` run on the calling thread. On
/// `wasm32` the cap is ignored and the call is sequential, because a
/// browser wallet cannot spawn these threads.
#[must_use]
pub fn verify_batch(items: &[BatchProof], workers: usize) -> Vec<bool> {
    if items.is_empty() {
        return Vec::new();
    }
    let slots = worker_slots(workers, items.len());
    if slots == 1 {
        return items.iter().map(verify_one).collect();
    }
    let ranges = chunk_ranges(items.len(), slots);
    let mut parts: Vec<Vec<bool>> = Vec::with_capacity(ranges.len());
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(ranges.len());
        for (start, end) in &ranges {
            let slice = &items[*start..*end];
            let len = end - start;
            handles.push((
                len,
                scope.spawn(move || slice.iter().map(verify_one).collect::<Vec<bool>>()),
            ));
        }
        for (len, handle) in handles {
            match handle.join() {
                Ok(flags) if flags.len() == len => parts.push(flags),
                _ => parts.push(vec![false; len]),
            }
        }
    });
    parts.into_iter().flatten().collect()
}

/// The pinned workload as four proof kinds, each repeated `copies` times.
#[must_use]
pub fn proofs_from_workload(workload: &PreparedWorkload, copies: usize) -> Vec<BatchProof> {
    let mut out = Vec::with_capacity(copies.saturating_mul(4));
    for _ in 0..copies {
        if let Some((leaf, proof)) = workload.merkle_entries().first() {
            out.push(BatchProof::Merkle(Box::new(MerkleCheck {
                leaf: *leaf,
                proof: proof.clone(),
                root: workload.merkle_root(),
            })));
        }
        out.push(BatchProof::Clsag(Box::new(ClsagCheck {
            message: CLSAG_WORKLOAD_MESSAGE.to_vec(),
            ring: workload.clsag_ring().clone(),
            pseudo: *workload.clsag_pseudo(),
            signature: workload.clsag_signature().clone(),
        })));
        out.push(BatchProof::Range(Box::new(RangeCheck {
            commitment: *workload.range_commitment(),
            proof: workload.range_proof().clone(),
        })));
        out.push(BatchProof::Bulletproof(Box::new(
            workload.bulletproof().clone(),
        )));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepare_verify_workload;

    #[test]
    fn chunk_ranges_cover_the_slice_once() {
        for len in [1usize, 2, 7, 8, 64] {
            for workers in [1usize, 2, 3, 8, 100] {
                let ranges = chunk_ranges(len, workers);
                assert_eq!(ranges.first().map(|r| r.0), Some(0));
                assert_eq!(ranges.last().map(|r| r.1), Some(len));
                let mut cursor = 0usize;
                for (start, end) in ranges {
                    assert_eq!(start, cursor);
                    assert!(end > start);
                    cursor = end;
                }
                assert_eq!(cursor, len);
            }
        }
        assert!(chunk_ranges(0, 4).is_empty());
    }

    #[test]
    fn empty_batch_is_empty() {
        let items: [BatchProof; 0] = [];
        assert!(verify_batch(&items, 4).is_empty());
    }

    #[test]
    fn parallel_matches_sequential_and_keeps_a_reject_in_place() {
        let workload = prepare_verify_workload().expect("workload");
        let mut items = proofs_from_workload(&workload, 2);
        assert!(items.len() >= 6);
        // Flip one CLSAG message. Its neighbors must stay accepts.
        let clsag_at = items
            .iter()
            .position(|item| matches!(item, BatchProof::Clsag(_)))
            .expect("clsag");
        if let BatchProof::Clsag(item) = &mut items[clsag_at] {
            item.message.clear();
            item.message.extend_from_slice(b"MFN-1/scale-clsag/other");
        }
        let sequential = verify_batch(&items, 1);
        let parallel = verify_batch(&items, 4);
        assert_eq!(parallel, sequential);
        assert!(!parallel[clsag_at]);
        assert!(parallel.iter().filter(|ok| **ok).count() + 1 == parallel.len());
        assert_eq!(verify_batch(&items, 0), sequential);
        assert_eq!(verify_batch(&items[..1], 8), verify_batch(&items[..1], 1));
    }
}
