//! Windowed SPoRA lottery ranking (**B-308** helper; **B-44** wires consensus).
//!
//! Path A `apply_block` still pays proofs in **body order** (first-to-publish).
//! This module is pure ranking:
//! given a window seed and operator identities, it returns a deterministic
//! winner order independent of proof arrival order.
//!
//! Wiring it is a coinbase fork (a later-arriving but lottery-winning proof
//! can displace a body-first proof). Do not call this from `apply_block`
//! until **B-32** multi-op evidence exists and **B-44** lands the windowed
//! pool.

use mfn_crypto::domain::SPORA_LOTTERY;
use mfn_crypto::hash::dhash;

/// Label mixed into [`SPORA_LOTTERY`] when deriving the window seed.
const SEED_LABEL: &[u8] = b"seed";
/// Label mixed into [`SPORA_LOTTERY`] when scoring an operator.
const RANK_LABEL: &[u8] = b"rank";

/// Derive the lottery seed for a proof window.
///
/// **B-44** should pass the **prior** sealed `block_id` (unpredictable at
/// submit time) and the window's first slot. A producer VRF here would let
/// the leader bias winners — do not use that.
#[must_use]
pub fn spora_lottery_window_seed(prior_block_id: &[u8; 32], window_start_slot: u64) -> [u8; 32] {
    dhash(
        SPORA_LOTTERY,
        &[
            SEED_LABEL,
            prior_block_id.as_slice(),
            &window_start_slot.to_le_bytes(),
        ],
    )
}

/// Rank operator identities for a window and return up to `max_winners`.
///
/// - Duplicate ids are collapsed (canonical unique set).
/// - Input order does **not** affect the result.
/// - Ties break on operator id bytes (total order).
/// - `max_winners == 0` or an empty set returns empty.
#[must_use]
pub fn rank_spora_lottery(
    window_seed: &[u8; 32],
    operator_ids: &[[u8; 32]],
    max_winners: usize,
) -> Vec<[u8; 32]> {
    if max_winners == 0 || operator_ids.is_empty() {
        return Vec::new();
    }
    let mut unique: Vec<[u8; 32]> = operator_ids.to_vec();
    unique.sort_unstable();
    unique.dedup();

    let mut scored: Vec<([u8; 32], [u8; 32])> = unique
        .into_iter()
        .map(|id| {
            let score = dhash(
                SPORA_LOTTERY,
                &[RANK_LABEL, window_seed.as_slice(), id.as_slice()],
            );
            (score, id)
        })
        .collect();
    scored.sort_unstable();
    scored
        .into_iter()
        .take(max_winners)
        .map(|(_, id)| id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(b0: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b0;
        id
    }

    #[test]
    fn b308_window_seed_is_deterministic_and_slot_sensitive() {
        let block = [7u8; 32];
        let a = spora_lottery_window_seed(&block, 100);
        let b = spora_lottery_window_seed(&block, 100);
        let c = spora_lottery_window_seed(&block, 101);
        let d = spora_lottery_window_seed(&[8u8; 32], 100);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn b308_rank_is_permutation_invariant() {
        let seed = [1u8; 32];
        let a = op(1);
        let b = op(2);
        let c = op(3);
        let forward = rank_spora_lottery(&seed, &[a, b, c], 3);
        let reverse = rank_spora_lottery(&seed, &[c, b, a], 3);
        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), 3);
        let unique: std::collections::HashSet<_> = forward.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn b308_same_seed_same_winners() {
        let seed = [9u8; 32];
        let ids = [op(10), op(20), op(30)];
        let first = rank_spora_lottery(&seed, &ids, 1);
        let second = rank_spora_lottery(&seed, &ids, 1);
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
    }

    #[test]
    fn b308_two_operators_both_win_across_seeds() {
        let a = op(0xaa);
        let b = op(0xbb);
        let mut saw_a = false;
        let mut saw_b = false;
        for i in 0u32..10_000 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            let winners = rank_spora_lottery(&seed, &[a, b], 1);
            match winners.first() {
                Some(w) if *w == a => saw_a = true,
                Some(w) if *w == b => saw_b = true,
                _ => panic!("expected a singleton winner"),
            }
            if saw_a && saw_b {
                break;
            }
        }
        assert!(
            saw_a && saw_b,
            "equal-latency operators must both be able to win across windows"
        );
    }

    #[test]
    fn b308_empty_and_zero_cap() {
        let seed = [2u8; 32];
        assert!(rank_spora_lottery(&seed, &[], 1).is_empty());
        assert!(rank_spora_lottery(&seed, &[op(1)], 0).is_empty());
    }

    #[test]
    fn b308_max_winners_caps_and_dedups() {
        let seed = [3u8; 32];
        let a = op(1);
        let full = rank_spora_lottery(&seed, &[a, a, op(2), op(3)], 8);
        assert_eq!(full.len(), 3);
        assert_eq!(full.iter().filter(|id| **id == a).count(), 1);
        let capped = rank_spora_lottery(&seed, &[a, op(2), op(3)], 2);
        assert_eq!(capped.len(), 2);
        assert_eq!(capped.as_slice(), &full[..2]);
    }
}
