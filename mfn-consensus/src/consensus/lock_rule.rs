//! Round voting with a lock, inactive on the current header version.
//!
//! One round of votes cannot both be safe and live. If a validator may
//! vote twice at the same height, two blocks can both collect a quorum.
//! If it may vote only once, a split leaves the height with no quorum
//! forever. This module is the small rule that closes that gap:
//!
//! - A polka (a quorum of votes for one block in a round) locks the
//!   validator onto that block.
//! - The validator keeps voting for the locked block.
//! - It may switch only when a polka from a strictly later round names
//!   the other block.
//! - With no lock, the next round is free, so a split can still finish.
//! - A height records at most one finalized block hash.
//!
//! [`HEADER_VERSION`](crate::block::HEADER_VERSION) is 1. The rule runs
//! only at [`HEADER_VERSION_LOCK_RULE`] and above, so Path A and F-A
//! keep today's single-round vote.

/// First header version that must follow the lock rule.
///
/// Versions 4–7 are B-35, Tier 2 rings, B-37 hidden fees, and B-317
/// retrieval. Version 8 is the equivocation height bind. This rule
/// starts at 9 so none of those gates turns the lock on. Not added
/// to the genesis allow-list.
pub const HEADER_VERSION_LOCK_RULE: u32 = 9;

/// What this validator is locked onto at the current height.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeightLock {
    /// Round of the polka that created the lock. `None` means unlocked.
    pub round: Option<u32>,
    /// Block hash the polka named.
    pub block_hash: Option<[u8; 32]>,
}

/// A quorum of votes for one block in one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polka {
    /// Round in which the quorum formed.
    pub round: u32,
    /// Block the quorum voted for.
    pub block_hash: [u8; 32],
}

/// `true` when `header_version` must follow the lock rule.
#[inline]
pub fn lock_rule_active(header_version: u32) -> bool {
    header_version >= HEADER_VERSION_LOCK_RULE
}

/// Whether this validator may vote for `block_hash` in `round`.
///
/// Below [`HEADER_VERSION_LOCK_RULE`] the answer is always yes.
/// A lock yields only for a polka from a strictly later round.
pub fn may_vote_locked(
    header_version: u32,
    lock: &HeightLock,
    round: u32,
    block_hash: &[u8; 32],
    newer_polka: Option<&Polka>,
) -> bool {
    if !lock_rule_active(header_version) {
        return true;
    }
    let (Some(locked_round), Some(locked_hash)) = (lock.round, lock.block_hash.as_ref()) else {
        let _ = round;
        return true;
    };
    if locked_hash == block_hash && round >= locked_round {
        return true;
    }
    matches!(
        newer_polka,
        Some(polka) if polka.round > locked_round && polka.block_hash.as_slice() == block_hash
    )
}

/// Adopt `polka` when it is strictly newer than the current lock.
pub fn lock_on_polka(lock: &mut HeightLock, polka: &Polka) {
    if let Some(round) = lock.round {
        if polka.round <= round {
            return;
        }
    }
    lock.round = Some(polka.round);
    lock.block_hash = Some(polka.block_hash);
}

/// `true` when `candidate` would be a second finalized block at this height.
///
/// Below [`HEADER_VERSION_LOCK_RULE`] the answer is always no, matching
/// today's single-round finality.
pub fn second_finalization_conflicts(
    header_version: u32,
    already_final: Option<&[u8; 32]>,
    candidate: &[u8; 32],
) -> bool {
    if !lock_rule_active(header_version) {
        return false;
    }
    matches!(already_final, Some(prior) if prior != candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_vote_recovers_in_the_next_round_and_one_hash_finalizes() {
        let version = HEADER_VERSION_LOCK_RULE;
        let left = [1u8; 32];
        let right = [2u8; 32];
        let mut lock = HeightLock::default();

        assert!(may_vote_locked(version, &lock, 0, &left, None));
        assert!(may_vote_locked(version, &lock, 0, &right, None));
        assert!(lock.round.is_none());

        let polka = Polka {
            round: 1,
            block_hash: right,
        };
        lock_on_polka(&mut lock, &polka);
        assert!(may_vote_locked(version, &lock, 1, &right, None));
        assert!(!may_vote_locked(version, &lock, 1, &left, None));

        assert!(!second_finalization_conflicts(version, None, &right));
        assert!(second_finalization_conflicts(version, Some(&right), &left));
        assert!(!second_finalization_conflicts(
            version,
            Some(&right),
            &right
        ));
        assert!(!second_finalization_conflicts(
            crate::block::HEADER_VERSION,
            Some(&right),
            &left
        ));
    }

    #[test]
    fn locked_validator_switches_only_on_a_newer_polka() {
        let version = HEADER_VERSION_LOCK_RULE;
        let locked_hash = [1u8; 32];
        let other = [2u8; 32];
        let mut lock = HeightLock::default();
        lock_on_polka(
            &mut lock,
            &Polka {
                round: 1,
                block_hash: locked_hash,
            },
        );

        assert!(may_vote_locked(version, &lock, 3, &locked_hash, None));
        assert!(!may_vote_locked(version, &lock, 3, &other, None));

        let same_round = Polka {
            round: 1,
            block_hash: other,
        };
        assert!(!may_vote_locked(
            version,
            &lock,
            3,
            &other,
            Some(&same_round)
        ));
        lock_on_polka(&mut lock, &same_round);
        assert_eq!(lock.block_hash, Some(locked_hash));

        let newer = Polka {
            round: 2,
            block_hash: other,
        };
        assert!(may_vote_locked(version, &lock, 3, &other, Some(&newer)));
        lock_on_polka(&mut lock, &newer);
        assert_eq!(lock.block_hash, Some(other));
        assert_eq!(lock.round, Some(2));

        assert!(may_vote_locked(
            crate::block::HEADER_VERSION,
            &lock,
            3,
            &locked_hash,
            None
        ));
        for version in 4u32..=8 {
            assert!(
                may_vote_locked(version, &lock, 3, &locked_hash, None),
                "header version {version} is not the lock rule"
            );
        }
    }
}
