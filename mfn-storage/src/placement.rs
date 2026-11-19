//! Choose replica operators so copies do not share one failure domain.
//!
//! Replication 3 priced into an endowment is not three places. If every
//! selected operator reports the same ASN, one network event takes the file.
//! This picker prefers a new ASN, then a new region, and is deterministic
//! when two candidates add the same diversity. Unknown geography (`0`) is
//! not a failure domain and does not count as diversity.
//!
//! Operator-side. Not an `apply_block` rule. Path A and F-A are unchanged.

use crate::replica_health::MIN_DIVERSE_FAILURE_DOMAINS;

/// One operator that can hold a replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementCandidate {
    /// Operator identity. A repeat of the same id is ignored.
    pub operator_id: [u8; 32],
    /// Autonomous system. `0` means not reported.
    pub asn: u32,
    /// Region code. `0` means not reported.
    pub region: u16,
}

/// The operators chosen for one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaPlacement {
    /// Chosen operator ids, in selection order.
    pub operators: Vec<[u8; 32]>,
    /// Distinct non-zero ASNs among the chosen set.
    pub distinct_asns: u16,
    /// Distinct non-zero regions among the chosen set.
    pub distinct_regions: u16,
}

/// Why a placement could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    /// Asked for zero replicas.
    WantedZero,
    /// No candidates.
    NoCandidates,
}

impl ReplicaPlacement {
    /// `true` when the chosen set reports at least
    /// [`MIN_DIVERSE_FAILURE_DOMAINS`] ASNs, or that many regions when no
    /// ASN was reported.
    #[must_use]
    pub fn diversity_met(&self) -> bool {
        let domains = if self.distinct_asns > 0 {
            self.distinct_asns
        } else {
            self.distinct_regions
        };
        domains >= MIN_DIVERSE_FAILURE_DOMAINS
    }
}

/// Pick `wanted` operators, preferring a new failure domain at each step.
///
/// # Errors
///
/// [`PlacementError::WantedZero`] or [`PlacementError::NoCandidates`].
pub fn place_replicas(
    candidates: &[PlacementCandidate],
    wanted: u8,
) -> Result<ReplicaPlacement, PlacementError> {
    if wanted == 0 {
        return Err(PlacementError::WantedZero);
    }
    if candidates.is_empty() {
        return Err(PlacementError::NoCandidates);
    }
    let mut remaining: Vec<PlacementCandidate> = Vec::new();
    for candidate in candidates {
        if remaining
            .iter()
            .any(|c| c.operator_id == candidate.operator_id)
        {
            continue;
        }
        remaining.push(*candidate);
    }
    if remaining.is_empty() {
        return Err(PlacementError::NoCandidates);
    }
    let mut chosen: Vec<PlacementCandidate> = Vec::new();
    let target = usize::from(wanted).min(remaining.len());
    while chosen.len() < target {
        let mut best_idx = 0usize;
        let mut best_gain = 0u8;
        let mut best_id = remaining[0].operator_id;
        for (i, candidate) in remaining.iter().enumerate() {
            let gain = diversity_gain(&chosen, candidate);
            let better = gain > best_gain || (gain == best_gain && candidate.operator_id < best_id);
            if better {
                best_idx = i;
                best_gain = gain;
                best_id = candidate.operator_id;
            }
        }
        chosen.push(remaining.swap_remove(best_idx));
    }
    Ok(ReplicaPlacement {
        operators: chosen.iter().map(|c| c.operator_id).collect(),
        distinct_asns: count_distinct(chosen.iter().filter_map(|c| nonzero_u32(c.asn))),
        distinct_regions: count_distinct(chosen.iter().filter_map(|c| nonzero_u16(c.region))),
    })
}

fn diversity_gain(chosen: &[PlacementCandidate], next: &PlacementCandidate) -> u8 {
    let new_asn = next.asn != 0 && chosen.iter().all(|c| c.asn != next.asn);
    let new_region = next.region != 0 && chosen.iter().all(|c| c.region != next.region);
    u8::from(new_asn).saturating_mul(2) + u8::from(new_region)
}

fn nonzero_u32(v: u32) -> Option<u32> {
    (v != 0).then_some(v)
}

fn nonzero_u16(v: u16) -> Option<u16> {
    (v != 0).then_some(v)
}

fn count_distinct<T: Copy + Ord>(values: impl Iterator<Item = T>) -> u16 {
    let mut seen: Vec<T> = values.collect();
    seen.sort_unstable();
    seen.dedup();
    u16::try_from(seen.len()).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(byte: u8, asn: u32, region: u16) -> PlacementCandidate {
        PlacementCandidate {
            operator_id: [byte; 32],
            asn,
            region,
        }
    }

    #[test]
    fn picker_includes_a_second_asn_before_filling_one_site() {
        let candidates = [op(1, 100, 1), op(2, 100, 1), op(3, 100, 1), op(4, 200, 2)];
        let placed = place_replicas(&candidates, 3).expect("place");
        assert_eq!(placed.operators.len(), 3);
        assert!(placed.operators.iter().any(|id| id[0] == 4));
        assert!(placed.diversity_met());
        assert!(placed.distinct_asns >= 2);
    }

    #[test]
    fn one_asn_is_not_diverse_even_when_the_count_is_met() {
        let candidates = [op(1, 100, 7), op(2, 100, 7), op(3, 100, 7)];
        let placed = place_replicas(&candidates, 3).expect("place");
        assert_eq!(placed.operators.len(), 3);
        assert!(!placed.diversity_met());
        assert_eq!(placed.distinct_asns, 1);
    }

    #[test]
    fn unknown_geography_does_not_invent_a_second_domain() {
        let candidates = [op(1, 0, 0), op(2, 0, 0), op(3, 0, 0)];
        let placed = place_replicas(&candidates, 3).expect("place");
        assert!(!placed.diversity_met());
        assert_eq!(placed.distinct_asns, 0);
        assert_eq!(placed.distinct_regions, 0);
    }

    #[test]
    fn regions_count_when_no_asn_is_reported() {
        let candidates = [op(1, 0, 10), op(2, 0, 20), op(3, 0, 10)];
        let placed = place_replicas(&candidates, 2).expect("place");
        assert_eq!(placed.distinct_regions, 2);
        assert!(placed.diversity_met());
        assert_ne!(placed.operators[0][0], placed.operators[1][0]);
    }

    #[test]
    fn duplicate_operator_is_not_two_replicas() {
        let candidates = [op(1, 100, 1), op(1, 200, 2)];
        let placed = place_replicas(&candidates, 2).expect("place");
        assert_eq!(placed.operators.len(), 1);
    }

    #[test]
    fn zero_wanted_and_empty_candidates_fail() {
        assert_eq!(
            place_replicas(&[op(1, 1, 1)], 0),
            Err(PlacementError::WantedZero)
        );
        assert_eq!(place_replicas(&[], 3), Err(PlacementError::NoCandidates));
    }

    #[test]
    fn ties_break_on_the_smaller_operator_id() {
        let candidates = [op(9, 100, 1), op(2, 200, 2)];
        let placed = place_replicas(&candidates, 1).expect("place");
        assert_eq!(placed.operators[0][0], 2);
    }
}
