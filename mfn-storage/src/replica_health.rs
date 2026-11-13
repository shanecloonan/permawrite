//! Replica teeth for a later permanence fork (**B-315** helpers; not wired).
//!
//! Path A prices `replication` into the endowment and, on public devnet,
//! accepts operator-salted proofs. It does not require distinct seals, a
//! second failure domain, or a retrieval receipt. These functions name that
//! policy so a future `apply_block` can call them instead of inventing a
//! second formula. Nothing here is read by consensus today.

use mfn_crypto::dhash;
use mfn_crypto::domain::REPLICA_SEAL;

/// Extra repair bounty per missing replica, in basis points (`+50%` each).
pub const REPAIR_BOUNTY_STEP_BPS: u16 = 5_000;

/// Cap so a fully missing file cannot unbounded-inflate the prize (2.5x).
pub const REPAIR_BOUNTY_CAP_BPS: u16 = 25_000;

/// Full payout weight when the replica set meets the rules that apply.
pub const REPLICA_PAYOUT_FULL_BPS: u16 = 10_000;

/// Payout weight when counts meet the target but every reported failure
/// domain is the same. The withheld half is the repair bounty for a new domain.
pub const REPLICA_PAYOUT_CONCENTRATED_BPS: u16 = 5_000;

/// Payout weight when geography is only partly diverse.
pub const REPLICA_PAYOUT_PARTIAL_BPS: u16 = 7_500;

/// Minimum distinct reported failure domains before geography counts as met.
/// Two is the feasible bar (a second host), not "one region per replica".
pub const MIN_DIVERSE_FAILURE_DOMAINS: u16 = 2;

/// Why a replica-window observation cannot be scored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaAssessError {
    /// `target_replication` was 0. The endowment floor is at least 1.
    TargetZero,
    /// `seal_roots` length does not match `operator_ids`.
    SealLenMismatch,
    /// `asns` length does not match `operator_ids`.
    AsnLenMismatch,
    /// `regions` length does not match `operator_ids`.
    RegionLenMismatch,
}

/// Geography of the provers in one window. Unknown is not a failure:
/// diversity is required only where operators actually report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoClass {
    /// No non-zero ASN and no non-zero region was reported.
    Unknown,
    /// Every reported ASN is one value and every reported region is one value.
    Concentrated,
    /// More than one domain, but fewer than [`MIN_DIVERSE_FAILURE_DOMAINS`]
    /// on the axis that was reported.
    Partial,
    /// At least [`MIN_DIVERSE_FAILURE_DOMAINS`] regions, or (when regions are
    /// absent) that many ASNs.
    Satisfied,
}

/// What one proof window says about a single commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaAssessment {
    /// Unique `operator_identity_from_payout` values.
    pub distinct_operators: u16,
    /// Unique [`replica_seal_root`] values. Fewer seals than operators means
    /// at least two keys presented one encoding.
    pub distinct_seals: u16,
    /// `target - min(operators, seals)`, saturating at 255.
    pub shortfall: u8,
    /// Operators beyond the distinct seal count (Sybil surplus).
    pub sybil_surplus: u16,
    /// Reported geography. Does not by itself zero the replica count.
    pub geo: GeoClass,
}

/// One commitment's provers in a window.
///
/// `asns` / `regions` use `0` for "not reported". Those zeros are not a
/// failure domain.
#[derive(Clone, Copy, Debug)]
pub struct ReplicaWindow<'a> {
    /// Protocol minimum (`EndowmentParams::min_replication`, default 3).
    pub target_replication: u8,
    /// One id per accepted proof, from `operator_identity_from_payout`.
    pub operator_ids: &'a [[u8; 32]],
    /// Seal root parallel to `operator_ids`.
    pub seal_roots: &'a [[u8; 32]],
    /// ASN parallel to `operator_ids`. `0` = not reported.
    pub asns: &'a [u32],
    /// Region code parallel to `operator_ids`. `0` = not reported.
    pub regions: &'a [u16],
}

/// Retrieval-audit outcome. Timeout is not slashable: an eclipse can look
/// like silence. Only a positive proof of bad bytes or a signed refusal
/// is slash-eligible. Timeout still opens a repair bounty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrievalAudit {
    /// Served bytes match the challenged chunk hash.
    Served,
    /// Served bytes hash to something other than the challenged chunk.
    ProvableMismatch,
    /// Operator signed a refusal of the challenge.
    SignedRefusal,
    /// No response before the window closed.
    Timeout,
}

/// `dhash(REPLICA_SEAL, operator_id, data_root, replica_index)`.
///
/// Same inputs are stable. A different operator, root, or index is a
/// different seal, so copying one replica's chunks under another key does
/// not satisfy a second seal check. Not written into `ChunkV2` today.
#[must_use]
pub fn replica_seal_root(
    operator_id: &[u8; 32],
    data_root: &[u8; 32],
    replica_index: u8,
) -> [u8; 32] {
    let index = [replica_index];
    dhash(REPLICA_SEAL, &[operator_id, data_root, &index])
}

/// Score one window. Does not touch chain state.
///
/// # Errors
///
/// [`ReplicaAssessError`] when the target is 0 or the parallel slices disagree.
pub fn assess_replica_window(
    window: ReplicaWindow<'_>,
) -> Result<ReplicaAssessment, ReplicaAssessError> {
    if window.target_replication == 0 {
        return Err(ReplicaAssessError::TargetZero);
    }
    let n = window.operator_ids.len();
    if window.seal_roots.len() != n {
        return Err(ReplicaAssessError::SealLenMismatch);
    }
    if window.asns.len() != n {
        return Err(ReplicaAssessError::AsnLenMismatch);
    }
    if window.regions.len() != n {
        return Err(ReplicaAssessError::RegionLenMismatch);
    }
    let distinct_operators = distinct_len(window.operator_ids);
    let distinct_seals = distinct_len(window.seal_roots);
    let unique = distinct_operators.min(distinct_seals);
    let shortfall_u16 = u16::from(window.target_replication).saturating_sub(unique);
    let shortfall = u8::try_from(shortfall_u16).unwrap_or(u8::MAX);
    let sybil_surplus = distinct_operators.saturating_sub(distinct_seals);
    Ok(ReplicaAssessment {
        distinct_operators,
        distinct_seals,
        shortfall,
        sybil_surplus,
        geo: classify_geo(window.asns, window.regions),
    })
}

/// Repair-bounty multiplier. `10_000` = 1.0x when the set is whole.
/// Each missing replica adds [`REPAIR_BOUNTY_STEP_BPS`], capped at
/// [`REPAIR_BOUNTY_CAP_BPS`]. Do not also multiply by the cold bounty in the
/// same fork; pick one escalator per proof.
#[must_use]
pub fn repair_bounty_multiplier_bps(shortfall: u8) -> u16 {
    let extra = u32::from(shortfall) * u32::from(REPAIR_BOUNTY_STEP_BPS);
    let raised = u32::from(REPLICA_PAYOUT_FULL_BPS).saturating_add(extra);
    u16::try_from(raised.min(u32::from(REPAIR_BOUNTY_CAP_BPS))).unwrap_or(REPAIR_BOUNTY_CAP_BPS)
}

/// Payout weight for provers in this window.
///
/// Shortfall pays `0` here (the repair bounty is the incentive, not a full
/// prize for an incomplete set). A Sybil surplus does not increase weight.
/// Concentrated geography pays half when the count is otherwise met.
#[must_use]
pub fn replica_payout_weight_bps(assessment: &ReplicaAssessment) -> u16 {
    if assessment.shortfall > 0 {
        return 0;
    }
    match assessment.geo {
        GeoClass::Unknown | GeoClass::Satisfied => REPLICA_PAYOUT_FULL_BPS,
        GeoClass::Partial => REPLICA_PAYOUT_PARTIAL_BPS,
        GeoClass::Concentrated => REPLICA_PAYOUT_CONCENTRATED_BPS,
    }
}

/// `true` when the audit is evidence enough to slash a bond.
/// Timeout is excluded on purpose.
#[must_use]
pub fn retrieval_slash_eligible(audit: RetrievalAudit) -> bool {
    matches!(
        audit,
        RetrievalAudit::ProvableMismatch | RetrievalAudit::SignedRefusal
    )
}

/// `true` when the file should open a repair bounty (anything but a good serve).
#[must_use]
pub fn retrieval_opens_repair_bounty(audit: RetrievalAudit) -> bool {
    !matches!(audit, RetrievalAudit::Served)
}

/// `true` when distinct operators and distinct seals both cover
/// `target_replication`.
///
/// A repeated bond identity or a repeated seal lowers the unique count, so
/// the shortfall is non-zero and this returns false. Not read by
/// `apply_block`: today's proofs do not carry a seal root, and rejecting
/// them would fork Path A and F-A.
#[must_use]
pub fn distinct_replica_floor_met(assessment: &ReplicaAssessment) -> bool {
    assessment.shortfall == 0
}

fn distinct_len(rows: &[[u8; 32]]) -> u16 {
    let mut v = rows.to_vec();
    v.sort_unstable();
    v.dedup();
    u16::try_from(v.len()).unwrap_or(u16::MAX)
}

fn distinct_nonzero_u32(values: &[u32]) -> u16 {
    let mut v: Vec<u32> = values.iter().copied().filter(|x| *x != 0).collect();
    v.sort_unstable();
    v.dedup();
    u16::try_from(v.len()).unwrap_or(u16::MAX)
}

fn distinct_nonzero_u16(values: &[u16]) -> u16 {
    let mut v: Vec<u16> = values.iter().copied().filter(|x| *x != 0).collect();
    v.sort_unstable();
    v.dedup();
    u16::try_from(v.len()).unwrap_or(u16::MAX)
}

fn classify_geo(asns: &[u32], regions: &[u16]) -> GeoClass {
    let asn_n = distinct_nonzero_u32(asns);
    let region_n = distinct_nonzero_u16(regions);
    if asn_n == 0 && region_n == 0 {
        return GeoClass::Unknown;
    }
    if region_n >= MIN_DIVERSE_FAILURE_DOMAINS
        || (region_n == 0 && asn_n >= MIN_DIVERSE_FAILURE_DOMAINS)
    {
        return GeoClass::Satisfied;
    }
    if region_n <= 1 && asn_n <= 1 {
        return GeoClass::Concentrated;
    }
    GeoClass::Partial
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn b315_seal_root_is_stable_and_operator_unique() {
        let root = [7u8; 32];
        let a = replica_seal_root(&id(1), &root, 0);
        let b = replica_seal_root(&id(1), &root, 0);
        let other_op = replica_seal_root(&id(2), &root, 0);
        let other_index = replica_seal_root(&id(1), &root, 1);
        assert_eq!(a, b);
        assert_ne!(a, other_op);
        assert_ne!(a, other_index);
    }

    #[test]
    fn b315_three_seals_meet_target_and_one_disk_does_not() {
        let ops = [id(1), id(2), id(3)];
        let seals = [id(10), id(11), id(12)];
        let asns = [0u32; 3];
        let regions = [0u16; 3];
        let ok = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &seals,
            asns: &asns,
            regions: &regions,
        })
        .expect("assess");
        assert_eq!(ok.shortfall, 0);
        assert_eq!(ok.sybil_surplus, 0);
        assert_eq!(ok.geo, GeoClass::Unknown);
        assert_eq!(replica_payout_weight_bps(&ok), REPLICA_PAYOUT_FULL_BPS);

        let shared = [id(10), id(10), id(10)];
        let sybil = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &shared,
            asns: &asns,
            regions: &regions,
        })
        .expect("assess");
        assert_eq!(sybil.distinct_seals, 1);
        assert_eq!(sybil.shortfall, 2);
        assert_eq!(sybil.sybil_surplus, 2);
        assert_eq!(replica_payout_weight_bps(&sybil), 0);
    }

    #[test]
    fn b315_geo_unknown_is_not_failure_and_one_region_pays_half() {
        let ops = [id(1), id(2), id(3)];
        let seals = [id(10), id(11), id(12)];
        let one_region = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &seals,
            asns: &[64500, 64500, 64500],
            regions: &[1, 1, 1],
        })
        .expect("assess");
        assert_eq!(one_region.geo, GeoClass::Concentrated);
        assert_eq!(one_region.shortfall, 0);
        assert_eq!(
            replica_payout_weight_bps(&one_region),
            REPLICA_PAYOUT_CONCENTRATED_BPS
        );

        let two_regions = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &seals,
            asns: &[1, 2, 1],
            regions: &[1, 2, 1],
        })
        .expect("assess");
        assert_eq!(two_regions.geo, GeoClass::Satisfied);
        assert_eq!(
            replica_payout_weight_bps(&two_regions),
            REPLICA_PAYOUT_FULL_BPS
        );
    }

    #[test]
    fn b315_repair_bounty_steps_then_caps() {
        assert_eq!(repair_bounty_multiplier_bps(0), 10_000);
        assert_eq!(repair_bounty_multiplier_bps(1), 15_000);
        assert_eq!(repair_bounty_multiplier_bps(3), 25_000);
        assert_eq!(repair_bounty_multiplier_bps(255), 25_000);
    }

    #[test]
    fn b315_retrieval_timeout_is_bounty_not_slash() {
        assert!(!retrieval_slash_eligible(RetrievalAudit::Timeout));
        assert!(retrieval_opens_repair_bounty(RetrievalAudit::Timeout));
        assert!(retrieval_slash_eligible(RetrievalAudit::ProvableMismatch));
        assert!(retrieval_slash_eligible(RetrievalAudit::SignedRefusal));
        assert!(!retrieval_slash_eligible(RetrievalAudit::Served));
        assert!(!retrieval_opens_repair_bounty(RetrievalAudit::Served));
    }

    #[test]
    fn duplicate_bond_identity_misses_the_replica_floor() {
        let ops = [id(1), id(1), id(1)];
        let seals = [id(10), id(11), id(12)];
        let got = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &seals,
            asns: &[0, 0, 0],
            regions: &[0, 0, 0],
        })
        .expect("assess");
        assert_eq!(got.distinct_operators, 1);
        assert!(!distinct_replica_floor_met(&got));
        let distinct = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &[id(1), id(2), id(3)],
            seal_roots: &seals,
            asns: &[0, 0, 0],
            regions: &[0, 0, 0],
        })
        .expect("assess");
        assert!(distinct_replica_floor_met(&distinct));
    }

    #[test]
    fn b315_mismatched_slices_fail_closed() {
        let ops = [id(1), id(2)];
        let err = assess_replica_window(ReplicaWindow {
            target_replication: 3,
            operator_ids: &ops,
            seal_roots: &[id(1)],
            asns: &[0, 0],
            regions: &[0, 0],
        });
        assert_eq!(err, Err(ReplicaAssessError::SealLenMismatch));
        assert_eq!(
            assess_replica_window(ReplicaWindow {
                target_replication: 0,
                operator_ids: &[],
                seal_roots: &[],
                asns: &[],
                regions: &[],
            }),
            Err(ReplicaAssessError::TargetZero)
        );
    }
}
