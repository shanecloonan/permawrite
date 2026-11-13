//! Zero-fee solvency stress for the permanence upgrade (**B-315**).
//!
//! Not read by `apply_block`. The model uses the shipped endowment and
//! emission helpers (one formula each) and answers two questions:
//!
//! 1. If storage-cost deflation stalls, how long does the endowment
//!    principal alone pay `C0` for one 1 GiB x `min_replication` file?
//! 2. With the robust parameter bundle (subsidy tail split, sized prize,
//!    full-year cold credit), how many such files stay funded for a
//!    century of zero fees?
//!
//! Path A defaults are not mutated. The robust bundle is a local copy.

use mfn_storage::{
    first_year_cost_base_units, recommended_backstop_proof_reward, required_endowment,
    BACKSTOP_REFERENCE_SIZE_BYTES, DEFAULT_ENDOWMENT_PARAMS, PPB,
};

use crate::emission::{
    annual_tail_emission, recommended_backstop_mint_cap_per_year, recommended_tail_emission,
    EmissionParams, DEFAULT_EMISSION_PARAMS,
};

/// How much operators are paid per file per year in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColdCreditPolicy {
    /// Path A: drip is off, and the 0.1 MFN prize is paid once per hot window.
    PathAPrize,
    /// Cold cadence, but each proof credits only the hot window. Pays about
    /// `C0 / 15` plus a sized prize — under the real stall cost.
    HotWindow,
    /// Cold cadence plus a remainder proof cover `slots_per_year` of drip
    /// (`C0`) plus one sized prize per cold proof. The activation rule.
    FullYear,
}

/// Which numbers the stress run uses. None of these write genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermanenceBundle {
    /// Live defaults: drip off, prize `0.1 MFN`, subsidy bps `0`, tail `>> 8`.
    PathA,
    /// Robust: subsidy `1000` bps, B-306c prize, tail stays `>> 8` (more
    /// files under a stall than the dilution tail).
    Robust,
    /// Same economics as [`PermanenceBundle::Robust`] but tail is
    /// [`recommended_tail_emission`] (`>> 9`). Fewer files, less dilution.
    RobustSmallerTail,
}

/// Where the year's payment comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingMode {
    /// Endowment principal only. No subsidy, no fees, no mint.
    EndowmentOnly,
    /// Endowment principal plus the bundle's tail subsidy, fees, and
    /// (when enabled) the backstop cap.
    Bundle,
}

/// Inputs to [`stress_solvency`]. One reference file is 1 GiB at
/// `min_replication` (default 3), anchored at year 0. Population is constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StressInput {
    /// Parameter bundle. Does not alter [`DEFAULT_EMISSION_PARAMS`].
    pub bundle: PermanenceBundle,
    /// Endowment-only isolates Kryder vs stall. Bundle adds subsidy.
    pub funding: FundingMode,
    /// Horizon in years. `100` is past the ~51-year endowment-only stall.
    pub years: u32,
    /// Realized annual cost decline, ppb. `0` = Kryder stalls. The endowment
    /// was priced at `inflation_ppb` (20_000_000).
    pub realized_deflation_ppb: u64,
    /// Fee volume already routed to the treasury, base units per year.
    pub annual_fee_to_treasury: u128,
    /// Count of reference files. Each contributes its own `E0` at year 0.
    pub reference_files: u64,
    /// When true, emergency mint cannot exceed 1% of that bundle's annual tail.
    pub enforce_backstop_cap: bool,
    /// How much of `C0` the drip formula is assumed to pay.
    pub cold_credit: ColdCreditPolicy,
}

/// One year of the stress ledger. All figures are base units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StressYear {
    /// Index from 0.
    pub year: u32,
    /// Real storage cost of the whole population this year.
    pub physical_cost: u128,
    /// What the protocol pays operators this year (population).
    pub protocol_pay: u128,
    /// `max(physical_cost, protocol_pay)` — the treasury must cover both
    /// the real disks and the prize it promised.
    pub obligation: u128,
    /// Tail subsidy credited to the treasury.
    pub subsidy_credit: u128,
    /// Fees credited.
    pub fee_credit: u128,
    /// Fresh mint used as backstop this year.
    pub backstop_minted: u128,
    /// Obligation still unpaid after mint.
    pub unmet: u128,
    /// Treasury after the year.
    pub treasury_end: u128,
}

/// Whether the horizon stayed solvent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolvencyVerdict {
    /// Every year paid. `backstop_minted` is the sum. `treasury_empty_year`
    /// is the first year the balance hit 0 (still solvent if obligation was paid).
    Covered {
        /// Horizon length.
        years: u32,
        /// Sum of emergency mint.
        backstop_minted: u128,
        /// First year treasury ended at 0, if any.
        treasury_empty_year: Option<u32>,
    },
    /// First year the cap (or a hard zero mint) left a gap.
    Shortfall {
        /// Year index.
        first_year: u32,
        /// Unpaid base units that year.
        unmet: u128,
    },
}

/// Full ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StressReport {
    /// Per-year rows. Empty when `years` is 0.
    pub years: Vec<StressYear>,
    /// Horizon verdict.
    pub verdict: SolvencyVerdict,
    /// `C0` of one reference file (year-0 physical, one file).
    pub per_file_c0: u128,
    /// `E0` locked per file.
    pub endowment_per_file: u128,
    /// Protocol pay for one file, constant across years in this model.
    pub per_file_protocol_pay: u128,
    /// Annual subsidy credit (0 in endowment-only mode).
    pub annual_subsidy_credit: u128,
}

/// Why a stress run refused to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StressError {
    /// `realized_deflation_ppb >= PPB` (100% or more per year).
    DeflationAtLeast100Percent,
    /// A product did not fit in `u128`.
    Overflow,
    /// Endowment or emission helper rejected the parameters.
    Pricing,
}

/// Local robust numbers. Tail stays at the Path A `>> 8` value unless
/// `smaller_tail` is set. Subsidy split is 1000 bps. Prize is the B-306c
/// backstop. Does not write defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RobustParameterSet {
    /// Per-block tail.
    pub tail_emission: u64,
    /// `subsidy_to_treasury_bps`.
    pub subsidy_to_treasury_bps: u16,
    /// Unchanged fee split (arm B-309 separately, after this fork).
    pub fee_to_treasury_bps: u16,
    /// Per-proof prize.
    pub storage_proof_reward: u64,
    /// `1` in the robust set.
    pub deflation_funded_drip: u8,
    /// Not priced here; bonds live on the endowment helper. This flag is the
    /// drip byte so a reader can see the bundle is not Path A.
    pub cold_credit: ColdCreditPolicy,
}

/// The robust bundle. `smaller_tail` selects B-313's `>> 9` tail.
///
/// # Errors
///
/// [`StressError::Pricing`] if the backstop prize helper fails.
pub fn robust_parameter_set(smaller_tail: bool) -> Result<RobustParameterSet, StressError> {
    let tail = if smaller_tail {
        recommended_tail_emission(&DEFAULT_EMISSION_PARAMS)
    } else {
        DEFAULT_EMISSION_PARAMS.tail_emission
    };
    let prize = recommended_backstop_proof_reward(&DEFAULT_ENDOWMENT_PARAMS)
        .map_err(|_| StressError::Pricing)?;
    Ok(RobustParameterSet {
        tail_emission: tail,
        subsidy_to_treasury_bps: 1_000,
        fee_to_treasury_bps: DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps,
        storage_proof_reward: prize,
        deflation_funded_drip: 1,
        cold_credit: ColdCreditPolicy::FullYear,
    })
}

/// Years of physical cost one file's `E0` can pay, capped at `max_years`.
///
/// `realized_deflation_ppb = 0` is a stall (cost stays `C0`). The value the
/// endowment was priced on is `DEFAULT_ENDOWMENT_PARAMS.inflation_ppb`.
///
/// # Errors
///
/// [`StressError`] on a bad deflation rate or overflow.
pub fn endowment_covers_physical_years(
    realized_deflation_ppb: u64,
    max_years: u32,
) -> Result<u32, StressError> {
    let input = StressInput {
        bundle: PermanenceBundle::PathA,
        funding: FundingMode::EndowmentOnly,
        years: max_years,
        realized_deflation_ppb,
        annual_fee_to_treasury: 0,
        reference_files: 1,
        enforce_backstop_cap: true,
        cold_credit: ColdCreditPolicy::FullYear,
    };
    let report = stress_solvency(&input)?;
    let mut covered = 0u32;
    for row in &report.years {
        if row.unmet > 0 {
            break;
        }
        covered += 1;
    }
    Ok(covered)
}

/// Largest `reference_files` in `0..=search_cap` that stays covered with
/// **zero** backstop mint. `search_cap` itself is returned when it still
/// qualifies (the search saturated).
///
/// # Errors
///
/// [`StressError`] from the underlying run.
pub fn max_files_covered_without_mint(
    input: &StressInput,
    search_cap: u64,
) -> Result<u64, StressError> {
    if search_cap == 0 {
        return Ok(0);
    }
    let mut lo = 0u64;
    let mut hi = search_cap;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let mut probe = *input;
        probe.reference_files = mid;
        let report = stress_solvency(&probe)?;
        if covered_without_mint(&report.verdict) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// Run the ledger.
///
/// # Errors
///
/// [`StressError`] when deflation is not a rate or a product overflows.
pub fn stress_solvency(input: &StressInput) -> Result<StressReport, StressError> {
    if u128::from(input.realized_deflation_ppb) >= PPB {
        return Err(StressError::DeflationAtLeast100Percent);
    }
    let params = DEFAULT_ENDOWMENT_PARAMS;
    let c0 = first_year_cost_base_units(
        BACKSTOP_REFERENCE_SIZE_BYTES,
        params.min_replication,
        &params,
    )
    .map_err(|_| StressError::Pricing)?;
    let e0 = required_endowment(
        BACKSTOP_REFERENCE_SIZE_BYTES,
        params.min_replication,
        &params,
    )
    .map_err(|_| StressError::Pricing)?;
    let emission = emission_for(input.bundle)?;
    let per_file_protocol = per_file_protocol_pay(input.cold_credit, c0, &emission)?;
    let subsidy_one_year = match input.funding {
        FundingMode::EndowmentOnly => 0,
        FundingMode::Bundle => {
            annual_tail_emission(params.slots_per_year, &emission)
                * u128::from(emission.subsidy_to_treasury_bps)
                / 10_000
        }
    };
    let cap = match input.funding {
        FundingMode::EndowmentOnly => 0,
        FundingMode::Bundle if input.enforce_backstop_cap => {
            recommended_backstop_mint_cap_per_year(params.slots_per_year, &emission)
        }
        FundingMode::Bundle => u128::MAX,
    };
    let files = u128::from(input.reference_files);
    let mut treasury = files.checked_mul(e0).ok_or(StressError::Overflow)?;
    let mut minted_total = 0u128;
    let mut empty_year = None;
    let mut verdict = SolvencyVerdict::Covered {
        years: input.years,
        backstop_minted: 0,
        treasury_empty_year: None,
    };
    let mut rows = Vec::with_capacity(input.years as usize);
    let mut cost = c0;
    let keep = PPB - u128::from(input.realized_deflation_ppb);
    for year in 0..input.years {
        let physical_one = cost;
        let physical = files
            .checked_mul(physical_one)
            .ok_or(StressError::Overflow)?;
        let protocol = files
            .checked_mul(per_file_protocol)
            .ok_or(StressError::Overflow)?;
        let obligation = match input.funding {
            FundingMode::EndowmentOnly => physical,
            FundingMode::Bundle => physical.max(protocol),
        };
        let subsidy = subsidy_one_year;
        let fee = input.annual_fee_to_treasury;
        let inflow = subsidy.saturating_add(fee);
        let available = treasury.saturating_add(inflow);
        let (mint, unmet, end) = settle(available, obligation, cap);
        minted_total = minted_total.saturating_add(mint);
        if end == 0 && empty_year.is_none() {
            empty_year = Some(year);
        }
        rows.push(StressYear {
            year,
            physical_cost: physical,
            protocol_pay: protocol,
            obligation,
            subsidy_credit: subsidy,
            fee_credit: fee,
            backstop_minted: mint,
            unmet,
            treasury_end: end,
        });
        if unmet > 0 {
            verdict = SolvencyVerdict::Shortfall {
                first_year: year,
                unmet,
            };
            // Keep the failing year, stop. Later years would all be unmet.
            break;
        }
        treasury = end;
        if input.realized_deflation_ppb != 0 {
            cost = ceil_div(cost.saturating_mul(keep), PPB).min(c0);
        }
    }
    if let SolvencyVerdict::Covered { .. } = verdict {
        verdict = SolvencyVerdict::Covered {
            years: input.years,
            backstop_minted: minted_total,
            treasury_empty_year: empty_year,
        };
    }
    Ok(StressReport {
        years: rows,
        verdict,
        per_file_c0: c0,
        endowment_per_file: e0,
        per_file_protocol_pay: per_file_protocol,
        annual_subsidy_credit: subsidy_one_year,
    })
}

fn emission_for(bundle: PermanenceBundle) -> Result<EmissionParams, StressError> {
    let mut emission = DEFAULT_EMISSION_PARAMS;
    match bundle {
        PermanenceBundle::PathA => {}
        PermanenceBundle::Robust => {
            let set = robust_parameter_set(false)?;
            emission.tail_emission = set.tail_emission;
            emission.subsidy_to_treasury_bps = set.subsidy_to_treasury_bps;
            emission.storage_proof_reward = set.storage_proof_reward;
        }
        PermanenceBundle::RobustSmallerTail => {
            let set = robust_parameter_set(true)?;
            emission.tail_emission = set.tail_emission;
            emission.subsidy_to_treasury_bps = set.subsidy_to_treasury_bps;
            emission.storage_proof_reward = set.storage_proof_reward;
        }
    }
    Ok(emission)
}

fn per_file_protocol_pay(
    credit: ColdCreditPolicy,
    c0: u128,
    emission: &EmissionParams,
) -> Result<u128, StressError> {
    let slots = DEFAULT_ENDOWMENT_PARAMS.slots_per_year;
    let hot = DEFAULT_ENDOWMENT_PARAMS.proof_reward_window_slots.max(1);
    let cold = mfn_storage::RECOMMENDED_COLD_PROOF_MAX_INTERVAL_SLOTS.max(1);
    let (proofs, drip) = match credit {
        ColdCreditPolicy::PathAPrize => (slots / hot, 0),
        ColdCreditPolicy::HotWindow => {
            let proofs = slots / cold;
            let drip = c0.saturating_mul(u128::from(proofs)) * u128::from(hot) / u128::from(slots);
            (proofs, drip)
        }
        ColdCreditPolicy::FullYear => (slots / cold, c0),
    };
    let prize = u128::from(emission.storage_proof_reward);
    let prize_pay = u128::from(proofs)
        .checked_mul(prize)
        .ok_or(StressError::Overflow)?;
    Ok(drip.saturating_add(prize_pay))
}

fn settle(available: u128, obligation: u128, cap: u128) -> (u128, u128, u128) {
    if available >= obligation {
        return (0, 0, available - obligation);
    }
    let shortfall = obligation - available;
    let mint = shortfall.min(cap);
    let unmet = shortfall - mint;
    (mint, unmet, 0)
}

fn covered_without_mint(verdict: &SolvencyVerdict) -> bool {
    matches!(
        verdict,
        SolvencyVerdict::Covered {
            backstop_minted: 0,
            ..
        }
    )
}

fn ceil_div(num: u128, den: u128) -> u128 {
    if den == 0 {
        return 0;
    }
    num.div_ceil(den)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_input(bundle: PermanenceBundle, years: u32, files: u64, cap: bool) -> StressInput {
        StressInput {
            bundle,
            funding: FundingMode::Bundle,
            years,
            realized_deflation_ppb: 0,
            annual_fee_to_treasury: 0,
            reference_files: files,
            enforce_backstop_cap: cap,
            cold_credit: match bundle {
                PermanenceBundle::PathA => ColdCreditPolicy::PathAPrize,
                PermanenceBundle::Robust | PermanenceBundle::RobustSmallerTail => {
                    ColdCreditPolicy::FullYear
                }
            },
        }
    }

    #[test]
    fn b315_defaults_are_not_the_robust_bundle() {
        let robust = robust_parameter_set(false).expect("robust");
        assert_eq!(robust.tail_emission, DEFAULT_EMISSION_PARAMS.tail_emission);
        assert_eq!(robust.subsidy_to_treasury_bps, 1_000);
        assert_eq!(robust.deflation_funded_drip, 1);
        assert_eq!(robust.fee_to_treasury_bps, 9_000);
        assert!(robust.storage_proof_reward < DEFAULT_EMISSION_PARAMS.storage_proof_reward);
        assert_eq!(DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps, 0);
        assert_eq!(DEFAULT_ENDOWMENT_PARAMS.deflation_funded_drip, 0);
        assert_eq!(DEFAULT_ENDOWMENT_PARAMS.min_storage_operator_bond, 0);
        let smaller = robust_parameter_set(true).expect("smaller");
        assert!(smaller.tail_emission < robust.tail_emission);
        assert!(smaller.tail_emission > 0);
    }

    #[test]
    fn b315_stall_endowment_lasts_51_years_kryder_lasts_the_horizon() {
        assert_eq!(endowment_covers_physical_years(0, 400).expect("stall"), 51);
        assert_eq!(
            endowment_covers_physical_years(DEFAULT_ENDOWMENT_PARAMS.inflation_ppb, 200)
                .expect("kryder"),
            200
        );
        let stall = stress_solvency(&StressInput {
            bundle: PermanenceBundle::PathA,
            funding: FundingMode::EndowmentOnly,
            years: 60,
            realized_deflation_ppb: 0,
            annual_fee_to_treasury: 0,
            reference_files: 1,
            enforce_backstop_cap: true,
            cold_credit: ColdCreditPolicy::FullYear,
        })
        .expect("stall report");
        assert_eq!(stall.per_file_c0, 644_245);
        assert_eq!(stall.endowment_per_file, 32_856_500);
        assert!(matches!(
            stall.verdict,
            SolvencyVerdict::Shortfall { first_year: 51, .. }
        ));
    }

    #[test]
    fn b315_hot_window_credit_underpays_a_cold_file() {
        let emission = emission_for(PermanenceBundle::Robust).expect("emission");
        let c0 = 644_245u128;
        let hot = per_file_protocol_pay(ColdCreditPolicy::HotWindow, c0, &emission).expect("hot");
        let full = per_file_protocol_pay(ColdCreditPolicy::FullYear, c0, &emission).expect("full");
        assert!(hot < c0);
        assert!(full >= c0);
    }

    #[test]
    fn b315_robust_one_file_century_stall_needs_no_mint() {
        let report =
            stress_solvency(&bundle_input(PermanenceBundle::Robust, 100, 1, true)).expect("robust");
        assert!(matches!(
            report.verdict,
            SolvencyVerdict::Covered {
                backstop_minted: 0,
                ..
            }
        ));
        let path_a =
            stress_solvency(&bundle_input(PermanenceBundle::PathA, 100, 1, false)).expect("path a");
        match path_a.verdict {
            SolvencyVerdict::Covered {
                backstop_minted, ..
            } => assert!(backstop_minted > 0),
            SolvencyVerdict::Shortfall { .. } => panic!("uncapped path A should mint through"),
        }
    }

    #[test]
    fn b315_path_a_prize_exceeds_the_cap_once_many_files_exist() {
        let one = stress_solvency(&bundle_input(PermanenceBundle::PathA, 5, 1, true)).expect("one");
        assert!(matches!(
            one.verdict,
            SolvencyVerdict::Covered {
                backstop_minted,
                ..
            } if backstop_minted > 0
        ));
        let many =
            stress_solvency(&bundle_input(PermanenceBundle::PathA, 5, 200, true)).expect("many");
        assert!(matches!(many.verdict, SolvencyVerdict::Shortfall { .. }));
    }

    #[test]
    fn b315_smaller_tail_funds_fewer_files_than_robust_tail() {
        let horizon = bundle_input(PermanenceBundle::Robust, 100, 1, true);
        let robust_n = max_files_covered_without_mint(&horizon, 50_000_000).expect("robust n");
        let mut small = horizon;
        small.bundle = PermanenceBundle::RobustSmallerTail;
        let small_n = max_files_covered_without_mint(&small, 50_000_000).expect("small n");
        assert!(robust_n > 1_000_000);
        assert!(small_n > 1_000_000);
        assert!(small_n < robust_n);
        assert_eq!(robust_n, 15_248_750);
        assert_eq!(small_n, 7_624_375);
        let mut at = horizon;
        at.reference_files = robust_n;
        assert!(covered_without_mint(
            &stress_solvency(&at).expect("at").verdict
        ));
        let mut over = at;
        over.reference_files = robust_n + 1;
        assert!(!covered_without_mint(
            &stress_solvency(&over).expect("over").verdict
        ));
    }

    #[test]
    fn b315_kryder_lowers_physical_cost_and_stall_does_not() {
        let mut stall = bundle_input(PermanenceBundle::Robust, 40, 1, true);
        stall.funding = FundingMode::EndowmentOnly;
        stall.cold_credit = ColdCreditPolicy::FullYear;
        let stall_report = stress_solvency(&stall).expect("stall");
        let mut kryder = stall;
        kryder.realized_deflation_ppb = DEFAULT_ENDOWMENT_PARAMS.inflation_ppb;
        kryder.years = 40;
        let kryder_report = stress_solvency(&kryder).expect("kryder");
        let stall_last = stall_report.years.last().expect("stall year").physical_cost;
        let kryder_last = kryder_report
            .years
            .last()
            .expect("kryder year")
            .physical_cost;
        assert_eq!(stall_last, stall_report.per_file_c0);
        assert!(kryder_last < stall_last);
    }
}
