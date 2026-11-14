//! Long-horizon check that repair plus an endowment keep a file alive.
//!
//! Twelve operators each hold one shard of a 12-shard stripe. Any four
//! shards rebuild the file. Each year a fixed number of operators leave.
//! If the file's endowment can still pay the annual storage cost, the
//! survivors copy the missing shards onto the operators that replaced
//! them. The cost and the opening balance come from the live endowment
//! helpers. This does not change consensus and does not touch Path A.

use crate::endowment::{
    endowment_annual_runway, first_year_cost_base_units, required_endowment, EndowmentParams,
    EndowmentRunwayAlert,
};

/// Shards in the stripe this simulation repairs.
pub const SIM_SHARDS: u32 = 12;
/// Shards required to rebuild one file.
pub const SIM_REPAIR_THRESHOLD: u32 = 4;

/// Inputs for one run. All fields are integers.
#[derive(Clone, Debug)]
pub struct PermanenceSim {
    /// How many years to step.
    pub years: u32,
    /// How many operators, one shard each at the start. Must be 12.
    pub operators: u32,
    /// Operators who leave at the start of each year, then get replaced.
    pub losses_per_year: u32,
    /// Copy missing shards back when four or more remain.
    pub repair: bool,
    /// Pay the annual cost from the endowment. When false, repair is refused.
    pub pay_endowment: bool,
    /// File size used to price the endowment.
    pub size_bytes: u64,
    /// Replication factor passed to the endowment formula.
    pub replication: u8,
    /// Schedule. Use [`crate::DEFAULT_ENDOWMENT_PARAMS`] for the documented run.
    pub params: EndowmentParams,
}

/// What the run concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermanenceReport {
    /// Files still reconstructable after `years`.
    pub files_alive: u32,
    /// Files that dropped below four shards.
    pub files_lost: u32,
    /// Annual storage cost `C₀` in base units.
    pub annual_cost: u128,
    /// Opening endowment in base units.
    pub endowment: u128,
    /// How many annual costs the opening endowment covers.
    pub runway_years: u128,
    /// Years actually stepped.
    pub years_simulated: u32,
}

/// Step churn and repair for one file.
///
/// # Errors
///
/// The endowment helpers' errors, as text, when the size or replication is rejected.
pub fn simulate_permanence(sim: &PermanenceSim) -> Result<PermanenceReport, String> {
    if sim.operators != SIM_SHARDS {
        return Err("this run gives one shard to each of 12 operators".into());
    }
    if sim.losses_per_year > SIM_SHARDS {
        return Err("losses_per_year cannot exceed 12".into());
    }
    let annual_cost = first_year_cost_base_units(sim.size_bytes, sim.replication, &sim.params)
        .map_err(|e| e.to_string())?;
    let endowment = required_endowment(sim.size_bytes, sim.replication, &sim.params)
        .map_err(|e| e.to_string())?;
    let runway_years = endowment.checked_div(annual_cost).unwrap_or(u128::MAX);
    let mut balance = if sim.pay_endowment { endowment } else { 0 };
    let mut holders: Vec<Option<u32>> = (0..SIM_SHARDS).map(Some).collect();
    let mut lost = false;
    for year in 0..sim.years {
        let funded = sim.pay_endowment
            && matches!(
                endowment_annual_runway(balance, annual_cost),
                EndowmentRunwayAlert::Healthy | EndowmentRunwayAlert::NoDrain
            );
        if funded {
            balance = balance.saturating_sub(annual_cost);
        }
        let mut dropped_seats = Vec::new();
        for k in 0..sim.losses_per_year {
            let seat = ((u64::from(year) * u64::from(sim.losses_per_year) + u64::from(k))
                % u64::from(sim.operators)) as u32;
            for holder in holders.iter_mut() {
                if *holder == Some(seat) {
                    *holder = None;
                    dropped_seats.push(seat);
                }
            }
        }
        let present = holders.iter().filter(|h| h.is_some()).count() as u32;
        if sim.repair && funded && present >= SIM_REPAIR_THRESHOLD {
            let mut n = 0usize;
            for holder in holders.iter_mut() {
                if holder.is_none() {
                    *holder = dropped_seats.get(n).copied();
                    n += 1;
                }
            }
        }
        let present = holders.iter().filter(|h| h.is_some()).count() as u32;
        if present < SIM_REPAIR_THRESHOLD {
            lost = true;
            break;
        }
    }
    Ok(PermanenceReport {
        files_alive: u32::from(!lost),
        files_lost: u32::from(lost),
        annual_cost,
        endowment,
        runway_years,
        years_simulated: sim.years,
    })
}

/// The documented run: three operators leave each year, repair is on, and the
/// default endowment pays. Twenty years is inside the default runway.
#[must_use]
pub fn documented_sim() -> PermanenceSim {
    PermanenceSim {
        years: 20,
        operators: 12,
        losses_per_year: 3,
        repair: true,
        pay_endowment: true,
        size_bytes: 1024 * 1024,
        replication: 3,
        params: crate::DEFAULT_ENDOWMENT_PARAMS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_and_endowment_keep_the_file_for_twenty_years() {
        let sim = documented_sim();
        let report = simulate_permanence(&sim).expect("sim");
        assert!(
            report.runway_years >= u128::from(sim.years),
            "runway {} cost {} endowment {}",
            report.runway_years,
            report.annual_cost,
            report.endowment
        );
        assert_eq!(report.files_alive, 1);
        assert_eq!(report.files_lost, 0);
        assert!(report.annual_cost > 0);
    }

    #[test]
    fn without_repair_the_same_churn_loses_the_file() {
        let mut sim = documented_sim();
        sim.repair = false;
        let report = simulate_permanence(&sim).expect("sim");
        assert_eq!(report.files_lost, 1);
    }

    #[test]
    fn an_empty_endowment_refuses_repair() {
        let mut sim = documented_sim();
        sim.pay_endowment = false;
        let report = simulate_permanence(&sim).expect("sim");
        assert_eq!(report.files_lost, 1);
        assert!(report.endowment > 0);
    }
}
