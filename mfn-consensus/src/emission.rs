//! Monetary policy.
//!
//! Permawrite is a permanence chain, so the subsidy CANNOT decay to zero —
//! storage providers must be paid *forever* to hold *forever* data. We
//! follow Monero's design: a Bitcoin-like halving curve that asymptotes to a
//! small constant per-block tail emission, plus an EIP-1559-style fee split
//! that routes most of the priority fee to the storage treasury.
//!
//! Ported from `cloonan-group/lib/network/emission.ts`, byte-for-byte
//! identical for the subset of behaviors this module covers (the TS module
//! includes inflation-rate display helpers we don't expose to consensus).
//!
//! ## Stream summary
//!
//! - **Emission** — fresh tokens minted into the block coinbase.
//! - **Fees** — split: `feeToTreasuryBps` / 10000 fraction to the storage
//!   treasury, remainder as priority tip to the producer.
//! - **Endowment yield** — payouts from locked permanence endowments
//!   (outside this module; lives in the future `mfn-storage`).
//!
//! Genesis (height 0) is unfunded. Height 1 produces the first reward.
//! Halvings occur at heights `k * halving_period + 1` for `k = 1..halving_count`.

/// One MFN = 10⁸ base units, mirroring Bitcoin's satoshi.
pub const MFN_DECIMALS: u32 = 8;

/// 10^MFN_DECIMALS.
pub const MFN_BASE: u64 = 100_000_000;

/// Cap on `halving_count`. After 64 halvings of a 64-bit reward, the era
/// emits 0; we conservatively reject configurations beyond this point.
pub const MAX_HALVING_COUNT: u32 = 64;

/// Monetary-policy parameters. Frozen at genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionParams {
    /// Reward at heights `1 ..= halving_period`. Smallest-unit (10⁻⁸ MFN).
    pub initial_reward: u64,
    /// Block-count per halving era.
    pub halving_period: u64,
    /// Number of halvings before the tail era kicks in.
    pub halving_count: u32,
    /// Permanent per-block emission after halvings end. Must be > 0 — that's
    /// what makes the security budget permanent.
    pub tail_emission: u64,
    /// Per-accepted-storage-proof reward paid INTO the block coinbase on top
    /// of subsidy + producer tip. Funded first from the on-chain treasury
    /// (treasury is filled by privacy-tx fees + endowment yield); the chain
    /// only mints fresh tokens via this stream when the treasury runs dry.
    pub storage_proof_reward: u64,
    /// Fraction of every tx fee that flows to the storage treasury, in basis
    /// points (10000 = 100%). The remainder is the priority tip to the
    /// producer.
    ///
    /// Default `9000` = 90% to treasury, 10% producer tip.
    pub fee_to_treasury_bps: u16,
}

/// Defaults from the whitepaper / TS reference.
///
/// `tail_emission = initial_reward >> 8 ≈ 0.195 MFN/block`, chosen one binary
/// halving below the last subsidy era so the schedule is monotonically
/// non-increasing across the tail boundary.
pub const DEFAULT_EMISSION_PARAMS: EmissionParams = EmissionParams {
    initial_reward: 50 * MFN_BASE,
    halving_period: 8_000_000,
    halving_count: 8,
    tail_emission: (50 * MFN_BASE) >> 8,
    storage_proof_reward: MFN_BASE / 10,
    fee_to_treasury_bps: 9000,
};

/// Errors returned by [`validate_emission_params`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EmissionError {
    /// `tail_emission == 0` — would let the security budget collapse to zero
    /// in the long run.
    #[error("tail_emission must be > 0 (permanent funding required)")]
    ZeroTail,
    /// `halving_period == 0`.
    #[error("halving_period must be > 0")]
    ZeroHalvingPeriod,
    /// `halving_count > MAX_HALVING_COUNT`.
    #[error("halving_count must be <= {MAX_HALVING_COUNT} (got {got})")]
    HalvingCountTooLarge {
        /// Configured count.
        got: u32,
    },
    /// `fee_to_treasury_bps > 10000`.
    #[error("fee_to_treasury_bps must be in [0, 10000] (got {got})")]
    BadFeeBps {
        /// Configured value.
        got: u16,
    },
    /// `tail_emission > initial_reward >> (halving_count - 1)` — would create
    /// an upward discontinuity entering the tail era.
    #[error(
        "tail_emission ({tail}) > last halving subsidy ({last_subsidy}); would jump up at tail"
    )]
    TailAboveLastSubsidy {
        /// Configured tail value.
        tail: u64,
        /// Subsidy in the final halving era.
        last_subsidy: u64,
    },
}

/// Validate monetary-policy parameters. Genesis must reject configurations
/// that violate these invariants — otherwise the chain could mint nothing
/// forever (tail = 0) or have a reward that jumps upward at the tail
/// boundary.
pub fn validate_emission_params(p: &EmissionParams) -> Result<(), EmissionError> {
    if p.tail_emission == 0 {
        return Err(EmissionError::ZeroTail);
    }
    if p.halving_period == 0 {
        return Err(EmissionError::ZeroHalvingPeriod);
    }
    if p.halving_count > MAX_HALVING_COUNT {
        return Err(EmissionError::HalvingCountTooLarge {
            got: p.halving_count,
        });
    }
    if p.fee_to_treasury_bps > 10_000 {
        return Err(EmissionError::BadFeeBps {
            got: p.fee_to_treasury_bps,
        });
    }
    if p.halving_count > 0 {
        let shift = p.halving_count - 1;
        let last_subsidy = if shift >= 64 {
            0
        } else {
            p.initial_reward >> shift
        };
        if p.tail_emission > last_subsidy && last_subsidy > 0 {
            return Err(EmissionError::TailAboveLastSubsidy {
                tail: p.tail_emission,
                last_subsidy,
            });
        }
    }
    Ok(())
}

/// Per-block emission at `height`. Genesis (height 0) is unfunded.
pub fn emission_at_height(height: u64, params: &EmissionParams) -> u64 {
    if height == 0 || params.halving_period == 0 {
        return if height == 0 { 0 } else { params.tail_emission };
    }
    let halvings = ((height - 1) / params.halving_period) as u32;
    if halvings >= params.halving_count {
        return params.tail_emission;
    }
    if halvings >= 64 {
        0
    } else {
        params.initial_reward >> halvings
    }
}

/// Cumulative tokens minted via emission from height 1 through `height`
/// inclusive. Closed-form per era → O(`halving_count`).
pub fn cumulative_emission(height: u64, params: &EmissionParams) -> u128 {
    if height == 0 || params.halving_period == 0 {
        return 0;
    }
    let mut total: u128 = 0;

    for era in 0..params.halving_count {
        let era_start: u64 = u64::from(era) * params.halving_period + 1;
        let era_end: u64 = (u64::from(era) + 1) * params.halving_period;
        if height < era_start {
            break;
        }
        let blocks_in_era = height.min(era_end) - era_start + 1;
        let subsidy = if era >= 64 {
            0
        } else {
            params.initial_reward >> era
        };
        total += u128::from(subsidy) * u128::from(blocks_in_era);
    }

    let tail_start: u64 = u64::from(params.halving_count) * params.halving_period + 1;
    if height >= tail_start {
        let tail_blocks = height - tail_start + 1;
        total += u128::from(params.tail_emission) * u128::from(tail_blocks);
    }

    total
}

/// Total tokens minted by the end of the last halving era. The "Bitcoin-like
/// cap" headline number, even though true supply is unbounded by the tail.
pub fn pre_tail_supply_cap(params: &EmissionParams) -> u128 {
    cumulative_emission(
        u64::from(params.halving_count) * params.halving_period,
        params,
    )
}

/// Annual tail emission given a `blocks_per_year` rate. Used by inflation
/// displays and endowment-yield calibration.
pub fn annual_tail_emission(blocks_per_year: u64, params: &EmissionParams) -> u128 {
    u128::from(params.tail_emission) * u128::from(blocks_per_year)
}

/// Annualized issuance rate at `height`, in parts-per-billion of current
/// supply. Returns 0 if supply is still zero (height < 1).
pub fn annualized_inflation_ppb(
    height: u64,
    blocks_per_year: u64,
    params: &EmissionParams,
) -> u128 {
    let supply = cumulative_emission(height, params);
    if supply == 0 {
        return 0;
    }
    let year_ahead = u128::from(emission_at_height(height, params)) * u128::from(blocks_per_year);
    year_ahead * 1_000_000_000 / supply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_validate() {
        assert!(validate_emission_params(&DEFAULT_EMISSION_PARAMS).is_ok());
    }

    #[test]
    fn genesis_pays_nothing() {
        assert_eq!(emission_at_height(0, &DEFAULT_EMISSION_PARAMS), 0);
        assert_eq!(cumulative_emission(0, &DEFAULT_EMISSION_PARAMS), 0);
    }

    #[test]
    fn first_block_pays_initial_reward() {
        let p = DEFAULT_EMISSION_PARAMS;
        assert_eq!(emission_at_height(1, &p), p.initial_reward);
    }

    #[test]
    fn last_block_of_era_pays_initial_reward() {
        let p = DEFAULT_EMISSION_PARAMS;
        assert_eq!(emission_at_height(p.halving_period, &p), p.initial_reward);
    }

    #[test]
    fn first_block_after_halving_pays_half() {
        let p = DEFAULT_EMISSION_PARAMS;
        assert_eq!(
            emission_at_height(p.halving_period + 1, &p),
            p.initial_reward / 2
        );
    }

    #[test]
    fn tail_kicks_in_after_last_halving() {
        let p = DEFAULT_EMISSION_PARAMS;
        let h = u64::from(p.halving_count) * p.halving_period + 1;
        assert_eq!(emission_at_height(h, &p), p.tail_emission);
        assert_eq!(emission_at_height(h + 1_000_000_000, &p), p.tail_emission);
    }

    #[test]
    fn no_upward_jump_at_tail_boundary() {
        let p = DEFAULT_EMISSION_PARAMS;
        let last_subsidy = emission_at_height(u64::from(p.halving_count) * p.halving_period, &p);
        let first_tail = emission_at_height(u64::from(p.halving_count) * p.halving_period + 1, &p);
        assert!(first_tail <= last_subsidy);
    }

    #[test]
    fn cumulative_matches_summation_over_first_two_eras() {
        let p = EmissionParams {
            initial_reward: 50,
            halving_period: 5,
            halving_count: 3,
            tail_emission: 1,
            storage_proof_reward: 0,
            fee_to_treasury_bps: 0,
        };
        let mut total: u128 = 0;
        for h in 1..=12u64 {
            total += u128::from(emission_at_height(h, &p));
        }
        assert_eq!(total, cumulative_emission(12, &p));
    }

    #[test]
    fn pre_tail_supply_cap_matches_closed_form() {
        let p = DEFAULT_EMISSION_PARAMS;
        // Σ initial · (1 + 1/2 + ... + 1/2^(K-1)) · halving_period
        let mut expected: u128 = 0;
        for k in 0..p.halving_count {
            expected += u128::from(p.initial_reward >> k) * u128::from(p.halving_period);
        }
        assert_eq!(pre_tail_supply_cap(&p), expected);
    }

    #[test]
    fn validate_rejects_zero_tail() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        p.tail_emission = 0;
        assert_eq!(validate_emission_params(&p), Err(EmissionError::ZeroTail));
    }

    #[test]
    fn validate_rejects_upward_jump_at_tail() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        // Last subsidy = initial >> 7. Set tail higher than that.
        p.tail_emission = (p.initial_reward >> 7) + 1;
        assert!(matches!(
            validate_emission_params(&p),
            Err(EmissionError::TailAboveLastSubsidy { .. })
        ));
    }

    #[test]
    fn validate_rejects_excessive_halving_count() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        p.halving_count = 100;
        assert!(matches!(
            validate_emission_params(&p),
            Err(EmissionError::HalvingCountTooLarge { .. })
        ));
    }

    #[test]
    fn validate_rejects_bad_fee_bps() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        p.fee_to_treasury_bps = 10_001;
        assert!(matches!(
            validate_emission_params(&p),
            Err(EmissionError::BadFeeBps { .. })
        ));
    }

    #[test]
    fn inflation_ppb_falls_over_time() {
        let p = DEFAULT_EMISSION_PARAMS;
        let bpy = 5_000_000u64;
        let early = annualized_inflation_ppb(1_000_000, bpy, &p);
        let later = annualized_inflation_ppb(40_000_000, bpy, &p);
        assert!(later < early);
    }
}
