//! Endowment math — turning "how big is this upload?" into "how many MFN
//! base units must you escrow into the storage treasury right now?"
//!
//! Port of `cloonan-group/lib/network/endowment.ts`. The on-chain
//! implementation of the whitepaper's §3 formula:
//!
//! ```text
//!     E₀  =  C₀ · (1 + i) / (r − i)
//! ```
//!
//! where
//!
//! - `E₀` = upfront endowment the user pays at upload time
//! - `C₀ = cost_per_byte_year · size_bytes · replication` = first-year storage cost
//! - `i` = annual inflation rate of storage cost (per year)
//! - `r` = annual real yield rate the treasury earns (per year)
//! - `r > i` (non-degeneracy condition, otherwise the geometric series diverges)
//!
//! ## Why on-chain
//!
//! - `apply_block` must validate that an upload tx's endowment escrow
//!   matches the protocol-required amount. Underfund the endowment and the
//!   permanence guarantee breaks.
//! - Wallets must agree on cost before submission so uploads aren't racey.
//! - The same formula computes the per-slot payout to storage providers,
//!   so liability and payout schedule come from one canonical source of
//!   truth.
//!
//! ## Precision
//!
//! All rates are in **parts per billion (PPB)**: `20_000_000 ppb = 2%`.
//! Gives 9 decimal places of precision without any floating-point math,
//! which is exactly determinism-safe across implementations. Final
//! monetary values use **ceiling division** so the protocol never
//! accidentally under-funds (max over-payment: 1 base unit, i.e. dust).
//!
//! ## Arithmetic width
//!
//! Intermediate products use `u128`. For realistic chain parameters
//! (block-bounded upload size ≤ 10⁹ bytes, replication ≤ 32, default
//! `cost_per_byte_year_ppb = 200_000`, default rates ≤ 5%) the numerator
//! peaks at ≈ 6×10²⁴ — comfortably within `u128`'s 3.4×10³⁸ ceiling. All
//! multiplications are `checked_mul` to surface overflow as a typed error
//! rather than a panic.

/// All rate values are expressed in PARTS PER BILLION.
/// `1% = 10_000_000 ppb`.
pub const PPB: u128 = 1_000_000_000;

/// Endowment parameters — the protocol-level monetary policy for
/// permanence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndowmentParams {
    /// Storage cost per byte per year per replica, in PPB of one MFN base
    /// unit. PPB precision is needed because one byte-year is much
    /// cheaper than one base unit at any plausible MFN valuation.
    ///
    /// Default calibration: `200_000` ⇒ 2 × 10⁻⁴ base units per
    /// byte-year per replica. 1 GB × 3× replication ≈ 0.3 MFN
    /// (Arweave-comparable).
    pub cost_per_byte_year_ppb: u64,
    /// Annual inflation of storage cost, in PPB. Storage has historically
    /// **deflated** (Kryder's law), so a positive `i` is a conservative
    /// bet. Default 2.0% (`20_000_000`).
    pub inflation_ppb: u64,
    /// Annual real yield the treasury captures, in PPB. `real_yield > inflation`
    /// is the non-degeneracy condition. Default 4.0% (`40_000_000`).
    pub real_yield_ppb: u64,
    /// Minimum independent replicas per upload. Hard floor: 3 (a two-replica
    /// system has no quorum recoverability after a single failure).
    pub min_replication: u8,
    /// Maximum replication factor (DOS protection — without it an attacker
    /// could pin tiny data at absurd replication to drain the treasury).
    pub max_replication: u8,
    /// Slots per year. Used to convert annual real yield into per-slot
    /// payout for storage providers. Default `2_629_800` (≈ 12-second
    /// slots).
    pub slots_per_year: u64,
    /// Anti-hoarding cap on the per-proof reward window: a successful
    /// proof credits the commitment with `min(elapsed_slots, this)` slots
    /// of yield.
    ///
    /// Without a cap, a malicious prover could lie dormant for a year and
    /// claim a year's yield in one proof. Default `7_200` (≈ 1 day at
    /// 12-second slots).
    pub proof_reward_window_slots: u64,
}

/// Canonical defaults.
pub const DEFAULT_ENDOWMENT_PARAMS: EndowmentParams = EndowmentParams {
    cost_per_byte_year_ppb: 200_000,
    inflation_ppb: 20_000_000,
    real_yield_ppb: 40_000_000,
    min_replication: 3,
    max_replication: 32,
    slots_per_year: 2_629_800,
    proof_reward_window_slots: 7_200,
};

/* ----------------------------------------------------------------------- *
 *  Validation                                                              *
 * ----------------------------------------------------------------------- */

/// Validate an [`EndowmentParams`] against the protocol's invariants.
///
/// # Errors
///
/// [`EndowmentError`] for every distinguishable failure mode (so callers
/// can surface a specific reason).
pub fn validate_endowment_params(p: &EndowmentParams) -> Result<(), EndowmentError> {
    if p.real_yield_ppb == 0 {
        return Err(EndowmentError::RealYieldZero);
    }
    if u128::from(p.real_yield_ppb) <= u128::from(p.inflation_ppb) {
        return Err(EndowmentError::RealYieldNotAboveInflation {
            real_yield_ppb: p.real_yield_ppb,
            inflation_ppb: p.inflation_ppb,
        });
    }
    if p.min_replication < 1 {
        return Err(EndowmentError::MinReplicationLessThanOne);
    }
    if p.min_replication > p.max_replication {
        return Err(EndowmentError::MinReplicationAboveMax);
    }
    if p.slots_per_year == 0 {
        return Err(EndowmentError::SlotsPerYearZero);
    }
    if p.proof_reward_window_slots == 0 {
        return Err(EndowmentError::ProofWindowZero);
    }
    Ok(())
}

/* ----------------------------------------------------------------------- *
 *  Required endowment                                                      *
 * ----------------------------------------------------------------------- */

/// Compute the required upfront endowment for an upload.
///
/// `E₀ = ceil(cost_per_byte_year_ppb · size · replication · (PPB + i) /
/// (PPB · (r − i)))`. The result is in **MFN base units**; uses ceiling
/// division so the protocol never under-funds (over-payment ≤ 1 base
/// unit, i.e. dust).
///
/// # Errors
///
/// - [`EndowmentError::ReplicationOutOfRange`] when `replication` falls
///   outside `[min_replication, max_replication]`.
/// - [`EndowmentError::Overflow`] when intermediate products exceed
///   `u128`.
/// - Anything [`validate_endowment_params`] reports.
pub fn required_endowment(
    size_bytes: u64,
    replication: u8,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    validate_endowment_params(params)?;
    if replication < params.min_replication || replication > params.max_replication {
        return Err(EndowmentError::ReplicationOutOfRange {
            got: replication,
            min: params.min_replication,
            max: params.max_replication,
        });
    }
    // Worked through symbolically:
    //   C₀         = (cost_per_byte_year_ppb / PPB) · size · repl   [base units]
    //   E₀         = C₀ · (PPB + i) / (r − i)                       [base units]
    // ⇒ E₀ · PPB · PPB = cost_per_byte_year_ppb · size · repl · (PPB + i)
    //                    --------------------------------------------
    //                                  PPB · (r − i)
    let size = u128::from(size_bytes);
    let repl = u128::from(replication);
    let size_repl = size.checked_mul(repl).ok_or(EndowmentError::Overflow)?;
    if size_repl == 0 {
        return Ok(0);
    }
    let cost = u128::from(params.cost_per_byte_year_ppb);
    let inflation = u128::from(params.inflation_ppb);
    let real_yield = u128::from(params.real_yield_ppb);
    let numerator = cost
        .checked_mul(size_repl)
        .and_then(|x| {
            x.checked_mul(
                PPB.checked_add(inflation)
                    .ok_or(EndowmentError::Overflow)
                    .ok()?,
            )
        })
        .ok_or(EndowmentError::Overflow)?;
    let denominator = PPB
        .checked_mul(real_yield - inflation)
        .ok_or(EndowmentError::Overflow)?;
    Ok(ceil_div(numerator, denominator))
}

/* ----------------------------------------------------------------------- *
 *  Treasury payout (per-slot, cumulative)                                  *
 * ----------------------------------------------------------------------- */

/// How many base units the treasury pays out for a single slot, given an
/// endowment of size `endowment`.
///
/// `per_slot = floor(endowment · real_yield_ppb / (PPB · slots_per_year))`.
/// Floor so the treasury never overdraws.
///
/// # Errors
///
/// [`EndowmentError::SlotsPerYearZero`] / [`EndowmentError::Overflow`].
pub fn payout_per_slot(
    endowment: u128,
    slots_per_year: u64,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    if slots_per_year == 0 {
        return Err(EndowmentError::SlotsPerYearZero);
    }
    let num = endowment
        .checked_mul(u128::from(params.real_yield_ppb))
        .ok_or(EndowmentError::Overflow)?;
    let den = PPB
        .checked_mul(u128::from(slots_per_year))
        .ok_or(EndowmentError::Overflow)?;
    Ok(num / den)
}

/// Cumulative payout from the treasury over `slots` slots. Higher
/// precision than `slots * payout_per_slot`: the multiplication is moved
/// inside the division so the per-slot fraction isn't lost.
///
/// Matches `accrue_proof_reward.payout` exactly when run against an empty
/// accumulator and `slots ≤ proof_reward_window_slots`.
///
/// # Errors
///
/// [`EndowmentError::SlotsPerYearZero`] / [`EndowmentError::Overflow`].
pub fn cumulative_payout(
    endowment: u128,
    slots: u64,
    slots_per_year: u64,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    if slots == 0 {
        return Ok(0);
    }
    if slots_per_year == 0 {
        return Err(EndowmentError::SlotsPerYearZero);
    }
    let num = u128::from(slots)
        .checked_mul(endowment)
        .and_then(|x| x.checked_mul(u128::from(params.real_yield_ppb)))
        .ok_or(EndowmentError::Overflow)?;
    let den = PPB
        .checked_mul(u128::from(slots_per_year))
        .ok_or(EndowmentError::Overflow)?;
    Ok(num / den)
}

/* ----------------------------------------------------------------------- *
 *  Per-proof reward accrual                                                *
 * ----------------------------------------------------------------------- */

/// Inputs to [`accrue_proof_reward`].
#[derive(Clone, Copy, Debug)]
pub struct AccrueArgs<'a> {
    /// Size of the upload in bytes.
    pub size_bytes: u64,
    /// Replication factor declared in the commitment.
    pub replication: u8,
    /// Per-commitment PPB accumulator carried across proofs.
    pub pending_ppb: u128,
    /// Slot number at which the previous proof was accepted (or the
    /// anchoring block's slot, on the first proof).
    pub last_proven_slot: u64,
    /// Current block's slot.
    pub current_slot: u64,
    /// Endowment params (defaults to [`DEFAULT_ENDOWMENT_PARAMS`]).
    pub params: &'a EndowmentParams,
}

/// Result of [`accrue_proof_reward`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccrueResult {
    /// Base units the producer earns for this proof.
    pub payout: u128,
    /// Updated PPB accumulator to persist on the commitment.
    pub new_pending_ppb: u128,
    /// Capped elapsed slots actually credited.
    pub credited_slots: u64,
}

/// Per-proof reward accrual with a PPB-precision accumulator.
///
/// **Why an accumulator.** At default params, even a 100 GB commitment
/// yields well under one base unit per slot. The naive `floor(per_slot)`
/// would clamp every reward to zero. The PPB accumulator carries unpaid
/// fractions across proofs; over the commitment's lifetime it eventually
/// crosses a base unit and pays out. Total payout over a year still
/// matches `endowment · real_yield` to the base unit, by construction.
///
/// **Anti-hoarding.** Without a cap on `elapsed_slots`, a prover could
/// lie dormant for a year and submit one proof for a year's yield.
/// [`EndowmentParams::proof_reward_window_slots`] caps elapsed credit at
/// roughly one day (default).
///
/// # Errors
///
/// Propagates [`required_endowment`] / [`validate_endowment_params`]
/// errors.
pub fn accrue_proof_reward(args: AccrueArgs<'_>) -> Result<AccrueResult, EndowmentError> {
    validate_endowment_params(args.params)?;
    if args.current_slot < args.last_proven_slot {
        // Defensive: should never happen with monotonic slot progression.
        // On rewinds we credit zero this proof.
        return Ok(AccrueResult {
            payout: 0,
            new_pending_ppb: args.pending_ppb,
            credited_slots: 0,
        });
    }
    let required_e = required_endowment(args.size_bytes, args.replication, args.params)?;
    let elapsed_raw = args.current_slot - args.last_proven_slot;
    let credited = elapsed_raw.min(args.params.proof_reward_window_slots);
    let incoming_ppb: u128 = if credited == 0 {
        0
    } else {
        // PPB-per-slot accumulator:
        //   per_slot_ppb = endowment · real_yield / slots_per_year
        //   total_ppb    = credited · endowment · real_yield / slots_per_year
        u128::from(credited)
            .checked_mul(required_e)
            .and_then(|x| x.checked_mul(u128::from(args.params.real_yield_ppb)))
            .ok_or(EndowmentError::Overflow)?
            / u128::from(args.params.slots_per_year)
    };
    let total_ppb = args
        .pending_ppb
        .checked_add(incoming_ppb)
        .ok_or(EndowmentError::Overflow)?;
    let payout = total_ppb / PPB;
    let new_pending_ppb = total_ppb - payout * PPB;
    Ok(AccrueResult {
        payout,
        new_pending_ppb,
        credited_slots: credited,
    })
}

/* ----------------------------------------------------------------------- *
 *  Inverse: max bytes for a fixed budget                                   *
 * ----------------------------------------------------------------------- */

/// Given a budget, the maximum bytes you can pay to permanently store at
/// a given replication. Useful for wallet UX: "you have 100 MFN; that's
/// enough to permanently store up to X TB."
///
/// Floor-divides so the inverse never overstates the budget.
///
/// # Errors
///
/// Validates params; reports [`EndowmentError::ReplicationOutOfRange`] if
/// `replication` is out of bounds.
pub fn max_bytes_for_endowment(
    endowment: u128,
    replication: u8,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    validate_endowment_params(params)?;
    if replication < params.min_replication || replication > params.max_replication {
        return Err(EndowmentError::ReplicationOutOfRange {
            got: replication,
            min: params.min_replication,
            max: params.max_replication,
        });
    }
    let denominator = u128::from(params.cost_per_byte_year_ppb)
        .checked_mul(u128::from(replication))
        .and_then(|x| x.checked_mul(PPB + u128::from(params.inflation_ppb)))
        .ok_or(EndowmentError::Overflow)?;
    if denominator == 0 {
        return Ok(0);
    }
    let numerator = endowment
        .checked_mul(PPB)
        .and_then(|x| {
            x.checked_mul(u128::from(params.real_yield_ppb) - u128::from(params.inflation_ppb))
        })
        .ok_or(EndowmentError::Overflow)?;
    Ok(numerator / denominator)
}

/* ----------------------------------------------------------------------- *
 *  Utilities                                                               *
 * ----------------------------------------------------------------------- */

/// Ceiling division for non-negative `u128`s. Panics in debug mode if
/// `denominator == 0`; callers must ensure the denominator is non-zero
/// (this is an internal helper).
#[inline]
fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    debug_assert!(denominator > 0, "ceil_div: denominator must be > 0");
    if numerator == 0 {
        return 0;
    }
    numerator.div_ceil(denominator)
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Endowment-math errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EndowmentError {
    /// `real_yield_ppb` was zero (treasury must earn something).
    #[error("real_yield_ppb must be > 0")]
    RealYieldZero,
    /// Non-degeneracy condition violated: `real_yield <= inflation`.
    #[error(
        "real_yield_ppb ({real_yield_ppb}) must exceed inflation_ppb ({inflation_ppb}) — geometric series diverges otherwise"
    )]
    RealYieldNotAboveInflation {
        /// Configured real-yield value (PPB).
        real_yield_ppb: u64,
        /// Configured inflation value (PPB).
        inflation_ppb: u64,
    },
    /// Minimum replication < 1.
    #[error("min_replication must be ≥ 1")]
    MinReplicationLessThanOne,
    /// Minimum replication > maximum replication.
    #[error("min_replication > max_replication")]
    MinReplicationAboveMax,
    /// Replication factor was out of the configured `[min, max]` band.
    #[error("replication {got} out of range [{min}, {max}]")]
    ReplicationOutOfRange {
        /// Caller-supplied replication factor.
        got: u8,
        /// Configured minimum.
        min: u8,
        /// Configured maximum.
        max: u8,
    },
    /// `slots_per_year` was zero.
    #[error("slots_per_year must be > 0")]
    SlotsPerYearZero,
    /// `proof_reward_window_slots` was zero.
    #[error("proof_reward_window_slots must be > 0")]
    ProofWindowZero,
    /// An intermediate `u128` product overflowed.
    #[error("u128 overflow in endowment math")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> EndowmentParams {
        DEFAULT_ENDOWMENT_PARAMS
    }

    #[test]
    fn default_params_validate() {
        validate_endowment_params(&p()).unwrap();
    }

    #[test]
    fn rejects_real_yield_zero() {
        let mut bad = p();
        bad.real_yield_ppb = 0;
        assert_eq!(
            validate_endowment_params(&bad),
            Err(EndowmentError::RealYieldZero)
        );
    }

    #[test]
    fn rejects_real_yield_below_inflation() {
        let mut bad = p();
        bad.real_yield_ppb = bad.inflation_ppb;
        assert!(matches!(
            validate_endowment_params(&bad),
            Err(EndowmentError::RealYieldNotAboveInflation { .. })
        ));
    }

    #[test]
    fn zero_size_zero_endowment() {
        assert_eq!(required_endowment(0, 3, &p()).unwrap(), 0);
    }

    #[test]
    fn one_gb_three_replication_in_arweave_band() {
        // 1 GiB × 3 replication should land between 0.1 and 1.0 MFN
        // (= 10⁷ … 10⁸ base units) at default params. (Arweave-comparable.)
        let e = required_endowment(1 << 30, 3, &p()).unwrap();
        assert!(
            (10_000_000..=100_000_000).contains(&e),
            "endowment for 1 GiB × 3 = {e}, expected 1e7..1e8"
        );
    }

    #[test]
    fn endowment_scales_linearly_in_size() {
        let small = required_endowment(1_000_000, 3, &p()).unwrap();
        let big = required_endowment(10_000_000, 3, &p()).unwrap();
        // ~10x larger, within ceiling-rounding slack.
        assert!(big >= 10 * small - 10);
        assert!(big <= 10 * small + 10);
    }

    #[test]
    fn endowment_scales_linearly_in_replication() {
        let r3 = required_endowment(1_000_000, 3, &p()).unwrap();
        let r6 = required_endowment(1_000_000, 6, &p()).unwrap();
        assert!(r6 >= 2 * r3 - 5);
        assert!(r6 <= 2 * r3 + 5);
    }

    #[test]
    fn replication_below_min_rejected() {
        assert!(matches!(
            required_endowment(1_000, 1, &p()),
            Err(EndowmentError::ReplicationOutOfRange { got: 1, min: 3, .. })
        ));
    }

    #[test]
    fn replication_above_max_rejected() {
        assert!(matches!(
            required_endowment(1_000, 200, &p()),
            Err(EndowmentError::ReplicationOutOfRange {
                got: 200,
                max: 32,
                ..
            })
        ));
    }

    #[test]
    fn cumulative_payout_matches_per_slot_sum_at_round_endowment() {
        // Pick an endowment large enough that floor-per-slot doesn't clamp
        // to zero, so the two paths agree to within one base unit.
        let e: u128 = 1_000_000_000_000; // 10000 MFN
        let pps = payout_per_slot(e, p().slots_per_year, &p()).unwrap();
        let cum = cumulative_payout(e, 100, p().slots_per_year, &p()).unwrap();
        // cum should equal 100 * pps within the per-slot floor slack.
        let direct = pps.saturating_mul(100);
        let diff = cum.abs_diff(direct);
        assert!(diff <= 100, "cum={cum}, direct={direct}, diff={diff}");
    }

    #[test]
    fn accrue_credits_zero_at_same_slot() {
        let res = accrue_proof_reward(AccrueArgs {
            size_bytes: 1 << 30,
            replication: 3,
            pending_ppb: 0,
            last_proven_slot: 100,
            current_slot: 100,
            params: &p(),
        })
        .unwrap();
        assert_eq!(res.payout, 0);
        assert_eq!(res.new_pending_ppb, 0);
        assert_eq!(res.credited_slots, 0);
    }

    #[test]
    fn accrue_caps_at_window() {
        let elapsed = p().proof_reward_window_slots * 10;
        let res = accrue_proof_reward(AccrueArgs {
            size_bytes: 1 << 30,
            replication: 3,
            pending_ppb: 0,
            last_proven_slot: 0,
            current_slot: elapsed,
            params: &p(),
        })
        .unwrap();
        assert_eq!(res.credited_slots, p().proof_reward_window_slots);
    }

    #[test]
    fn accrue_persists_pending_ppb() {
        // Run two back-to-back accruals — the second should pick up the
        // pending fraction from the first.
        let params = p();
        let args = |last, now, pending| AccrueArgs {
            size_bytes: 1 << 20,
            replication: 3,
            pending_ppb: pending,
            last_proven_slot: last,
            current_slot: now,
            params: &params,
        };
        let r1 = accrue_proof_reward(args(0, 1, 0)).unwrap();
        let r2 = accrue_proof_reward(args(1, 2, r1.new_pending_ppb)).unwrap();
        // Carry-over: after two slots' accrual the total payout +
        // remainder should match a fresh two-slot accrual on an empty
        // accumulator.
        let r_combined = accrue_proof_reward(args(0, 2, 0)).unwrap();
        assert_eq!(r1.payout + r2.payout, r_combined.payout, "split = combined");
        assert_eq!(r2.new_pending_ppb, r_combined.new_pending_ppb);
    }

    #[test]
    fn accrue_zero_on_rewind() {
        let res = accrue_proof_reward(AccrueArgs {
            size_bytes: 1 << 30,
            replication: 3,
            pending_ppb: 12_345,
            last_proven_slot: 100,
            current_slot: 50,
            params: &p(),
        })
        .unwrap();
        assert_eq!(res.payout, 0);
        assert_eq!(res.new_pending_ppb, 12_345);
        assert_eq!(res.credited_slots, 0);
    }

    #[test]
    fn max_bytes_inverse_of_required_endowment_in_arweave_band() {
        // For a fixed budget, max_bytes_for_endowment should give a size
        // whose required_endowment is ≤ that budget (and within ceiling
        // slack).
        let budget: u128 = 100_000_000_000; // 1000 MFN
        let max = max_bytes_for_endowment(budget, 3, &p()).unwrap();
        let max_u64 = u64::try_from(max).expect("max_bytes fits in u64");
        let need = required_endowment(max_u64, 3, &p()).unwrap();
        assert!(need <= budget, "need={need}, budget={budget}");
        // And one more byte exceeds the budget.
        let need_plus = required_endowment(max_u64 + 1, 3, &p()).unwrap();
        assert!(need_plus > budget, "need_plus={need_plus}, budget={budget}");
    }

    #[test]
    fn endowment_is_monotonic_in_size() {
        let mut prev = 0u128;
        for s in [0u64, 1_000, 10_000, 100_000, 1_000_000, 10_000_000] {
            let e = required_endowment(s, 3, &p()).unwrap();
            assert!(e >= prev, "size {s}: {e} should ≥ prev {prev}");
            prev = e;
        }
    }
}
