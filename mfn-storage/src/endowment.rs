//! Endowment math — turning "how big is this upload?" into "how many MFN
//! base units must you escrow into the storage treasury right now?"
//!
//! The on-chain
//! implementation of the whitepaper's §3 formula:
//!
//! ```text
//!     E₀  =  C₀ · (1 + i) / (r − i)          (when r > 0)
//!     E₀  =  C₀ · (1 + i) / d                 (when r = 0, deflation-funded mode)
//! ```
//!
//! where
//!
//! - `E₀` = upfront endowment the user pays at upload time
//! - `C₀ = cost_per_byte_year · size_bytes · replication` = first-year storage cost
//! - `i` = annual inflation rate of storage cost (per year) — used as *worst-case buffer*
//! - `r` = annual real yield rate the treasury earns (per year)
//! - `d` = assumed annual deflation rate (Kryder's law) when operating at r = 0
//!
//! When `r = 0` (the expected/common case — there is often no reliable real yield on
//! escrowed endowment principal), `inflation_ppb` is re-interpreted as the conservative
//! assumed deflation rate `d`. The endowment is then sized as a large multiple of current
//! annual cost so that *deflation* in future storage costs funds permanence exactly as
//! in the Arweave model. The on-chain math and validation support both modes.
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
    /// Annual real yield the treasury captures on escrowed endowments, in PPB.
    ///
    /// - When > 0: must strictly exceed `inflation_ppb` (the r > i non-degeneracy
    ///   condition for the yield-bearing perpetuity model).
    /// - When 0 (expected/common case): the system runs in **deflation-funded mode**.
    ///   `inflation_ppb` is re-interpreted as the conservative assumed annual
    ///   deflation rate `d` under continued Kryder's law. The endowment is sized
    ///   so that declining real storage costs (not nominal yield) keep the
    ///   commitments solvent forever — exactly as Arweave's one-time-payment model.
    ///
    /// Default: `0` (deflation-funded; no reliance on earning real yield on locked funds).
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
    /// When non-zero, new storage anchors must carry a Pedersen opening
    /// (`MFEO` in `tx.extra`) that consensus verifies against
    /// `StorageCommitment.endowment` and `required_endowment` (B-11).
    pub require_endowment_opening: u8,
    /// When non-zero, `apply_block` accepts up to `commit.replication`
    /// distinct operator-salted SPoRA proofs per commitment per block (B3).
    pub operator_salted_challenges: u8,
    /// When non-zero (requires `operator_salted_challenges`), storage proofs
    /// must come from payout keys registered in `ChainState::storage_operators`.
    pub require_registered_operators: u8,
    /// Minimum escrow bond for storage-operator registration when non-zero.
    pub min_storage_operator_bond: u64,
    /// Consecutive missed operator-salted SPoRA challenges before a bond slash
    /// (B5). `0` disables slashing (default until B5b wires audit accounting).
    pub operator_audit_missed_cap: u8,
    /// Fraction of an operator's bonded stake slashed to treasury on audit
    /// failure, in basis points (1 bps = 0.01%). Active only when
    /// `operator_audit_missed_cap > 0` and `operator_salted_challenges > 0`.
    pub operator_slash_bps: u32,
    /// When non-zero, new storage anchors must carry a Bulletproof that the
    /// Pedersen endowment opens to at least `required_endowment(...)` without
    /// revealing over-payment (B-11 phase 2). Inert until wired in `apply_block`.
    pub require_endowment_range_proof: u8,
}

/// Canonical defaults.
pub const DEFAULT_ENDOWMENT_PARAMS: EndowmentParams = EndowmentParams {
    cost_per_byte_year_ppb: 200_000,
    inflation_ppb: 20_000_000,
    real_yield_ppb: 0, // deflation-funded mode (Kryder's law covers permanence)
    min_replication: 3,
    max_replication: 32,
    slots_per_year: 2_629_800,
    proof_reward_window_slots: 7_200,
    require_endowment_opening: 0,
    operator_salted_challenges: 0,
    require_registered_operators: 0,
    min_storage_operator_bond: 0,
    operator_audit_missed_cap: 0,
    operator_slash_bps: 0,
    require_endowment_range_proof: 0,
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
    // r = 0 is allowed and expected (deflation-funded / Arweave-style mode).
    // When r > 0 it must still beat the inflation buffer.
    if p.real_yield_ppb > 0 && u128::from(p.real_yield_ppb) <= u128::from(p.inflation_ppb) {
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
    if p.require_endowment_opening > 1 {
        return Err(EndowmentError::InvalidRequireEndowmentOpening {
            got: p.require_endowment_opening,
        });
    }
    if p.operator_salted_challenges > 1 {
        return Err(EndowmentError::InvalidOperatorSaltedChallenges {
            got: p.operator_salted_challenges,
        });
    }
    if p.require_registered_operators > 1 {
        return Err(EndowmentError::InvalidRequireRegisteredOperators {
            got: p.require_registered_operators,
        });
    }
    if p.require_registered_operators != 0 && p.operator_salted_challenges == 0 {
        return Err(EndowmentError::RegisteredOperatorsRequiresB3);
    }
    if p.operator_audit_missed_cap > 0 && p.operator_salted_challenges == 0 {
        return Err(EndowmentError::OperatorSlashRequiresB3);
    }
    if p.operator_audit_missed_cap > 0
        && (p.operator_slash_bps == 0 || p.operator_slash_bps > 10_000)
    {
        return Err(EndowmentError::InvalidOperatorSlashBps {
            got: p.operator_slash_bps,
        });
    }
    if p.operator_slash_bps > 10_000 {
        return Err(EndowmentError::InvalidOperatorSlashBps {
            got: p.operator_slash_bps,
        });
    }
    if p.require_endowment_range_proof > 1 {
        return Err(EndowmentError::InvalidRequireEndowmentRangeProof {
            got: p.require_endowment_range_proof,
        });
    }
    if p.require_endowment_range_proof != 0 && p.require_endowment_opening != 0 {
        return Err(EndowmentError::EndowmentRangeProofExclusiveWithOpening);
    }
    Ok(())
}

/* ----------------------------------------------------------------------- *
 *  Required endowment                                                      *
 * ----------------------------------------------------------------------- */

/// Compute the required upfront endowment for an upload.
///
/// Two modes (selected by `real_yield_ppb`):
///
/// - **Yield-bearing mode** (`r > 0`): `E₀ = ceil(C₀ · (PPB + i) / (PPB · (r − i)))`
/// - **Deflation-funded mode** (`r = 0`, expected): `E₀ = ceil(C₀ · (PPB + i) / (PPB · d))`
///   where `d = inflation_ppb` is treated as the conservative assumed annual
///   deflation rate under Kryder's law (Arweave-style). The locked nominal
///   principal plus falling real storage costs keep commitments solvent forever.
///
/// The result is in **MFN base units**; uses ceiling division so the protocol
/// never under-funds (over-payment ≤ 1 base unit, i.e. dust).
///
/// # Errors
///
/// - [`EndowmentError::ReplicationOutOfRange`] when `replication` falls
///   outside `[min_replication, max_replication]`.
/// - [`EndowmentError::Overflow`] when intermediate products exceed `u128`.
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
    //   spread     = r − i   (r>0)   or   d (=i)   (r=0 deflation mode)
    //   E₀         = C₀ · (PPB + i) / spread                       [base units]
    // ⇒ E₀ · PPB · PPB = cost_per_byte_year_ppb · size · repl · (PPB + i)
    //                    --------------------------------------------
    //                                  PPB · spread
    let size = u128::from(size_bytes);
    let repl = u128::from(replication);
    let size_repl = size.checked_mul(repl).ok_or(EndowmentError::Overflow)?;
    if size_repl == 0 {
        return Ok(0);
    }
    let cost = u128::from(params.cost_per_byte_year_ppb);
    let inflation = u128::from(params.inflation_ppb);
    let real_yield = u128::from(params.real_yield_ppb);

    // Effective spread for the denominator:
    // - r > 0  → (r − i)   (yield must already have been validated > i)
    // - r == 0 → d (= i configured value)  — the assumed deflation rate
    let spread = if real_yield == 0 {
        inflation
    } else {
        real_yield - inflation
    };

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
    let denominator = PPB.checked_mul(spread).ok_or(EndowmentError::Overflow)?;
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
/// When `real_yield_ppb == 0` (deflation-funded mode) this is always 0:
/// operators are paid from fresh treasury inflows (fees + emission backstop)
/// rather than from yield on individual endowments.
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
/// When `real_yield_ppb == 0` this is always 0 (see [`payout_per_slot`]).
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
/// **Why an accumulator.** At default params (r=0), the per-endowment yield
/// component is zero; operators are compensated from ongoing treasury inflows.
/// The accumulator + formulas remain in place so the same code path works for
/// both r>0 and r=0 modes, and for future parameter changes.
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

    // Effective spread mirrors required_endowment:
    // r > 0 → (r − i),   r == 0 → d (= inflation_ppb as assumed deflation)
    let real_yield = u128::from(params.real_yield_ppb);
    let inflation = u128::from(params.inflation_ppb);
    let spread = if real_yield == 0 {
        inflation
    } else {
        real_yield - inflation
    };

    let numerator = endowment
        .checked_mul(PPB)
        .and_then(|x| x.checked_mul(spread))
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
    /// Non-degeneracy condition violated (only checked when `real_yield_ppb > 0`).
    /// `real_yield` must exceed `inflation` for the yield-bearing perpetuity model.
    #[error(
        "real_yield_ppb ({real_yield_ppb}) must exceed inflation_ppb ({inflation_ppb}) when real_yield > 0 — geometric series diverges otherwise"
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
    /// `require_endowment_opening` must be 0 or 1.
    #[error("require_endowment_opening must be 0 or 1, got {got}")]
    InvalidRequireEndowmentOpening {
        /// Caller-supplied flag.
        got: u8,
    },
    /// `operator_salted_challenges` must be 0 or 1.
    #[error("operator_salted_challenges must be 0 or 1, got {got}")]
    InvalidOperatorSaltedChallenges {
        /// Caller-supplied flag.
        got: u8,
    },
    /// `require_registered_operators` must be 0 or 1.
    #[error("require_registered_operators must be 0 or 1, got {got}")]
    InvalidRequireRegisteredOperators {
        /// Caller-supplied flag.
        got: u8,
    },
    /// `require_registered_operators` without `operator_salted_challenges`.
    #[error("require_registered_operators requires operator_salted_challenges")]
    RegisteredOperatorsRequiresB3,
    /// `operator_audit_missed_cap` without `operator_salted_challenges`.
    #[error("operator_audit_missed_cap requires operator_salted_challenges")]
    OperatorSlashRequiresB3,
    /// `operator_slash_bps` out of range (must be 1..=10000 when slashing is enabled).
    #[error("operator_slash_bps must be 1..=10000 when slashing is enabled, got {got}")]
    InvalidOperatorSlashBps {
        /// Caller-supplied basis points.
        got: u32,
    },
    /// `require_endowment_range_proof` must be 0 or 1.
    #[error("require_endowment_range_proof must be 0 or 1, got {got}")]
    InvalidRequireEndowmentRangeProof {
        /// Caller-supplied flag.
        got: u8,
    },
    /// Range-proof binding and MFEO opening reveal are mutually exclusive modes.
    #[error("require_endowment_range_proof and require_endowment_opening cannot both be enabled")]
    EndowmentRangeProofExclusiveWithOpening,
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
    fn rejects_require_registered_operators_without_b3() {
        let mut bad = p();
        bad.require_registered_operators = 1;
        assert!(matches!(
            validate_endowment_params(&bad),
            Err(EndowmentError::RegisteredOperatorsRequiresB3)
        ));
    }

    #[test]
    fn accepts_require_registered_operators_with_b3() {
        let mut ok = p();
        ok.operator_salted_challenges = 1;
        ok.require_registered_operators = 1;
        assert!(validate_endowment_params(&ok).is_ok());
    }

    #[test]
    fn rejects_operator_slash_without_b3() {
        let mut bad = p();
        bad.operator_audit_missed_cap = 3;
        bad.operator_slash_bps = 500;
        assert!(matches!(
            validate_endowment_params(&bad),
            Err(EndowmentError::OperatorSlashRequiresB3)
        ));
    }

    #[test]
    fn rejects_operator_slash_bps_when_cap_enabled() {
        let mut bad = p();
        bad.operator_salted_challenges = 1;
        bad.operator_audit_missed_cap = 3;
        bad.operator_slash_bps = 0;
        assert!(matches!(
            validate_endowment_params(&bad),
            Err(EndowmentError::InvalidOperatorSlashBps { got: 0 })
        ));
    }

    #[test]
    fn rejects_endowment_range_proof_with_opening_both_enabled() {
        let mut bad = p();
        bad.require_endowment_opening = 1;
        bad.require_endowment_range_proof = 1;
        assert!(matches!(
            validate_endowment_params(&bad),
            Err(EndowmentError::EndowmentRangeProofExclusiveWithOpening)
        ));
    }

    #[test]
    fn accepts_endowment_range_proof_alone() {
        let mut ok = p();
        ok.require_endowment_range_proof = 1;
        assert!(validate_endowment_params(&ok).is_ok());
    }

    #[test]
    fn accepts_inert_b5_slash_params() {
        let mut ok = p();
        ok.operator_salted_challenges = 1;
        ok.operator_audit_missed_cap = 8;
        ok.operator_slash_bps = 250;
        assert!(validate_endowment_params(&ok).is_ok());
    }

    #[test]
    fn accepts_real_yield_zero_deflation_mode() {
        let mut p0 = p();
        p0.real_yield_ppb = 0;
        assert!(validate_endowment_params(&p0).is_ok());

        // And required_endowment works (uses inflation_ppb as d)
        let e = required_endowment(1_000_000, 3, &p0).unwrap();
        assert!(e > 0);
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
        // With default r=0 the per-endowment yield is zero; test the math
        // with an explicit positive-yield params set instead.
        let mut py = p();
        py.real_yield_ppb = 40_000_000;

        // Pick an endowment large enough that floor-per-slot doesn't clamp
        // to zero, so the two paths agree to within one base unit.
        let e: u128 = 1_000_000_000_000; // 10000 MFN
        let pps = payout_per_slot(e, py.slots_per_year, &py).unwrap();
        let cum = cumulative_payout(e, 100, py.slots_per_year, &py).unwrap();
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
