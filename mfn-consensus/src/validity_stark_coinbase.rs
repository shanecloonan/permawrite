//! F5 phase **4a** algebraic leaves (B-316). Not consensus.
//!
//! Winterfell proofs of two integer statements that `apply_block` already
//! checks in the clear:
//!
//! - [`emission_at_height`](crate::emission::emission_at_height)
//! - the basis-point split inside
//!   [`producer_portion_amount`](crate::emission::producer_portion_amount)
//!   when no storage-proof term is present
//!
//! `verify_*` does not re-run those functions. The honest `prove_*` /
//! `*_claim` constructors do, and refuse a claim that drifts from them.
//! Nothing here is written into a header, a genesis file, or `DEFAULT_*`.
//!
//! Backend notes live in `docs/VALIDITY_STARK_BACKEND.md`.

use crate::emission::{self, EmissionParams};
use thiserror::Error;
use winter_utils::Deserializable;
use winterfell::math::{fields::f128::BaseElement, FieldElement, ToElements};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

type Hasher = Blake3_256<BaseElement>;

const SPLIT_LEN: usize = 8;
const SPLIT_BITS: usize = 14;
const SPLIT_WIDTH: usize = 66;
const S_STEP: usize = 65;
const S_SUBSIDY: usize = 0;
const S_SBPS: usize = 1;
const S_FEE: usize = 2;
const S_FBPS: usize = 3;
const S_TRE_S: usize = 4;
const S_PRO_S: usize = 5;
const S_TRE_F: usize = 6;
const S_PRO_F: usize = 7;
const S_PORTION: usize = 8;
const S_SUB_BITS: usize = 9;
const S_SUB_GAP: usize = 23;
const S_FEE_BITS: usize = 37;
const S_FEE_GAP: usize = 51;

const EMISSION_LEN: usize = 128;
const EMISSION_CHECK: u128 = 64;
const EMISSION_WIDTH: usize = 48;
const E_HEIGHT: usize = 0;
const E_PERIOD: usize = 1;
const E_COUNT: usize = 2;
const E_INITIAL: usize = 3;
const E_TAIL: usize = 4;
const E_SUBSIDY: usize = 5;
const E_ERA: usize = 6;
const E_ERA_REM: usize = 7;
const E_USE_TAIL: usize = 8;
const E_HEIGHT_ZERO: usize = 9;
const E_HINV: usize = 10;
const E_ERA_PERIOD: usize = 11;
const E_MASK_TAIL: usize = 12;
const E_MASK_SHIFT: usize = 13;
const E_LT_INV: usize = 14;
const E_PROD_LT: usize = 15;
const E_STEP: usize = 16;
const E_ERA_BIT: usize = 17;
const E_ACC_ERA: usize = 18;
const E_SLACK_ERA: usize = 19;
const E_GAP_BIT: usize = 20;
const E_ACC_GAP: usize = 21;
const E_SLACK_GAP: usize = 22;
const E_DELTA_BIT: usize = 23;
const E_ACC_DELTA: usize = 24;
const E_SLACK_DELTA: usize = 25;
const E_LT_BIT: usize = 26;
const E_ACC_LT: usize = 27;
const E_SLACK_LT: usize = 28;
const E_PLACE: usize = 29;
const E_LOW_BIT: usize = 30;
const E_SHIFT_PLACE: usize = 31;
const E_ACC_LOW: usize = 32;
const E_LOW_CONTRIB: usize = 33;
const E_SLACK_LOW: usize = 34;
const E_STEPS: usize = 35;
const E_ALIVE: usize = 36;
const E_ALIVE_INV: usize = 37;
const E_ALIVE_OK: usize = 38;
const E_SCALED: usize = 39;
const E_SLACK_DIV: usize = 40;
const E_SLACK_TAIL: usize = 41;
const E_SLACK_STEPS: usize = 42;
const E_SLACK_PROD: usize = 43;
const E_SLACK_PROD_DEF: usize = 44;
const E_SLACK_LT0: usize = 45;
const E_SLACK_DELTA0: usize = 46;
const E_SLACK_INIT: usize = 47;

const HELD_EMISSION: [usize; 16] = [
    E_HEIGHT,
    E_PERIOD,
    E_COUNT,
    E_INITIAL,
    E_TAIL,
    E_SUBSIDY,
    E_ERA,
    E_ERA_REM,
    E_USE_TAIL,
    E_HEIGHT_ZERO,
    E_HINV,
    E_ERA_PERIOD,
    E_MASK_TAIL,
    E_MASK_SHIFT,
    E_LT_INV,
    E_PROD_LT,
];

/// Failures of the off-consensus 4a leaves.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidityLeafError {
    /// A treasury bps value was above 10_000.
    #[error("fee or subsidy bps above 10000")]
    BadBps,
    /// Linear sums or ordering of a split claim do not hold over the integers.
    #[error("coinbase split claim is not an integer partition of its inputs")]
    SplitBound,
    /// Claim outputs disagree with the integer division the leaf proves.
    #[error("coinbase split claim disagrees with integer bps division")]
    SplitDrift,
    /// `halving_period` was 0, or `halving_count` was above 64.
    #[error("emission params are outside the leaf's statement")]
    BadSchedule,
    /// Claimed subsidy disagrees with [`emission::emission_at_height`].
    #[error("subsidy claim disagrees with emission_at_height")]
    SubsidyDrift,
    /// Honest witness could not be laid out on the trace.
    #[error("validity leaf trace is inconsistent")]
    TraceInconsistent,
    /// Winterfell prover returned an error.
    #[error("stark prove failed")]
    ProveFailed,
    /// Proof bytes were not a Winterfell proof.
    #[error("stark proof decode failed")]
    ProofDecode,
    /// Winterfell rejected the proof for these public inputs.
    #[error("stark proof invalid")]
    ProofInvalid,
}

/// Public coinbase split: inputs plus the treasury / producer outputs.
///
/// `producer_portion = producer_subsidy + producer_fee`. There is no
/// storage-proof term; that is a later leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaseSplitClaim {
    /// Block subsidy in base units (`emission_at_height`).
    pub subsidy: u64,
    /// `subsidy_to_treasury_bps`.
    pub subsidy_to_treasury_bps: u16,
    /// Sum of transaction fees in the block.
    pub fee_sum: u64,
    /// `fee_to_treasury_bps`.
    pub fee_to_treasury_bps: u16,
    /// `subsidy * subsidy_to_treasury_bps / 10000`.
    pub treasury_subsidy: u64,
    /// `subsidy - treasury_subsidy`.
    pub producer_subsidy: u64,
    /// `fee_sum * fee_to_treasury_bps / 10000`.
    pub treasury_fee: u64,
    /// `fee_sum - treasury_fee`.
    pub producer_fee: u64,
    /// `producer_subsidy + producer_fee`.
    pub producer_portion: u64,
}

/// Public statement for one call of `emission_at_height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionAtHeightClaim {
    /// Block height. Height 0 is unfunded.
    pub height: u64,
    /// Blocks per halving era. Must be non-zero.
    pub halving_period: u64,
    /// Eras before the tail. Must be <= 64.
    pub halving_count: u32,
    /// Subsidy in era 0.
    pub initial_reward: u64,
    /// Per-block subsidy once `era >= halving_count`.
    pub tail_emission: u64,
    /// Claimed per-block subsidy.
    pub subsidy: u64,
}

/// Build the split claim with the same integer division as consensus.
pub fn coinbase_split_claim(
    subsidy: u64,
    subsidy_to_treasury_bps: u16,
    fee_sum: u64,
    fee_to_treasury_bps: u16,
) -> Result<CoinbaseSplitClaim, ValidityLeafError> {
    let (treasury_subsidy, producer_subsidy, _) = bps_div(subsidy, subsidy_to_treasury_bps)?;
    let (treasury_fee, producer_fee, _) = bps_div(fee_sum, fee_to_treasury_bps)?;
    let producer_portion = producer_subsidy
        .checked_add(producer_fee)
        .ok_or(ValidityLeafError::SplitBound)?;
    let claim = CoinbaseSplitClaim {
        subsidy,
        subsidy_to_treasury_bps,
        fee_sum,
        fee_to_treasury_bps,
        treasury_subsidy,
        producer_subsidy,
        treasury_fee,
        producer_fee,
        producer_portion,
    };
    check_split_bounds(&claim)?;
    Ok(claim)
}

/// Prove [`CoinbaseSplitClaim`]. Refuses a claim that is not the integer quotient.
pub fn prove_coinbase_split(claim: &CoinbaseSplitClaim) -> Result<Vec<u8>, ValidityLeafError> {
    let honest = coinbase_split_claim(
        claim.subsidy,
        claim.subsidy_to_treasury_bps,
        claim.fee_sum,
        claim.fee_to_treasury_bps,
    )?;
    if honest != *claim {
        return Err(ValidityLeafError::SplitDrift);
    }
    let rows = split_rows(claim)?;
    let prover = SplitProver {
        options: proof_options(),
    };
    let proof = prover
        .prove(rows_to_trace(&rows))
        .map_err(|_| ValidityLeafError::ProveFailed)?;
    Ok(proof.to_bytes())
}

/// Verify a coinbase-split STARK. Does not divide.
pub fn verify_coinbase_split(
    claim: &CoinbaseSplitClaim,
    proof_bytes: &[u8],
) -> Result<(), ValidityLeafError> {
    check_split_bounds(claim)?;
    let proof = Proof::read_from_bytes(proof_bytes).map_err(|_| ValidityLeafError::ProofDecode)?;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
    verify::<SplitAir, Hasher, DefaultRandomCoin<Hasher>, MerkleTree<Hasher>>(
        proof,
        SplitPublic::from_claim(claim),
        &min_opts,
    )
    .map_err(|_| ValidityLeafError::ProofInvalid)
}

/// Subsidy claim that matches [`emission::emission_at_height`].
pub fn emission_at_height_claim(
    height: u64,
    params: &EmissionParams,
) -> Result<EmissionAtHeightClaim, ValidityLeafError> {
    check_schedule(params.halving_period, params.halving_count)?;
    let subsidy = emission::emission_at_height(height, params);
    let witness = emission_witness(
        height,
        params.halving_period,
        params.halving_count,
        params.initial_reward,
        params.tail_emission,
    )?;
    if witness.subsidy != subsidy {
        return Err(ValidityLeafError::SubsidyDrift);
    }
    Ok(EmissionAtHeightClaim {
        height,
        halving_period: params.halving_period,
        halving_count: params.halving_count,
        initial_reward: params.initial_reward,
        tail_emission: params.tail_emission,
        subsidy,
    })
}

/// Prove [`EmissionAtHeightClaim`]. Refuses a subsidy that drifts from consensus.
pub fn prove_emission_at_height(
    claim: &EmissionAtHeightClaim,
) -> Result<Vec<u8>, ValidityLeafError> {
    check_schedule(claim.halving_period, claim.halving_count)?;
    let expected = emission::emission_at_height(claim.height, &schedule_params(claim));
    if claim.subsidy != expected {
        return Err(ValidityLeafError::SubsidyDrift);
    }
    let rows = emission_rows(claim)?;
    let prover = EmissionProver {
        options: proof_options(),
    };
    let proof = prover
        .prove(rows_to_trace(&rows))
        .map_err(|_| ValidityLeafError::ProveFailed)?;
    Ok(proof.to_bytes())
}

/// Verify an emission-at-height STARK. Does not call `emission_at_height`.
pub fn verify_emission_at_height(
    claim: &EmissionAtHeightClaim,
    proof_bytes: &[u8],
) -> Result<(), ValidityLeafError> {
    check_schedule(claim.halving_period, claim.halving_count)?;
    let proof = Proof::read_from_bytes(proof_bytes).map_err(|_| ValidityLeafError::ProofDecode)?;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
    verify::<EmissionAir, Hasher, DefaultRandomCoin<Hasher>, MerkleTree<Hasher>>(
        proof,
        EmissionPublic::from_claim(claim),
        &min_opts,
    )
    .map_err(|_| ValidityLeafError::ProofInvalid)
}

fn schedule_params(claim: &EmissionAtHeightClaim) -> EmissionParams {
    EmissionParams {
        initial_reward: claim.initial_reward,
        halving_period: claim.halving_period,
        halving_count: claim.halving_count,
        tail_emission: claim.tail_emission,
        storage_proof_reward: 0,
        fee_to_treasury_bps: 0,
        subsidy_to_treasury_bps: 0,
    }
}

fn check_schedule(period: u64, count: u32) -> Result<(), ValidityLeafError> {
    if period == 0 || count > 64 {
        Err(ValidityLeafError::BadSchedule)
    } else {
        Ok(())
    }
}

fn bps_div(amount: u64, bps: u16) -> Result<(u64, u64, u64), ValidityLeafError> {
    if bps > 10_000 {
        return Err(ValidityLeafError::BadBps);
    }
    let product = u128::from(amount) * u128::from(bps);
    let treasury = u64::try_from(product / 10_000).expect("quotient fits u64");
    let rem = u64::try_from(product % 10_000).expect("remainder fits");
    Ok((treasury, amount - treasury, rem))
}

fn check_split_bounds(claim: &CoinbaseSplitClaim) -> Result<(), ValidityLeafError> {
    if claim.subsidy_to_treasury_bps > 10_000 || claim.fee_to_treasury_bps > 10_000 {
        return Err(ValidityLeafError::BadBps);
    }
    if u128::from(claim.treasury_subsidy) + u128::from(claim.producer_subsidy)
        != u128::from(claim.subsidy)
        || claim.treasury_subsidy > claim.subsidy
    {
        return Err(ValidityLeafError::SplitBound);
    }
    if u128::from(claim.treasury_fee) + u128::from(claim.producer_fee) != u128::from(claim.fee_sum)
        || claim.treasury_fee > claim.fee_sum
    {
        return Err(ValidityLeafError::SplitBound);
    }
    if u128::from(claim.producer_subsidy) + u128::from(claim.producer_fee)
        != u128::from(claim.producer_portion)
    {
        return Err(ValidityLeafError::SplitBound);
    }
    Ok(())
}

fn bit_at(value: u128, index: usize) -> u128 {
    (value >> index) & 1
}

fn fe(value: u128) -> BaseElement {
    BaseElement::new(value)
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31)
}

fn rows_to_trace(rows: &[Vec<BaseElement>]) -> TraceTable<BaseElement> {
    let width = rows[0].len();
    let mut trace = TraceTable::new(width, rows.len());
    trace.fill(
        |state| {
            state.copy_from_slice(&rows[0]);
        },
        |step, state| {
            state.copy_from_slice(&rows[step + 1]);
        },
    );
    trace
}

fn write_bits(cells: &mut [BaseElement], start: usize, value: u128) {
    for i in 0..SPLIT_BITS {
        cells[start + i] = fe(bit_at(value, i));
    }
}

fn split_rows(claim: &CoinbaseSplitClaim) -> Result<Vec<Vec<BaseElement>>, ValidityLeafError> {
    let (_, _, sub_rem) = bps_div(claim.subsidy, claim.subsidy_to_treasury_bps)?;
    let (_, _, fee_rem) = bps_div(claim.fee_sum, claim.fee_to_treasury_bps)?;
    let mut cells = vec![BaseElement::ZERO; SPLIT_WIDTH];
    cells[S_SUBSIDY] = fe(u128::from(claim.subsidy));
    cells[S_SBPS] = fe(u128::from(claim.subsidy_to_treasury_bps));
    cells[S_FEE] = fe(u128::from(claim.fee_sum));
    cells[S_FBPS] = fe(u128::from(claim.fee_to_treasury_bps));
    cells[S_TRE_S] = fe(u128::from(claim.treasury_subsidy));
    cells[S_PRO_S] = fe(u128::from(claim.producer_subsidy));
    cells[S_TRE_F] = fe(u128::from(claim.treasury_fee));
    cells[S_PRO_F] = fe(u128::from(claim.producer_fee));
    cells[S_PORTION] = fe(u128::from(claim.producer_portion));
    write_bits(&mut cells, S_SUB_BITS, u128::from(sub_rem));
    write_bits(&mut cells, S_SUB_GAP, u128::from(9_999 - sub_rem));
    write_bits(&mut cells, S_FEE_BITS, u128::from(fee_rem));
    write_bits(&mut cells, S_FEE_GAP, u128::from(9_999 - fee_rem));
    let mut rows = Vec::with_capacity(SPLIT_LEN);
    for row in 0..SPLIT_LEN {
        let mut step_row = cells.clone();
        step_row[S_STEP] = fe(row as u128);
        rows.push(step_row);
    }
    Ok(rows)
}

struct EmissionWitness {
    subsidy: u64,
    era: u64,
    era_rem: u64,
    use_tail: u64,
    height_zero: u64,
    delta: u64,
    lt: u64,
    low: u64,
    gap: u64,
}

fn emission_witness(
    height: u64,
    period: u64,
    count: u32,
    initial: u64,
    tail: u64,
) -> Result<EmissionWitness, ValidityLeafError> {
    check_schedule(period, count)?;
    if height == 0 {
        return Ok(EmissionWitness {
            subsidy: 0,
            era: 0,
            era_rem: 0,
            use_tail: 0,
            height_zero: 1,
            delta: 0,
            lt: 0,
            low: 0,
            gap: period - 1,
        });
    }
    let era = (height - 1) / period;
    let era_rem = (height - 1) % period;
    let use_tail = u64::from(era >= u64::from(count));
    let (subsidy, low, delta, lt) = if use_tail == 1 {
        (tail, 0, era - u64::from(count), 0)
    } else {
        if era >= 64 {
            return Err(ValidityLeafError::TraceInconsistent);
        }
        let low = if era == 0 {
            0
        } else {
            initial & u64::try_from((1u128 << era) - 1).expect("shift mask fits")
        };
        (initial >> era, low, 0, u64::from(count) - era)
    };
    let gap = u64::try_from(u128::from(period) - 1 - u128::from(era_rem))
        .map_err(|_| ValidityLeafError::TraceInconsistent)?;
    if use_tail == 0 && (u128::from(subsidy) << era) + u128::from(low) != u128::from(initial) {
        return Err(ValidityLeafError::TraceInconsistent);
    }
    Ok(EmissionWitness {
        subsidy,
        era,
        era_rem,
        use_tail,
        height_zero: 0,
        delta,
        lt,
        low,
        gap,
    })
}

fn ratio(numer: BaseElement, denom: BaseElement) -> BaseElement {
    if denom == BaseElement::ZERO {
        BaseElement::ZERO
    } else {
        numer * denom.inv()
    }
}

#[allow(clippy::too_many_lines)]
fn emission_rows(
    claim: &EmissionAtHeightClaim,
) -> Result<Vec<Vec<BaseElement>>, ValidityLeafError> {
    let w = emission_witness(
        claim.height,
        claim.halving_period,
        claim.halving_count,
        claim.initial_reward,
        claim.tail_emission,
    )?;
    if w.subsidy != claim.subsidy {
        return Err(ValidityLeafError::SubsidyDrift);
    }
    let mask_shift = u64::from(w.use_tail == 0 && w.height_zero == 0);
    let mask_tail = u64::from(w.use_tail == 1 && w.height_zero == 0);
    let hinv = if claim.height == 0 {
        BaseElement::ZERO
    } else {
        fe(u128::from(claim.height)).inv()
    };
    let lt_inv = if w.lt == 0 {
        BaseElement::ZERO
    } else {
        fe(u128::from(w.lt)).inv()
    };
    let prod_lt = u128::from(u64::from(w.lt > 0));
    let era_period = u128::from(w.era) * u128::from(claim.halving_period);
    let check = fe(EMISSION_CHECK);

    let mut place = 1u128;
    let mut shift_place = 1u128;
    let mut acc_era = 0u128;
    let mut acc_gap = 0u128;
    let mut acc_delta = 0u128;
    let mut acc_lt = 0u128;
    let mut acc_low = 0u128;
    let mut steps = u128::from(w.era * mask_shift);
    let mut rows = Vec::with_capacity(EMISSION_LEN);
    for row in 0..EMISSION_LEN {
        let alive = u64::from(steps > 0);
        let era_bit = if row < 64 {
            bit_at(u128::from(w.era_rem), row)
        } else {
            0
        };
        let gap_bit = if row < 64 {
            bit_at(u128::from(w.gap), row)
        } else {
            0
        };
        let delta_bit = if row < 64 {
            bit_at(u128::from(w.delta), row)
        } else {
            0
        };
        let lt_bit = if row < 64 {
            bit_at(u128::from(w.lt), row)
        } else {
            0
        };
        let low_bit = if alive == 1 && row < 64 {
            bit_at(u128::from(w.low), row)
        } else {
            0
        };
        let step_fe = fe(row as u128);
        let era_fe = fe(u128::from(w.era));
        let mask_shift_fe = fe(u128::from(mask_shift));
        let mask_tail_fe = fe(u128::from(mask_tail));
        let acc_era_fe = fe(acc_era);
        let acc_gap_fe = fe(acc_gap);
        let acc_delta_fe = fe(acc_delta);
        let acc_lt_fe = fe(acc_lt);
        let acc_low_fe = fe(acc_low);
        let shift_fe = fe(shift_place);
        let steps_fe = fe(steps);
        let subsidy_fe = fe(u128::from(claim.subsidy));
        let scaled = subsidy_fe * shift_fe;
        let denom = step_fe - check;
        let init_numer = steps_fe - era_fe * mask_shift_fe;
        if row == 0 && init_numer != BaseElement::ZERO {
            return Err(ValidityLeafError::TraceInconsistent);
        }
        if row == EMISSION_CHECK as usize {
            let division =
                fe(era_period) + fe(u128::from(w.era_rem)) + fe(1) - fe(u128::from(claim.height));
            let division = division * (fe(1) - fe(u128::from(w.height_zero)));
            let tail_ok = mask_tail_fe * (subsidy_fe - fe(u128::from(claim.tail_emission)));
            let shift_ok =
                mask_shift_fe * (fe(u128::from(claim.initial_reward)) - scaled - acc_low_fe);
            if acc_era_fe != fe(u128::from(w.era_rem))
                || acc_gap_fe != fe(u128::from(w.gap))
                || steps_fe != BaseElement::ZERO
                || division != BaseElement::ZERO
                || tail_ok != BaseElement::ZERO
                || shift_ok != BaseElement::ZERO
            {
                return Err(ValidityLeafError::TraceInconsistent);
            }
        }
        let mut cells = vec![BaseElement::ZERO; EMISSION_WIDTH];
        cells[E_HEIGHT] = fe(u128::from(claim.height));
        cells[E_PERIOD] = fe(u128::from(claim.halving_period));
        cells[E_COUNT] = fe(u128::from(claim.halving_count));
        cells[E_INITIAL] = fe(u128::from(claim.initial_reward));
        cells[E_TAIL] = fe(u128::from(claim.tail_emission));
        cells[E_SUBSIDY] = subsidy_fe;
        cells[E_ERA] = era_fe;
        cells[E_ERA_REM] = fe(u128::from(w.era_rem));
        cells[E_USE_TAIL] = fe(u128::from(w.use_tail));
        cells[E_HEIGHT_ZERO] = fe(u128::from(w.height_zero));
        cells[E_HINV] = hinv;
        cells[E_ERA_PERIOD] = fe(era_period);
        cells[E_MASK_TAIL] = mask_tail_fe;
        cells[E_MASK_SHIFT] = mask_shift_fe;
        cells[E_LT_INV] = lt_inv;
        cells[E_PROD_LT] = fe(prod_lt);
        cells[E_STEP] = step_fe;
        cells[E_ERA_BIT] = fe(era_bit);
        cells[E_ACC_ERA] = acc_era_fe;
        cells[E_SLACK_ERA] = ratio(fe(u128::from(w.era_rem)) - acc_era_fe, denom);
        cells[E_GAP_BIT] = fe(gap_bit);
        cells[E_ACC_GAP] = acc_gap_fe;
        cells[E_SLACK_GAP] = ratio(
            acc_gap_fe - (fe(u128::from(claim.halving_period)) - fe(1) - fe(u128::from(w.era_rem))),
            denom,
        );
        cells[E_DELTA_BIT] = fe(delta_bit);
        cells[E_ACC_DELTA] = acc_delta_fe;
        cells[E_SLACK_DELTA] = ratio(
            fe(u128::from(w.use_tail))
                * (era_fe - fe(u128::from(claim.halving_count)) - acc_delta_fe),
            denom,
        );
        cells[E_LT_BIT] = fe(lt_bit);
        cells[E_ACC_LT] = acc_lt_fe;
        cells[E_SLACK_LT] = ratio(
            mask_shift_fe * (fe(u128::from(claim.halving_count)) - era_fe - acc_lt_fe),
            denom,
        );
        cells[E_PLACE] = fe(place);
        cells[E_LOW_BIT] = fe(low_bit);
        cells[E_SHIFT_PLACE] = shift_fe;
        cells[E_ACC_LOW] = acc_low_fe;
        cells[E_LOW_CONTRIB] = fe(low_bit * shift_place);
        cells[E_SLACK_LOW] = ratio(
            mask_shift_fe * (fe(u128::from(claim.initial_reward)) - scaled - acc_low_fe),
            denom,
        );
        cells[E_STEPS] = steps_fe;
        cells[E_ALIVE] = fe(u128::from(alive));
        cells[E_ALIVE_INV] = if steps == 0 {
            BaseElement::ZERO
        } else {
            steps_fe.inv()
        };
        cells[E_ALIVE_OK] = fe(u128::from(alive));
        cells[E_SCALED] = scaled;
        let hz = fe(u128::from(w.height_zero));
        cells[E_SLACK_DIV] = ratio(
            (fe(1) - hz)
                * (fe(era_period) + fe(u128::from(w.era_rem)) - fe(u128::from(claim.height))
                    + fe(1)),
            denom,
        );
        cells[E_SLACK_TAIL] = ratio(
            mask_tail_fe * (subsidy_fe - fe(u128::from(claim.tail_emission))),
            denom,
        );
        cells[E_SLACK_STEPS] = ratio(steps_fe, denom);
        cells[E_SLACK_PROD] = ratio(mask_shift_fe * (fe(prod_lt) - fe(1)), denom);
        cells[E_SLACK_PROD_DEF] = ratio(fe(prod_lt) - acc_lt_fe * lt_inv, denom);
        cells[E_SLACK_LT0] = ratio(fe(u128::from(w.use_tail)) * acc_lt_fe, denom);
        cells[E_SLACK_DELTA0] = ratio((fe(1) - fe(u128::from(w.use_tail))) * acc_delta_fe, denom);
        cells[E_SLACK_INIT] = ratio(init_numer, step_fe);
        rows.push(cells);
        if row + 1 == EMISSION_LEN {
            break;
        }
        acc_era += era_bit * place;
        acc_gap += gap_bit * place;
        acc_delta += delta_bit * place;
        acc_lt += lt_bit * place;
        place <<= 1;
        if alive == 1 {
            acc_low += low_bit * shift_place;
            shift_place <<= 1;
            steps -= 1;
        }
    }
    Ok(rows)
}

#[derive(Debug, Clone, Copy)]
struct SplitPublic {
    subsidy: BaseElement,
    subsidy_bps: BaseElement,
    fee_sum: BaseElement,
    fee_bps: BaseElement,
    treasury_subsidy: BaseElement,
    producer_subsidy: BaseElement,
    treasury_fee: BaseElement,
    producer_fee: BaseElement,
    portion: BaseElement,
}

impl SplitPublic {
    fn from_claim(claim: &CoinbaseSplitClaim) -> Self {
        Self {
            subsidy: fe(u128::from(claim.subsidy)),
            subsidy_bps: fe(u128::from(claim.subsidy_to_treasury_bps)),
            fee_sum: fe(u128::from(claim.fee_sum)),
            fee_bps: fe(u128::from(claim.fee_to_treasury_bps)),
            treasury_subsidy: fe(u128::from(claim.treasury_subsidy)),
            producer_subsidy: fe(u128::from(claim.producer_subsidy)),
            treasury_fee: fe(u128::from(claim.treasury_fee)),
            producer_fee: fe(u128::from(claim.producer_fee)),
            portion: fe(u128::from(claim.producer_portion)),
        }
    }
}

impl ToElements<BaseElement> for SplitPublic {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.subsidy,
            self.subsidy_bps,
            self.fee_sum,
            self.fee_bps,
            self.treasury_subsidy,
            self.producer_subsidy,
            self.treasury_fee,
            self.producer_fee,
            self.portion,
        ]
    }
}

fn split_acc<E: FieldElement + From<BaseElement>>(row: &[E], start: usize) -> E {
    let mut acc = E::ZERO;
    let mut place = E::ONE;
    let two = E::from(2u32);
    for i in 0..SPLIT_BITS {
        acc += row[start + i] * place;
        place *= two;
    }
    acc
}

struct SplitAir {
    context: AirContext<BaseElement>,
    public: SplitPublic,
}

impl Air for SplitAir {
    type BaseField = BaseElement;
    type PublicInputs = SplitPublic;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, public: SplitPublic, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(2); SPLIT_CONSTRAINTS];
        Self {
            context: AirContext::new(trace_info, degrees, SPLIT_ASSERTIONS, options),
            public,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let one = E::ONE;
        let mut vals = Vec::with_capacity(SPLIT_CONSTRAINTS);
        for col in 0..S_STEP {
            vals.push(nxt[col] - cur[col]);
        }
        // `step` is non-constant so the degree-2 term is not the zero polynomial.
        vals.push(nxt[S_STEP] - cur[S_STEP] - one);
        vals.push(cur[S_STEP] * (nxt[S_STEP] - cur[S_STEP] - one));
        vals.push(cur[S_PRO_S] + cur[S_TRE_S] - cur[S_SUBSIDY]);
        vals.push(cur[S_PRO_F] + cur[S_TRE_F] - cur[S_FEE]);
        vals.push(cur[S_PORTION] - cur[S_PRO_S] - cur[S_PRO_F]);
        for col in 0..SPLIT_BITS {
            for start in [S_SUB_BITS, S_SUB_GAP, S_FEE_BITS, S_FEE_GAP] {
                let bit = cur[start + col];
                vals.push(bit * (bit - one));
            }
        }
        let ten_k = E::from(10_000u32);
        let cap = E::from(9_999u32);
        let sub_rem = split_acc(cur, S_SUB_BITS);
        let sub_gap = split_acc(cur, S_SUB_GAP);
        let fee_rem = split_acc(cur, S_FEE_BITS);
        let fee_gap = split_acc(cur, S_FEE_GAP);
        vals.push(cur[S_SUBSIDY] * cur[S_SBPS] - cur[S_TRE_S] * ten_k - sub_rem);
        vals.push(sub_rem + sub_gap - cap);
        vals.push(cur[S_FEE] * cur[S_FBPS] - cur[S_TRE_F] * ten_k - fee_rem);
        vals.push(fee_rem + fee_gap - cap);
        assert_eq!(vals.len(), result.len(), "split constraint count");
        result.copy_from_slice(&vals);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let p = &self.public;
        vec![
            Assertion::single(S_SUBSIDY, 0, p.subsidy),
            Assertion::single(S_SBPS, 0, p.subsidy_bps),
            Assertion::single(S_FEE, 0, p.fee_sum),
            Assertion::single(S_FBPS, 0, p.fee_bps),
            Assertion::single(S_TRE_S, 0, p.treasury_subsidy),
            Assertion::single(S_PRO_S, 0, p.producer_subsidy),
            Assertion::single(S_TRE_F, 0, p.treasury_fee),
            Assertion::single(S_PRO_F, 0, p.producer_fee),
            Assertion::single(S_PORTION, 0, p.portion),
            Assertion::single(S_STEP, 0, BaseElement::ZERO),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

const SPLIT_ASSERTIONS: usize = 10;
const SPLIT_CONSTRAINTS: usize = S_STEP + 2 + SPLIT_BITS * 4 + 3 + 4;

struct SplitProver {
    options: ProofOptions,
}

impl Prover for SplitProver {
    type BaseField = BaseElement;
    type Air = SplitAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = MerkleTree<Hasher>;
    type RandomCoin = DefaultRandomCoin<Hasher>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Hasher, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, SplitAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> SplitPublic {
        SplitPublic {
            subsidy: trace.get(S_SUBSIDY, 0),
            subsidy_bps: trace.get(S_SBPS, 0),
            fee_sum: trace.get(S_FEE, 0),
            fee_bps: trace.get(S_FBPS, 0),
            treasury_subsidy: trace.get(S_TRE_S, 0),
            producer_subsidy: trace.get(S_PRO_S, 0),
            treasury_fee: trace.get(S_TRE_F, 0),
            producer_fee: trace.get(S_PRO_F, 0),
            portion: trace.get(S_PORTION, 0),
        }
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a SplitAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

#[derive(Debug, Clone, Copy)]
struct EmissionPublic {
    height: BaseElement,
    period: BaseElement,
    count: BaseElement,
    initial: BaseElement,
    tail: BaseElement,
    subsidy: BaseElement,
}

impl EmissionPublic {
    fn from_claim(claim: &EmissionAtHeightClaim) -> Self {
        Self {
            height: fe(u128::from(claim.height)),
            period: fe(u128::from(claim.halving_period)),
            count: fe(u128::from(claim.halving_count)),
            initial: fe(u128::from(claim.initial_reward)),
            tail: fe(u128::from(claim.tail_emission)),
            subsidy: fe(u128::from(claim.subsidy)),
        }
    }
}

impl ToElements<BaseElement> for EmissionPublic {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.height,
            self.period,
            self.count,
            self.initial,
            self.tail,
            self.subsidy,
        ]
    }
}

struct EmissionAir {
    context: AirContext<BaseElement>,
    public: EmissionPublic,
}

impl Air for EmissionAir {
    type BaseField = BaseElement;
    type PublicInputs = EmissionPublic;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, public: EmissionPublic, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(2); EMISSION_CONSTRAINTS];
        Self {
            context: AirContext::new(trace_info, degrees, EMISSION_ASSERTIONS, options),
            public,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let one = E::ONE;
        let two = E::from(2u32);
        let check = E::from(EMISSION_CHECK as u32);
        let gate = cur[E_STEP] - check;
        let mut vals = Vec::with_capacity(EMISSION_CONSTRAINTS);
        for &col in &HELD_EMISSION {
            vals.push(nxt[col] - cur[col]);
        }
        vals.push(nxt[E_STEP] - cur[E_STEP] - one);
        for col in [E_ERA_BIT, E_GAP_BIT, E_DELTA_BIT, E_LT_BIT, E_LOW_BIT] {
            vals.push(cur[col] * (cur[col] - one));
        }
        vals.push((one - cur[E_ALIVE]) * cur[E_LOW_BIT]);
        vals.push(cur[E_ALIVE] * (cur[E_ALIVE] - one));
        vals.push((one - cur[E_ALIVE]) * cur[E_STEPS]);
        vals.push(cur[E_ALIVE_OK] - cur[E_STEPS] * cur[E_ALIVE_INV]);
        vals.push(cur[E_ALIVE] * (cur[E_ALIVE_OK] - one));
        vals.push(cur[E_SCALED] - cur[E_SUBSIDY] * cur[E_SHIFT_PLACE]);
        vals.push(cur[E_LOW_CONTRIB] - cur[E_LOW_BIT] * cur[E_SHIFT_PLACE]);
        vals.push(cur[E_HEIGHT_ZERO] * (cur[E_HEIGHT_ZERO] - one));
        vals.push(cur[E_HEIGHT_ZERO] * cur[E_HEIGHT]);
        vals.push((one - cur[E_HEIGHT_ZERO]) * (cur[E_HEIGHT] * cur[E_HINV] - one));
        vals.push(cur[E_USE_TAIL] * (cur[E_USE_TAIL] - one));
        vals.push(cur[E_ERA_PERIOD] - cur[E_ERA] * cur[E_PERIOD]);
        vals.push(cur[E_MASK_TAIL] - cur[E_USE_TAIL] * (one - cur[E_HEIGHT_ZERO]));
        vals.push(cur[E_MASK_SHIFT] - (one - cur[E_USE_TAIL]) * (one - cur[E_HEIGHT_ZERO]));
        vals.push(cur[E_HEIGHT_ZERO] * cur[E_SUBSIDY]);
        vals.push(cur[E_HEIGHT_ZERO] * cur[E_ERA]);
        vals.push(cur[E_HEIGHT_ZERO] * cur[E_ERA_REM]);
        vals.push(
            (cur[E_STEPS] - cur[E_ERA] * cur[E_MASK_SHIFT]) - cur[E_STEP] * cur[E_SLACK_INIT],
        );
        vals.push(nxt[E_PLACE] - cur[E_PLACE] * two);
        vals.push(nxt[E_ACC_ERA] - cur[E_ACC_ERA] - cur[E_ERA_BIT] * cur[E_PLACE]);
        vals.push(nxt[E_ACC_GAP] - cur[E_ACC_GAP] - cur[E_GAP_BIT] * cur[E_PLACE]);
        vals.push(nxt[E_ACC_DELTA] - cur[E_ACC_DELTA] - cur[E_DELTA_BIT] * cur[E_PLACE]);
        vals.push(nxt[E_ACC_LT] - cur[E_ACC_LT] - cur[E_LT_BIT] * cur[E_PLACE]);
        vals.push(nxt[E_SHIFT_PLACE] - cur[E_SHIFT_PLACE] * (one + cur[E_ALIVE]));
        vals.push(nxt[E_ACC_LOW] - cur[E_ACC_LOW] - cur[E_ALIVE] * cur[E_LOW_CONTRIB]);
        vals.push(nxt[E_STEPS] - (cur[E_STEPS] - cur[E_ALIVE]));
        vals.push((cur[E_ERA_REM] - cur[E_ACC_ERA]) - gate * cur[E_SLACK_ERA]);
        vals.push(
            (cur[E_ACC_GAP] - (cur[E_PERIOD] - one - cur[E_ERA_REM])) - gate * cur[E_SLACK_GAP],
        );
        vals.push(
            (one - cur[E_HEIGHT_ZERO]) * (cur[E_ERA_PERIOD] + cur[E_ERA_REM] - cur[E_HEIGHT] + one)
                - gate * cur[E_SLACK_DIV],
        );
        vals.push(cur[E_MASK_TAIL] * (cur[E_SUBSIDY] - cur[E_TAIL]) - gate * cur[E_SLACK_TAIL]);
        vals.push(
            cur[E_MASK_SHIFT] * (cur[E_INITIAL] - cur[E_SCALED] - cur[E_ACC_LOW])
                - gate * cur[E_SLACK_LOW],
        );
        vals.push(
            cur[E_USE_TAIL] * (cur[E_ERA] - cur[E_COUNT] - cur[E_ACC_DELTA])
                - gate * cur[E_SLACK_DELTA],
        );
        vals.push((one - cur[E_USE_TAIL]) * cur[E_ACC_DELTA] - gate * cur[E_SLACK_DELTA0]);
        vals.push(
            cur[E_MASK_SHIFT] * (cur[E_COUNT] - cur[E_ERA] - cur[E_ACC_LT])
                - gate * cur[E_SLACK_LT],
        );
        vals.push(cur[E_USE_TAIL] * cur[E_ACC_LT] - gate * cur[E_SLACK_LT0]);
        vals.push(cur[E_STEPS] - gate * cur[E_SLACK_STEPS]);
        vals.push((cur[E_PROD_LT] - cur[E_ACC_LT] * cur[E_LT_INV]) - gate * cur[E_SLACK_PROD_DEF]);
        vals.push(cur[E_MASK_SHIFT] * (cur[E_PROD_LT] - one) - gate * cur[E_SLACK_PROD]);
        assert_eq!(vals.len(), result.len(), "emission constraint count");
        result.copy_from_slice(&vals);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let p = &self.public;
        vec![
            Assertion::single(E_HEIGHT, 0, p.height),
            Assertion::single(E_PERIOD, 0, p.period),
            Assertion::single(E_COUNT, 0, p.count),
            Assertion::single(E_INITIAL, 0, p.initial),
            Assertion::single(E_TAIL, 0, p.tail),
            Assertion::single(E_SUBSIDY, 0, p.subsidy),
            Assertion::single(E_STEP, 0, BaseElement::ZERO),
            Assertion::single(E_PLACE, 0, BaseElement::ONE),
            Assertion::single(E_SHIFT_PLACE, 0, BaseElement::ONE),
            Assertion::single(E_ACC_ERA, 0, BaseElement::ZERO),
            Assertion::single(E_ACC_GAP, 0, BaseElement::ZERO),
            Assertion::single(E_ACC_DELTA, 0, BaseElement::ZERO),
            Assertion::single(E_ACC_LT, 0, BaseElement::ZERO),
            Assertion::single(E_ACC_LOW, 0, BaseElement::ZERO),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

const EMISSION_ASSERTIONS: usize = 14;
const EMISSION_CONSTRAINTS: usize = 16 + 1 + 5 + 7 + 10 + 1 + 8 + 12;

struct EmissionProver {
    options: ProofOptions,
}

impl Prover for EmissionProver {
    type BaseField = BaseElement;
    type Air = EmissionAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = MerkleTree<Hasher>;
    type RandomCoin = DefaultRandomCoin<Hasher>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Hasher, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, EmissionAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> EmissionPublic {
        EmissionPublic {
            height: trace.get(E_HEIGHT, 0),
            period: trace.get(E_PERIOD, 0),
            count: trace.get(E_COUNT, 0),
            initial: trace.get(E_INITIAL, 0),
            tail: trace.get(E_TAIL, 0),
            subsidy: trace.get(E_SUBSIDY, 0),
        }
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a EmissionAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::{emission_at_height, producer_portion_amount, DEFAULT_EMISSION_PARAMS};

    fn schedule(initial: u64, period: u64, count: u32, tail: u64) -> EmissionParams {
        EmissionParams {
            initial_reward: initial,
            halving_period: period,
            halving_count: count,
            tail_emission: tail,
            storage_proof_reward: 0,
            fee_to_treasury_bps: 9_000,
            subsidy_to_treasury_bps: 0,
        }
    }

    #[test]
    fn b316_split_edges_match_integer_division_without_a_proof() {
        let zero_bps = coinbase_split_claim(5_000, 0, 100, 0).unwrap();
        assert_eq!(zero_bps.treasury_subsidy, 0);
        assert_eq!(zero_bps.producer_portion, 5_100);
        let full = coinbase_split_claim(5_000, 10_000, 100, 10_000).unwrap();
        assert_eq!(full.producer_subsidy, 0);
        assert_eq!(full.treasury_fee, 100);
        assert_eq!(full.producer_portion, 0);
        let rem = coinbase_split_claim(9_999, 1, 1, 1).unwrap();
        assert_eq!(rem.treasury_subsidy, 0);
        assert_eq!(rem.producer_subsidy, 9_999);
        assert!(coinbase_split_claim(1, 10_001, 0, 0).is_err());
    }

    #[test]
    fn b316_coinbase_split_matches_producer_portion_and_rejects_tamper() {
        let cases = [
            (DEFAULT_EMISSION_PARAMS, 10_000u64),
            (
                {
                    let mut params = DEFAULT_EMISSION_PARAMS;
                    params.subsidy_to_treasury_bps = 1_000;
                    params
                },
                12_345,
            ),
        ];
        for (params, fee) in cases {
            let subsidy = emission_at_height(1, &params);
            let claim = coinbase_split_claim(
                subsidy,
                params.subsidy_to_treasury_bps,
                fee,
                params.fee_to_treasury_bps,
            )
            .unwrap();
            assert_eq!(
                u128::from(claim.producer_portion),
                u128::from(producer_portion_amount(1, &params, u128::from(fee)))
            );
            let proof = prove_coinbase_split(&claim).unwrap();
            verify_coinbase_split(&claim, &proof).unwrap();
            let mut tampered = claim;
            tampered.treasury_subsidy += 1;
            tampered.producer_subsidy -= 1;
            tampered.producer_portion -= 1;
            assert!(verify_coinbase_split(&tampered, &proof).is_err());
            assert!(prove_coinbase_split(&tampered).is_err());
        }
    }

    #[test]
    fn b316_emission_at_height_stark_matches_consensus_and_rejects_tamper() {
        let cases = [
            (0, DEFAULT_EMISSION_PARAMS),
            (1, DEFAULT_EMISSION_PARAMS),
            (5, schedule(100, 4, 8, 10)),
            (8 * 4 + 1, schedule(128, 4, 8, 16)),
            (1_000, schedule(64, 3, 1, 8)),
        ];
        for (height, params) in cases {
            let claim = emission_at_height_claim(height, &params).unwrap();
            assert_eq!(claim.subsidy, emission_at_height(height, &params));
            let proof = prove_emission_at_height(&claim).unwrap();
            verify_emission_at_height(&claim, &proof).unwrap();
            let mut tampered = claim;
            tampered.subsidy = tampered.subsidy.wrapping_add(1);
            assert!(verify_emission_at_height(&tampered, &proof).is_err());
            assert!(prove_emission_at_height(&tampered).is_err());
        }
    }
}
