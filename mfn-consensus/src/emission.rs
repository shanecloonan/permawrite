//! Monetary policy.
//!
//! Permawrite is a permanence chain, so the subsidy CANNOT decay to zero —
//! storage providers must be paid *forever* to hold *forever* data. We
//! follow Monero's design: a Bitcoin-like halving curve that asymptotes to a
//! small constant per-block tail emission, plus an EIP-1559-style fee split
//! that routes most of the priority fee to the storage treasury.
//!
//! //! identical for the subset of behaviors this module covers (the protocol module
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
    /// Fraction of each block's emission subsidy credited to the storage
    /// treasury before storage-reward drain (**F6** tail split). Remainder
    /// goes to the producer coinbase. Default `0` preserves legacy behavior.
    pub subsidy_to_treasury_bps: u16,
}

/// Defaults from the whitepaper / protocol.
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
    subsidy_to_treasury_bps: 0,
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
    /// `subsidy_to_treasury_bps > 10000`.
    #[error("subsidy_to_treasury_bps must be in [0, 10000] (got {got})")]
    BadSubsidyBps {
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
    if p.subsidy_to_treasury_bps > 10_000 {
        return Err(EmissionError::BadSubsidyBps {
            got: p.subsidy_to_treasury_bps,
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

use std::collections::{HashMap, HashSet};

use mfn_storage::{
    accrue_proof_reward, operator_identity_from_payout, AccrueArgs, EndowmentParams, StorageProof,
};

use crate::block::StorageEntry;
use crate::coinbase::{CoinbaseOutputSpec, PayoutAddress};

fn proof_operator_dedup_key(commit_hash: &[u8; 32], operator_id: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(commit_hash);
    key[32..].copy_from_slice(operator_id);
    key
}

/// Per-operator PPB bonuses for coinbase compose (B3 frozen-baseline +
/// `replication: 1` payout split when `operator_salted_challenges` is enabled).
///
/// Soft-skips unknown commit / duplicate operator / over-replication /
/// accrue failure. [`crate::block::apply_block`] hard-rejects those same
/// cases — producers must seal **only** the returned proofs (see B-64),
/// not the raw proof-pool drain.
pub fn storage_proof_operator_settlements(
    proofs: &[StorageProof],
    storage: &HashMap<[u8; 32], StorageEntry>,
    slot: u32,
    endowment_params: &EndowmentParams,
) -> Vec<(StorageProof, u128)> {
    let b3 = endowment_params.operator_salted_challenges != 0;
    let mut commit_baseline: HashMap<[u8; 32], (u64, u128)> = HashMap::new();
    let mut seen_operator_proofs: HashSet<[u8; 64]> = HashSet::new();
    let mut commit_proof_count: HashMap<[u8; 32], u8> = HashMap::new();
    let current_slot = u64::from(slot);
    let mut settlements = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let Some(entry) = storage.get(&proof.commit_hash) else {
            continue;
        };
        if b3 {
            let count = commit_proof_count
                .get(&proof.commit_hash)
                .copied()
                .unwrap_or(0);
            if count >= entry.commit.replication {
                continue;
            }
            let operator_id =
                operator_identity_from_payout(&proof.operator_view_pub, &proof.operator_spend_pub);
            let dedup_key = proof_operator_dedup_key(&proof.commit_hash, &operator_id);
            if !seen_operator_proofs.insert(dedup_key) {
                continue;
            }
            commit_proof_count
                .entry(proof.commit_hash)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }
        let (baseline_slot, baseline_pending) = if b3 {
            *commit_baseline
                .entry(proof.commit_hash)
                .or_insert((entry.last_proven_slot, entry.pending_yield_ppb))
        } else {
            (entry.last_proven_slot, entry.pending_yield_ppb)
        };
        let payout_replication = if b3 { 1 } else { entry.commit.replication };
        if let Ok(accrual) = accrue_proof_reward(AccrueArgs {
            size_bytes: entry.commit.size_bytes,
            replication: payout_replication,
            pending_ppb: baseline_pending,
            last_proven_slot: baseline_slot,
            current_slot,
            params: endowment_params,
        }) {
            settlements.push((proof.clone(), accrual.payout));
        }
    }
    settlements
}

/// PPB endowment yield bonus for storage proofs about to be mined (mirrors
/// `apply_block` `storage_bonus_total`).
pub fn storage_proof_coinbase_bonus(
    proofs: &[StorageProof],
    storage: &HashMap<[u8; 32], StorageEntry>,
    slot: u32,
    endowment_params: &EndowmentParams,
) -> u128 {
    storage_proof_operator_settlements(proofs, storage, slot, endowment_params)
        .into_iter()
        .map(|(_, bonus)| bonus)
        .fold(0u128, u128::saturating_add)
}

/// B-28 Path A draft treasury floor (base units). Ops alert if live
/// `treasury_base_units` falls below this while the tip advances.
pub const B28_PATH_A_TREASURY_FLOOR_BASE_UNITS: u128 = 1_000_000;

/// **B-20** / FEES §5.5 stressed-runway fee→treasury step (basis points).
/// Upper end of the drafted +500–1000 range; saturates at 10000.
pub const RECOMMENDED_FEE_SHIFT_STEP_BPS: u16 = 1_000;

/// Rolling-window observation for [`recommended_fee_to_treasury_bps`].
///
/// Not an on-chain oracle (**PM22** research). Callers feed B-28 / telemetry
/// numbers; this helper only names the one-lever fee split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeShiftObservation {
    /// Live treasury balance (base units).
    pub treasury_base_units: u128,
    /// Floor to compare against (Path A draft: [`B28_PATH_A_TREASURY_FLOOR_BASE_UNITS`]).
    pub treasury_floor_base_units: u128,
    /// Blocks in the window that included ≥1 accepted storage proof.
    pub proof_blocks: u64,
    /// Proof blocks whose storage payout required emission backstop minting.
    pub backstop_blocks: u64,
}

impl FeeShiftObservation {
    /// Treasury at/under the floor **and** backstop funded a majority of
    /// proof blocks. An empty window is not stress (no evidence).
    #[must_use]
    pub fn permanence_runway_stressed(&self) -> bool {
        if self.proof_blocks == 0 {
            return false;
        }
        let near_floor = self.treasury_base_units <= self.treasury_floor_base_units;
        let backstop_majority = self.backstop_blocks.saturating_mul(2) >= self.proof_blocks;
        near_floor && backstop_majority
    }
}

/// Recommend `fee_to_treasury_bps` for a later **B-20** parameter fork.
///
/// Healthy runway → hold `current_bps`. Stressed runway →
/// `min(10000, current_bps + RECOMMENDED_FEE_SHIFT_STEP_BPS)`.
/// Does not mutate [`DEFAULT_EMISSION_PARAMS`] and is not read by `apply_block`.
#[must_use]
pub fn recommended_fee_to_treasury_bps(current_bps: u16, obs: &FeeShiftObservation) -> u16 {
    if !obs.permanence_runway_stressed() {
        return current_bps;
    }
    current_bps
        .saturating_add(RECOMMENDED_FEE_SHIFT_STEP_BPS)
        .min(10_000)
}

/// **PM41** yearly backstop-mint budget as basis points of annual tail.
/// `100` = 1% extra inflation from emergency mint — F5's circuit breaker.
pub const RECOMMENDED_BACKSTOP_CAP_ANNUAL_BPS: u16 = 100;

/// Per-slot backstop mint cap: `floor(tail_emission · bps / 10000)`.
///
/// At DEFAULT tail (`(50 MFN) >> 8`) this is **195_312** base units. Path A's
/// `storage_proof_reward` (`MFN_BASE / 10`) is larger, so wiring the cap
/// today would reject honest proofs — apply only after **B-306c** prize
/// shrink. Does not mutate [`DEFAULT_EMISSION_PARAMS`].
#[must_use]
pub fn recommended_backstop_mint_cap_per_slot(params: &EmissionParams) -> u128 {
    u128::from(params.tail_emission) * u128::from(RECOMMENDED_BACKSTOP_CAP_ANNUAL_BPS) / 10_000
}

/// Window cap: per-slot cap × `window_slots` (saturating).
#[must_use]
pub fn recommended_backstop_mint_cap_for_window(
    params: &EmissionParams,
    window_slots: u64,
) -> u128 {
    recommended_backstop_mint_cap_per_slot(params).saturating_mul(u128::from(window_slots))
}

/// Yearly cap: `annual_tail_emission · bps / 10000` (1% of annual tail).
#[must_use]
pub fn recommended_backstop_mint_cap_per_year(
    blocks_per_year: u64,
    params: &EmissionParams,
) -> u128 {
    annual_tail_emission(blocks_per_year, params) * u128::from(RECOMMENDED_BACKSTOP_CAP_ANNUAL_BPS)
        / 10_000
}

/// Rolling-window observation for [`BackstopMintObservation::cap_binds`].
///
/// Callers feed minted backstop base units (treasury-shortfall mint, not
/// subsidy). Not read by `apply_block` (**PM41** wire is later).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackstopMintObservation {
    /// Fresh tokens minted as storage-reward shortfall in the window.
    pub minted_in_window: u128,
    /// Window length in slots (1 = per-block; endowment `slots_per_year` = year).
    pub window_slots: u64,
}

impl BackstopMintObservation {
    /// `true` when minted backstop exceeds the PM41 window cap.
    #[must_use]
    pub fn cap_binds(&self, params: &EmissionParams) -> bool {
        self.minted_in_window > recommended_backstop_mint_cap_for_window(params, self.window_slots)
    }
}

/// Checkpointed subsidy overlay. `activation_height == 0` is inactive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubsidyBpsSchedule {
    /// Height at which [`Self::activation_value`] overlays base bps.
    pub activation_height: u32,
    /// Overlay `subsidy_to_treasury_bps` at/after [`Self::activation_height`].
    pub activation_value: u16,
}

impl SubsidyBpsSchedule {
    /// [`effective_emission_params`] for `height` against `base`.
    #[must_use]
    pub fn effective(self, base: &EmissionParams, height: u32) -> EmissionParams {
        effective_emission_params(base, height, self.activation_height, self.activation_value)
    }

    /// Refuse an overlay that would take more than 100% of subsidy.
    ///
    /// `activation_height == 0` is inactive, but a stored
    /// `activation_value > 10000` is still rejected so a later height
    /// flip cannot arm an illegal split. Does not mutate
    /// [`DEFAULT_EMISSION_PARAMS`].
    pub fn validate(self) -> Result<(), EmissionError> {
        if self.activation_value > 10_000 {
            return Err(EmissionError::BadSubsidyBps {
                got: self.activation_value,
            });
        }
        Ok(())
    }
}

/// Height-aware emission params: copy `base`, then overlay
/// `subsidy_to_treasury_bps` when `activation_height != 0` and
/// `height >= activation_height`.
///
/// Never writes back to `base`. `activation_height == 0` is inactive
/// (Path A today). Does not change [`DEFAULT_EMISSION_PARAMS`].
#[must_use]
pub fn effective_emission_params(
    base: &EmissionParams,
    height: u32,
    activation_height: u32,
    activation_value: u16,
) -> EmissionParams {
    let mut p = *base;
    if activation_height != 0 && height >= activation_height {
        p.subsidy_to_treasury_bps = activation_value;
    }
    p
}

/// Treasury tranche of block subsidy when a producer coinbase is required.
pub fn subsidy_treasury_credit(height: u64, params: &EmissionParams) -> u128 {
    let subsidy = u128::from(emission_at_height(height, params));
    subsidy * u128::from(params.subsidy_to_treasury_bps) / 10_000
}

/// Producer coinbase subsidy tranche after the F6 tail split.
pub fn subsidy_producer_amount(height: u64, params: &EmissionParams) -> u128 {
    let subsidy = u128::from(emission_at_height(height, params));
    subsidy.saturating_sub(subsidy_treasury_credit(height, params))
}

/// Producer coinbase portion only: producer subsidy tranche + producer fee share.
pub fn producer_portion_amount(height: u64, params: &EmissionParams, fee_sum: u128) -> u64 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let producer_fee = fee_sum.saturating_sub(treasury_fee);
    let total = subsidy_producer_amount(height, params).saturating_add(producer_fee);
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// Per-proof operator payout: base storage reward + PPB bonus.
pub fn storage_payout_amount(base_reward: u64, bonus: u128) -> u64 {
    u64::try_from(u128::from(base_reward).saturating_add(bonus)).unwrap_or(u64::MAX)
}

/// Build coinbase output specs for a block: output 0 = producer, 1..N = operators.
pub fn block_coinbase_specs(
    height: u64,
    params: &EmissionParams,
    fee_sum: u128,
    producer_payout: PayoutAddress,
    accepted_proofs: &[(StorageProof, u128)],
) -> Vec<CoinbaseOutputSpec> {
    let mut specs = Vec::with_capacity(1 + accepted_proofs.len());
    specs.push(CoinbaseOutputSpec {
        payout: producer_payout,
        amount: producer_portion_amount(height, params, fee_sum),
    });
    for (proof, bonus) in accepted_proofs {
        specs.push(CoinbaseOutputSpec {
            payout: PayoutAddress {
                view_pub: proof.operator_view_pub,
                spend_pub: proof.operator_spend_pub,
            },
            amount: storage_payout_amount(params.storage_proof_reward, *bonus),
        });
    }
    specs
}

/// Coinbase amount [`crate::coinbase::build_coinbase`] must use so
/// [`crate::block::apply_block`] accepts the block (subsidy + producer fee
/// share + per-proof reward + PPB bonus).
pub fn producer_coinbase_amount(
    height: u64,
    params: &EmissionParams,
    fee_sum: u128,
    accepted_storage_proofs: usize,
    storage_bonus: u128,
) -> u64 {
    let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
    let producer_fee = fee_sum.saturating_sub(treasury_fee);
    let storage_reward_total = u128::from(params.storage_proof_reward)
        .saturating_mul(accepted_storage_proofs as u128)
        .saturating_add(storage_bonus);
    let total = subsidy_producer_amount(height, params)
        .saturating_add(producer_fee)
        .saturating_add(storage_reward_total);
    u64::try_from(total).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_validate() {
        assert!(validate_emission_params(&DEFAULT_EMISSION_PARAMS).is_ok());
    }

    #[test]
    fn default_subsidy_bps_stays_zero() {
        assert_eq!(DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps, 0);
    }

    #[test]
    fn b306c_path_a_prize_stays_tenth_mfn_and_dwarfs_backstop() {
        use mfn_storage::{recommended_backstop_proof_reward, DEFAULT_ENDOWMENT_PARAMS};
        assert_eq!(DEFAULT_EMISSION_PARAMS.storage_proof_reward, MFN_BASE / 10);
        let backstop = recommended_backstop_proof_reward(&DEFAULT_ENDOWMENT_PARAMS)
            .expect("default endowment");
        assert!(backstop >= 1);
        assert!(
            u128::from(DEFAULT_EMISSION_PARAMS.storage_proof_reward) / u128::from(backstop)
                >= 5_000,
            "Path A 0.1 MFN prize must remain a bootstrap prize, not the C0 backstop"
        );
    }

    #[test]
    fn b268e_schedule_rejects_bps_above_10000() {
        let bad = SubsidyBpsSchedule {
            activation_height: 1,
            activation_value: 10_001,
        };
        assert_eq!(
            bad.validate(),
            Err(EmissionError::BadSubsidyBps { got: 10_001 })
        );
        let inactive_bomb = SubsidyBpsSchedule {
            activation_height: 0,
            activation_value: 10_001,
        };
        assert_eq!(
            inactive_bomb.validate(),
            Err(EmissionError::BadSubsidyBps { got: 10_001 })
        );
        assert_eq!(
            SubsidyBpsSchedule {
                activation_height: 1,
                activation_value: 1000,
            }
            .validate(),
            Ok(())
        );
        assert_eq!(SubsidyBpsSchedule::default().validate(), Ok(()));
        assert_eq!(DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps, 0);
    }

    #[test]
    fn effective_emission_inactive_schedule_is_base() {
        let p = effective_emission_params(&DEFAULT_EMISSION_PARAMS, 1_000, 0, 1000);
        assert_eq!(p, DEFAULT_EMISSION_PARAMS);
        assert_eq!(p.subsidy_to_treasury_bps, 0);
    }

    #[test]
    fn effective_emission_overlays_at_and_after_activation() {
        let pre = effective_emission_params(&DEFAULT_EMISSION_PARAMS, 9, 10, 1000);
        let at = effective_emission_params(&DEFAULT_EMISSION_PARAMS, 10, 10, 1000);
        let post = effective_emission_params(&DEFAULT_EMISSION_PARAMS, 11, 10, 1000);
        assert_eq!(pre.subsidy_to_treasury_bps, 0);
        assert_eq!(at.subsidy_to_treasury_bps, 1000);
        assert_eq!(post.subsidy_to_treasury_bps, 1000);
        assert_eq!(
            pre.fee_to_treasury_bps,
            DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps
        );
        assert_eq!(DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps, 0);
        let mut mutated = DEFAULT_EMISSION_PARAMS;
        mutated.subsidy_to_treasury_bps = 1000;
        assert_eq!(at, mutated);
        assert!(validate_emission_params(&at).is_ok());
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
            subsidy_to_treasury_bps: 0,
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
    fn validate_rejects_bad_subsidy_bps() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        p.subsidy_to_treasury_bps = 10_001;
        assert!(matches!(
            validate_emission_params(&p),
            Err(EmissionError::BadSubsidyBps { .. })
        ));
    }

    #[test]
    fn subsidy_tail_split_partitions_emission() {
        let mut p = DEFAULT_EMISSION_PARAMS;
        p.subsidy_to_treasury_bps = 1000;
        let h = 1;
        let subsidy = u128::from(emission_at_height(h, &p));
        assert_eq!(subsidy_treasury_credit(h, &p), subsidy / 10);
        assert_eq!(subsidy_producer_amount(h, &p), subsidy - subsidy / 10);
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

    fn obs(
        treasury: u128,
        floor: u128,
        proof_blocks: u64,
        backstop_blocks: u64,
    ) -> FeeShiftObservation {
        FeeShiftObservation {
            treasury_base_units: treasury,
            treasury_floor_base_units: floor,
            proof_blocks,
            backstop_blocks,
        }
    }

    #[test]
    fn b309_hold_when_treasury_above_floor() {
        let current = DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps;
        let healthy = obs(2_909_711, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 100, 80);
        assert!(!healthy.permanence_runway_stressed());
        assert_eq!(recommended_fee_to_treasury_bps(current, &healthy), current);
    }

    #[test]
    fn b309_hold_when_backstop_not_majority() {
        let current = DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps;
        let drought_fees_but_treasury_covers =
            obs(500_000, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 100, 10);
        assert!(!drought_fees_but_treasury_covers.permanence_runway_stressed());
        assert_eq!(
            recommended_fee_to_treasury_bps(current, &drought_fees_but_treasury_covers),
            current
        );
    }

    #[test]
    fn b309_empty_window_is_not_stress() {
        let current = DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps;
        let empty = obs(0, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 0, 0);
        assert!(!empty.permanence_runway_stressed());
        assert_eq!(recommended_fee_to_treasury_bps(current, &empty), current);
    }

    #[test]
    fn b309_stress_adds_step_and_saturates_at_10000() {
        let current = DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps;
        let stress = obs(500_000, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 100, 60);
        assert!(stress.permanence_runway_stressed());
        assert_eq!(
            recommended_fee_to_treasury_bps(current, &stress),
            10_000,
            "9000 + 1000 = 10000 (all fees to treasury; producer keeps subsidy/tail)"
        );
        assert_eq!(recommended_fee_to_treasury_bps(9_500, &stress), 10_000);
        assert_eq!(recommended_fee_to_treasury_bps(10_000, &stress), 10_000);
    }

    #[test]
    fn b309_path_a_default_stays_9000() {
        assert_eq!(DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps, 9000);
        assert_eq!(RECOMMENDED_FEE_SHIFT_STEP_BPS, 1_000);
        let stress = obs(1, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 2, 2);
        let rec =
            recommended_fee_to_treasury_bps(DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps, &stress);
        assert_ne!(
            rec, DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps,
            "helper is a real lever; Path A must not silently enable it"
        );
        assert!(validate_emission_params(&DEFAULT_EMISSION_PARAMS).is_ok());
        let mut shifted = DEFAULT_EMISSION_PARAMS;
        shifted.fee_to_treasury_bps = rec;
        assert!(validate_emission_params(&shifted).is_ok());
        assert_eq!(shifted.subsidy_to_treasury_bps, 0);
    }

    #[test]
    fn b309_fee_split_identity_conserves_fee_sum() {
        let fee_sum = 10_000u128;
        let hold = DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps;
        let stress = obs(0, B28_PATH_A_TREASURY_FLOOR_BASE_UNITS, 1, 1);
        let shifted = recommended_fee_to_treasury_bps(hold, &stress);
        let hold_treasury = fee_sum * u128::from(hold) / 10_000;
        let hold_producer = fee_sum.saturating_sub(hold_treasury);
        let shift_treasury = fee_sum * u128::from(shifted) / 10_000;
        let shift_producer = fee_sum.saturating_sub(shift_treasury);
        assert_eq!(hold_treasury + hold_producer, fee_sum);
        assert_eq!(shift_treasury + shift_producer, fee_sum);
        assert!(shift_treasury > hold_treasury);
        assert!(shift_producer < hold_producer);
    }

    #[test]
    fn b311_per_slot_cap_is_one_percent_of_tail() {
        let p = DEFAULT_EMISSION_PARAMS;
        let cap = recommended_backstop_mint_cap_per_slot(&p);
        assert_eq!(cap, u128::from(p.tail_emission) / 100);
        assert_eq!(cap, 195_312);
        assert_eq!(RECOMMENDED_BACKSTOP_CAP_ANNUAL_BPS, 100);
    }

    #[test]
    fn b311_yearly_cap_is_one_percent_of_annual_tail() {
        let p = DEFAULT_EMISSION_PARAMS;
        let bpy = mfn_storage::DEFAULT_ENDOWMENT_PARAMS.slots_per_year;
        let annual = annual_tail_emission(bpy, &p);
        let yearly = recommended_backstop_mint_cap_per_year(bpy, &p);
        assert_eq!(yearly, annual / 100);
        assert_eq!(
            recommended_backstop_mint_cap_for_window(&p, bpy),
            recommended_backstop_mint_cap_per_slot(&p) * u128::from(bpy)
        );
    }

    #[test]
    fn b311_path_a_prize_exceeds_per_slot_cap() {
        let p = DEFAULT_EMISSION_PARAMS;
        let cap = recommended_backstop_mint_cap_per_slot(&p);
        assert!(
            u128::from(p.storage_proof_reward) > cap,
            "Path A 0.1 MFN prize must not silently sit under the cap"
        );
        let one_proof = BackstopMintObservation {
            minted_in_window: u128::from(p.storage_proof_reward),
            window_slots: 1,
        };
        assert!(one_proof.cap_binds(&p));
        assert!(validate_emission_params(&p).is_ok());
    }

    #[test]
    fn b311_sized_prize_fits_under_cap() {
        let p = DEFAULT_EMISSION_PARAMS;
        let cap = recommended_backstop_mint_cap_per_slot(&p);
        let sized =
            mfn_storage::recommended_backstop_proof_reward(&mfn_storage::DEFAULT_ENDOWMENT_PARAMS)
                .expect("defaults");
        assert!(u128::from(sized) < cap);
        let one_proof = BackstopMintObservation {
            minted_in_window: u128::from(sized),
            window_slots: 1,
        };
        assert!(!one_proof.cap_binds(&p));
    }

    #[test]
    fn b311_zero_mint_does_not_bind() {
        let p = DEFAULT_EMISSION_PARAMS;
        let idle = BackstopMintObservation {
            minted_in_window: 0,
            window_slots: 1,
        };
        assert!(!idle.cap_binds(&p));
        let empty_window = BackstopMintObservation {
            minted_in_window: 1,
            window_slots: 0,
        };
        assert!(
            empty_window.cap_binds(&p),
            "any mint in a zero-length window is over cap (fail closed)"
        );
    }
}
