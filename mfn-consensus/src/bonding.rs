//! Validator bonding and rotation **parameters** (Milestone M1).
//!
//! The full state transition (bond / unbond txs, churn queues) is specified
//! in [`docs/M1_VALIDATOR_ROTATION.md`](../../docs/M1_VALIDATOR_ROTATION.md)
//! and will plug into [`crate::block::apply_block`] in a follow-up PR.
//! This module ships **defaults** and **pure validation helpers** so every
//! later change has a single source of truth for numeric bounds.

use thiserror::Error;

/// Economic and scheduling bounds for validator entry, exit, and unbonding.
///
/// All fields are intentionally small and copy-friendly; they are expected
/// to become part of [`crate::block::ConsensusParams`] or genesis config
/// once rotation is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondingParams {
    /// Minimum effective stake (base units) required to register a validator.
    pub min_validator_stake: u64,
    /// Number of block heights a validator must wait after requesting unbond
    /// before stake may be released (must cover max evidence propagation).
    pub unbond_delay_heights: u32,
    /// Maximum new validators that may **enter** the active set per epoch.
    pub max_entry_churn_per_epoch: u32,
    /// Maximum validators that may **fully exit** per epoch (after delay).
    pub max_exit_churn_per_epoch: u32,
    /// Epoch length in block heights (`epoch_id = height / slots_per_epoch`).
    pub slots_per_epoch: u32,
}

/// Default bonding parameters — conservative starting point; tune at
/// genesis before mainnet.
pub const DEFAULT_BONDING_PARAMS: BondingParams = BondingParams {
    // One million base units (1 MFN if 1e8 decimals) — high enough to deter
    // spam bonds, low enough for local testnets to override in genesis.
    min_validator_stake: 1_000_000,
    // ~24h at 6s slots ≈ 14_400; we use a round 20_000 for documentation
    // simplicity until tied to real slot time config.
    unbond_delay_heights: 20_000,
    max_entry_churn_per_epoch: 4,
    max_exit_churn_per_epoch: 4,
    slots_per_epoch: 7200,
};

/// Validation failures for bonding / churn rules.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BondingError {
    /// Stake is below the configured minimum.
    #[error("stake {stake} is below min_validator_stake {min}")]
    StakeBelowMinimum {
        /// Observed stake.
        stake: u64,
        /// Required minimum.
        min: u64,
    },
    /// Too many validators already entered this epoch.
    #[error("entry churn {current} exceeds max_entry_churn_per_epoch {max}")]
    EntryChurnExceeded {
        /// Attempted count after applying the new entry.
        current: u32,
        /// Allowed maximum.
        max: u32,
    },
    /// Too many validators already exited this epoch.
    #[error("exit churn {current} exceeds max_exit_churn_per_epoch {max}")]
    ExitChurnExceeded {
        /// Attempted count after applying the new exit.
        current: u32,
        /// Allowed maximum.
        max: u32,
    },
    /// `slots_per_epoch` must be positive.
    #[error("slots_per_epoch must be > 0")]
    ZeroEpochLength,
}

/// `epoch_id` for a block height (genesis height `0` ⇒ epoch `0`).
pub fn epoch_id_for_height(height: u32, slots_per_epoch: u32) -> Result<u64, BondingError> {
    if slots_per_epoch == 0 {
        return Err(BondingError::ZeroEpochLength);
    }
    Ok(u64::from(height) / u64::from(slots_per_epoch))
}

/// First block height that belongs to `epoch_id + 1`.
#[must_use]
pub fn height_of_next_epoch(epoch_id: u64, slots_per_epoch: u32) -> u32 {
    ((epoch_id + 1) * u64::from(slots_per_epoch)) as u32
}

/// Check `stake` against [`BondingParams::min_validator_stake`].
pub fn validate_stake(stake: u64, params: &BondingParams) -> Result<(), BondingError> {
    if stake < params.min_validator_stake {
        return Err(BondingError::StakeBelowMinimum {
            stake,
            min: params.min_validator_stake,
        });
    }
    Ok(())
}

/// Increment entry-churn counter after a successful bond, or error.
pub fn try_register_entry_churn(
    entries_so_far_this_epoch: u32,
    params: &BondingParams,
) -> Result<u32, BondingError> {
    let next = entries_so_far_this_epoch.saturating_add(1);
    if next > params.max_entry_churn_per_epoch {
        return Err(BondingError::EntryChurnExceeded {
            current: next,
            max: params.max_entry_churn_per_epoch,
        });
    }
    Ok(next)
}

/// Increment exit-churn counter after a completed exit, or error.
pub fn try_register_exit_churn(
    exits_so_far_this_epoch: u32,
    params: &BondingParams,
) -> Result<u32, BondingError> {
    let next = exits_so_far_this_epoch.saturating_add(1);
    if next > params.max_exit_churn_per_epoch {
        return Err(BondingError::ExitChurnExceeded {
            current: next,
            max: params.max_exit_churn_per_epoch,
        });
    }
    Ok(next)
}

/// Block height at which an unbond requested at `request_height` may settle.
#[must_use]
pub fn unbond_unlock_height(request_height: u32, params: &BondingParams) -> u32 {
    request_height.saturating_add(params.unbond_delay_heights)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_math_roundtrip() {
        let p = DEFAULT_BONDING_PARAMS;
        assert_eq!(epoch_id_for_height(0, p.slots_per_epoch).unwrap(), 0);
        assert_eq!(
            epoch_id_for_height(p.slots_per_epoch - 1, p.slots_per_epoch).unwrap(),
            0
        );
        assert_eq!(
            epoch_id_for_height(p.slots_per_epoch, p.slots_per_epoch).unwrap(),
            1
        );
        assert_eq!(
            height_of_next_epoch(0, p.slots_per_epoch),
            p.slots_per_epoch
        );
    }

    #[test]
    fn zero_epoch_rejected() {
        assert_eq!(
            epoch_id_for_height(10, 0),
            Err(BondingError::ZeroEpochLength)
        );
    }

    #[test]
    fn stake_minimum() {
        let p = DEFAULT_BONDING_PARAMS;
        assert!(validate_stake(p.min_validator_stake, &p).is_ok());
        assert_eq!(
            validate_stake(p.min_validator_stake - 1, &p),
            Err(BondingError::StakeBelowMinimum {
                stake: p.min_validator_stake - 1,
                min: p.min_validator_stake,
            })
        );
    }

    #[test]
    fn entry_churn_cap() {
        let p = DEFAULT_BONDING_PARAMS;
        let mut n = 0u32;
        for _ in 0..p.max_entry_churn_per_epoch {
            n = try_register_entry_churn(n, &p).unwrap();
        }
        assert_eq!(
            try_register_entry_churn(n, &p),
            Err(BondingError::EntryChurnExceeded {
                current: p.max_entry_churn_per_epoch + 1,
                max: p.max_entry_churn_per_epoch,
            })
        );
    }

    #[test]
    fn unbond_delay_saturates() {
        let mut p = DEFAULT_BONDING_PARAMS;
        p.unbond_delay_heights = u32::MAX;
        assert_eq!(unbond_unlock_height(u32::MAX, &p), u32::MAX);
    }
}
