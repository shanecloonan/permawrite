//! PM8 permanence carve-out (**B-310** helper; not wired into the block log).
//!
//! Linear state growth is a permanence risk: if a full node becomes exotic,
//! the operator set shrinks. The only artifact this helper marks as a prune
//! candidate is **historical `chain.blocks` bodies** strictly below a
//! finalized checkpoint height.
//!
//! Path A does **not** prune. Spent outputs stay in [`ChainState::utxo`] so
//! they remain CLSAG decoys. Storage commitments, endowment params, and
//! SPoRA operator state are never prune candidates.

/// How an artifact must be retained after a finalized chain checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// SPoRA / endowment / chunks / authorship-over-`data_root`.
    /// Dropping this is a permanence bug.
    PermanenceKeep,
    /// Ring decoys, spent key images, UTXO accumulator.
    /// Dropping this is a privacy (or double-spend) bug.
    PrivacyKeep,
    /// Params, treasury, validators, block-id chain.
    /// Dropping this forks consensus.
    ConsensusKeep,
    /// Historical tx bodies in `chain.blocks` below a finalized checkpoint.
    /// The only PM8 prune candidate. Path A does not prune.
    HistoricalBody,
}

/// Every field on [`crate::block::ChainState`].
///
/// When `ChainState` gains a field, add a variant here **and** bump
/// [`CHAIN_STATE_FIELD_COUNT`]. The count test fails closed so a new
/// map cannot ship unclassified (CSV complexity / state-growth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStateField {
    /// [`crate::block::ChainState::height`].
    Height,
    /// [`crate::block::ChainState::utxo`] — spent outputs stay (decoys).
    Utxo,
    /// [`crate::block::ChainState::spent_key_images`].
    SpentKeyImages,
    /// [`crate::block::ChainState::storage`].
    Storage,
    /// [`crate::block::ChainState::storage_operators`].
    StorageOperators,
    /// [`crate::block::ChainState::storage_operator_stats`].
    StorageOperatorStats,
    /// [`crate::block::ChainState::claims`].
    Claims,
    /// [`crate::block::ChainState::block_ids`].
    BlockIds,
    /// [`crate::block::ChainState::validators`].
    Validators,
    /// [`crate::block::ChainState::validator_stats`].
    ValidatorStats,
    /// [`crate::block::ChainState::params`].
    Params,
    /// [`crate::block::ChainState::emission_params`].
    EmissionParams,
    /// [`crate::block::ChainState::subsidy_bps_activation_height`].
    SubsidyBpsActivationHeight,
    /// [`crate::block::ChainState::subsidy_bps_activation_value`].
    SubsidyBpsActivationValue,
    /// [`crate::block::ChainState::endowment_params`].
    EndowmentParams,
    /// [`crate::block::ChainState::treasury`].
    Treasury,
    /// [`crate::block::ChainState::utxo_tree`].
    UtxoTree,
    /// [`crate::block::ChainState::bonding_params`].
    BondingParams,
    /// [`crate::block::ChainState::bond_epoch_id`].
    BondEpochId,
    /// [`crate::block::ChainState::bond_epoch_entry_count`].
    BondEpochEntryCount,
    /// [`crate::block::ChainState::bond_epoch_exit_count`].
    BondEpochExitCount,
    /// [`crate::block::ChainState::next_validator_index`].
    NextValidatorIndex,
    /// [`crate::block::ChainState::pending_unbonds`].
    PendingUnbonds,
    /// [`crate::block::ChainState::header_version`].
    HeaderVersion,
}

/// Must equal the number of fields on [`crate::block::ChainState`].
pub const CHAIN_STATE_FIELD_COUNT: usize = 24;

/// Exhaustive field inventory (order matches [`ChainStateField`] discriminants).
pub const CHAIN_STATE_FIELDS: [ChainStateField; CHAIN_STATE_FIELD_COUNT] = [
    ChainStateField::Height,
    ChainStateField::Utxo,
    ChainStateField::SpentKeyImages,
    ChainStateField::Storage,
    ChainStateField::StorageOperators,
    ChainStateField::StorageOperatorStats,
    ChainStateField::Claims,
    ChainStateField::BlockIds,
    ChainStateField::Validators,
    ChainStateField::ValidatorStats,
    ChainStateField::Params,
    ChainStateField::EmissionParams,
    ChainStateField::SubsidyBpsActivationHeight,
    ChainStateField::SubsidyBpsActivationValue,
    ChainStateField::EndowmentParams,
    ChainStateField::Treasury,
    ChainStateField::UtxoTree,
    ChainStateField::BondingParams,
    ChainStateField::BondEpochId,
    ChainStateField::BondEpochEntryCount,
    ChainStateField::BondEpochExitCount,
    ChainStateField::NextValidatorIndex,
    ChainStateField::PendingUnbonds,
    ChainStateField::HeaderVersion,
];

/// Retention class for a live [`crate::block::ChainState`] field.
///
/// No field is [`Retention::HistoricalBody`] — bodies live in `chain.blocks`,
/// not in the checkpointed maps.
#[must_use]
pub fn chain_state_field_retention(field: ChainStateField) -> Retention {
    match field {
        ChainStateField::Storage
        | ChainStateField::StorageOperators
        | ChainStateField::StorageOperatorStats
        | ChainStateField::Claims
        | ChainStateField::EndowmentParams => Retention::PermanenceKeep,
        ChainStateField::Utxo | ChainStateField::SpentKeyImages | ChainStateField::UtxoTree => {
            Retention::PrivacyKeep
        }
        ChainStateField::Height
        | ChainStateField::BlockIds
        | ChainStateField::Validators
        | ChainStateField::ValidatorStats
        | ChainStateField::Params
        | ChainStateField::EmissionParams
        | ChainStateField::SubsidyBpsActivationHeight
        | ChainStateField::SubsidyBpsActivationValue
        | ChainStateField::Treasury
        | ChainStateField::BondingParams
        | ChainStateField::BondEpochId
        | ChainStateField::BondEpochEntryCount
        | ChainStateField::BondEpochExitCount
        | ChainStateField::NextValidatorIndex
        | ChainStateField::PendingUnbonds
        | ChainStateField::HeaderVersion => Retention::ConsensusKeep,
    }
}

/// `true` only for historical block-log bodies strictly below a finalized
/// checkpoint. Path A must not call this to delete `chain.blocks`.
#[must_use]
pub fn historical_block_body_may_prune(
    block_height: u32,
    finalized_checkpoint_height: u32,
) -> bool {
    finalized_checkpoint_height > 0 && block_height < finalized_checkpoint_height
}

/// Storage commitments are never a prune candidate.
#[must_use]
pub const fn storage_may_prune() -> bool {
    false
}

/// The UTXO map is never a prune candidate (spent outputs are decoys).
#[must_use]
pub const fn utxo_may_prune() -> bool {
    false
}

/// Spent key images are never a prune candidate (double-spend gate).
#[must_use]
pub const fn spent_key_image_may_prune() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b310_every_chain_state_field_is_classified() {
        assert_eq!(CHAIN_STATE_FIELDS.len(), CHAIN_STATE_FIELD_COUNT);
        for field in CHAIN_STATE_FIELDS {
            let r = chain_state_field_retention(field);
            assert_ne!(
                r,
                Retention::HistoricalBody,
                "{field:?} lives in ChainState, not chain.blocks"
            );
        }
    }

    #[test]
    fn b310_storage_and_endowment_are_permanence_keep() {
        for field in [
            ChainStateField::Storage,
            ChainStateField::StorageOperators,
            ChainStateField::StorageOperatorStats,
            ChainStateField::Claims,
            ChainStateField::EndowmentParams,
        ] {
            assert_eq!(
                chain_state_field_retention(field),
                Retention::PermanenceKeep
            );
        }
        assert!(!storage_may_prune());
    }

    #[test]
    fn b310_utxo_and_key_images_are_privacy_keep() {
        for field in [
            ChainStateField::Utxo,
            ChainStateField::SpentKeyImages,
            ChainStateField::UtxoTree,
        ] {
            assert_eq!(chain_state_field_retention(field), Retention::PrivacyKeep);
        }
        assert!(!utxo_may_prune());
        assert!(!spent_key_image_may_prune());
    }

    #[test]
    fn b310_only_bodies_below_checkpoint_are_prune_candidates() {
        assert!(historical_block_body_may_prune(100, 101));
        assert!(historical_block_body_may_prune(0, 1));
        assert!(!historical_block_body_may_prune(101, 101));
        assert!(!historical_block_body_may_prune(102, 101));
        assert!(
            !historical_block_body_may_prune(5, 0),
            "no checkpoint ⇒ do not prune"
        );
    }

    #[test]
    fn b310_path_a_does_not_enable_prune() {
        assert!(
            !storage_may_prune() && !utxo_may_prune() && !spent_key_image_may_prune(),
            "Path A keeps maps; helper must not silently enable drop"
        );
    }

    /// Compile-fail if `ChainState` grows without a matching inventory row.
    #[test]
    fn b310_chain_state_struct_matches_inventory() {
        let crate::block::ChainState {
            height,
            utxo,
            spent_key_images,
            storage,
            storage_operators,
            storage_operator_stats,
            claims,
            block_ids,
            validators,
            validator_stats,
            params,
            emission_params,
            subsidy_bps_activation_height,
            subsidy_bps_activation_value,
            endowment_params,
            treasury,
            utxo_tree,
            bonding_params,
            bond_epoch_id,
            bond_epoch_entry_count,
            bond_epoch_exit_count,
            next_validator_index,
            pending_unbonds,
            header_version,
        } = crate::block::ChainState::empty();
        let _ = (
            height,
            utxo,
            spent_key_images,
            storage,
            storage_operators,
            storage_operator_stats,
            claims,
            block_ids,
            validators,
            validator_stats,
            params,
            emission_params,
            subsidy_bps_activation_height,
            subsidy_bps_activation_value,
            endowment_params,
            treasury,
            utxo_tree,
            bonding_params,
            bond_epoch_id,
            bond_epoch_entry_count,
            bond_epoch_exit_count,
            next_validator_index,
            pending_unbonds,
            header_version,
        );
        assert_eq!(CHAIN_STATE_FIELD_COUNT, 24);
    }
}
