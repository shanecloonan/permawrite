//! G-6: supply, storage settlement, key images, and endowment principal.
//!
//! These are the conservation rules a hostile block must not break.
//! `admit_key_image` is the same function `apply_block` calls.

use std::collections::HashSet;

use mfn_consensus::{admit_key_image, settle_storage_reward, SupplyAudit};
use mfn_storage::{endowment_principal_after_slots, EndowmentParams, DEFAULT_ENDOWMENT_PARAMS};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn storage_settlement_conserves_reward_and_treasury(
        treasury in any::<u128>(),
        reward in any::<u128>(),
    ) {
        let settled = settle_storage_reward(treasury, reward);
        prop_assert_eq!(
            settled.paid_from_treasury.checked_add(settled.minted_backstop),
            Some(reward)
        );
        prop_assert_eq!(
            settled.treasury_after.checked_add(settled.paid_from_treasury),
            Some(treasury)
        );
        prop_assert!(settled.treasury_after <= treasury);
        prop_assert!(settled.paid_from_treasury <= reward);
        // A mint happens only after the treasury is fully drawn.
        prop_assert!(settled.minted_backstop == 0 || settled.paid_from_treasury == treasury);
    }

    #[test]
    fn supply_audit_matches_checked_addition(
        before in any::<u128>(),
        subsidy in any::<u128>(),
        backstop in any::<u128>(),
        after in any::<u128>(),
    ) {
        let audit = SupplyAudit {
            supply_before: before,
            subsidy_minted: subsidy,
            backstop_minted: backstop,
            supply_after: after,
        };
        let expected = before.checked_add(subsidy).and_then(|v| v.checked_add(backstop));
        prop_assert_eq!(audit.holds(), expected == Some(after));
    }

    #[test]
    fn key_image_is_spendable_once(raw in proptest::collection::vec(any::<[u8; 32]>(), 0..64)) {
        let mut spent = HashSet::new();
        let mut seen = HashSet::new();
        for key_image in raw {
            let fresh = !seen.contains(&key_image);
            prop_assert_eq!(admit_key_image(&mut spent, key_image), fresh);
            seen.insert(key_image);
            prop_assert!(!admit_key_image(&mut spent, key_image));
        }
        prop_assert_eq!(spent.len(), seen.len());
    }

    #[test]
    fn endowment_principal_never_grows_or_wraps(
        endowment in any::<u64>(),
        slots in 0u64..50_000,
    ) {
        let params: EndowmentParams = DEFAULT_ENDOWMENT_PARAMS;
        let left = endowment_principal_after_slots(
            u128::from(endowment),
            slots,
            params.slots_per_year,
            &params,
        );
        if let Ok(left) = left {
            prop_assert!(left <= u128::from(endowment));
        }
    }
}

#[test]
fn honest_supply_audit_holds() {
    let audit = SupplyAudit {
        supply_before: 1_000,
        subsidy_minted: 50,
        backstop_minted: 3,
        supply_after: 1_053,
    };
    assert!(audit.holds());
}
