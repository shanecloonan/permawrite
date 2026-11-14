//! **B-24** local settlement identity for two storage operators.
//!
//! This is the treasury equation the live multi-operator pack still owes:
//! fees split, both operator payouts are paid from treasury then mint, and
//! the supply audit counts only subsidy plus backstop. No network.

use mfn_consensus::{
    settle_storage_reward, subsidy_producer_amount, subsidy_treasury_credit, SupplyAudit,
    DEFAULT_EMISSION_PARAMS,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn b24_two_operator_payouts_conserve_treasury_and_supply(
        fee in 0u64..2_000_000u64,
        treasury in 0u128..5_000_000u128,
        bonus0 in 0u64..20_000u64,
        bonus1 in 0u64..20_000u64,
        height in 1u64..10_000u64,
    ) {
        let params = DEFAULT_EMISSION_PARAMS;
        let fee_sum = u128::from(fee);
        let treasury_fee = fee_sum * u128::from(params.fee_to_treasury_bps) / 10_000;
        let producer_fee = fee_sum - treasury_fee;
        let subsidy_treasury = subsidy_treasury_credit(height, &params);
        let subsidy_producer = subsidy_producer_amount(height, &params);
        let base = u128::from(params.storage_proof_reward);
        let payouts = [base + u128::from(bonus0), base + u128::from(bonus1)];
        let storage_total = payouts[0] + payouts[1];
        let pending = treasury
            .saturating_add(treasury_fee)
            .saturating_add(subsidy_treasury);
        let settlement = settle_storage_reward(pending, storage_total);
        prop_assert_eq!(
            settlement.paid_from_treasury + settlement.minted_backstop,
            storage_total
        );
        prop_assert_eq!(
            settlement.treasury_after + settlement.paid_from_treasury,
            pending
        );
        let producer_coinbase = subsidy_producer + producer_fee;
        let paid_out = producer_coinbase + storage_total;
        let minted = subsidy_producer + subsidy_treasury + settlement.minted_backstop;
        prop_assert!(paid_out >= producer_coinbase);
        let audit = SupplyAudit {
            supply_before: treasury,
            subsidy_minted: subsidy_producer + subsidy_treasury,
            backstop_minted: settlement.minted_backstop,
            supply_after: treasury + minted,
        };
        prop_assert!(audit.holds());
        prop_assert_eq!(params.fee_to_treasury_bps, 9000);
        prop_assert_eq!(params.subsidy_to_treasury_bps, 0);
    }
}
