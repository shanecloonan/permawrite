# B-309 — Producer↔treasury runway fee-shift helper

**Status:** **B-309** calibration helper + Path A pin (this unit). **Not** a `DEFAULT_EMISSION_PARAMS` flip. **Not** B-13c. **Not** an on-chain oracle. **Not** B-20 armed.
**Owner:** lane 6 · **Does not change** live Path A `fee_to_treasury_bps = 9000`
**Depends on:** **B-28** draft treasury floor (`1_000_000` base units); **B-13a** identity sims
**Blocks:** honest **B-20** sequencing (one lever, after B-13c soak + B-25)

## Why this exists

CSV / [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume) + [§4](./PROBLEMS.md#4-producer-and-storage-operator-incentives-are-only-loosely-aligned): when privacy fees drought, producers still collect the 10% fee tip + subsidy/tail while operators drain the treasury and then the emission backstop. Drip (**B-306**) and subsidy-to-treasury (**B-13**) are other inflow levers. This one **couples** the remaining fee tip to permanence runway.

[`F5.md` F6](./F5.md) / [`FEES.md` §5.5](./FEES.md#55-producertreasury-runway-fee-shift-b-20--draft-policy) is the policy: if treasury is pinned at the B-28 floor **and** backstop mints on a majority of proof blocks, raise `fee_to_treasury_bps` by 500–1000 in a **separate** fork from B-13c. No automatic oracle on Path A (**PM22**).

## Target (no privacy/permanence tradeoff)

Keep Path A at **9000** (90% treasury / 10% producer). Do not touch ring policy, SPoRA verification, or `subsidy_to_treasury_bps` in the same lever.

| Config | `fee_to_treasury_bps` | Role |
| --- | --- | --- |
| Path A / DEFAULT today | **9000** | Hold (unchanged this unit) |
| Stressed runway (helper) | `min(10000, current + 1000)` | One-lever **B-20** fork after B-13c + B-25 |

[`recommended_fee_to_treasury_bps`](../mfn-consensus/src/emission.rs) is stress iff:

1. `proof_blocks > 0` (empty window ≠ stress)
2. `treasury_base_units ≤ treasury_floor` (Path A draft floor [`B28_PATH_A_TREASURY_FLOOR_BASE_UNITS`](../mfn-consensus/src/emission.rs) = **1_000_000**)
3. `backstop_blocks * 2 ≥ proof_blocks` (majority)

Then add [`RECOMMENDED_FEE_SHIFT_STEP_BPS`](../mfn-consensus/src/emission.rs) = **1000** (upper end of §5.5), saturating at 10000. At DEFAULT 9000 that is **10000**: all fees to treasury; producers keep subsidy/tail (security budget is not the fee tip).

Fee split identity: `treasury_fee + producer_fee = fee_sum` at both 9000 and 10000.

### Why not flip DEFAULT or wire apply_block?

Changing `fee_to_treasury_bps` on Path A is a coinbase fork (producer outputs shrink). Standing one-lever rule: never in the same fork as **B-13c**. F6's automatic threshold belongs to **PM22** research — this helper is the named number ops/humans apply later.

## Tests (pass in this unit)

- Hold when treasury is above the B-28 floor (even if backstop is noisy).
- Hold when treasury is under the floor but backstop is not majority.
- Empty window is not stress.
- Stress at DEFAULT 9000 recommends 10000; already-10000 saturates.
- `DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps == 9000`; shifted params still validate; subsidy bps untouched.
- Fee-sum identity at hold vs stress.
- Path A public-devnet genesis stays 9000 and is **below** the stressed recommendation.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **B-20** | Named parameter fork applying the helper after **B-13c** soak + **B-25** (or human waiver). Still not an on-chain oracle. |
| **B-13c** | Independent subsidy lever — must land first so this remains a *second* fork |
| **PM22** | Public runway metric / alerts (ops, not consensus) |
| **B-306b** | Independent: drip + proof-prize backstop on Path B |

## See also

- [`FEES.md` §5.5](./FEES.md#55-producertreasury-runway-fee-shift-b-20--draft-policy)
- [`B306_ENDOWMENT_DRIP.md`](./B306_ENDOWMENT_DRIP.md)
- [`B13_SUBSIDY_FORK_SIGNOFF.md`](./B13_SUBSIDY_FORK_SIGNOFF.md)
- [`PROBLEMS.md` §4](./PROBLEMS.md#4-producer-and-storage-operator-incentives-are-only-loosely-aligned)
