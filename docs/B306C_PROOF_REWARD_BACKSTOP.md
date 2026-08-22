# B-306c — Size `storage_proof_reward` as a true backstop

**Status:** **B-306c** calibration helper + Path A pin (this unit). **Not** a `DEFAULT_EMISSION_PARAMS` flip. **Not** B-13c. **Not** B-306b drip enable.
**Owner:** lane 6 · **Does not change** live Path A coinbase
**Depends on:** **B-306** C₀ drip math (inert flag)
**Blocks:** honest Path B genesis that enables drip without leaving a 0.1 MFN/proof prize drowning it

## Why this exists

[`apply_block`](../mfn-consensus/src/block/apply.rs) pays

```text
storage_reward = storage_proof_reward · N_accepted + Σ accrue_proof_reward.payout
```

**B-306** makes the second term drip first-year cost `C₀` when `deflation_funded_drip = 1`. The first term is still `DEFAULT_EMISSION_PARAMS.storage_proof_reward = 0.1 MFN` (`MFN_BASE / 10` = 10_000_000 base units) per accepted proof.

`storage_proof_reward` is paid **per accepted proof**, and accrue credits at most `proof_reward_window_slots` (default 7_200 ≈ 1 day) of C₀. At default endowment params, one 1 GiB × 3× file therefore drips

```text
C₀                                         = 644_245 base units / year
floor(C₀ / slots_per_year)                 = 0          (do not use this)
floor(C₀ · window / slots_per_year)        = 1_763      (~1.76×10⁻⁵ MFN / proof)
```

The Path A prize is **~5_670×** that window quantum. Enabling drip without shrinking the prize does not change operator income. Privacy volume plus the prize still dominate; the sized principal stays a cover-charge.

That is the residual in [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume).

## Target (no privacy/permanence tradeoff)

Keep the prize as a **floor**, not as the job.

| Config | `storage_proof_reward` | Role |
| --- | --- | --- |
| Path A today | `0.1 MFN` | Bootstrap prize (unchanged this unit) |
| Path B / post-B-25 after **B-306b** | [`recommended_backstop_proof_reward`](../mfn-storage/src/endowment.rs) | Floor ≈ one 1 GiB file's window-capped C₀ so drip can dominate |

`recommended_backstop_proof_reward` is:

```text
max(1, floor(C₀(1 GiB, min_replication) · proof_reward_window_slots / slots_per_year))
```

Per-slot `floor(C₀ / slots)` is 0 at 1 GiB × 3 defaults; using it would pin the prize at dust `1` and mis-state the drip. Emergency mint when the treasury is empty is unchanged. Ring / SPoRA / endowment sizing stay unchanged.

### Why not flip DEFAULT on Path A?

Cutting `storage_proof_reward` changes coinbase amounts. That is a hard fork of the live experimental chain. Standing board rule: no DEFAULT emission flip.

Path B sets `emission.storage_proof_reward` in genesis JSON (B-265 merge already exists). Live Path A enable is a named fork after **B-25**, same class as **B-306b**.

## Tests (pass in this unit)

- `recommended_backstop_proof_reward` equals `floor(C₀(1 GiB, 3) · window / slots_per_year)` at defaults (1763).
- Per-slot `floor(C₀ / slots)` is 0 at that size (documents why the helper uses the window).
- Path A prize / backstop ≥ 5_000 (documents the residual).
- `DEFAULT_EMISSION_PARAMS.storage_proof_reward == MFN_BASE / 10`.
- Public devnet genesis keeps that prize and `min_storage_operator_bond = 0`.
- Zero `slots_per_year` returns `SlotsPerYearZero`.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **B-306b** | Enable `deflation_funded_drip = 1` (Path B / after B-25); set `emission.storage_proof_reward` to `recommended_backstop_proof_reward` in the same ceremony |
| **PM1** | Mandatory operator bonds on Path B (`min_storage_operator_bond > 0`) — CSV residual, separate lever |

## See also

- [`B306_ENDOWMENT_DRIP.md`](./B306_ENDOWMENT_DRIP.md)
- [`ECONOMICS.md` §12.5](./ECONOMICS.md#125-what-would-close-the-gap)
- [`PATH_B_GENESIS_FREEZE.md`](./PATH_B_GENESIS_FREEZE.md)
