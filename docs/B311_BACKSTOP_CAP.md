# B-311 — Emission backstop circuit-breaker helper (not wired)

**Status:** **B-311** calibration helper + Path A honesty (this unit). **Not** a `DEFAULT_EMISSION_PARAMS` flip. **Not** B-13c. **Not** wired into `apply_block`.
**Owner:** lane 6 · **Does not change** live Path A coinbase
**Depends on:** **B-306c** sized prize (Path B must shrink the 0.1 MFN prize before a cap can bind fairly)
**Blocks:** honest **PM41** wire after **B-306b** (capping Path A's prize today would reject every backstop proof)

## Why this exists

CSV / [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume): when privacy fees drought, treasury drains and `storage_proof_reward` **mints**. That is the correct solvency backstop. Unbounded mint is a permanence **and** monetary catastrophe — inflation becomes the thing that keeps old data alive.

[`F5.md` PM41](./F5.md) wants a cap: backstop mint ≤ **1% of annual tail**. [`recommended_backstop_mint_cap_per_year`](../mfn-consensus/src/emission.rs) is that number. Per-slot / per-window helpers are the same budget sliced by slot count.

This unit names the ceiling. It does not refuse proofs.

## Target (no privacy/permanence tradeoff)

Keep Path A mint **unbounded** (today's STF). Do not touch ring policy, SPoRA verification, or drip.

| Config | Backstop mint | Role |
| --- | --- | --- |
| Path A / DEFAULT today | Unbounded shortfall mint | Hold (unchanged this unit) |
| PM41 helper | `floor(annual_tail · 100 / 10000)` per year | Circuit breaker after prize shrink |

[`RECOMMENDED_BACKSTOP_CAP_ANNUAL_BPS`](../mfn-consensus/src/emission.rs) = **100** (1%). At DEFAULT tail:

```text
tail_emission                              = 19_531_250
recommended_backstop_mint_cap_per_slot     = 195_312
Path A storage_proof_reward                = 10_000_000   (~51× the slot cap)
B-306c recommended_backstop_proof_reward   = 1_763        (fits under the slot cap)
```

[`BackstopMintObservation::cap_binds`](../mfn-consensus/src/emission.rs) is `minted_in_window > cap(window_slots)`. Empty mint never binds. A mint in a zero-length window always binds (fail closed).

### Why not wire apply_block on Path A?

One Path A backstop proof already exceeds the per-slot cap. Enforcing it now would halt SPoRA payouts whenever the treasury is empty — the opposite of permanence. Wire only after **B-306b** applies the B-306c prize (and drip), so honest 1-proof/slot mint stays under 1% of tail.

## Tests (pass in this unit)

- Per-slot cap = `tail / 100` = **195_312** at DEFAULT.
- Yearly cap = `annual_tail / 100` at endowment `slots_per_year`.
- Path A prize exceeds the slot cap; one-proof observation binds.
- B-306c sized prize fits; one-proof observation does not bind.
- Zero mint does not bind; mint in a 0-slot window binds.
- Path A genesis JSON still has prize `MFN_BASE/10` (unbounded).

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **B-306b** | Enable drip + shrink prize — **prerequisite** for a fair cap |
| **PM41 wire** | `apply_block` refuses (or logs + truncates) backstop mint above the window cap after B-306b |
| **B-20** | Independent fee-shift lever (inflow), not this ceiling |
| **PM22** | Ops alert when `cap_binds` on telemetry (not consensus) |

## See also

- [`B306C_PROOF_REWARD_BACKSTOP.md`](./B306C_PROOF_REWARD_BACKSTOP.md)
- [`B309_FEE_SHIFT.md`](./B309_FEE_SHIFT.md)
- [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume)
- [`ECONOMICS.md` §12.5](./ECONOMICS.md#125-what-would-close-the-gap)
