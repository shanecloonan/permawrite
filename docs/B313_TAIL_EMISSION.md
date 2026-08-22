# B-313 — Tail-emission size helper (not a schedule flip)

**Status:** **B-313** CSV §3 calibration helper + Path A honesty (this unit). **Not** a `DEFAULT_EMISSION_PARAMS` flip. **Not** B-13c. **Not** a PM13 violation (`tail_emission` stays `> 0`).
**Owner:** lane 6 · **Does not change** live Path A coinbase
**Depends on:** existing halving schedule (`initial_reward >> k`); PM13 zero-tail ban
**Blocks:** a later parameter fork that actually sets `tail_emission = recommended_tail_emission` (human / Path B — not this unit)

## Why this exists

CSV / [`PROBLEMS.md` §3](./PROBLEMS.md#3-permanent-tail-emission-is-large-in-absolute-terms-and-creates-ongoing-dilution): DEFAULT tail is `(50 MFN) >> 8 ≈ 0.195 MFN/block` forever. At `slots_per_year = 2_629_800` that is **~513,633 MFN/year** — about **0.0645%/year** of pre-tail supply (~796.9M MFN). The *rate* is already below Monero's long-run inflation; the *absolute* mint is still large.

PM13 forbids `tail_emission = 0`. The next value on the **same binary schedule** the protocol already uses is one extra right-shift:

```text
DEFAULT     tail = initial_reward >> halving_count     = 50 MFN >> 8  = last_subsidy / 2
recommended tail = initial_reward >> (halving_count+1) = 50 MFN >> 9  = last_subsidy / 4
```

[`recommended_tail_emission`](../mfn-consensus/src/emission.rs) is that step. [`tail_start_inflation_ppb`](../mfn-consensus/src/emission.rs) is the dilution display (ppb of pre-tail supply).

## Target (no privacy/permanence tradeoff)

Keep Path A STF and DEFAULT tail unchanged. Do not zero the tail.

| Signal | DEFAULT | Recommended |
| --- | --- | --- |
| `tail_emission` | 19_531_250 (0.19531250 MFN) | 9_765_625 (0.09765625 MFN) |
| Annual mint @ 2_629_800 slots | ~513,633 MFN | ~256,816 MFN |
| Tail-start inflation | **644_558 ppb** (0.0645%) | **322_279 ppb** (0.0322%) |

Applying the helper still validates: `1 ≤ recommended ≤ last_subsidy`. Tiny configs that would shift to 0 saturate at **1** (constitutional).

### Why not flip DEFAULT this unit?

Shrinking tail is a **coinbase fork** (producer subsidy halves at every tail-era height). Path A already seals blocks under `>> 8`. Enable on Path B / after **B-25** with a named human ceremony — same doctrine as B-306b / B-13c.

## Tests (pass in this unit)

- Recommended = `initial >> (halving_count+1)` = `50 MFN >> 9`; DEFAULT stays `>> 8` (2×).
- Applying recommended still `validate_emission_params` OK; DEFAULT still OK.
- Path A genesis tail unchanged and **greater** than recommended.
- DEFAULT tail-start inflation **644_558** ppb; recommended **322_279** ppb.
- `blocks_per_year = 0` → inflation 0; tiny `initial_reward` still recommends `1`.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| Path B / post-B-25 | Set genesis `tail_emission` to `recommended_tail_emission` in the same ceremony as drip/prize (optional; human) |
| **B-13c** | Distinct lever (`subsidy_to_treasury_bps`); do not bundle with this shrink |
| Display | RPC/UI can call `tail_start_inflation_ppb` without changing consensus |

## See also

- [`ECONOMICS.md` §2](./ECONOMICS.md#2-subsidy-curve--bitcoin-halvings-monero-tail)
- [`B311_BACKSTOP_CAP.md`](./B311_BACKSTOP_CAP.md) (cap is 1% of *whatever* tail is live)
- [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md)
