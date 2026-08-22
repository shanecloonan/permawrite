# B-306 — Deflation-funded endowment drip (work package)

**Status:** **B-306** math + inert flag (this unit). **Not** enabled on Path A. **Not** B-13c. **Not** a `storage_proof_reward` DEFAULT flip.
**Owner:** lane 6 (endowment math + sims) · **Review:** lane 4 (`accrue_proof_reward` already feeds `apply_block` bonus)
**Depends on:** nothing further — `apply_block` already adds `accrue_proof_reward.payout` to storage rewards
**Blocks:** honest Path B / post-B-25 genesis that wants Arweave-style principal funding without privacy-volume dependence

## Why this exists

Permawrite already *sizes* uploads as a Kryder perpetuity (`E₀ = C₀ · (1+i) / d` at `real_yield_ppb = 0`). That is the Arweave formula.

It does **not**, in the default configuration, *pay operators from that principal*. [`payout_per_slot`](../mfn-storage/src/endowment.rs) and [`accrue_proof_reward`](../mfn-storage/src/endowment.rs) return **0** when `r = 0`. Consensus then pays a flat [`storage_proof_reward`](../mfn-consensus/src/emission.rs) (0.1 MFN per accepted proof) from the shared treasury, refilled by 90% of every fee (including privacy transfers) and by emergency mint when short.

That is the gap [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume) names: privacy volume is the primary *ongoing* inflow after the upload cover-charge, not an extra layer on a self-funding endowment.

Privacy is not the problem. The payout plumbing is.

## Target blend (no privacy/permanence tradeoff)

Keep both guarantees. Change which stream is *required* vs *surplus*.

| Layer | Role | Path A today | Target (Path B / post-B-25 enable) |
| --- | --- | --- | --- |
| **1. Upload endowment** | Size perpetual principal (`E₀ ≈ 51×C₀` at 2% `d`) | Shipped | Unchanged |
| **2. C₀ drip** | Pay first-year storage cost per slot from that principal | **Off** (`accrue` = 0 at `r = 0`) | **On** (`deflation_funded_drip = 1`) |
| **3. Privacy fees (90%)** | Surplus that grows the shared pool | Treated as primary inflow | Surplus — old data does not need new transfers |
| **4. Subsidy→treasury (B-13)** | Scheduled floor independent of demand | Field shipped, value `0` | `1000` after **B-33** / **B-13c** — separate lever |
| **5. Flat proof prize** | Bootstrap / backstop | `storage_proof_reward = 0.1 MFN` (dominates C₀) | Shrink toward a true floor (**B-306c**) — not this unit |
| **6. Emergency mint** | Unconditional operator payment if treasury is empty | Shipped | Unchanged last resort |

Ring policy, stealth, CLSAG, SPoRA, and `UploadUnderfunded` stay exactly as they are. This unit does not weaken any of them.

### Why not just turn `r` back up?

There is often no safe real yield on escrowed crypto principal. `r = 0` is the honest mode. The Arweave move is: **size for deflation, drip current cost, do not pretend the treasury is a hedge fund.**

### Why not enable on Path A in this unit?

Turning drip on (or cutting `storage_proof_reward`) changes coinbase amounts. That is a hard fork of the live experimental chain. Standing board rule: no `DEFAULT` flip, no B-13c enable. The flag defaults to **0**; Path A checkpoints decode missing bytes as 0.

## Consensus wire (this unit)

New `EndowmentParams` flag:

```text
deflation_funded_drip: u8   // 0 = legacy (Path A), 1 = C₀/slot drip when r = 0
```

- `validate_endowment_params` accepts only `0` or `1`.
- When `real_yield_ppb > 0`, the flag is ignored (yield-bearing path unchanged).
- When `r = 0` and the flag is `1`:

```text
C₀     = floor(cost_per_byte_year_ppb · size · replication / PPB)
payout = floor(C₀ · credited_slots / slots_per_year)
```

`apply_block` already does `storage_reward = storage_proof_reward · N + Σ accrue.payout`. Enabling the flag on a *new* genesis therefore requires no apply_block rewrite.

Checkpoint **v13** persists the flag. v12 and below decode as `0`.

Genesis JSON may set `endowment.deflation_funded_drip`. Public devnet v1 **must not** (stay `0`).

## Follow-ups (not this unit)

| Id | Item | Why later |
| --- | --- | --- |
| **B-306b** | Enable `deflation_funded_drip = 1` on Path B genesis or a named activation | Needs human/B-25; forks Path A if flipped live |
| **B-306c** | Size `storage_proof_reward` as a true backstop, not a 0.1 MFN/block prize | Flat prize still dwarfs C₀ drip (~0.25 base units/slot for 1 GiB × 3). Closing §2 *fully* needs both drip **and** a smaller prize. Separate lever. |
| **B-13c** | `subsidy_to_treasury_bps = 1000` | Independent scheduled floor; already designed |

## Tests (pass in this unit)

- Default params: `deflation_funded_drip = 0`, `accrue_proof_reward` still 0 at `r = 0`.
- Flag `1` + `r = 0`: one year of window-capped accruals pays `first_year_cost_base_units` (floor identity).
- Flag `1` + `r > 0`: still uses `real_yield_ppb` (no double pay).
- Flag `> 1` rejected.
- Checkpoint v13 round-trip with flag `1`; v12 decode defaults flag `0`.
- `DEFAULT_ENDOWMENT_PARAMS.deflation_funded_drip == 0`.

## See also

- [`ECONOMICS.md` §12](./ECONOMICS.md#12-permanence-durability-vs-arweave--is-this-model-more-likely-to-break)
- [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume)
- [`FEES.md` §5.4](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury) — B-13 (orthogonal lever)
