# Economic Model

For intuition first, see [`OVERVIEW.md`](./OVERVIEW.md).

---

<p align="center">
  <img src="./img/money-flow.svg" alt="The Permawrite money flow, numbered as a loop: (1) emission mints fresh MFN into the coinbase; (2) the coinbase pays the producer; (3-4) MFN circulates and is spent in privacy transactions; (5) each fee splits 90 percent to the storage treasury and 10 percent to the producer; (6) uploads must fund the treasury with the required endowment; (7) each block a SPoRA proof is verified; (8) the treasury drains to fund the storage reward, which is settled into the producer coinbase, with emission as a backstop when the treasury is short; the loop then returns to step 2." width="100%">
</p>

## Three flows

There are exactly three money flows on Permawrite. Everything else is derivable from these.

1. **Subsidy** — fresh MFN minted into each block's coinbase per the emission curve.
2. **Fees** — paid by each transaction sender, split between the block producer and the storage treasury.
3. **Storage yield** — paid out of the treasury (with an emission backstop) to storage operators who submit valid SPoRA proofs.

The treasury sits between the in-flow (fees) and the out-flow (storage yield). It's a self-balancing buffer.

---

## 1. The permanence equation, derived

**The claim.** A user who pays an upfront endowment `E₀` at time `t = 0` for a file with first-year storage cost `C₀` can guarantee perpetual storage payouts — *as long as the real yield exceeds the storage-cost inflation rate*.

Let:

- `C_t` = the storage cost (per replica per year) at time `t`. Assume cost grows annually at rate `i`: `C_t = C₀ · (1 + i)^t`.
- `r` = the annual real yield the endowment earns.
- `payout_t` = the cost we must pay year `t` to keep the file alive.

**For the endowment to be perpetually solvent**, the principal `E_t` must satisfy:

```text
E_{t+1} = E_t · (1 + r) − payout_t
       = E_t · (1 + r) − C_t
       = E_t · (1 + r) − C₀ · (1 + i)^t
```

We want `E_t ≥ 0` for all `t`. The steady-state condition is that `E_t` grows at *at least* the same rate as `C_t` — i.e., `E_t = E₀ · (1 + i)^t` is the minimum trajectory.

Substituting:

```text
E₀ · (1 + i)^(t+1) = E₀ · (1 + i)^t · (1 + r) − C₀ · (1 + i)^t
```

Dividing by `(1 + i)^t`:

```text
E₀ · (1 + i) = E₀ · (1 + r) − C₀

E₀ · (1 + i) − E₀ · (1 + r) = −C₀

E₀ · ((1 + i) − (1 + r)) = −C₀

E₀ · (i − r) = −C₀

E₀ = C₀ / (r − i)
```

But this gives us `E₀` only if we ignore the **first-year payout**. The protocol pays year 0 too, so we need to budget for it. Adjust:

```text
E₀ = C₀ · (1 + i) / (r − i)
```

The `(1 + i)` factor accounts for the fact that we owe `C_0` immediately *and* `C_1 = C₀(1 + i)` next year, etc. The formula prices the endowment to cover one year ahead of its yield.

### Non-degeneracy (two modes)

- **Yield-bearing** (`real_yield_ppb > 0`): the denominator `r − i` must be positive (`r > i`).
- **Deflation-funded** (`real_yield_ppb = 0` — expected/common case): `r = 0` is allowed and the default. `inflation_ppb` is treated as the conservative assumed deflation rate `d`. The formula becomes `E₀ = C₀ · (1 + i) / d`. Declining real storage costs (Kryder's law) keep the fixed nominal principal solvent forever, exactly as Arweave.

`validate_endowment_params` only enforces the old `r > i` rule when `r > 0`:

```rust
if real_yield_ppb > 0 && real_yield_ppb <= inflation_ppb {
    return Err(EndowmentError::RealYieldNotAboveInflation { … });
}
```

`r = 0` is valid. The protocol deliberately does **not** require the treasury (or operators) to earn real yield on escrowed endowment principal — there is often no safe, sustainable way to do so. Continued hardware cost deflation supplies the margin.

### Why the old `r > i` story (and the new r = 0 default) are both plausible

Historical storage cost has *deflated* by roughly 35% per year (Kryder's law) for decades. The default `inflation_ppb = 2%` is a tiny conservative buffer against the *possibility* that Kryder's law eventually ends and costs begin to rise.

When `r = 0` (the new default), the same 2% knob becomes the assumed *deflation* rate `d` used to size endowments. Paying ~51× the current annual cost upfront is an extremely safe multiple under any realistic continuation of cost declines.

If Kryder's law ever reverses, a future consensus parameter update can raise `real_yield_ppb` (or the inflation buffer) while the chain is live. The two-mode math already supports both worlds.

The 200-bp margin is the safety buffer.

---

## 2. Subsidy curve — Bitcoin halvings, Monero tail

**Goal.** Provide a high subsidy early to bootstrap security; decay to a small permanent tail to maintain a forever security budget.

### Formula

For block height `h ≥ 1`:

```text
emission(h) = match h:
    1 .. halving_period             → initial_reward
    halving_period+1 .. 2·hp        → initial_reward >> 1
    2·hp+1 .. 3·hp                  → initial_reward >> 2
    …
    halving_count·hp+1 ..           → tail_emission
```

Bitcoin-style integer halvings (`>>`) until `halving_count` halvings complete, then a permanent constant `tail_emission`.

### Defaults

```rust
pub const DEFAULT_EMISSION_PARAMS: EmissionParams = EmissionParams {
    initial_reward:        50 * MFN_BASE,        // 50 MFN/block
    halving_period:        8_000_000,            // ≈ 3 years at 12-second slots
    halving_count:         8,                    // 8 halvings = 24 years
    tail_emission:         (50 * MFN_BASE) >> 8, // ≈ 0.195 MFN/block forever
    storage_proof_reward:  MFN_BASE / 10,        // 0.1 MFN emission-backstop cap
    fee_to_treasury_bps:   9000,                 // 90% of fees → treasury
};
```

Pre-tail cumulative supply ceiling: approximately

```text
sum_{k=0..7} (50 * 8M >> k) = 50·8M · (1 + 1/2 + 1/4 + … + 1/128)
                            = 50·8M · 255/128
                            ≈ 7.97 × 10^8 MFN
```

For a labeled supply curve and year-by-year schedule, see [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md).

Plus tail emission forever: 0.19531250 MFN/block · 2.628M slots/year ≈ 513,281 MFN/year. That is about **0.064%/year at tail start** and declines as supply grows — Monero-equivalent permanence funding without runaway dilution.

### The tail-continuity constraint

The last halving subsidy is:

```text
last_subsidy = initial_reward >> (halving_count - 1) = 50 MFN >> 7 ≈ 0.39 MFN/block
```

The tail emission must satisfy `tail_emission ≤ last_subsidy` or there'd be an **upward jump** in subsidy at the tail boundary, which would create a perverse incentive (validators would want to delay the tail).

```rust
if u128::from(tail) > u128::from(initial_reward) >> (halving_count - 1) {
    return Err(EmissionError::TailAboveLastSubsidy { … });
}
```

Default: `tail = initial_reward >> 8 = last_subsidy / 2`. Monotonically non-increasing across the boundary, no jump.

### Why hybrid

Pure Bitcoin (no tail): security budget → 0 in the long run. Storage operators have no incentive. ❌

Pure Monero (constant emission): subsidies decay slowly but never stop; inflation rate also never goes to 0. Long-run dilution is real (~0.85% in Monero today). Acceptable for a privacy chain; less acceptable for a permanence chain where the endowment needs to retain value.

Hybrid (ours): high initial subsidy bootstraps security and seeds the storage treasury; tail emission keeps an ongoing security budget without uncontrolled dilution; **most ongoing revenue is fee-based, not minted**, which preserves the value of stored endowments.

---

## 3. Fee economics

> **Plain-language fee guide:** see [`FEES.md`](./FEES.md) for "if I spend a
> dollar, what % goes to the network?" and the 2026-07 parameter review.

### Per-transaction fee

Consensus carries a single scalar `tx.fee` per transaction — there is no
`base_fee + per_byte × size` formula enforced on-chain today.

| Tx type | Fee rule | Enforced by |
|---|---|---|
| Plain transfer / claim | Wallet default `0.0001 MFN`; any value accepted | Wallet convention; mempool priority only |
| Storage upload | `min_fee = ceil(required_endowment × 10_000 / fee_to_treasury_bps)` | **Consensus** (`UploadUnderfunded` reject) |

For uploads, the treasury share of the fee must cover the protocol-required
endowment (`fee × fee_to_treasury_bps / 10_000 ≥ Σ required_endowment`). The
wallet computes `fee` before submission; the chain re-validates at mempool
admit and in `apply_block`.

### Two-sided fee split

```rust
producer_share = fee × (10_000 - fee_to_treasury_bps) / 10_000
treasury_share = fee × fee_to_treasury_bps           / 10_000
```

Default `fee_to_treasury_bps = 9000` ⇒ 90% treasury, 10% producer.

### Producer revenue per block

```text
producer_revenue_per_block = emission(height) + Σ_{tx} producer_share(tx)
```

This is the amount the coinbase commits to. `apply_block` reconstructs the expected coinbase amount and rejects mismatches.

### Treasury revenue per block

```text
treasury_inflow_per_block = Σ_{tx} treasury_share(tx)
```

Added to `ChainState::treasury` (a `u128`).

### Storage reward per block

```text
storage_reward_per_block = Σ_{accepted_proof} accrued_payout
```

Drained from treasury first; emission backstop covers any shortfall.

### Equilibrium

In steady-state, with enough privacy-tx activity:

```text
treasury_inflow ≈ storage_reward_per_block
```

The treasury balance stays roughly stable. The emission backstop is rarely tapped.

**If privacy demand collapses** (low fees), the treasury slowly drains, and the emission backstop covers more of the storage rewards. The chain remains solvent but inflation ticks up slightly.

**If privacy demand booms** (high fees), the treasury grows. Excess accumulation is *fine* — the treasury is a buffer; it just means more cushion for lean periods.

The system is **dynamically self-balancing**: privacy demand and permanence cost float around each other.

---

## 4. Parameter sensitivity

### Endowment formula response to each parameter

| Knob | Effect on `E₀` |
|---|---|
| `cost_per_byte_year_ppb` doubles | `E₀` doubles |
| `replication` doubles | `E₀` doubles |
| `size_bytes` doubles | `E₀` doubles |
| `inflation` from 2% → 4% | `E₀` ≈ doubles (denominator shrinks from 2% to 0% — singular) |
| `real_yield` from 4% → 8% | `E₀` ≈ halves (denominator widens from 2% to 6%) |

Sensitivity to the `r − i` denominator is the highest-leverage knob. **Narrow `r − i`** = expensive endowments; **wide `r − i`** = cheap endowments but less safety margin.

### Comparing to Arweave

Arweave's endowment formula is similar in spirit but uses different precision and includes additional terms for replication overhead. A rough comparison at 1 GB, 3× replication:

- **Arweave (current pricing):** ≈ $4.50 (varies with token price).
- **Permawrite (default calibration, hypothetical MFN price = Arweave equivalent):** ≈ 0.3 MFN.

If 1 MFN ≈ $15, that's ≈ $4.50. The calibration was deliberately chosen to be Arweave-comparable. Adjustments via governance / next-major-fork can re-tune.

### Calibration discipline

`cost_per_byte_year_ppb` is **not** a market-discovered parameter. It's a protocol constant calibrated against real-world storage cost data. The hard-coded default assumes:

- Storage operators are paying for cloud storage at the AWS S3 Glacier price band.
- Multi-replica overhead is included in the `replication` multiplier, not in `cost_per_byte_year_ppb`.
- Per-byte cost reflects long-term cost including bandwidth and proof generation.

If real-world storage costs diverge significantly from the calibration, governance must hard-fork to adjust. This is intentional — it forces the parameter to be honest, not gameable.

---

## 5. Treasury dynamics — worked scenarios

### Scenario A: equilibrium

Assume:
- 100 txs/block average.
- Average fee per tx: 0.01 MFN.
- Fee-to-treasury split: 90/10.
- Storage rewards per block: 0.05 MFN (average across all live commitments).

```
treasury_inflow_per_block = 100 × 0.01 × 0.9 = 0.9 MFN
storage_reward_per_block  = 0.05 MFN
treasury_delta_per_block  = +0.85 MFN
```

Treasury grows. Over time, it buffers against fee droughts.

### Scenario B: fee drought

Assume privacy demand collapses to 10 txs/block, same fee, same storage reward:

```
treasury_inflow = 10 × 0.01 × 0.9 = 0.09 MFN
storage_reward  = 0.05 MFN
treasury_delta  = +0.04 MFN
```

Still positive — barely. The treasury survives.

### Scenario C: severe fee drought + storage growth

Assume 1 tx/block, 0.01 MFN fee, but storage rewards balloon to 0.5 MFN/block:

```
treasury_inflow = 0.009 MFN
storage_reward  = 0.5 MFN
treasury_delta  = -0.491 MFN
```

The treasury drains. Once empty:

```
emission_backstop = 0.491 MFN minted as fresh tokens per block
```

This is the emergency mode. Inflation effectively rises to cover the storage commitments the chain has made.

In this scenario, the chain is still **solvent in the cryptoeconomic sense** — storage commitments are honored — but the *currency is inflating* to pay for them. This is exactly the failure mode the design is engineered to recover from gracefully: rather than abandon commitments (catastrophic), the chain dilutes the currency (recoverable).

If the drought is permanent (privacy demand vanishes forever), the chain becomes inflation-funded and behaves like a pure storage chain. Acceptable degradation; not a system-collapse failure.

### Scenario D: fee boom

Assume 1000 txs/block, 0.1 MFN average fee:

```
treasury_inflow = 1000 × 0.1 × 0.9 = 90 MFN/block
storage_reward  = 1 MFN/block (rough scale)
treasury_delta  = +89 MFN/block
```

Treasury overflows. With a 100-year file pre-funded once at 0.3 MFN, the treasury inflow far exceeds the total liability. The system is **massively over-collateralized** during boom periods.

This is a *good* failure mode — over-collateralization means more headroom for future bear markets.

---

## 6. Producer economics

A producer's expected revenue per block:

```text
E[producer_revenue] = subsidy(height) + 0.1 × E[total_fee_in_block]
```

For the initial era (height ≤ 8M):

```
subsidy = 50 MFN
producer_share of fees = 0.1 × Σ_tx fee
```

A block with 100 txs at 0.01 MFN average fee:

```
producer_revenue = 50 + 0.1 × 100 × 0.01 = 50.1 MFN/block
```

The producer fee share is **small**. This is by design — we want the *treasury* to grow, not the producer. The producer's incentive is dominated by the subsidy in early eras and by the tail emission later.

### Producer-revenue post-tail

When the tail era kicks in:

```
producer_revenue = 0.195 + 0.1 × fees
```

In the post-tail era, fees become a more significant share of producer compensation. This is correct behavior: as the subsidy decays, the network needs to be self-sustaining via fees.

### Why this prevents the "fee-only chain death spiral"

A pure fee-funded chain (e.g., Bitcoin post-tail-emission-debate) has a coordination problem: producers might collude to artificially raise fees, but they can also choose to give priority to no-fee txs at any time.

Permawrite's treasury-funded storage rewards mean there's always a non-fee revenue source (storage yield to operators ≠ producers, but both are stake-aligned). The producer's revenue floor is `subsidy + producer_share_of_fees`. The tail emission ensures this floor is never zero. Death spirals are structurally prevented.

---

## 7. Storage-operator economics

> **Implementation reality (read this first).** Each accepted
> [`StorageProof`](../mfn-storage/src/spora.rs) carries
> `operator_view_pub` / `operator_spend_pub`. Settlement mints **per-operator
> coinbase outputs** (outputs 1..N) to those stealth keys; output 0 is the
> producer (`subsidy + producer_fee`). Treasury drains first; emission
> backstop mints any shortfall. See
> [`block_coinbase_specs`](../mfn-consensus/src/emission.rs) and
> [`STORAGE.md § 5.5`](./STORAGE.md). The historical producer-only payout gap
> is closed — see [`PROBLEMS.md § 17`](./PROBLEMS.md#17-storage-rewards-are-paid-to-the-block-producer-not-to-the-operator-that-proved-the-data).

A storage operator earns by:

1. **Capturing the SPoRA challenge race.** The first valid proof for the
   deterministic challenge that a producer includes wins the per-proof yield.
2. **Holding popular files.** Files with larger endowments yield more per slot.

### Expected revenue per file

For a file with endowment `E₀` proven once per slot on average:

```
per_slot_payout = E₀ × r / slots_per_year
```

For 1 GB × 3× at default calibration:

```
per_slot_payout = 30.6M × 0.04 / 2.63M ≈ 0.465 base units/slot
```

Per year: `0.465 × 2.63M ≈ 1.22M base units = 0.012 MFN/year`.

That's **0.012 MFN per year per file**. Operators win at scale: holding 10000 files yields 120 MFN/year per replica.

### Competition

Multiple operators compete to win each challenge. The deterministic challenge means all eligible operators see the same target chunk. Network latency determines who publishes first.

In practice, operators specialize: some hold "hot" recent uploads; some hold cold archives; some hold by geography. The protocol doesn't dictate operator strategy.

### Why this works economically

- **No oracle.** Reward is paid only on cryptographic proof of holding, not on operator self-attestation.
- **No long lockup.** Operators can join or leave with no protocol-side bonding (a future upgrade may add bonding for higher-yield "guaranteed" replicas).
- **Cost vs revenue.** Operating cost is the actual storage cost (~`cost_per_byte_year`). Revenue is the protocol-paid yield. The endowment formula sets these equal in expectation.

---

## 8. Currency lifecycle summary

```
                            ┌──────────────────┐
                            │   Emission curve │  (decays Bitcoin-style; permanent tail)
                            └────────┬─────────┘
                                     │
                  fresh MFN per block ▼
                            ┌──────────────────┐
                            │     COINBASE     │  out 0: subsidy + producer_fee
                            └────────┬─────────┘  out 1..N: operator storage rewards
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
             PRODUCER WALLET                   OPERATOR WALLETS
                    ▲                                 ▲
                    │                                 │
                    │         storage_reward_total    │
                    │         (treasury drain first;  │
                    │          emission backstop if   │
                    │          short)                 │
                    │                                 │
                    │         ┌───────────────────────┘
                    │         │
                    ▼         ▼
               PRIVACY TX ──► TREASURY ──► SPoRA payouts
                    │
         producer_share (10%) + treasury_share (90%)
                    │
                    └──── (if treasury empty) ──► EMISSION BACKSTOP (fresh mint)
```

Two issuance pipes: the subsidy curve (main) and the emission backstop (rare).
Storage rewards settle into **operator coinbase outputs**, not the producer's
output 0 (see [§ 7](#7-storage-operator-economics)).

The economy is **closed** in the sense that no value leaves the chain. It's **open** in the sense that fresh tokens can enter (subsidy + backstop) and old tokens can be effectively burned (no formal mechanism, but indefinite holding has the same balance-sheet effect).

---

## 9. Validator bond economics (M1, closed loop)

Validator rotation, shipped in M1, is itself a self-balancing money flow that **plugs directly into the treasury** rather than introducing a separate validator-reward pipeline.

### Burn-on-bond

Every successful `BondOp::Register` credits the validator's declared `stake` (in MFN base units) to `ChainState::treasury` and appends a new active validator with a fresh `ValidatorStats` row. There is no separate "validator deposit" account, no Pedersen-committed escrow, no lockup-token. The treasury — the same pool that funds permanence — is the canonical permanence-funding sink, and validator bonds add to it.

### Slash-to-treasury

Both classes of slashing route the forfeited stake to the treasury (saturating `u128`):

- **Equivocation slashing.** Full stake forfeit. The validator's `stake` is set to zero in the next state.
- **Liveness slashing.** Multiplicative `liveness_slash_bps` forfeit per consecutive-miss threshold trip. The delta (`old_stake − new_stake`) accrues to the treasury.

### Unbond settlement

When a `BondOp::Unbond` matures (`height ≥ unlock_height`), the validator's stake is zeroed and they become a non-signing zombie. The originally bonded MFN **remains in the treasury** as a permanent contribution to the permanence endowment. M1 deliberately introduces no operator payout on settlement; that's deferred to a future milestone (and would itself debit the treasury, just like any other operator-side outflow). Settlement runs **after** slashing, so equivocating during the delay window still credits the treasury and zeroes the validator — there's no rage-quit exit.

### The closed loop

Putting the three flows together, M1 makes the treasury the single accounting hub for the validator-incentive system:

```
                ┌────────────────────────────┐
                │      ChainState.treasury   │
                └────┬────────┬──────────┬───┘
                     ▲        ▲          │
   Register burn ────┘        │          │
   Slash credit ───────────────┘          │
                                          ▼
                                Storage-operator rewards
                                (drains treasury per accepted SPoRA proof,
                                 emission-backstopped on shortfall)
```

- **Inflows.** `register_burn(op) + slash_credit(equivocation, liveness)` per block.
- **Outflows.** `Σ accrued_payout(proof)` per block, drained from treasury first; emission backstop covers any shortfall.

Validator bonds are therefore a **one-way contribution to the permanence endowment in M1**. Two consequences worth noting:

1. **No new issuance path is needed to fund validator economics.** The chain's existing emission curve + fee split remains the only mechanism producing fresh MFN; validator commitment redirects into permanence rather than out into new tokens.
2. **A malicious validator directly subsidizes the network they attacked.** Equivocation evidence anchored against an attacker who locked up `stake` worth of bond converts the entire bond into storage funding the moment the evidence is included.

This is the economic engine M1 unlocked: privacy demand pays the treasury via fees, validators pay the treasury via bonds, slashes pay the treasury via punishment, and the treasury pays permanence operators. No leakage; no second pool to govern.

### M5 settlement test matrix

**Per-block settlement (`tests/producer_treasury_settlement.rs`, default CI, `f117ce6` through `dde886e`):**

- 90/10 fee split (`default_fee_split_is_ninety_ten`, `fee_only_block_credits_treasury_ninety_percent`).
- Coinbase = emission + producer fee share + full storage rewards (`producer_coinbase_amount_*`, `ppb_bonus_increases_validator_coinbase_and_treasury_drain`).
- Treasury drains prefunded balance before emission backstop (`storage_reward_drains_prefunded_treasury_first`, `emission_backstop_only_when_treasury_short`).
- Invalid / overpaid coinbase reject without state mutation (`invalid_coinbase_amount_rejected_without_state_change`, `overpaid_coinbase_amount_rejected_without_state_change`).
- Bond burn + fee inflow compose in a closed treasury loop (`bond_burn_and_fee_inflow_compose_in_treasury_closed_loop`).
- Equivocation slash + fee + SPoRA drain compose, including PPB pending-yield carry-over (`equivocation_slash_fee_and_storage_proof_compose_in_treasury_closed_loop`, `ppb_pending_carryover_pays_on_second_proof_block`; `13616bc`).
- Liveness slash, bond burn, fee inflow, and storage proof drain compose in the same treasury ledger (`liveness_slash_fee_and_storage_proof_compose_in_treasury_closed_loop`, `bond_burn_liveness_slash_and_fee_compose_in_treasury_closed_loop`, `bond_liveness_slash_fee_and_storage_proof_compose_in_treasury_closed_loop`, `equivocation_bond_and_liveness_slash_compose_in_treasury_closed_loop`; `ffe93d5`, `cbecb3b`, `5a8fb83`, `40bfb57`), including the PPB-augmented proof-drain variant for bond + liveness + fee inflow (`bond_liveness_fee_ppb_storage_proof_compose_in_treasury_closed_loop`; `1279cee`).
- The five-path block (equivocation slash + bond burn + liveness slash + CLSAG fee + SPoRA proof) composes without ledger drift (`equivocation_bond_liveness_fee_and_storage_proof_compose_in_treasury_closed_loop`; `dde886e`), and the six-path PPB-augmented variant adds integer pending-yield proof bonus to the same ledger identity (`equivocation_bond_liveness_fee_ppb_and_storage_proof_compose_in_treasury_closed_loop`; `c880d27`).

**Long-run ledger identity** vs `apply_block` over CLSAG fee, mixed CLSAG + SPoRA, validator-mode chains, liveness-slash blocks, combined bond/slash/fee/proof inflow stacks, validator combined-inflow random-fee proptests, equivocation combined-inflow random-fee proptests, random-schedule combined-inflow proptests, no-equivocation random-schedule combined-inflow proptests, 32/64-block equivocation combined-inflow simulations, prefunded treasury backstop simulations, and no-equivocation PPB combined-inflow simulations lives in `tests/emission_simulation.rs` and `tests/apply_block_proptest.rs` (M5.0–M5.30; see [`CI.md`](./CI.md)).

### When the deferred operator payout lands

A future milestone may restore an explicit settlement payout — either via an augmented coinbase output for the settling validator, or a dedicated payout transaction class. Both shapes treat the payout as a `treasury` outflow on the same accounting footing as storage rewards. The economics here are robust to either choice; the loop above is the invariant.

---

## 10. Open economic questions

These are deliberately not yet hard-coded:

0. **Subsidy tail split (approved, not yet shipped).** Route 10% of
   `emission_at_height(h)` to the treasury (`subsidy_to_treasury_bps = 1000`);
   producer coinbase keeps the remainder. Permanence-first doctrine favors
   predictable treasury inflow over emergency backstop spikes — see
   [`FEES.md § 5.4`](./FEES.md#54-subsidy-tail-split--approved-for-next-parameter-fork-10--treasury).
   Requires consensus hard fork (F6 phase 2).
1. **Operator bonding.** Should operators stake MFN as a slashable bond to qualify as a "premium" replica? Tradeoff: more skin in the game (better SLA) vs. higher operator friction (less open participation).
2. **Replication-dependent yield curves.** Today, a `replication=3` file pays its operators flat-rate. Should `replication=10` files pay each operator less (since redundancy is higher) or more (since operators are committing more)? Currently flat-rate per slot.
3. **Long-tail decay.** Should very-rarely-proven commitments (e.g., proved 1× per year) eventually expire, freeing their pinned bytes? Today: no — *true* permanence. But this means dead bytes accumulate forever. May need a "stale eviction with refund" mechanism.

These are open research questions, not bugs. They'll be addressed via governance / parameter forks as the chain matures.

---

## 11. Public API surface

The economic functions are all in `mfn-consensus::emission` and `mfn-storage::endowment`:

```rust
// Emission
let subsidy: u64 = emission_at_height(height, &emission_params);
let cum_supply: u128 = cumulative_emission(height, &emission_params);
let inflation: u64 = annualized_inflation_ppb(height, &emission_params);

// Endowment
let required: u128 = required_endowment(size_bytes, replication, &endowment_params)?;
let per_slot_ppb: u128 = payout_per_slot_ppb(endowment, &endowment_params)?;
let max_bytes: u64 = max_bytes_for_endowment(amount, replication, &endowment_params)?;

// Validation
validate_emission_params(&emission_params)?;
validate_endowment_params(&endowment_params)?;
```

For full type signatures see the per-crate READMEs.

---

## 12. Permanence durability vs Arweave — is this model more likely to break?

Honest comparison as of 2026-07. Both projects share the same core bet:
**pay once upfront, assume real storage costs decline (Kryder's law), and let
the endowment's purchasing power compound.** Permawrite deliberately
calibrated to Arweave-comparable upload pricing (~$4.50/GB at equivalent token
prices). The endowment *math* is not the weak link. The differences are in
**where ongoing money comes from** and **what happens under stress**.

### 12.1 What is structurally the same

| Property | Arweave | Permawrite |
|---|---|---|
| Payment model | One-time endowment at upload | One-time endowment at upload |
| Solvency bet | Storage costs decline over time | Storage costs decline over time (2% floor vs Arweave's 0.5% Kryder+ assumption) |
| Audit primitive | Recall / mining proofs | SPoRA Merkle proofs every block |
| On-chain anchor | Permanent, no delete | Permanent, no delete |
| Token-price risk | Endowment buys less real storage if AR falls | Same for MFN |

Permawrite's 51× first-year buffer (`inflation_ppb = 2%`) is **more
conservative** than Arweave's "200 years at 0.5% decline" pricing for the same
realized deflation rate. If Kryder's law continues anywhere near historical
rates, both models are massively over-collateralized at upload time.

### 12.2 Where the models diverge (this is what matters)

**Arweave — self-contained endowment faucet.**

- ~80–85% of each upload fee is locked into a **network-wide storage
  endowment** (token sink).
- Miners are paid from block rewards + instant tx fees **first**; the endowment
  drips only when those are insufficient to cover replication costs.
- Each upload's endowment contribution is designed to fund **that cohort of
  data** over decades without requiring unrelated transaction activity.

**Permawrite — shared treasury cross-subsidized by privacy demand.**

- Upload fees must cover `required_endowment`, but with `real_yield_ppb = 0`
  (default), the endowment is **not** a per-file yield-bearing principal.
  Instead, the treasury share capitalizes a **shared pool** that pays all
  operators.
- Ongoing operator revenue comes from:
  1. 90% of **every privacy transaction fee** (not just upload fees),
  2. validator bonds and slashes,
  3. the emission backstop (unconditional mint if treasury is short).
- Privacy-tx volume is the **primary long-term treasury inflow** — see
  [`PROBLEMS.md § 2`](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume).

This is the central architectural difference. Arweave's permanence loop is
**mostly self-funding per upload**. Permawrite's is **explicitly a fusion
thesis**: confidential cash pays for permanent storage.

### 12.3 Failure-mode comparison

| Stress scenario | Arweave (observed / designed) | Permawrite (designed) |
|---|---|---|
| **Kryder's law stalls** | Endowment horizon shrinks from "indefinite" toward the priced ~200-year floor; needs parameter/governance response | Same — 51× buffer erodes toward the 2% floor; needs hard fork to widen `inflation_ppb` or enable `real_yield_ppb` |
| **Token price collapse** | Endowment releases more AR per byte of real storage; miner attrition risk | Same purchasing-power risk, **plus** backstop mints more MFN (dilution spiral risk) |
| **Low transaction volume** | Block rewards + endowment drip still pay miners; new uploads still add endowment | Treasury drains; backstop takes over; permanence **holds** but inflation rises — privacy volume is a single point of failure |
| **Operator/miner exit** | Recall-mining hardware barrier; geographic concentration | SPoRA is consumer-grade (easier entry) but proof-winning is a latency race (different centralization shape) |
| **Implementation error** | Years of mainnet operation, petabyte-scale | Pre-audit experimental software; large attack surface ([`PROBLEMS.md § 8`](./PROBLEMS.md#8-extreme-complexity-and-large-attack-surface)) |

### 12.4 Verdict

**Is Permawrite more likely to break than Arweave?**

**It depends what "break" means.**

1. **Enter economic stress** (treasury drought, elevated inflation, degraded
   mode): **Yes, Permawrite is more exposed.** The shared-treasury design
   requires sustained privacy-tx fee inflow in a way Arweave's per-upload
   endowment sink does not. If confidential-cash adoption stalls, Permawrite
   falls back to the emission backstop — exactly the inflation tradeoff the
   operator has accepted (see [`FEES.md § 5`](./FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury)).

2. **Actually stop paying operators / lose data**: **No — not more likely, and
   possibly less likely.** The emission backstop mints operator payouts
   unconditionally when the treasury is empty. Operators are paid in full every
   block regardless of fee volume. Data loss requires mass operator exit with
   no replacement — a social/operational failure, not a treasury-balance
   failure. Arweave has no equivalent unconditional mint; it throttles endowment
   release when miners are already profitable, which is efficient but does not
   add a hard payment floor.

3. **Suffer a consensus/protocol bug that invalidates commitments**: **Yes,
   more likely today.** Arweave is battle-tested production infrastructure.
   Permawrite is pre-testnet experimental software composing Monero-grade
   privacy + custom PoS + SPoRA in one `apply_block` pipeline. The
   implementation-risk category is not comparable until audit and mainnet
   time accrue.

**Bottom line:** Permawrite trades Arweave's self-contained per-upload
endowment loop for a **stronger unconditional payment guarantee** (backstop)
and a **larger potential revenue pool** (privacy fees, if Monero-scale
confidential-cash demand materializes). Under the project's stated preference
— *permanence over everything, willing to pay inflation* — the model is
**not more likely to break permanence**. It **is** more likely to enter
inflation-funded degraded mode if the privacy-demand thesis fails, and **is**
more likely to suffer an implementation-level break before mainnet maturity.

Arweave is the safer bet on **proven track record and fewer dependency
assumptions**. Permawrite is the higher-upside bet on **privacy demand
cross-subsidizing storage at scale**, with a harder backstop floor that
Arweave does not replicate.

### 12.5 What would close the gap

Ordered by leverage:

1. **Ship `subsidy_to_treasury_bps`** (10% tail → treasury; F6 phase 2) —
   scheduled permanence inflow independent of privacy demand.
2. **Operator bonding + slashing at scale** — skin in the game for replicas
   (partially shipped on public devnet; default bond still 0).
3. **Mainnet telemetry** — watch `treasury_base_units` and backstop frequency;
   [`treasury-telemetry-watch.sh`](../scripts/public-devnet-v1/treasury-telemetry-watch.sh).
4. **Audit + time** — the implementation-risk gap vs Arweave closes only with
   production evidence, not parameter tuning.

---

## See also

- [`FEES.md`](./FEES.md) — plain-language fee breakdown and parameter review
- [`STORAGE.md`](./STORAGE.md) — the engineering side of storage proofs and yield accrual
- [`CONSENSUS.md`](./CONSENSUS.md) — who earns the subsidy + the producer fee share
- [`PRIVACY.md`](./PRIVACY.md) — the demand engine that funds the treasury
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the full system view
- [`ROADMAP.md`](./ROADMAP.md) — future economic upgrades (operator bonding, etc.)
