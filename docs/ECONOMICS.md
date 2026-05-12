# Economic Model

> **Audience.** Anyone who wants to understand the money — researchers, validators, storage operators, casual readers willing to follow algebra at the pace of a careful proof.
> The non-formula version is in [`OVERVIEW.md`](./OVERVIEW.md).

---

<p align="center">
  <img src="./img/money-flow.svg" alt="The Permawrite money flow: emission mints into the coinbase paid to the producer; transaction fees split 90/10 between treasury and producer; the treasury drains every block to pay storage operators via SPoRA proofs; emission acts only as a backstop when the treasury runs short. Producer and operator income re-enters circulation as users pay more fees, closing the loop." width="100%">
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

### Non-degeneracy

The denominator `r − i` must be **positive**:

```text
r > i    (the permanence non-degeneracy condition)
```

If this is violated, the endowment can't keep up with the cost. The geometric series diverges. The model collapses.

This is the **single most important invariant** in the economic design. The consensus code enforces it in [`validate_endowment_params`](../mfn-storage/src/endowment.rs):

```rust
if real_yield_ppb <= inflation_ppb {
    return Err(EndowmentError::RealYieldNotAboveInflation { … });
}
```

Any consensus parameter set violating `r > i` is rejected at genesis. The chain refuses to start.

### Why `r > i` is plausible long-term

Historical storage cost has *deflated* by roughly 35% per year (Kryder's law) for decades. Even a very modest 1-2% real yield (much less than equity-market historical real returns) clears the bar by an enormous margin.

If Kryder's law breaks down — i.e., storage cost stops falling and starts rising — we'd need a real yield higher than the new inflation rate. The default calibration assumes:

- `i = 2%/year` (conservative — assumes Kryder's law reverses, costs go *up* 2% / year)
- `r = 4%/year` (modest real return — well below historical equities and well above defensible US Treasury real yields)

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

Plus tail emission forever: 0.195 MFN/block · 2.63M slots/year ≈ 0.5 MFN/year as a percentage of supply, which goes to **less than 0.1%/year inflation after several decades** — Monero-equivalent.

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

### Per-transaction fee

```text
fee = base_fee + per_byte_fee × tx_size_bytes + endowment_required_share
```

Where `endowment_required_share` is the additional amount needed *for storage uploads* to ensure the treasury share of the fee covers the protocol-required endowment.

The wallet computes `fee` before submission; the chain re-validates.

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

A storage operator earns by:

1. **Capturing the SPoRA challenge race.** The first operator to publish a valid proof for the deterministic challenge wins the per-proof yield.
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
                            │     COINBASE     │
                            └────────┬─────────┘
                                     │
       producer's payout (subsidy + producer_share_of_fees)
                                     │
                                     ▼
                              PRODUCER WALLET ─── eventually circulates ───┐
                                                                            │
                                                                            ▼
                                                                       PRIVACY TX
                                                                            │
                                                                       pays fee
                                                                            │
                                                  ┌─────────────────────────┼───────────┐
                                                  │                         │           │
                                       producer_share (10%)        treasury_share (90%) │
                                                  │                         │           │
                                                  ▼                         ▼           │
                                          PRODUCER WALLET            TREASURY (drains for storage rewards)
                                                                            │           │
                                                                            ▼           │
                                                                  STORAGE-OPERATOR WALLET
                                                                            │           │
                                                                            └───── circulates ─────────┐
                                                                                                       ▼
                                                                                                  (loop back to PRIVACY TX)
                                                                            (if treasury empty)
                                                                                     │
                                                                              EMISSION BACKSTOP
                                                                                     │
                                                                              fresh MFN minted
```

Two issuance pipes: the subsidy curve (main) and the emission backstop (rare). Three sinks: producer compensation, storage-operator compensation, and held savings.

The economy is **closed** in the sense that no value leaves the chain. It's **open** in the sense that fresh tokens can enter (subsidy + backstop) and old tokens can be effectively burned (no formal mechanism, but indefinite holding has the same balance-sheet effect).

---

## 9. Open economic questions

These are deliberately not yet hard-coded:

1. **Operator bonding.** Should operators stake MFN as a slashable bond to qualify as a "premium" replica? Tradeoff: more skin in the game (better SLA) vs. higher operator friction (less open participation).
2. **Replication-dependent yield curves.** Today, a `replication=3` file pays its operators flat-rate. Should `replication=10` files pay each operator less (since redundancy is higher) or more (since operators are committing more)? Currently flat-rate per slot.
3. **Long-tail decay.** Should very-rarely-proven commitments (e.g., proved 1× per year) eventually expire, freeing their pinned bytes? Today: no — *true* permanence. But this means dead bytes accumulate forever. May need a "stale eviction with refund" mechanism.

These are open research questions, not bugs. They'll be addressed via governance / parameter forks as the chain matures.

---

## 10. Public API surface

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

## See also

- [`STORAGE.md`](./STORAGE.md) — the engineering side of storage proofs and yield accrual
- [`CONSENSUS.md`](./CONSENSUS.md) — who earns the subsidy + the producer fee share
- [`PRIVACY.md`](./PRIVACY.md) — the demand engine that funds the treasury
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the full system view
- [`ROADMAP.md`](./ROADMAP.md) — future economic upgrades (operator bonding, etc.)
