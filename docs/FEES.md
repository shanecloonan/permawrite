# Transaction Fees — What You Pay and Where It Goes

Plain-language answers first, mechanics second, then the 2026-07 parameter
review (should fees rise? should the tail emission feed the treasury?).

All numbers below are the defaults in
[`DEFAULT_EMISSION_PARAMS`](../mfn-consensus/src/emission.rs) and
[`DEFAULT_ENDOWMENT_PARAMS`](../mfn-storage/src/endowment.rs), which are what
the public devnet runs today.

---

## 1. The short answer: "if I spend a dollar, what % goes to the network?"

**The fee is a flat amount per transaction, not a percentage of what you
send.** Sending 1 MFN and sending 1,000,000 MFN cost the same fee.

- **Reference-wallet default transfer fee:** `10_000` base units =
  **0.0001 MFN** ([`DEFAULT_TRANSFER_FEE`](../mfn-cli/src/wallet_cmd.rs)).
- **100% of the fee goes to the network.** Nothing is burned and nothing goes
  to any company or foundation:
  - **90%** → the on-chain **storage treasury** (funds permanence — SPoRA
    storage-operator payouts).
  - **10%** → the **block producer** (the priority tip that gets your
    transaction included).

So as a percentage of the amount you move:

| You send | Fee (default) | Fee as % of amount | Goes to treasury | Goes to producer |
|---|---|---|---|---|
| 1 MFN | 0.0001 MFN | 0.01% | 0.00009 MFN | 0.00001 MFN |
| 100 MFN | 0.0001 MFN | 0.0001% | 0.00009 MFN | 0.00001 MFN |
| "a dollar" (0.067 MFN at a hypothetical 1 MFN ≈ $15) | 0.0001 MFN ≈ $0.0015 | ≈ 0.15% | ≈ $0.00135 | ≈ $0.00015 |

The dollar figures are illustrative only — MFN has no market price; the
$15/MFN calibration is the same hypothetical used in
[`ECONOMICS.md § 4`](./ECONOMICS.md#4-parameter-sensitivity).

Two important caveats:

1. **The flat fee is a wallet convention, not a consensus rule.** Consensus
   accepts any fee on a plain transfer (even zero); the mempool drains
   highest-fee-first and supports replace-by-fee, so the fee is a priority
   signal. See § 3.
2. **Storage uploads are different.** They carry a consensus-enforced minimum
   fee that scales with the bytes you store — that is the permanence price.
   See § 4.

---

## 2. Every fee stream at a glance

| You do | You pay (default) | Enforced by | Where it goes |
|---|---|---|---|
| Private transfer | 0.0001 MFN flat | Wallet convention only | 90% treasury / 10% producer |
| Authorship claim | 0.0001 MFN flat | Wallet convention only | 90% treasury / 10% producer |
| Storage upload | `ceil(required_endowment × 10000/9000)` + 0.00001 MFN tip | **Consensus** (`UploadUnderfunded` reject) | 90% treasury / 10% producer |
| Validator bond | your full stake | **Consensus** | 100% treasury (one-way; see [`ECONOMICS.md § 9`](./ECONOMICS.md#9-validator-bond-economics-m1-closed-loop)) |
| Slashing (equivocation / liveness / missed audits) | forfeited stake or bond share | **Consensus** | 100% treasury |

There is no per-byte fee on plain transfers, no EIP-1559-style base fee, and
no fee burn.

---

## 3. Transfer-fee mechanics

- The transaction carries a single scalar `tx.fee`; the balance proof binds it
  (`Σ pseudo-commitments = Σ outputs + fee·H`) in
  [`verify_transaction`](../mfn-consensus/src/transaction/verify.rs).
- At block settlement ([`apply_block`](../mfn-consensus/src/block/apply.rs)):

```text
treasury_fee  = fee × fee_to_treasury_bps / 10_000   (default bps = 9000 → 90%)
producer_fee  = fee − treasury_fee                    (10%)
```

  `treasury_fee` credits `ChainState.treasury`; `producer_fee` is paid in
  coinbase output 0 via
  [`producer_portion_amount`](../mfn-consensus/src/emission.rs).
- The mempool ([`mfn-runtime/src/mempool.rs`](../mfn-runtime/src/mempool.rs))
  has a local `min_fee` policy knob (default 0), drains highest-fee-first
  into blocks, and allows replace-by-fee. Under contention, a higher fee buys
  earlier inclusion; there is no protocol fee floor for transfers.
- The 90/10 split is pinned by the `default_fee_split_is_ninety_ten` test in
  [`producer_treasury_settlement.rs`](../mfn-consensus/tests/producer_treasury_settlement.rs).

**Legacy / no-coinbase harness.** When `require_coinbase` is false (legacy
integration tests or validators without payout addresses), there is no producer
coinbase output. Settlement credits the **full** `fee_sum` to
`ChainState.treasury` instead of splitting 90/10 — the producer share is not
burned. This path is dev/test only; production validator sets always mint
coinbase. See PROBLEMS.md § 16 and
[`apply_block`](../mfn-consensus/src/block/apply.rs).

---

## 4. Upload fees — the permanence price

Uploads are where the network "takes what it needs." A transaction anchoring
new storage must satisfy, in consensus:

```text
fee × fee_to_treasury_bps / 10_000  ≥  Σ required_endowment(new anchors)
```

i.e. the **treasury share of your fee must fully fund the perpetual-storage
endowment** for the bytes you anchor
([`apply_block`](../mfn-consensus/src/block/apply.rs) `UploadUnderfunded`;
mirrored at mempool admit). The wallet therefore computes:

```text
min_fee = ceil(required_endowment × 10_000 / fee_to_treasury_bps)
```

and adds a small default producer tip (0.00001 MFN). See
[`mfn-wallet/src/upload.rs`](../mfn-wallet/src/upload.rs).

**Worked example** (defaults: `cost_per_byte_year_ppb = 200_000`, 2% assumed
deflation, replication 3, deflation-funded mode — see
[`ECONOMICS.md § 1`](./ECONOMICS.md#1-the-permanence-equation-derived)):

```text
1 GiB × 3 replicas:
  first-year cost  C₀ ≈ 0.0064 MFN
  endowment        E₀ = C₀ × 51 ≈ 0.33 MFN
  min upload fee      = 0.33 × 10000/9000 ≈ 0.37 MFN   (≈ $5.50 at $15/MFN)
```

Payload sizes are padded to power-of-two buckets before pricing (a privacy
measure — see B13 in [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md)), so
you pay for the bucket, not the raw byte count. On the public devnet the
endowment amount inside the Pedersen commitment is additionally bound to
`required_endowment` by an `MFER` range proof
([`B1_ENDOWMENT_RANGE_PROOF.md`](./B1_ENDOWMENT_RANGE_PROOF.md)).

**MFN per byte:** catalog, minimum-fee, and effective paid rates — how to
compute them, implementation effort, and privacy —
[`STORAGE_COST_MODEL.md` § 11](./STORAGE_COST_MODEL.md#11-mfn-per-byte--can-we-measure-it-how-hard-is-it-privacy-impact).

---

## 5. Parameter review (2026-07): should fees rise, and should the tail feed the treasury?

Reviewed with permanence as the priority, per the project doctrine. Verdict
up front:

- **Keep now:** 90/10 fee split, flat wallet transfer fee.
- **Ship at next parameter fork:** route **10% of block subsidy** (including
  tail emission) to the treasury — permanence-first doctrine and operator
  preference favor predictable treasury inflow over relying on emergency
  backstop minting during fee droughts.

### 5.1 Permanence is already guaranteed — the question is *how* we pay for it

Storage operators are paid per accepted SPoRA proof out of the treasury, and
when the treasury is short, **the emission backstop mints the shortfall
unconditionally** ([`apply_block`](../mfn-consensus/src/block/apply.rs)
settlement; `emission_backstop_only_when_treasury_short` test). Data never
stops being funded.

What *does* vary is the **inflation profile**:

| Funding path | When it kicks in | Inflation character |
|---|---|---|
| Tx fees → treasury (90%) | Steady-state privacy demand | User-paid; no new mint |
| Scheduled subsidy → treasury (proposed 10%) | Every block in tail era | Predictable, small, constant |
| Emission backstop | Treasury empty + proofs accepted | Spiky, drought-triggered, unscheduled |

Choosing a tail split is not about *whether* permanence holds — it already
does. It is about trading a small, **scheduled** producer subsidy cut for a
treasury buffer that reduces how often the chain must tap the **emergency**
backstop. Under permanence-first doctrine, that trade is worth making.

**Important:** a tail/subsidy split does **not** mint extra tokens. Total
per-block emission stays the same; only the recipient changes (producer
coinbase → treasury credit). The inflation sacrifice is indirect: producers
earn slightly less, and backstop spikes should become rarer.

### 5.2 Raising the fee split (90% → 95%+): keep at 90/10 for now

- The treasury already takes 90% of every fee. The remaining 10% is the
  producer's inclusion incentive; in the tail era (subsidy ≈ 0.195
  MFN/block) fees become a meaningful part of the producer security budget
  ([`ECONOMICS.md § 6`](./ECONOMICS.md#6-producer-economics)).
- Permanence-first does **not** mean squeeze the producer tip — a chain that
  can be cheaply reorged protects no data. The tail split (§ 5.4) is the
  right lever: it funds permanence from *subsidy*, not from *fees*.
- `fee_to_treasury_bps` is frozen at genesis; any change is a hard fork.

### 5.3 Raising the flat transfer fee: keep at 0.0001 MFN for now

`DEFAULT_TRANSFER_FEE` is client-side convention with no consensus floor
behind it. Raising the default taxes reference-wallet users while custom
wallets pay whatever they want — it buys the treasury almost nothing.
The fee that actually matters for permanence — the upload endowment gate — is
already consensus-enforced and scales with bytes stored.

### 5.4 Subsidy tail split — **approved for next parameter fork** (10% → treasury)

**Proposed parameter:** `subsidy_to_treasury_bps = 1000` (10% of
`emission_at_height(h)` credits `ChainState.treasury`; the remainder goes to
the producer coinbase as today).

**Numbers at tail era** (defaults, ~2.63M slots/year):

| Stream | Per block | Per year |
|---|---|---|
| Total tail emission | 0.1953125 MFN | ~513,281 MFN |
| → treasury (10%) | 0.01953125 MFN | ~51,328 MFN |
| → producer (90%) | 0.17578125 MFN | ~461,953 MFN |

During the halving eras the same 10% applies to the (larger) subsidy — the
treasury buffer builds faster early, which is desirable.

**Why ship this:**

1. **Demand-independent permanence floor.** ~51k MFN/year flows to the
   treasury even with zero privacy txs — a cushion against fee droughts
   without waiting for backstop spikes.
2. **Predictable vs. emergency inflation.** Backstop minting is
   unscheduled and can cluster during droughts. A tail split front-loads a
   small, constant treasury inflow so backstop taps are rarer and inflation
   is smoother.
3. **Modest producer cost.** Producer tail income drops from 0.195 to
   0.176 MFN/block — ~10%. Fees (10% of tx volume) still flow to the
   producer; security budget remains viable.
4. **Respects tail-continuity.** Total emission unchanged; no upward jump
   at the tail boundary ([`ECONOMICS.md § 2`](./ECONOMICS.md#2-subsidy-curve--bitcoin-halvings-monero-tail)).

**Shipped in consensus (F6 phase 2).** `EmissionParams.subsidy_to_treasury_bps`
defaults to `0` at genesis; checkpoint **v11** persists the field.
[`apply_block`](../mfn-consensus/src/block/apply.rs) credits
`subsidy_treasury_credit(height)` to `ChainState.treasury` on producer-coinbase
blocks; [`producer_portion_amount`](../mfn-consensus/src/emission.rs) and
[`get_chain_params`](../mfn-rpc/src/dispatch.rs) expose the parameter.
**Enabling `1000` on public devnet** remains a separate parameter-fork decision
(same `genesis_id` policy as other emission knobs).

**Do not combine with** raising `fee_to_treasury_bps` in the same fork — one
lever at a time so telemetry can attribute effects.

The `treasury_base_units` field of `get_chain_params` and per-block backstop
behavior are the telemetry inputs. Read-only helper:
`bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --plan-only`
(live: `--rpc HOST:PORT`).

---

## See also

- [`ECONOMICS.md`](./ECONOMICS.md) — full monetary model: emission curve, treasury dynamics, worked drought/boom scenarios, [§ 12 Arweave durability comparison](./ECONOMICS.md#12-permanence-durability-vs-arweave--is-this-model-more-likely-to-break)
- [`STORAGE.md`](./STORAGE.md) — SPoRA proofs and how operators actually collect the treasury outflow
- [`STORAGE_COST_MODEL.md`](./STORAGE_COST_MODEL.md) — per-gigabyte endowment projections in fiat terms
- [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md) — scheduled supply by year/decade/century
