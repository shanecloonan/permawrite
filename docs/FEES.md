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

---

## 5. Parameter review (2026-07): should fees rise, and should the tail feed the treasury?

Reviewed with permanence as the priority, per the project doctrine. Verdict
up front: **keep the current parameters** — the 90/10 split, the flat wallet
transfer fee, and 100% of tail emission to the producer. Reasoning and
revisit triggers below.

### 5.1 Why the permanence guarantee does not depend on the fee level

Storage operators are paid per accepted SPoRA proof out of the treasury, and
when the treasury is short, **the emission backstop mints the shortfall
unconditionally** ([`apply_block`](../mfn-consensus/src/block/apply.rs)
settlement; `emission_backstop_only_when_treasury_short` test). Operators are
paid in full in every block regardless of fee volume. Fee levels therefore
change **who bears the cost** — transactors (fees) vs. all holders (dilution
via backstop minting) — not **whether data stays paid-for**. Raising fees is
a cost-allocation decision, not a permanence-safety decision.

### 5.2 Raising the fee split (90% → 95%+): rejected for now

- The treasury already takes 90 basis points of every 100. The remaining 10%
  is the producer's inclusion incentive; in the tail era (subsidy ≈ 0.195
  MFN/block) fees become a meaningful part of the producer security budget
  ([`ECONOMICS.md § 6`](./ECONOMICS.md#6-producer-economics)). Squeezing the
  tip risks weakening consensus security — and a chain that can be cheaply
  reorged protects no data. Marginal treasury gain, real security cost.
- `fee_to_treasury_bps` is frozen at genesis and not genesis-JSON
  configurable ([`genesis_spec.rs`](../mfn-runtime/src/genesis_spec.rs) always
  loads `DEFAULT_EMISSION_PARAMS`), so any change is a hard fork for the
  running devnet.

### 5.3 Raising the flat transfer fee: rejected for now

`DEFAULT_TRANSFER_FEE` is client-side convention with no consensus floor
behind it. Raising the default taxes reference-wallet users while custom
wallets pay whatever they want — it buys the treasury almost nothing.
Introducing a real consensus minimum (per-byte fee market) is a much larger
protocol change and is not justified while blocks are far from full. The
fee that actually matters for permanence — the upload endowment gate — is
already consensus-enforced and scales with bytes stored.

### 5.4 Routing ~10% of tail emission to the treasury: rejected for now

The idea: split the permanent tail (0.195 MFN/block) so e.g. 10% accrues to
the treasury instead of the producer, giving permanence a demand-independent
income floor.

**For it:** it converts *unscheduled* backstop minting into *scheduled*
emission (more predictable inflation), and builds a drought buffer so the
treasury rarely empties.

**Against it (decisive today):**

1. **Economically near-redundant.** The backstop already guarantees operator
   payouts when the treasury is dry. A tail split changes the inflation
   *accounting*, not the permanence *guarantee*.
2. **It cuts producer income exactly when it is thinnest.** In the tail era
   the producer lives on `0.195 MFN + 10% of fees`. Diverting 10% of the tail
   weakens the consensus security budget in the era it matters most —
   security is a precondition for permanence, not a competitor to it.
3. **Hard fork cost.** `EmissionParams` are frozen at genesis; this cannot be
   rolled out as a config change on the live devnet.

**Revisit triggers** (any of these reopens both § 5.2 and § 5.4 as a single
parameter fork):

- Testnet/mainnet telemetry shows the treasury pinned near zero with the
  emission backstop minting in a majority of blocks over a sustained window
  (weeks), i.e. structural — not transient — fee drought while storage
  liabilities grow.
- Realized inflation from backstop minting materially exceeds the scheduled
  emission curve in [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md).
- If reopened: prefer raising `cost_per_byte_year_ppb` (make new uploads pay
  more) first, then a tail split (respecting the tail-continuity constraint
  in [`ECONOMICS.md § 2`](./ECONOMICS.md#2-subsidy-curve--bitcoin-halvings-monero-tail)),
  and only then a higher `fee_to_treasury_bps`.

The `treasury_base_units` field of the `get_chain_params` RPC and per-block
backstop behavior give exactly the telemetry needed to watch these triggers.
Read-only helper: `bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --plan-only`
(live: `--rpc HOST:PORT`).

---

## See also

- [`ECONOMICS.md`](./ECONOMICS.md) — full monetary model: emission curve, treasury dynamics, worked drought/boom scenarios
- [`STORAGE.md`](./STORAGE.md) — SPoRA proofs and how operators actually collect the treasury outflow
- [`STORAGE_COST_MODEL.md`](./STORAGE_COST_MODEL.md) — per-gigabyte endowment projections in fiat terms
- [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md) — scheduled supply by year/decade/century
