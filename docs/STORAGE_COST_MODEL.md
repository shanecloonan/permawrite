# Storage cost model -- per-gigabyte projections

Canonical pricing reference for Permawrite permanence at default protocol parameters. Numbers derive from [`mfn-storage/src/endowment.rs`](../mfn-storage/src/endowment.rs). See [`ECONOMICS.md`](./ECONOMICS.md) and [`STORAGE.md`](./STORAGE.md).

---

## 1. What you are buying

A permanence upload pays a **one-time endowment** `E0` in MFN. In exchange:

- The file Merkle root is anchored on-chain forever (no delete, no expiry).
- At least `replication` independent operators are economically bound to retain the bytes.
- Every block, **SPoRA** (Succinct Proofs of Random Access) challenges a random 256 KiB chunk; operators who still hold the data earn treasury-funded rewards.

There is **no recurring bill**. The endowment capitalizes storage liability up front. Ongoing operator compensation comes from the **storage treasury** (90% of privacy-transaction fees, plus a rare emission backstop).

---

## 2. Default parameters (genesis calibration)

| Parameter | On-chain value | Meaning |
|---|---|---|
| `cost_per_byte_year_ppb` | `200_000` | 2e-4 MFN base units per byte-year per replica |
| `inflation_ppb` | `20_000_000` | 2.0% / year (deflation floor `d` when r=0) |
| `real_yield_ppb` | `0` | Deflation-funded mode (default) |
| `min_replication` | `3` | Minimum independent replicas |
| `max_replication` | `32` | DoS ceiling |
| `MFN_BASE` | `100_000_000` | 1 MFN = 10^8 base units |

Calibration targets **0.1-1.0 MFN for 1 GiB x 3 replication** (Arweave-comparable at equivalent token prices).

---

## 3. Closed-form formula

First-year storage liability (all replicas):

```text
C0 = cost_per_byte_year_ppb x size_bytes x r / PPB
   = 200_000 x size_bytes x r / 10^9   base units per year
```

Required one-time endowment (default r=0):

```text
E0 = ceil( C0 x (PPB + inflation_ppb) / (PPB x inflation_ppb) )
   = ceil( C0 x 1.02 / 0.02 )
   = ceil( 51 x C0 )
```

Compact form: `E0 = ceil( 0.0102 x size_bytes x r )` base units.

You prepay **51x the first-year storage bill** at the 2% deflation floor.

---

## 4. Reference price table (3x replication)

| Payload | size_bytes | C0 (year-1) | E0 (one-time) | MFN |
|---|---:|---:|---:|---:|
| 1 KiB | 1,024 | 614 | 31,338 | 0.00031338 |
| 1 MiB | 1,048,576 | 629 | 32,087 | 0.00032087 |
| 10 MiB | 10,485,760 | 6,291 | 320,864 | 0.00320864 |
| 100 MB (decimal) | 100,000,000 | 60,000 | 3,060,000 | **0.03060000** |
| 1 GB (decimal) | 1,000,000,000 | 600,000 | 30,600,000 | **0.30600000** |
| 1 GiB (binary) | 1,073,741,824 | 644,245 | 32,856,500 | **0.32856500** |
| 10 GiB | 10,737,418,240 | 6,442,451 | 328,565,001 | 3.28565001 |
| 1 TiB | 1,099,511,627,776 | 659,707 | 33,645,057 | 336.45057 |

100 MB decimal matches [`STORAGE.md`](./STORAGE.md) worked examples (3,060,000 base units). 1 GiB is pinned by `one_gb_three_replication_in_arweave_band` in `endowment.rs` (10^7..10^8 base units).

**Binary vs decimal:** "100 MB" (10^8 bytes) and "100 MiB" (104,857,600 bytes) differ by ~4.9%; endowment scales linearly with `size_bytes`.

---

## 5. Replication multiplier

E0 scales linearly: `E0(r) = r x E0(1)` at fixed size.

| 1 GiB | r=3 | r=5 | r=10 | r=32 |
|---|---:|---:|---:|---:|
| MFN | 0.329 | 0.548 | 1.096 | 3.507 |

---

## 6. Fiat equivalents (illustrative)

At calibration (1 MFN ~ $15, Arweave-comparable):

| MFN price | 1 GiB x3 | 1 GB x3 | 100 MB x3 |
|---:|---:|---:|---:|
| $5 | $1.64 | $1.53 | $0.15 |
| $15 | **$4.93** | **$4.59** | **$0.46** |
| $50 | $16.43 | $15.30 | $1.53 |
| $150 | $49.28 | $45.90 | $4.59 |

Spot conversions only; solvency depends on real storage cost trends and treasury inflows, not day-one FX.

---

## 7. Kryder's law scenarios

`C_t = C0 x (1+g)^t` where `g` is annual real storage cost change (negative = deflation):

| Scenario | g | Year-10 vs C0 | Year-50 vs C0 |
|---|---:|---:|---:|
| Historical Kryder (~35%/yr) | -35% | 2.6% | 0.003% |
| Moderate deflation | -10% | 35% | 0.5% |
| Protocol floor | -2% | 82% | 37% |
| Flat costs | 0% | 100% | 100% |
| Rising costs (stress) | +2% | 122% | 269% |

The 51x buffer is designed for the -2% floor. Faster deflation yields surplus; sustained rising costs require a parameter fork (`real_yield_ppb > 0` or a wider buffer).

Both Permawrite and Arweave inherit this bet at upload time. For how hardware
deflation interacts with **zero privacy-tx demand** (ongoing treasury funding
vs Arweave's per-upload endowment sink), see
[`ECONOMICS.md` § 12.6](./ECONOMICS.md#126-hardware-deflation-and-zero-privacy-demand).

---

## 8. Comparison to other systems

| System | Payment | Audit | Payment privacy | Retention |
|---|---|---|---|---|
| Cloud | Subscription | Provider attestation | KYC trail | Stops when you stop paying |
| IPFS | None default | None on-chain | N/A | Pins expire |
| Filecoin | Deal renewals | PoRep/PoSt | Transparent | Contracts expire |
| Arweave | One-time endowment | Recall mining | Transparent | Deflation endowment |
| Permawrite | One-time endowment | SPoRA every block | RingCT/CLSAG | Deflation + fee treasury + emission backstop |

For a full durability comparison (failure modes, stress scenarios, verdict),
see [`ECONOMICS.md § 12`](./ECONOMICS.md#12-permanence-durability-vs-arweave--is-this-model-more-likely-to-break).

---

## 9. Worked example

50 MB decimal (50_000_000 bytes), replication=3, paid via CLSAG ring signature:

```text
C0 = 200_000 x 50_000_000 x 3 / 10^9 = 30_000 base units/year
E0 = ceil(30_000 x 51) = 1_530_000 base units = 0.0153 MFN
```

At $15/MFN: about **$0.23** once, with no renewal and no public payer address.

---

## 10. Parameter sensitivity

| Change | Effect on E0 |
|---|---|
| cost_per_byte_year_ppb doubles | doubles |
| replication doubles | doubles |
| inflation_ppb halved | approx doubles |
| real_yield_ppb > inflation_ppb | decreases (yield-bearing mode) |

---

## 11. MFN per byte — can we measure it, how hard is it, privacy impact

Users often want a single number: **how many MFN per byte** (or per GiB) does
permanence cost? The protocol does not expose one on-chain scalar called
`mfn_per_byte`, but several **well-defined rates** can be computed. They
differ in what they measure.

### 11.1 Three rates (do not mix them)

| Rate | What it measures | Depends on |
|---|---|---|
| **Catalog endowment rate** | Protocol-required endowment `E₀` for a bucket size | `get_chain_params.endowment` only — same for every uploader |
| **Minimum upload-fee rate** | Smallest `tx.fee` that passes consensus for one new anchor | `E₀` + `fee_to_treasury_bps` (default 90% → treasury) |
| **Effective paid rate** | What a particular upload actually paid | That tx's `fee` and/or revealed endowment opening |

All rates use **on-chain `size_bytes`** — the power-of-two **bucket** length
(B13), not the uploader's raw file length. A 900-byte file is priced as a
1,024-byte bucket.

### 11.2 Catalog endowment rate (easy — pure math)

At default parameters (`real_yield_ppb = 0`, `inflation_ppb = 2%`,
`fee_to_treasury_bps = 9000`), from [§ 3](#3-closed-formula):

```text
E₀_base = ceil( 0.0102 × size_bytes × replication )

catalog_MFN_per_bucket_byte = E₀_base / (MFN_BASE × size_bytes)
                            ≈ 0.0102 × replication / MFN_BASE   (ignoring ceil)

catalog_MFN_per_GiB(r=3) ≈ 0.328565 MFN   (binary GiB, see § 4 table)
```

**Replication `r` multiplies the rate linearly** — you are buying `r`
independent replicas, not one byte stored once.

Reference constants at `r = 3` (defaults):

| Unit | Catalog endowment (`E₀`) | ≈ MFN / unit |
|---|---:|---:|
| per bucket-byte | 0.0306 base units | **3.06 × 10⁻¹⁰ MFN** |
| per KiB bucket | 31,338 base units | 0.000313 MFN |
| per GiB bucket | 32,856,500 base units | **0.329 MFN** |

**How to compute today**

1. Read params: JSON-RPC `get_chain_params` → `endowment` block, or
   `mfn-storage::required_endowment(size_bytes, replication, &params)` in
   Rust.
2. Apply the closed form — no chain scan, no wallet, no historical data.

**Difficulty:** trivial. The tables in § 4–§ 5 are already this metric.

### 11.3 Minimum upload-fee rate (easy — one more division)

Consensus requires the treasury share of the fee to cover `E₀`:

```text
min_fee_base = ceil( E₀ × 10_000 / fee_to_treasury_bps )
             ≈ ceil( E₀ × 10/9 )          // default bps = 9000

min_MFN_per_bucket_byte = min_fee_base / (MFN_BASE × size_bytes)
```

The reference wallet adds a small producer tip on top (default 0.00001 MFN);
that tip is **not** required by consensus.

**Example** (1 GiB bucket, `r = 3`): `E₀ = 32,856,500` base →
`min_fee ≈ 36,507,223` base ≈ **0.365 MFN** → ≈ **3.40 × 10⁻¹⁰ MFN /
bucket-byte** (≈ 11% above the catalog endowment rate because 90% of the fee
must fund the endowment).

**Difficulty:** trivial — same inputs as § 11.2 plus `emission.fee_to_treasury_bps`.

### 11.4 Effective paid rate per upload (moderate — chain data)

To ask "what did *this* upload pay per byte?" you need a **numerator** and the
public **`size_bytes`** denominator:

| Numerator source | On-chain? | Notes |
|---|---|---|
| `tx.fee` | **Yes** — every tx in every block body | Upload txs are recognizable (outputs carry `StorageCommitment`), but **ring signatures hide the payer** |
| `MFEO` opening `value` | **Yes** when `require_endowment_opening = 1` | Exact endowment inside the Pedersen commitment; public devnet requires this (B-11) |
| Pedersen `endowment` point alone | Point only | **Amount hidden** unless opening/range proof data is present |
| Over-payment above `min_fee` | Sometimes | Wallet may pay more; only `tx.fee` reveals total paid, not treasury vs producer split beyond the 90/10 rule |

```text
effective_MFN_per_bucket_byte ≈ tx.fee / (MFN_BASE × commit.size_bytes)
```

or, when openings are required:

```text
effective_MFN_per_bucket_byte ≈ MFEO.value / (MFN_BASE × commit.size_bytes)
```

**Difficulty**

| Task | Effort | Status |
|---|---|---|
| Quote before upload (size + replication → `E₀`, `min_fee`) | ~few lines wrapping `required_endowment` | Logic exists in wallet; no dedicated `mfn-cli price` yet |
| Sum **total anchored bucket bytes** | Scan `ChainState.storage` or paginate `list_recent_uploads` | **Possible today** via RPC; no dedicated aggregate RPC |
| Per-upload effective rate index | Block scanner: storage outputs + `tx.fee` (+ optional `MFEO` parse) | Moderate indexer work; data is already public |
| Network-wide **average** MFN/byte historically | Sum fees or openings / sum `size_bytes` | Moderate; skewed by over-tips and multi-anchor txs |

`ChainStats` today exposes `treasury` and tip metadata only — **not**
`total_storage_bytes` or network MFN/byte averages. Adding those aggregates
would be a small RPC extension (sum over public `StorageCommitment.size_bytes`
fields).

### 11.5 Which metric should UX show?

| Audience | Recommended metric | Why |
|---|---|---|
| Pre-upload estimator | **Catalog endowment** + **min fee** for the bucket | Deterministic; matches consensus floor |
| Comparisons to Arweave / cloud | **MFN per GiB** at default `r` | Human-scale; § 4 table |
| Block explorer / analytics | **Effective paid rate** (fee or MFEO / bucket bytes) | Observed economics; optional |
| Treasury health | **Not** MFN/byte — use `treasury` balance + backstop frequency | [`treasury-telemetry-watch`](../scripts/public-devnet-v1/treasury-telemetry-watch.sh) |

Avoid quoting **raw file bytes** in user-facing price copy — always label
**bucket bytes** so expectations match B13 padding.

### 11.6 Privacy impact — does publishing MFN/byte hurt privacy?

**Short answer: catalog and min-fee rates are safe. Effective-rate analytics
use data that is already public; they do not break ring confidentiality.**

| Action | Privacy impact |
|---|---|
| Document / display **catalog** MFN per GiB from chain params | **None** — pure protocol math, no user data |
| Pre-upload **quote** API (`size_bytes`, `replication` → `E₀`) | **None** — same as wallet math before broadcast |
| Sum **total anchored bucket bytes** on-chain | **None new** — `size_bytes` is already in every `StorageCommitment` and `list_recent_uploads` |
| Compute **effective** rate = `tx.fee / size_bytes` for upload txs | **Low / metadata only** — `tx.fee` is public in blocks; upload txs are structurally identifiable, but **CLSAG still hides which ring member paid**. Reveals over-tipping, not identity |
| Index **MFEO** openings → exact endowment per commitment | **Already required** on public devnet for consensus binding — not introduced by pricing UX |
| Quote using **raw** file length instead of bucket | **Bad UX + leaks size intent off-chain** if you transmit raw len to a server; on-chain anchor still uses bucket only |
| Fiat conversion ($/GiB) | **None** at protocol layer — oracle/UX concern only |

**What MFN/byte does *not* reveal:** payer address, input UTXO set, or exact
pre-pad file length (bucket rounding is consensus-mandatory).

**What it can reveal (already on-chain):** that a given commitment used a
~1 KiB / ~1 MiB / ~1 GiB **bucket**, and whether the sender paid above the
minimum — coarse metadata comparable to Arweave's transparent upload pricing.

**Design rule:** ship **param-derived quotes** (§ 11.2–11.3) freely; treat
**per-tx effective-rate dashboards** as optional analytics on public fields,
not as wallet defaults that encourage fee fingerprinting.

### 11.7 Verdict

| Question | Answer |
|---|---|
| Is MFN/byte calculable? | **Yes** — catalog and min-fee rates exactly; effective rates per upload when `tx.fee` and/or `MFEO` is known |
| How hard? | **Trivial** for quotes from params; **easy** for total bucket-bytes; **moderate** for a full explorer index |
| Does doing it hurt privacy? | **No** for catalog/min-fee displays; **no new deanonymization** for effective rates beyond public tx metadata and bucket sizes already enforced by B13 |

---

## See also

- [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md)
- [`STORAGE.md`](./STORAGE.md)
- [`ECONOMICS.md`](./ECONOMICS.md)
