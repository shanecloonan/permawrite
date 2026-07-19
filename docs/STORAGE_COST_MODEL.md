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

## See also

- [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md)
- [`STORAGE.md`](./STORAGE.md)
- [`ECONOMICS.md`](./ECONOMICS.md)
