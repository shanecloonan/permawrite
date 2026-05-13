# M2.0.14 — `Wallet::build_storage_upload`

> *"The privacy half is end-to-end accessible through the wallet. The
> permanence half should be too — same standards, same ergonomics, same
> typed errors. Anything less leaves users hand-rolling RingCT to
> permanently store a tweet."*

This milestone closes the symmetry. After M2.0.14, **every operation
the Permawrite network supports has a first-class wallet entry point**:

| User intent | Wallet entry point | Tx shape |
|---|---|---|
| Send MFN privately | `Wallet::build_transfer` | RingCT, `storage: None` everywhere |
| Permanently store data | `Wallet::build_storage_upload` | RingCT + one `OutputSpec::ToRecipient { storage: Some(commit), ... }` |

The mempool already accepts both shapes (`M2.0.13`); the chain already
anchors both (`M2.0.5` + `M2.0.6`). What was missing was the *uploader*.

## Motivation

Up to M2.0.13, the **only** way to land a storage-anchoring tx on chain
was to hand-construct an `OutputSpec::Raw` with a `StorageCommitment`
and pass it directly to `mfn_consensus::sign_transaction`. Every
end-to-end test that exercised storage anchoring (in `mfn-node`'s
integration tests) did exactly this — bespoke chain plumbing per call
site, no decoy selection, no greedy coin-selection, no change output,
and no typed errors for any of the failure modes the mempool / chain
would later raise.

That's fine for tests. It's unacceptable for the consumer-facing
wallet path. **The wallet must build uploads with the same first-class
ergonomics it builds transfers with.**

## Goals

1. **One call** to upload data. The caller passes `data`, `replication`,
   `fee`, an anchor recipient, and a few standard RingCT knobs; the
   wallet does coin selection, decoy sampling, commitment construction,
   change-output bookkeeping, CLSAG signing, and returns a fully sealed
   `SignedTransaction`.

2. **Typed errors for every mempool / chain rejection**. Every reason
   the storage-anchoring gate in `Mempool::admit` (M2.0.13) or
   `apply_block` could refuse a tx must surface as a wallet-side
   `WalletError` variant **before** signing — so the wallet never burns
   CLSAG work on a doomed upload and never leaks input key images for
   nothing.

3. **Return more than just the tx**. The uploader must retain the
   Merkle tree (to serve SPoRA chunk audits later) and the endowment
   Pedersen blinding (in case anyone ever wants to open the commitment
   to prove it matches `required_endowment`). Both are returned via an
   `UploadArtifacts` struct.

4. **Self-anchoring is the default ergonomic path**. The wallet exposes
   `Wallet::recipient()` so callers writing the common "anchor my data
   to my own keys" case don't have to manually plumb view-pub +
   spend-pub through.

## Architecture

```text
mfn-wallet
├── src/
│   ├── lib.rs              ← re-exports build_storage_upload, UploadArtifacts, ...
│   ├── error.rs            ← +5 new WalletError variants (UploadUnderfunded, ...)
│   ├── spend.rs            ← unchanged (privacy transfer path)
│   ├── upload.rs           ← NEW: low-level build_storage_upload + StorageUploadPlan
│   │                         + UploadArtifacts + estimate_minimum_fee_for_upload
│   └── wallet.rs           ← +Wallet::recipient()
│                             +Wallet::build_storage_upload()
│                             +Wallet::build_storage_upload_with_blinding()
│                             +Wallet::upload_min_fee()
└── tests/
    └── end_to_end.rs       ← +3 new integration tests
```

### Layering

```text
┌─────────────────────────────────────────────────────────────────┐
│  Wallet::build_storage_upload          ← user-facing convenience │
│        │                                                         │
│        ▼                                                         │
│  greedy select_inputs() → change calc → decoy_pool → ...         │
│        │                                                         │
│        ▼                                                         │
│  build_storage_upload(StorageUploadPlan)    ← low-level adapter  │
│        │                                                         │
│        ├─► required_endowment()        ← mfn-storage             │
│        ├─► build_storage_commitment()  ← mfn-storage             │
│        ├─► CLSAG ring assembly         ← per-input gamma decoys  │
│        ▼                                                         │
│  sign_transaction()                    ← mfn-consensus           │
└─────────────────────────────────────────────────────────────────┘
```

The split mirrors `build_transfer` / `Wallet::build_transfer` exactly.
The low-level adapter is exposed so tests, deterministic-output
callers, and "anchor to arbitrary recipient" workflows can drive it
directly; the high-level wrapper is the common path.

## The eight-step admission gate (wallet edition)

`build_storage_upload` re-implements byte-for-byte every check the
mempool's M2.0.13 storage gate runs (which itself mirrors `apply_block`
exactly):

| Step | Check | Error variant |
|------|-------|---------------|
| 1 | `ring_size ≥ 2`, `decoy_pool.len() + 1 ≥ ring_size` | `DecoyPoolTooSmall` |
| 2 | `replication ∈ [min, max]` from `chain_state.endowment_params` | `UploadReplicationOutOfRange { got, min, max }` |
| 3 | `required_endowment(data.len(), replication, params)` succeeds | `Endowment(EndowmentError)` |
| 4 | Computed burden fits in `u64` (committable in `StorageCommitment.endowment`) | `UploadEndowmentExceedsU64 { burden }` |
| 5 | `fee_to_treasury_bps > 0` when `burden > 0` | `UploadTreasuryRouteDisabled` |
| 6 | `fee · fee_to_treasury_bps / 10_000 ≥ burden` | `UploadUnderfunded { fee, treasury_share, burden, min_fee }` |
| 7 | `Σ inputs = anchor_value + Σ change + fee` exactly | `InsufficientFunds { requested, available }` |
| 8 | `build_storage_commitment` succeeds (chunking, Merkle build) | `Spora(SporaError)` |

Only after **all eight gates clear** does the wallet build the CLSAG
ring and invoke `sign_transaction`. The privacy guarantee is sacred:
**we never broadcast inputs we'll have to throw away**.

### Why hoist the underfunded gate?

The mempool's `UploadUnderfunded` rejection is purely economic, not
cryptographic — the tx is technically valid CLSAG-wise. But by the
time the mempool sees it:

- The signing wallet has burned a few hundred ms of compute on range
  proofs + CLSAG signatures.
- The wire transaction (with its inputs' `key_image`s) has been
  serialized and possibly already broadcast to peers.
- Adversaries scraping the gossip layer now have a "signed but
  rejected" transaction tying those specific key images to the
  uploader's intent to store this specific commitment.

Hoisting the check to the wallet layer is a **defense-in-depth privacy
win** on top of the obvious "save a few hundred ms" win.

### `estimate_minimum_fee_for_upload`

To make the fee-too-low path actionable, the wallet exposes a pure
helper:

```rust
pub fn estimate_minimum_fee_for_upload(
    data_len: u64,
    replication: u8,
    endowment_params: &EndowmentParams,
    fee_to_treasury_bps: u16,
) -> Result<u64, WalletError>;
```

returning the smallest `fee` such that `fee · bps / 10_000 ≥ burden`.
This is the inverse of the chain's gate, formulated with **ceiling
division** so the returned value always satisfies the gate exactly
(never one base unit short due to integer truncation). The matching
test `estimate_minimum_fee_satisfies_gate_exactly` asserts both
`min_fee` clears the gate and `min_fee - 1` does not — for a 4×4 grid
of (size, replication) combinations.

For convenience, `Wallet::upload_min_fee(data_len, replication,
&chain_state)` curries the chain's endowment params + fee bps from
chain state.

## What the wallet does NOT do

Out of scope for M2.0.14 (kept simple to avoid creep):

- **Persist `data`**: the wallet holds the bytes in memory long enough
  to chunk + Merkleize them, then discards. Serving those chunks to
  storage operators when challenged is a downstream concern (likely
  M2.1.x once we have a storage-operator daemon).

- **Build storage proofs**: `mfn_storage::build_storage_proof` is for
  whoever answers SPoRA challenges — the block producer / storage
  operator. The uploader's role ends when the tx anchors.

- **Auto-dedup**: if the wallet uploads the same `(data, replication,
  chunk_size, endowment_amount)` twice, the *second* tx anchors a
  distinct `StorageCommitment` (because the Pedersen blinding is
  fresh-random), so its hash differs, so the chain anchors it as a
  new commitment. The wallet does not pre-check `state.storage` for
  this case — by design. Callers who want true content-addressed dedup
  should compare `art.built.commit.data_root` against known anchored
  data-roots before calling.

## API surface

### Public re-exports

```rust
pub use upload::{
    build_storage_upload,            // low-level
    estimate_minimum_fee_for_upload, // pure fee floor calculator
    StorageUploadPlan,               // low-level input struct
    UploadArtifacts,                 // returned by both paths
};
```

### `Wallet` methods

```rust
impl Wallet {
    pub fn recipient(&self) -> Recipient;

    pub fn upload_min_fee(
        &self,
        data_len: u64,
        replication: u8,
        chain_state: &ChainState,
    ) -> Result<u64, WalletError>;

    pub fn build_storage_upload<R: FnMut() -> f64>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        chain_state: &ChainState,
        extra: &[u8],
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>;

    pub fn build_storage_upload_with_blinding<R: FnMut() -> f64>(
        // identical signature + `endowment_blinding: Scalar`
    ) -> Result<UploadArtifacts, WalletError>;
}
```

### `UploadArtifacts`

```rust
pub struct UploadArtifacts {
    pub signed: SignedTransaction,    // submit to a mempool
    pub built: BuiltCommitment,       // keep: Merkle tree + blinding
    pub burden: u128,                 // chain-required upfront endowment
    pub min_fee: u64,                 // smallest fee that satisfies the gate
}
```

## Test matrix

### Unit (`mfn-wallet/src/upload.rs`, 11 tests)

| Name | Asserts |
|------|---------|
| `happy_path_anchors_data_and_returns_artifacts` | Round-trip: tx has 2 outputs (storage + change), `storage_commitment_hash` of `tx.outputs[0].storage` equals `art.built.commit`, blinding opens the endowment Pedersen, `treasury_share ≥ burden` |
| `replication_below_min_rejected_with_typed_error` | `replication = 1` → `UploadReplicationOutOfRange { got: 1, min: 3, max: 32 }` |
| `replication_above_max_rejected_with_typed_error` | `replication = 99` → `UploadReplicationOutOfRange { got: 99, ... }` |
| `fee_below_minimum_rejected_with_actionable_min_fee` | 100 KiB upload, `fee = 1` → `UploadUnderfunded { min_fee, .. }`, paying `min_fee` would clear the gate |
| `fee_to_treasury_bps_zero_yields_typed_error_when_burden_positive` | `bps = 0` + non-zero burden → `UploadTreasuryRouteDisabled` |
| `empty_data_zero_burden_zero_min_fee_is_fine` | `data = &[]` accepted, anchors an empty commitment with `size_bytes = 0` |
| `estimate_minimum_fee_is_monotonic_in_size_at_fixed_replication` | `min_fee(1_000) < min_fee(1_000_000)` |
| `estimate_minimum_fee_satisfies_gate_exactly` | For 4×4 grid of (size, repl), `min_fee` clears the gate and `min_fee - 1` does not |
| `estimate_minimum_fee_rejects_replication_out_of_range` | Replication validation precedes fee math |
| `insufficient_funds_on_unbalanced_inputs` | `Σ inputs ≠ anchor + change + fee` → `InsufficientFunds` |
| `pinned_blinding_is_returned_for_later_endowment_opening` | Caller-pinned blinding round-trips in `BuiltCommitment.blinding` and opens the on-wire Pedersen |

### Integration (`mfn-wallet/tests/end_to_end.rs`, 3 new tests)

| Name | Path exercised |
|------|----------------|
| `wallet_storage_upload_through_mempool_producer_and_chain` | wallet → mempool admit → drain → producer → chain.apply → `state.storage[hash]` populated → wallet.ingest reflects change. LightChain follows in lockstep. |
| `wallet_storage_upload_rejects_insufficient_funds_before_signing` | Wallet hits `InsufficientFunds` in coin selection before reaching the upload primitives |
| `wallet_storage_upload_rejects_fee_too_low_before_signing` | Underfunded fee surfaces as `WalletError::UploadUnderfunded { min_fee }` (with the actionable correct value) |

### Total impact

- mfn-wallet: 26 → 37 unit tests (+11), 2 → 5 integration tests (+3)
- Workspace total: 516 → **530 tests** passing
- Source files: 109 → 110 (+1 new module `mfn-wallet/src/upload.rs`)

## What this unlocks

**The permanence half of the Permawrite thesis is now end-to-end
accessible through a single Rust API call.** A consumer of `mfn-wallet`
can — with no other crate knowledge — permanently anchor arbitrary
bytes on the chain in a confidential transaction:

```rust
let wallet = Wallet::from_seed(&seed);
wallet.ingest_block(&block);                  // ... funds Alice

let data = std::fs::read("manifesto.txt")?;
let min_fee = wallet.upload_min_fee(data.len() as u64, 3, chain.state())?;

let art = wallet.build_storage_upload(
    &data,
    /* replication */ 3,
    /* fee */         min_fee + 1_000,        // tip to producer
    wallet.recipient(),                       // anchor to self
    /* anchor_value */ 1_000,                  // tiny self-payment UTXO
    /* chunk_size */ None,                     // default 256 KiB
    /* ring_size */ 8,
    chain.state(),
    b"manifesto-v1",
    &mut rng,
)?;

mempool.admit(art.signed.tx, chain.state())?;
// art.built.tree retained locally to serve SPoRA challenges later.
```

This is the API the future `mfn-cli wallet upload` command will sit
on top of, and the API the future browser-wallet WASM bindings will
expose. With M2.0.14, **the storage path has the same UX as the
transfer path**.

### Roadmap connection

- **M2.0.15 — Persistent `Chain` state (`mfn-store`)** — full node
  restart support. Critical before any daemon work.
- **M2.0.16 — Storage operator daemon prototype** — serve SPoRA chunk
  audits using `art.built.tree` artifacts uploaders retain.
- **M2.1.0 — single-node `mfn-node` daemon** — first runnable binary
  with RPC. The wallet methods built here become the RPC surface for
  `wallet.uploadData(...)`.

## References

- `mfn-storage::build_storage_commitment` — Merkle + Pedersen primitives.
- `mfn-consensus::sign_transaction` — RingCT ceremony.
- M2.0.13 — Mempool's storage-anchoring admission gate (the rules this
  wallet mirrors).
- M2.0.5 / M2.0.6 — `apply_block`'s storage anchoring + burden math
  (the underlying consensus rules).
- Whitepaper §3 — endowment math.
