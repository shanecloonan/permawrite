# M2.0.12 — `mfn-node::mempool`: in-memory transaction pool

| Item                  | Value                                                          |
|-----------------------|----------------------------------------------------------------|
| Crate                 | `mfn-node` (new module: `mempool`)                             |
| Milestone             | M2.0.12                                                        |
| Roadmap line          | "The bridge between wallets and the producer."                 |
| Workspace test delta  | +18 tests (488 → 506 passing)                                  |
| External dependencies | none new — re-uses `mfn-consensus` + `thiserror`               |
| Public API surface    | `Mempool`, `MempoolConfig`, `MempoolEntry`, `AdmitError`, `AdmitOutcome` |

## Motivation

M2.0.11 shipped a wallet that signs `TransactionWire`s. M2.0.4 shipped a producer that turns `BlockInputs.txs` into sealed blocks. There was no piece between them.

Every blockchain needs a holding pen — a place where a wallet's freshly signed transactions wait until a producer is ready to include them in a block, and where the system enforces:

- **Validity** — only transactions the chain will accept land in the pool. The producer trusts the pool's output verbatim.
- **Conflict resolution** — when two transactions spend the same input (key-image conflict), the pool picks one rather than letting the chain reject both.
- **Fee priority** — the producer drains the pool in fee-descending order so blocks naturally include the most economically valuable transactions first.
- **Cleanup** — when a block lands, the pool evicts every transaction the block included.

M2.0.12 ships exactly that primitive, **in memory**, **per-node**, **without P2P**. The mempool is the deterministic, testable kernel that future P2P relay (M2.x), persistent mempool (M3.x), and policy gates (min-relay-fee, dust limits) will all attach to.

## Goals

1. **Equivalence with `apply_block`.** A tx admitted to the mempool is one the chain will accept, modulo state changes between admit and inclusion. Concretely: the mempool re-runs every per-tx gate the chain runs, against the *current* `ChainState`.
2. **Replace-by-fee.** When a new tx conflicts on key images with an existing pool entry, the higher fee wins. Equal-fee replacements are rejected (prevents replacement-spam griefing).
3. **Bounded memory.** A `max_entries` cap with lowest-fee eviction guarantees the pool can't grow unboundedly under DoS.
4. **Pure, deterministic, no IO.** `&Mempool` is `Sync`, every method is synchronous and side-effect free outside the pool itself. Suitable for unit tests, fuzzing, and (eventually) WASM.
5. **Stay out of the producer's way.** `drain(max)` returns a `Vec<TransactionWire>` in highest-fee order with ties broken by `tx_id` — byte-deterministic, ready to splat into `BlockInputs.txs[1..]` after the producer prepends the coinbase.

## Architecture

### Where the mempool sits

```
                         ┌─────────────────┐
                         │   mfn-wallet    │
                         │  build_transfer │
                         └────────┬────────┘
                                  │ TransactionWire
                                  ▼
                        ┌──────────────────┐
                        │ mfn-node::Mempool│  (this milestone)
                        │     admit()      │
                        └────────┬─────────┘
                                  │ drain(max) → Vec<TransactionWire>
                                  ▼
                        ┌──────────────────┐
                        │ mfn-node producer│
                        │ produce_solo_blk │
                        └────────┬─────────┘
                                  │ Block
                                  ▼
                        ┌──────────────────┐
                        │   mfn-node::Chain│
                        │      apply()     │
                        └────────┬─────────┘
                                  │ &Block
                                  ▼
                        ┌──────────────────┐
                        │ Mempool          │
                        │ remove_mined()   │
                        └──────────────────┘
```

### Storage

The mempool holds two maps:

```text
by_tx_id      : HashMap<[u8;32], MempoolEntry>      // primary store
by_key_image  : HashMap<[u8;32], [u8;32]>           // ki → tx_id reverse index
```

Each `MempoolEntry` caches the wire-form tx, its `tx_id`, its `fee`, the compressed key-image bytes for each input, and the chain height at admission. The key-image map turns "is this new tx's input also being spent by something else in the pool?" into an O(1) lookup, which is the hot path for both RBF and `remove_mined`.

### `admit(tx, &ChainState)` — the eight-step gate

The admit function replicates every per-tx check `apply_block` runs (modulo storage uploads — see "Deferred" below). It is critical that mempool admission and chain acceptance agree, otherwise admitted txs cause the producer to build blocks the chain rejects.

The eight gates, in order:

1. **Reject coinbases** (`inputs.is_empty()`). Coinbases never go through the mempool — the producer synthesizes them.
2. **Reject storage-anchoring txs** (`outputs[i].storage.is_some()`). The wallet (M2.0.11) doesn't build these and the `apply_block`-level storage gates require cross-tx state we defer to a follow-up milestone.
3. **Local min-fee policy** (`tx.fee < config.min_fee`). Operator-tunable. Consensus enforces no minimum.
4. **`verify_transaction`** — CLSAG signatures, range proofs, balance equation, within-tx key-image uniqueness, version. This is the heaviest check; runs once per admit.
5. **Ring-membership chain guard** — for every input, every `(P, C)` ring member must be present in `state.utxo` *and* its on-chain `commit` must equal the `C` column the spender provided. Identical to the check at `mfn-consensus/src/block.rs:1333-1392`.
6. **Cross-chain double-spend** — every key image must be absent from `state.spent_key_images`.
7. **Mempool RBF** — if any key image already maps to an existing pool entry, the new fee must **strictly exceed** the *maximum* existing-conflicting fee. Conservative-dominating semantics: replacing N entries requires beating all of them.
8. **Size-cap eviction** — if the projected pool size would exceed `max_entries`, find the lowest-fee non-conflicting entry. If the incoming tx pays strictly more, evict the victim; otherwise reject.

Mutations are applied **only after every check passes** — `admit` is all-or-nothing.

### `drain(max)` — highest-fee, byte-deterministic

```text
fn drain(&mut self, max: usize) -> Vec<TransactionWire>
```

Returns up to `max` transactions, removing them from the pool. Ordering:

- Primary: `fee` descending.
- Tie-break: `tx_id` ascending lexicographic.

The tie-break matters because two producers running the same software with the same mempool contents must produce the **same block bytes**. Once consensus picks one of them, deterministic ordering means everyone else can reproduce the block to verify.

### `remove_mined(&Block)` — post-block cleanup

When a block applies to the chain, every key image in the block is now in `state.spent_key_images`. Any mempool entry sharing one of those key images is now invalid — its CLSAG signature is still mathematically valid, but the chain will reject it on the next admission attempt.

`remove_mined` walks `block.txs[*].inputs[*].sig.key_image`, looks each one up in `by_key_image`, and evicts the matching pool entries. Coinbase txs are skipped naturally (empty `inputs`). Returns the count of evictions.

### Error surface

```rust
pub enum AdmitError {
    TxInvalid { tx_id_hex: String, errors: Vec<String> },
    RingMemberNotInUtxoSet  { tx_id_hex: String, input: usize, ring_index: usize },
    RingMemberCommitMismatch { tx_id_hex: String, input: usize, ring_index: usize },
    KeyImageAlreadyOnChain { tx_id_hex: String },
    ReplaceTooLow { existing_fee: u64, proposed_fee: u64 },
    BelowMinFee { min_fee: u64, tx_fee: u64 },
    DuplicateTx { tx_id_hex: String },
    PoolFull { max_entries: usize, lowest_fee: u64, proposed_fee: u64 },
    StorageTxsNotYetSupported,
    NoInputs,
}
```

Every variant carries enough context for an RPC layer to surface a useful 4xx-style error to a wallet client. `tx_id_hex` is the first 8 bytes — short enough for logs, long enough for cross-referencing.

### `AdmitOutcome` — distinguishes success modes

A successful admit returns one of:

- `Fresh { tx_id }` — clean addition.
- `ReplacedByFee { tx_id, displaced }` — one or more existing entries evicted via RBF.
- `EvictedLowest { tx_id, evicted }` — pool was full; lowest-fee entry made room.

P2P relay (future) will want to know whether to forward the new tx as "new" or "replacement" so peers update their pools correctly.

## What this milestone deliberately defers

- **Storage-anchoring txs.** The wallet doesn't build them yet, and the `apply_block`-level storage gates (`UploadUnderfunded`, replication bounds, cross-tx dedup against `state.storage`) require cross-tx state. Surfaced as a typed `AdmitError::StorageTxsNotYetSupported` so the deferment is visible.
- **Time-based eviction.** Entries live forever until they conflict, are mined, or are explicitly evicted. Age-based eviction is a one-liner addition when the pool sees real traffic.
- **Persistent storage.** A node restart loses the pool. Matches Bitcoin/Monero behaviour at this layer — finality lives on the chain.
- **P2P relay.** No network code; the mempool is per-node. The relay layer is a separate M2.x milestone that uses `Mempool::admit` as its gate.
- **Configurable RBF policy.** Currently "strictly higher fee wins". A future milestone may add fee-rate-based comparison (fee per byte) and minimum-bump policies.

## Test matrix

**Unit tests (`mfn-node/src/mempool.rs` — 15 tests):**

| Test                                                | Asserts                                                                |
|-----------------------------------------------------|------------------------------------------------------------------------|
| `admit_happy_path_fresh`                            | Plain admission of a signed wallet tx → `AdmitOutcome::Fresh`.         |
| `admit_rejects_coinbase_shaped_tx`                  | `inputs.is_empty()` → `AdmitError::NoInputs`.                          |
| `admit_rejects_storage_anchoring_tx`                | `outputs[i].storage.is_some()` → `StorageTxsNotYetSupported`.          |
| `admit_rejects_below_min_fee`                       | `tx.fee < config.min_fee` → `BelowMinFee`.                             |
| `admit_rejects_unbalanced_tx`                       | Post-hoc-mutated tx fails `verify_transaction` → `TxInvalid`.          |
| `admit_rejects_ring_member_not_in_utxo_set`         | Tx whose ring members aren't in chain UTXO set → `RingMemberNotInUtxoSet`. |
| `rbf_accepts_strictly_higher_fee`                   | Conflicting key images + higher fee → `ReplacedByFee`.                 |
| `rbf_rejects_equal_or_lower_fee`                    | Equal fee → `ReplaceTooLow`.                                           |
| `duplicate_tx_id_is_rejected`                       | Re-admit same tx → `DuplicateTx`.                                      |
| `size_cap_evicts_lowest_fee_when_pool_full`         | `max_entries=1` + higher-fee admission → `EvictedLowest`.              |
| `drain_orders_by_fee_descending_then_tx_id`         | Three txs with fees 100/500/300 drain in 500/300/100 order.            |
| `remove_mined_evicts_txs_with_block_key_images`     | Block containing pool tx → 1 eviction.                                 |
| `remove_mined_is_idempotent_when_unrelated`         | Block with unrelated key images → 0 evictions.                         |
| `evict_by_id_returns_true_when_present`             | Explicit `evict(&id)` returns correct boolean.                         |
| `drained_tx_can_be_applied_to_chain`                | Sanity: drained bytes match the signed bytes (no mutation in transit). |

**Integration tests (`mfn-node/tests/mempool_integration.rs` — 3 tests):**

| Test                                                       | Path exercised                                                                                                         |
|------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `wallet_to_mempool_to_producer_to_chain_round_trip`        | wallet → `Mempool::admit` → `drain` → `produce_solo_block` → `Chain::apply` → `LightChain::apply_block` → wallet ingest. Bob receives `transfer_value`, Alice's balance accounts for the change + producer fee. |
| `mempool_evicts_tx_after_block_includes_it_via_remove_mined` | Producer builds without draining; chain applies; `remove_mined` evicts the now-mined tx.                              |
| `mempool_admit_after_chain_advanced_still_works`           | Tx signed at height 1, chain advanced to height 2 without including it, mempool admits at height 2 (ring members still valid, key images still unspent). |

## What this unlocks

- **A complete tx submission path.** Wallets can now submit txs to a node, the node admits them, and the producer includes them — without any test-only scaffolding.
- **Single-node demo.** The producer loop can `loop { sleep(slot_dur); drain; produce; apply; remove_mined; }` and serve a single user with a real wallet.
- **The foundation for P2P relay.** When P2P lands, it will use `Mempool::admit` as its gate — a peer's tx is accepted if and only if our mempool would accept it locally. No duplicate validation logic.
- **The foundation for RPC.** `submit_tx` becomes a thin wrapper around `Mempool::admit`. The typed `AdmitError` variants map cleanly to HTTP status codes.

## Risks and notes

- **`utxo` is never pruned on spend** in the current consensus implementation. This means `RingMemberNotInUtxoSet` does not fire for "someone else spent this decoy member already" — it only fires for fabricated members. Don't over-index on UTXO eviction for invalidation; key-image conflicts are the dominant invalidation source.
- **Storage txs as a typed deferment** — surfacing the deferment as `StorageTxsNotYetSupported` (rather than silently accepting and letting the chain reject) means callers see the boundary clearly. The follow-up milestone (M2.0.13 candidate) will replicate the storage-fee economics here.
- **Producer trusts the caller verbatim** — `BlockInputs.txs` is passed straight into `build_unsealed_header`. This means a buggy mempool can break consensus. The integration test `wallet_to_mempool_to_producer_to_chain_round_trip` exists to catch any drift between mempool acceptance and chain acceptance.

## What ships in this commit

- `mfn-node/src/mempool.rs` (~700 lines, 15 unit tests).
- `mfn-node/tests/mempool_integration.rs` (3 integration tests).
- `mfn-node/src/lib.rs` — wires the module into the public API.
- `mfn-node/Cargo.toml` — adds `curve25519-dalek`, `mfn-light`, `mfn-wallet` as dev-dependencies (cycle through dev-deps only is fine).
- `docs/M2_MEMPOOL.md` — this document.
- `docs/ROADMAP.md` — milestone status.
- `docs/ARCHITECTURE.md` — crate layout update.
- `README.md` — test count + crate listing.
- `CODEBASE_STATS.md` — regenerated.
