# `mfn-node`

Node-side glue around [`mfn-consensus`](../mfn-consensus/README.md). The future home of the mempool, P2P stack, persistent storage, RPC server, and producer / voter loops — the things that turn a state-transition function into a **running chain**.

**Tests:** 10 passing (7 unit + 3 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.3 — `Chain` driver landed)

This is the **smallest useful "running chain in a process"** artifact: a `Chain` struct owning a `ChainState`, exposing ergonomic read-only queries (`tip_id`, `tip_height`, `validators`, `treasury`, `stats`), and applying blocks sequentially through [`mfn_consensus::apply_block`]. Everything in this crate is **deterministic and synchronous** — no IO, no clock, no async runtime, no background threads. Those concerns belong in later M2.x sub-milestones (mempool, RPC, P2P, store, producer loop) which will all attach *around* this driver.

The integration test [`tests/single_validator_flow.rs`](tests/single_validator_flow.rs) demonstrates the full end-to-end loop:

1. Build a single validator with ed25519 + VRF + BLS keys.
2. `Chain::from_genesis(...)` — drives `build_genesis` + `apply_genesis` and lands at height 0.
3. For three blocks: producer-proof + BLS finality-vote + `seal_block` → `chain.apply(&block)`.
4. Assert tip_height / tip_id move each block, the validator set is unchanged, and the treasury stays at zero (no fees, no slashings).

That's the same path a real validator daemon will run in a loop, just without the network / disk / clock infrastructure.

---

## Modules

| Module | Responsibility |
|---|---|
| [`chain`](src/chain.rs) | `Chain` driver, `ChainConfig`, `ChainError`, `ChainStats`. The full public surface today. |

Planned in future M2.x sub-milestones (deliberately *not* in this crate yet):

| Module | Purpose | Milestone |
|---|---|---|
| `mempool` | Pending-tx admission, fee ordering, replace-by-fee, eviction. | M2.1 |
| `producer` | Block-production loop: collect mempool txs, build candidate header, vote, seal. | M2.1 |
| `network` | libp2p / direct-TCP P2P gossip. Block + tx propagation. | M2.2 |
| `store` | RocksDB-backed persistent chain state. Snapshot/replay/restore. | M2.2 |
| `rpc` | JSON-RPC + WebSocket. Block, tx, balance, storage-status queries. | M2.2 |
| `bin/mfnd` | The daemon entrypoint. | M2.1+ |

---

## Public API (today)

```rust
use mfn_node::{Chain, ChainConfig, ChainError, ChainStats};

// Construct a chain at genesis.
let mut chain = Chain::from_genesis(ChainConfig::new(genesis_cfg))?;
assert_eq!(chain.tip_height(), Some(0));

// Apply a candidate block. On success: chain advances; on failure:
// state is unchanged (apply_block is pure — we never partially commit).
let new_tip_id: [u8; 32] = chain.apply(&block)?;

// Read-only queries.
let h: Option<u32>       = chain.tip_height();
let tip: Option<&[u8;32]> = chain.tip_id();
let validators           = chain.validators();
let total_stake: u64     = chain.total_stake();
let treasury: u128       = chain.treasury();
let state                = chain.state();   // full read-only ChainState view

// Cheap snapshot for diagnostics / RPC / tests.
let snap: ChainStats = chain.stats();
```

The driver intentionally does **not** hand out `&mut ChainState`. Callers can't sidestep `apply_block` and mutate the chain.

---

## Design — why a separate crate from `mfn-consensus`?

`mfn-consensus` is the **specification**: the state-transition function and every byte format that goes on the wire. It must remain library-pure (no IO, no async, no clock) so it can be ported to a light-client crate, a wasm binding, and any number of independent implementations without dragging in a runtime.

`mfn-node` is the **first orchestration layer**. It tracks the live chain tip, owns `ChainState`, and is where mempool / P2P / RPC will eventually attach. Even at the skeleton stage that separation matters:

- A future light-client crate (`mfn-light`) wants `apply_block` but **not** a `Chain` driver.
- A daemon wants a `Chain` driver but **shouldn't** be reimplementing one against the spec.
- A wasm binding wants a `Chain` driver, but compiled for the browser — keeping it library-pure (no `tokio`, no `rocksdb`) keeps the wasm story clean.

This crate is the load-bearing centre of the future M2.x milestones; getting its shape right is more valuable than rushing into mempool / P2P implementation details.

---

## Test categories

- **Unit (`chain::tests`)**: `Chain::from_genesis` lands at height 0; tip_id equals genesis_id at construction; back-to-back empty-block application advances height + tip_id; bad-prev-hash blocks rejected with state unchanged; bad-height blocks rejected with state unchanged; `ChainStats` agrees with individual accessors; genesis is deterministic across constructions.
- **Integration (`tests/single_validator_flow.rs`)**: a 1-validator chain runs through 3 real BLS-signed blocks via the driver; `ChainStats` agrees with individual accessors after the run; replaying the same block is rejected with state preserved (driver never partially commits even pathological input).

```bash
cargo test -p mfn-node
```

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- No background threads, no clocks, no IO — every public method is synchronous, deterministic, and re-entrant-safe.
- `Chain` does not implement `Sync` (its `ChainState` uses `HashMap`s). Wrap in a `Mutex` if shared across threads is needed — but the intended pattern is single-owner: the producer / RPC handlers (future) will channel requests *to* the chain rather than locking it.

---

## Dependencies

```
mfn-crypto    = path     # cryptographic primitives, codec, Merkle, accumulator
mfn-bls       = path     # BLS12-381 signatures + committee aggregation
mfn-storage   = path     # SPoRA + endowment math
mfn-consensus = path     # state-transition function, block headers, ChainState
thiserror     = "1.0"
```

No async runtime, no networking crate, no on-disk store — yet. Those land in M2.1+ with full architectural intent.

---

## See also

- [`docs/ROADMAP.md § Milestone M2.x`](../docs/ROADMAP.md) — the phased path from this crate to a public testnet.
- [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — the system view (state machine, `apply_block` phases, header structure).
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate orchestrates.
