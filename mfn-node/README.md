# `mfn-node`

Node-side glue around [`mfn-consensus`](../mfn-consensus/README.md). The future home of the mempool, P2P stack, persistent storage, RPC server, and producer / voter loops — the things that turn a state-transition function into a **running chain**.

**Tests:** 17 passing (11 unit + 6 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.3 `Chain` driver + M2.0.4 producer helpers + M2.0.5 light-header agreement landed)

This is the **smallest useful "running chain in a process"** artifact: a `Chain` struct owning a `ChainState`, exposing ergonomic read-only queries (`tip_id`, `tip_height`, `validators`, `treasury`, `stats`), and applying blocks sequentially through [`mfn_consensus::apply_block`]. Plus a `producer` module that wraps the consensus-layer building blocks (`build_unsealed_header` / `try_produce_slot` / `cast_vote` / `finalize` / `seal_block`) into a clean three-stage protocol with a one-call `produce_solo_block` convenience for the single-validator case. Everything in this crate is **deterministic and synchronous** — no IO, no clock, no async runtime, no background threads. Those concerns belong in later M2.x sub-milestones (mempool, RPC, P2P, store) which will all attach *around* these primitives.

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
| [`producer`](src/producer.rs) | Block-production helpers. Three-stage protocol (`build_proposal` → `vote_on_proposal` → `seal_proposal`) plus one-call `produce_solo_block` for the single-validator case. The shape that future P2P / RPC / mempool integration will consume. |

Planned in future M2.x sub-milestones (deliberately *not* in this crate yet):

| Module | Purpose | Milestone |
|---|---|---|
| `mempool` | Pending-tx admission, fee ordering, replace-by-fee, eviction. | M2.1 |
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

### Producing blocks

```rust
use mfn_node::{produce_solo_block, BlockInputs};

// Solo case (producer = sole voter): one call.
let inputs = BlockInputs {
    height,
    slot: height,
    timestamp,
    txs,
    bond_ops: Vec::new(),
    slashings: Vec::new(),
    storage_proofs: Vec::new(),
};
let block = produce_solo_block(&chain, &producer, &secrets, params, inputs)?;
chain.apply(&block)?;

// Multi-validator case: explicit three-stage protocol.
use mfn_node::{build_proposal, vote_on_proposal, seal_proposal};

let proposal = build_proposal(chain.state(), &producer, &producer_secrets, params, inputs)?;
// Each committee member (over the P2P wire, in production):
let vote_a = vote_on_proposal(&proposal, chain.state(), &v_a, &s_a, &producer, params)?;
let vote_b = vote_on_proposal(&proposal, chain.state(), &v_b, &s_b, &producer, params)?;
// Producer aggregates + seals once quorum is reached:
let block = seal_proposal(proposal, &[vote_a, vote_b], 2, total_signing_stake)?;
chain.apply(&block)?;
```

Note that callers are responsible for building the coinbase tx (if the producer has a `ValidatorPayout`) and placing it as `txs[0]`. The producer helper does **not** synthesize the coinbase; that's a higher-level concern that depends on which payout policy the node is configured with.

---

## Design — why a separate crate from `mfn-consensus`?

`mfn-consensus` is the **specification**: the state-transition function and every byte format that goes on the wire. It must remain library-pure (no IO, no async, no clock) so it can be ported to a light-client crate, a wasm binding, and any number of independent implementations without dragging in a runtime.

`mfn-node` is the **first orchestration layer**. It tracks the live chain tip, owns `ChainState`, and is where mempool / P2P / RPC will eventually attach. Even at the skeleton stage that separation matters:

- A future light-client crate (`mfn-light`) wants [`mfn_consensus::verify_header`] (M2.0.5) but **not** a `Chain` driver — same spec crate, different consumer.
- A daemon wants a `Chain` driver but **shouldn't** be reimplementing one against the spec.
- A wasm binding wants a `Chain` driver, but compiled for the browser — keeping it library-pure (no `tokio`, no `rocksdb`) keeps the wasm story clean.

This crate is the load-bearing centre of the future M2.x milestones; getting its shape right is more valuable than rushing into mempool / P2P implementation details.

---

## Test categories

- **Unit (`chain::tests`)**: `Chain::from_genesis` lands at height 0; tip_id equals genesis_id at construction; back-to-back empty-block application advances height + tip_id; bad-prev-hash blocks rejected with state unchanged; bad-height blocks rejected with state unchanged; `ChainStats` agrees with individual accessors; genesis is deterministic across constructions.
- **Unit (`producer::tests`)**: `produce_solo_block` yields an `apply_block`-acceptable block; 5-in-a-row solo production drives the chain forward each time; `build_proposal` refuses ineligible (stake-zero) producers with a typed error; the staged API (`build_proposal` → `vote_on_proposal` → `seal_proposal`) produces an identical block-id to `produce_solo_block` for a solo validator (determinism contract).
- **Integration (`tests/single_validator_flow.rs`)**: a 1-validator chain runs through 3 real BLS-signed blocks via the driver + producer helpers; `ChainStats` agrees with individual accessors after the run; replaying the same block is rejected with state preserved (driver never partially commits even pathological input).
- **Integration (`tests/light_header_verify.rs`, M2.0.5)**: for every block of a real 3-block chain, [`mfn_consensus::verify_header`] accepts the header iff `apply_block` does (load-bearing light-client agreement invariant); a stable validator set verifies under both pre- and post-block trusted snapshots; tampered `validator_root` / `producer_proof` / `height` are rejected by both verification layers and the clean block still applies cleanly afterwards.

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
