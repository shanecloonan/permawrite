# `mfn-node`

Node-side glue around [`mfn-consensus`](../mfn-consensus/README.md). The future home of the mempool, P2P stack, persistent storage, RPC server, and producer / voter loops — the things that turn a state-transition function into a **running chain**.

**Tests:** 160 passing (120 unit + 40 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.3 `Chain` driver + M2.0.4 producer + M2.0.5 light-header tests + M2.0.12 `Mempool` + M2.0.13 storage admission + M2.0.15 checkpoint adapter + M2.1.0 `ChainStore` + **M2.1.1 `mfnd` binary** + **M2.1.2 JSON `--genesis` spec** + **M2.1.3 `mfnd step`** + **M2.1.4 mempool-aware step + `--blocks N`** + **M2.1.5 `--checkpoint-each`** + **M2.1.6 `mfnd serve` (TCP `get_tip` / `submit_tx`)** + **M2.1.6.1 serve `submit_tx` subprocess tests** + **M2.1.7 `chain.blocks` + genesis `synthetic_decoy_utxos` + signed `submit_tx` over `serve`** + **M2.1.8 JSON-RPC 2.0 on `serve`** + **M2.1.8.1 `submit_tx` array `params`** + **M2.1.9 `read_block_log_validated`** + **M2.1.10 `serve` `get_block`** + **M2.1.11 `serve` `get_block_header`** + **M2.1.12 `serve` `get_mempool`** + **M2.1.13 `serve` `get_mempool_tx`** + **M2.1.14 `serve` `remove_mempool_tx`** + **M2.1.15 `serve` `clear_mempool`** + **M2.1.16 `serve` `get_checkpoint`** + **M2.1.17 `serve` `save_checkpoint`** + **M2.1.18 `serve` `list_methods`**; M2.0.6 / M2.0.7 consumed by `mfn-light`)

This is the **smallest useful "running chain in a process"** artifact: a `Chain` struct owning a `ChainState`, exposing ergonomic read-only queries (`tip_id`, `tip_height`, `validators`, `treasury`, `stats`), and applying blocks sequentially through [`mfn_consensus::apply_block`]. Plus a `producer` module that wraps the consensus-layer building blocks (`build_unsealed_header` / `try_produce_slot` / `cast_vote` / `finalize` / `seal_block`) into a clean three-stage protocol with a one-call `produce_solo_block` convenience for the single-validator case, a `Mempool` that feeds the producer, and a `ChainStore` that persists checkpoint bytes to disk. The **`mfnd`** binary (`cargo run -p mfn-node --bin mfnd`) wires `load_or_genesis` / `save` to the shell (`status`, `save`, `run`, **`step`**, **`serve`**) and accepts **`--genesis path.json`** for a versioned chain spec (see [`testdata/devnet_one_validator.json`](testdata/devnet_one_validator.json)). **`step`** runs solo block production: an in-memory [`Mempool`] is **`drain`ed** (highest-fee-first, up to 256 txs), a coinbase is built with `emission + producer_fee_share` of drained txs (matching `apply_block` fee split), then `produce_solo_block` → `Chain::apply` → `Mempool::remove_mined` → **`ChainStore::append_block`** (M2.1.7 `chain.blocks`) → **`ChainStore::save`**. **`--blocks N`** applies N sequential blocks per run (by default one checkpoint after the last block). **`--checkpoint-each`** persists after **every** applied block and prints `step_checkpoint …` lines for observability. **`serve`** keeps chain + mempool in one long-lived process: it listens on **`--rpc-listen`** (default `127.0.0.1:18731`), prints `mfnd_serve_listening=…` on stdout, and answers **one JSON line per TCP connection** (`get_tip`, `submit_tx`, **`get_block`**, **`get_block_header`**, **`get_mempool`**, **`get_mempool_tx`**, **`remove_mempool_tx`**, **`clear_mempool`**, **`get_checkpoint`**, **`save_checkpoint`**, **`list_methods`**) using a **JSON-RPC 2.0** response envelope (**M2.1.8**): `jsonrpc`, `id`, `result` or structured `error` (`code` / `message`); **`submit_tx`** accepts **`params`** as `{"tx_hex":"…"}` or a one-element array `["…"]` (**M2.1.8.1**); **`get_block`** (**M2.1.10**) accepts `{"height":N}` or `[N]` and returns `block_hex` from **`read_block_log_validated`** for heights `1..=tip_height`; **`get_block_header`** (**M2.1.11**) returns the same heights with `header_hex` ([`mfn_consensus::block_header_bytes`]) and `block_id`; **`get_mempool`** (**M2.1.12**) returns `mempool_len` and sorted lowercase-hex **`tx_ids`** with `params` omitted, `null`, `{}`, or `[]` only; **`get_mempool_tx`** (**M2.1.13**) returns `tx_id` + **`tx_hex`** for one pending entry when `params` are `{"tx_id":"…"}` or `["…"]` (64 hex digits, optional `0x`); **`remove_mempool_tx`** (**M2.1.14**) evicts by **`tx_id`** if present, returning **`removed`** and **`pool_len`**; **`clear_mempool`** (**M2.1.15**) clears every pending tx via **`Mempool::clear`**, returning **`cleared_count`** and **`pool_len`** (same empty-only **`params`** rule as **`get_mempool`**); **`get_checkpoint`** (**M2.1.16**) returns [`Chain::encode_checkpoint`](src/chain.rs) bytes as **`checkpoint_hex`** plus **`byte_len`** (same empty-only **`params`**); **`save_checkpoint`** (**M2.1.17**) calls **`ChainStore::save`** (same rotation as **`mfnd save`**), returning **`bytes_written`**, **`checkpoint_path`**, **`backup_path`** (IO errors: **`-32004`**); **`list_methods`** (**M2.1.18**) returns **`methods`**: every implemented method name as a JSON string, sorted lexicographically (includes **`list_methods`**; same empty-only **`params`** as **`get_mempool`**); batching, HTTP, and WebSocket remain for the future `rpc` module. On Unix, `run` saves on Ctrl+C via the `ctrlc` crate; on Windows it waits for Enter so `windows-gnu` toolchains without MSVC link helpers are not pulled in through `windows-sys`. Everything remains **synchronous and deterministic at the consensus boundary** except the intentional IO in `store`, optional genesis file reads, blocking TCP in `serve`, and `mfnd`; clock / full RPC / P2P stay in later M2.x milestones.

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
| [`chain`](src/chain.rs) | `Chain` driver, `ChainConfig`, `ChainError`, `ChainStats`. **M2.0.15** added `Chain::checkpoint()`, `Chain::encode_checkpoint()`, `Chain::from_checkpoint(cfg, ck)`, and `Chain::from_checkpoint_bytes(cfg, &[u8])` — the in-process adapter over [`mfn_consensus::chain_checkpoint`]'s deterministic byte codec. Restoration re-derives the local genesis_id from `ChainConfig` and rejects any mismatch with `ChainError::GenesisMismatch { expected, got }`; bad bytes surface as `ChainError::CheckpointDecode(ChainCheckpointError)`. |
| [`producer`](src/producer.rs) | Block-production helpers. Three-stage protocol (`build_proposal` → `vote_on_proposal` → `seal_proposal`) plus one-call `produce_solo_block` for the single-validator case. The shape that future P2P / RPC / mempool integration will consume. |
| [`mempool`](src/mempool.rs) | **M2.0.12 + M2.0.13** in-memory transaction pool. `Mempool::admit` runs every per-tx gate `apply_block` runs — both **privacy** (`verify_transaction` + ring-membership + commit match + key-image dedup against chain + pool) and **permanence** (M2.0.13: replication bounds, `required_endowment` math, treasury-share-vs-burden, with already-anchored and within-tx-duplicate data roots silently skipped — mirrors `apply_block` byte-for-byte). Replace-by-fee, lowest-fee eviction at the size cap, highest-fee-first `drain(max)` with `tx_id` tie-break for byte-deterministic block bodies. `remove_mined(&Block)` evicts mined entries after a block applies. |
| [`store`](src/store.rs) | **M2.1.0 + M2.1.1 + M2.1.7 + M2.1.9** filesystem checkpoint store + append-only `chain.blocks`. `ChainStore::load(cfg)` restores a saved chain if `chain.checkpoint` exists; `load_or_genesis(cfg)` boots from checkpoint or genesis; `save(&chain)` writes checkpoint bytes through `chain.checkpoint.tmp`, rotates the old primary to `chain.checkpoint.bak`, and publishes the new primary. `append_block` / `read_block_log` manage canonical `encode_block` records (M2.1.7); **`read_block_log_validated`** checks count + linkage vs the loaded [`Chain`] (M2.1.9). `has_any_checkpoint()` reports whether primary or backup exists (staging `.tmp` ignored). `clear()` removes checkpoint + block-log files. |
| [`demo_genesis`](src/demo_genesis.rs) | **M2.1.1** built-in empty-validator dev genesis when `mfnd` runs without `--genesis`. |
| [`genesis_spec`](src/genesis_spec.rs) | **M2.1.2 + M2.1.7** JSON chain spec → [`mfn_consensus::GenesisConfig`]. Version `1` only; optional `consensus` overrides; optional **`synthetic_decoy_utxos`** (capped) for local ring decoys; validators from 32-byte VRF/BLS seeds (hex); payout keys from `payout_seed_hex` or derived from BLS seed via [`mfn_crypto::stealth_wallet_from_seed`]; `omit_payout` burns coinbase. |
| [`mfnd_serve`](src/mfnd_serve.rs) | **M2.1.6 + M2.1.8 + M2.1.8.1 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18** blocking TCP control plane: `run_serve` accepts one UTF-8 line per connection, returns one **JSON-RPC 2.0** line, closes. Methods `get_tip`, `submit_tx` (hex `encode_transaction` bytes), **`get_block`** (full `encode_block` hex), **`get_block_header`** (`block_header_bytes` + `block_id`), **`get_mempool`** (`mempool_len` + sorted `tx_ids`), **`get_mempool_tx`** (lookup by `tx_id`), **`remove_mempool_tx`** (`Mempool::evict` by `tx_id`), **`clear_mempool`** (`Mempool::clear`), **`get_checkpoint`** (`Chain::encode_checkpoint` hex), **`save_checkpoint`** (`ChainStore::save`), **`list_methods`** (sorted JSON string names); **`submit_tx`** `params` may be `{"tx_hex":"…"}` or `["…"]`. |
| [`bin/mfnd`](src/bin/mfnd.rs) | **M2.1.1** process entrypoint calling [`mfn_node::mfnd_main`]; CLI in [`mfnd_cli`](src/mfnd_cli.rs). **M2.1.3** `step`; **M2.1.4** mempool drain + fee coinbase + `--blocks N`; **M2.1.5** `--checkpoint-each`; **M2.1.6** `serve` + `--rpc-listen`; **M2.1.7** `chain.blocks` on `step`; **M2.1.8** JSON-RPC responses on `serve`; **M2.1.8.1** array `params` for `submit_tx`; **M2.1.10** `get_block` on `serve`; **M2.1.11** `get_block_header` on `serve`; **M2.1.12** `get_mempool` on `serve`; **M2.1.13** `get_mempool_tx` on `serve`; **M2.1.14** `remove_mempool_tx` on `serve`; **M2.1.15** `clear_mempool` on `serve`; **M2.1.16** `get_checkpoint` on `serve`; **M2.1.17** `save_checkpoint` on `serve`; **M2.1.18** `list_methods` on `serve`. |

Planned in future M2.x sub-milestones (deliberately *not* in this crate yet):

| Module | Purpose | Milestone |
|---|---|---|
| `network` | libp2p / direct-TCP P2P gossip. Block + tx propagation. | M2.2 |
| `store` extensions | Fork-choice replay + indexing, RocksDB/sled column families, pruning/retention, crash-fuzzing. M2.1.0 checkpoint + **M2.1.7** append-only `chain.blocks` are live. | M2.1+ |
| `rpc` | JSON-RPC + WebSocket. Block, tx, balance, storage-status queries. | M2.2 |

---

## Public API (today)

```rust
use mfn_node::{Chain, ChainConfig, ChainError, ChainStats, ChainStore};

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

// Persist / restore the latest checkpoint bytes.
let store = ChainStore::new("./data");
store.save(&chain)?;
let restored = store.load_or_genesis(ChainConfig::new(genesis_cfg))?;
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

- The light-client crate ([`mfn-light`](../mfn-light/README.md)) wants [`mfn_consensus::verify_header`] (M2.0.5) and [`mfn_consensus::verify_block_body`] (M2.0.7) but **not** a `Chain` driver — same spec crate, different consumer.
- A daemon wants a `Chain` driver but **shouldn't** be reimplementing one against the spec.
- A wasm binding wants a `Chain` driver, but compiled for the browser — keeping it library-pure (no `tokio`, no `rocksdb`) keeps the wasm story clean.

This crate is the load-bearing centre of the future M2.x milestones; getting its shape right is more valuable than rushing into mempool / P2P implementation details.

---

## Test categories

- **Unit (`chain::tests`)**: `Chain::from_genesis` lands at height 0; tip_id equals genesis_id at construction; back-to-back empty-block application advances height + tip_id; bad-prev-hash blocks rejected with state unchanged; bad-height blocks rejected with state unchanged; `ChainStats` agrees with individual accessors; genesis is deterministic across constructions.
- **Unit (`producer::tests`)**: `produce_solo_block` yields an `apply_block`-acceptable block; 5-in-a-row solo production drives the chain forward each time; `build_proposal` refuses ineligible (stake-zero) producers with a typed error; the staged API (`build_proposal` → `vote_on_proposal` → `seal_proposal`) produces an identical block-id to `produce_solo_block` for a solo validator (determinism contract).
- **Unit (`mempool::tests`, M2.0.12 + M2.0.13)**: 22 tests — happy-path admission, coinbase / unbalanced / below-min-fee / ring-not-in-utxo-set rejection, replace-by-fee accept-higher-reject-equal, duplicate tx, size-cap lowest-fee eviction, fee-priority drain with tx_id tie-break, `remove_mined` eviction + idempotency, manual `evict`, drained-bytes-equal-signed-bytes round-trip, **storage-anchoring** happy path, replication-too-low / too-high, underfunded, already-anchored silent skip, within-tx-duplicate silent skip, mixed-output (storage + plain), burden-scales-with-size.
- **Unit (`store::tests`, M2.1.0 + M2.1.7 + M2.1.9)**: 10 tests — missing snapshot returns `None` and `load_or_genesis` boots height 0; save/load round-trips byte-identical checkpoint state; foreign genesis config returns `ChainError::GenesisMismatch` through `StoreError::Chain`; backup checkpoint recovers when primary is missing after an interrupted rotation; stale temp files are removed and `clear()` deletes primary / backup / temp / **`chain.blocks`**; **`read_block_log`** empty when missing; **`read_block_log_validated`** at genesis with empty log; **`read_block_log_validated`** rejects log length vs `tip_height` mismatch.
- **Unit (`mfnd_serve::tests`, M2.1.8 + M2.1.8.1 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18)**: 57 tests — JSON-RPC envelope, `submit_tx` object + array `params`, empty array, bad `params[0]`, non-object/array `params`, missing `params`, **`get_block`** / **`get_block_header`** height / params / validated-read error path, header vs full-block agreement, **`get_mempool`** / **`clear_mempool`** / **`get_checkpoint`** / **`save_checkpoint`** / **`list_methods`** (omit / `{}` / `[]` / reject non-empty `params`), **`get_mempool_tx`** / **`remove_mempool_tx`** (params / hex / not-found or absent / type guards), **`get_checkpoint`** wire vs `Chain::encode_checkpoint`, **`save_checkpoint`** writes `chain.checkpoint`, **`list_methods`** sorted dispatch set, and related guards.
- **Unit (`mfnd_cli::tests`, M2.1.1–M2.1.8.1)**: 11 tests — `status` / `step` / `serve` argument shapes, `--genesis`, `--blocks`, `--checkpoint-each`, **`--rpc-listen`** (including rejection unless `serve`), missing `--data-dir`, and step without env seeds.
- **Integration (`tests/mfnd_smoke.rs`, M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.6.1 + M2.1.7 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18)**: spawns the real `mfnd` binary — `status` / `save` / `--genesis` boot, missing `--data-dir` error path, **`step`** twice on `devnet_one_validator.json` with env seeds (tip reaches height 2 + checkpoint on disk), **`step`** without env fails, **`step`** on empty-validator demo genesis fails, **`step --blocks 3`** reaches height 3 in one invocation, **`step --blocks 2 --checkpoint-each`** emits two `step_checkpoint` lines, **`mfnd_step_block_log_passes_validated_read`** (`read_block_log_validated` after one `step`), **`serve --rpc-listen 127.0.0.1:0`** + TCP `get_tip` (`mfnd_serve_get_tip_over_tcp`) + **`mfnd_serve_get_tip_jsonrpc_echoes_id`** + **`mfnd_serve_get_mempool_over_tcp_empty`** + **`mfnd_serve_get_mempool_lists_tx_after_submit`** (non-empty pool, **`get_mempool_tx`** round-trip, **`remove_mempool_tx`**, empty **`get_mempool`**) + **`mfnd_serve_clear_mempool_after_submit`** + **`mfnd_serve_get_checkpoint_round_trips_over_tcp_after_step`** + **`mfnd_serve_save_checkpoint_creates_checkpoint_file`** + **`mfnd_serve_list_methods_over_tcp`**, **`mfnd_serve_get_block_over_tcp_after_step`** (also **`get_block_header`** vs `read_block_log_validated`), **`serve`** `submit_tx` negative paths (`mfnd_serve_submit_tx_rejects_*`, **`mfnd_serve_submit_tx_array_params_rejects_bad_hex`**), **`mfnd_step_writes_block_log_then_serve_submit_tx_admits_transfer`** (synth-decoy genesis + `chain.blocks` + signed transfer admitted as `Fresh`).
- **Integration (`tests/single_validator_flow.rs`)**: a 1-validator chain runs through 3 real BLS-signed blocks via the driver + producer helpers; `ChainStats` agrees with individual accessors after the run; replaying the same block is rejected with state preserved (driver never partially commits even pathological input).
- **Integration (`tests/light_header_verify.rs`, M2.0.5)**: for every block of a real 3-block chain, [`mfn_consensus::verify_header`] accepts the header iff `apply_block` does (load-bearing light-client agreement invariant); a stable validator set verifies under both pre- and post-block trusted snapshots; tampered `validator_root` / `producer_proof` / `height` are rejected by both verification layers and the clean block still applies cleanly afterwards.
- **Integration (`tests/mempool_integration.rs`, M2.0.12 + M2.0.13)**: 6 tests proving the full wallet → mempool → producer → chain loop. **M2.0.12**: `wallet_to_mempool_to_producer_to_chain_round_trip` drives 4 blocks (3 coinbase + 1 transfer) with both `Chain` and `LightChain` in lockstep; `mempool_evicts_tx_after_block_includes_it_via_remove_mined` covers the cleanup path when the producer didn't drain; `mempool_admit_after_chain_advanced_still_works` checks that a tx remains admissible after the chain advances without including it. **M2.0.13**: `storage_tx_through_full_mempool_producer_chain_pipeline` admits a hand-built storage-anchoring tx, drains, builds + applies the block, asserts `state.storage[hash]` is populated, then re-admits and gets `KeyImageAlreadyOnChain`; `storage_tx_underfunded_is_rejected_by_mempool_before_producer` proves the mempool catches `UploadUnderfunded` so the producer never builds a chain-rejecting block; `already_anchored_storage_tx_silently_skips_burden_in_mempool` proves pre-anchored data roots are inert (a fresh tx at `fee=1` admits because the burden is zero).

```bash
cargo test -p mfn-node
```

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- No background threads in the library, no clocks, no async runtime. **`mfnd serve`** uses a blocking **`std::net::TcpListener`** accept loop on the main thread (one client at a time); P2P / libp2p / `tokio` remain future milestones.
- Filesystem IO is isolated in `store`; consensus state mutation still flows only through `Chain::apply`.
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

No async runtime. **`serve`** uses stdlib TCP only (no `tokio`, no libp2p). The M2.1.0 on-disk store is a narrow stdlib filesystem adapter over checkpoint bytes; richer RocksDB/sled storage lands later with full architectural intent.

Dev-dependencies (tests only): `curve25519-dalek`, `hex`, `mfn-light`, `mfn-wallet`. The mfn-light / mfn-wallet edges are dev-only (Cargo allows dev-dep cycles), enabling end-to-end mempool integration tests against real wallets and a light client.

---

## See also

- [`docs/ROADMAP.md § Milestone M2.x`](../docs/ROADMAP.md) — the phased path from this crate to a public testnet.
- [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — the system view (state machine, `apply_block` phases, header structure).
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate orchestrates.
