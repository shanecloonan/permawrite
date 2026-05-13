//! # `mfn-node`
//!
//! Node-side glue around [`mfn_consensus`]. This crate is the future home
//! of the mempool, P2P stack, persistent storage, RPC server, and producer
//! / voter loops — the things that turn a state-transition function into
//! a **running chain**.
//!
//! ## What this crate provides today (M2.0.3 + M2.0.4 + M2.0.12 + M2.1.0)
//!
//! - [`Chain`] — an in-memory chain driver that owns a [`ChainState`],
//!   exposes ergonomic queries (`tip_id`, `tip_height`, `validators`,
//!   `treasury`, …), and applies blocks sequentially through
//!   [`mfn_consensus::apply_block`].
//! - [`ChainError`] — typed wrapper around [`mfn_consensus::BlockError`]
//!   plus higher-level "chain hasn't reached genesis yet" guards.
//! - [`producer`] — block-production helpers. Wraps the consensus
//!   layer's `build_unsealed_header` / `try_produce_slot` /
//!   `cast_vote` / `finalize` / `seal_block` into a three-stage
//!   protocol ([`producer::build_proposal`] →
//!   [`producer::vote_on_proposal`] → [`producer::seal_proposal`]),
//!   with a one-call [`producer::produce_solo_block`] for the
//!   single-validator case.
//! - [`mempool`] (M2.0.12) — in-memory transaction pool. Admits
//!   txs after replicating every per-tx gate `apply_block` runs
//!   (`verify_transaction` + ring-membership + commit match +
//!   key-image dedup against chain + mempool). Implements
//!   replace-by-fee on key-image conflict, size-cap eviction of
//!   the lowest-fee entry, and `drain(max)` for highest-fee-first
//!   block inclusion. M2.0.13 adds storage-anchoring admission gates
//!   that mirror `apply_block`'s permanence checks.
//! - [`store`] (M2.1.0) — filesystem checkpoint store over
//!   [`Chain::encode_checkpoint`] / [`Chain::from_checkpoint_bytes`].
//!   This is the first IO-bearing node primitive: boot from a saved
//!   checkpoint if present, otherwise build genesis; save latest state
//!   via a temp-file + backup-slot rotation.
//!
//! Everything below `Chain` / `producer` / `mempool` remains
//! deterministic and synchronous. `store` is intentionally the first
//! narrow IO boundary; network, RPC, and clock concerns remain later
//! M2.x sub-milestones.
//!
//! ## Design — why a separate crate from `mfn-consensus`?
//!
//! `mfn-consensus` is the **specification**: the state-transition function
//! and every byte format that goes on the wire. It must remain
//! library-pure (no IO, no async, no clock) so it can be ported to a
//! light-client crate, a wasm binding, and any number of independent
//! implementations without dragging in a runtime.
//!
//! `mfn-node` is the **first orchestration layer**. It tracks the live
//! chain tip, owns `ChainState`, and is where mempool / P2P / RPC will
//! eventually attach. Even at the skeleton stage that separation matters:
//! a light-client crate (`mfn-light`, future) wants `apply_block` but
//! *not* a `Chain` driver — and a daemon wants a `Chain` driver but
//! shouldn't be reimplementing one against the spec.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No background threads, no clocks, no async runtime.
//! - The only filesystem IO lives in [`store`], isolated behind typed
//!   errors and deterministic checkpoint bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chain;
pub mod mempool;
pub mod producer;
pub mod store;

pub use chain::{Chain, ChainConfig, ChainError, ChainStats};
pub use mempool::{AdmitError, AdmitOutcome, Mempool, MempoolConfig, MempoolEntry};
pub use producer::{
    build_proposal, produce_solo_block, seal_proposal, vote_on_proposal, BlockInputs,
    BlockProposal, ProducerError,
};
pub use store::{ChainStore, StoreError, StoreSave};
