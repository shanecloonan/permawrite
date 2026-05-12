//! # `mfn-node`
//!
//! Node-side glue around [`mfn_consensus`]. This crate is the future home
//! of the mempool, P2P stack, persistent storage, RPC server, and producer
//! / voter loops — the things that turn a state-transition function into
//! a **running chain**.
//!
//! ## What this crate provides today (M2.0.3 + M2.0.4)
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
//!
//! Everything in this crate is **deterministic and synchronous**.
//! Network / disk / clock concerns are deliberately absent — they belong
//! in later M2.x sub-milestones. Keeping the chain driver pure makes it
//! the same code path the producer loop, the RPC handler, and the (later)
//! sync replay engine will all share.
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
//! - No background threads, no clocks, no IO — every public method is
//!   synchronous, deterministic, and re-entrant-safe.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chain;
pub mod producer;

pub use chain::{Chain, ChainConfig, ChainError, ChainStats};
pub use producer::{
    build_proposal, produce_solo_block, seal_proposal, vote_on_proposal, BlockInputs,
    BlockProposal, ProducerError,
};
