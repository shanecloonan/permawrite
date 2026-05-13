//! # `mfn-light`
//!
//! Light-client chain follower for the Permawrite protocol. Built on
//! top of the M2.0.5 ([`mfn_consensus::verify_header`]), M2.0.7
//! ([`mfn_consensus::verify_block_body`]), and M2.0.8 (the
//! `validator_evolution` module) primitives.
//!
//! A light client *follows* a chain without holding the full
//! `ChainState`: it tracks the current tip's height and `block_id`,
//! it holds a *trusted* validator set (bootstrapped from a
//! [`mfn_consensus::GenesisConfig`]) plus the small shadow state
//! needed to evolve it across rotations (per-validator liveness
//! stats, pending-unbond queue, four bond-epoch counters), and for
//! every new block it:
//!
//! 1. **Verifies chain linkage** — `header.prev_hash` matches the
//!    current `tip_id`, `header.height == current_height + 1`.
//! 2. **Cryptographically verifies the header** via the M2.0.5 light
//!    primitive: `validator_root` matches the trusted set,
//!    producer-proof + BLS finality aggregate verify.
//! 3. **(M2.0.7) Body verification.** The four header-bound body
//!    roots (`tx_root`, `bond_root`, `slashing_root`,
//!    `storage_proof_root`) are re-derived from the body and matched
//!    against the (now authenticated) header.
//! 4. **(M2.0.8) Validator-set evolution.** Apply equivocation
//!    slashings, liveness slashings (from the verified finality
//!    bitmap), bond ops, and unbond settlements — byte-for-byte the
//!    same evolution `mfn-consensus::apply_block` runs, via the
//!    shared `mfn-consensus::validator_evolution` pure helpers.
//! 5. **Advances tip** — new `tip_id = block_id(&header)`.
//!
//! That's enough to follow the chain across arbitrary rotations:
//! the next block's `validator_root` is the cryptographic audit of
//! the previous block's evolution. If the light client gets the
//! evolution wrong, the very next `apply_block` fails with
//! `HeaderVerify` / `ValidatorRootMismatch`.
//!
//! ## Why a separate crate?
//!
//! - **No `ChainState` dependency.** A light client has no UTXO tree,
//!   no storage tree, no validator-stats history — just the
//!   trusted-validators set + tip pointer. Mixing that into
//!   `mfn-consensus` would bloat the spec crate; mixing it into
//!   `mfn-node` would couple light-clients to a daemon they don't
//!   need. A dedicated crate keeps the surface tight.
//! - **WASM / mobile-friendly.** No `tokio`, no `rocksdb`, no
//!   `getrandom` paths that don't work in the browser — pure-Rust
//!   consensus-spec dependencies only. The same crate can compile to
//!   `wasm32-unknown-unknown` for in-browser wallets.
//! - **Stateless verification.** Every method is pure; the
//!   `LightChain` struct is the *only* state, and even it is just a
//!   small fixed-size header (`O(validators)` memory).
//!
//! ## Lifecycle
//!
//! ```text
//!   LightChain::from_genesis(cfg)        ──► tip_height = 0
//!     │
//!     ├── chain.apply_block(&blk1)?      ──► tip_height = 1
//!     ├── chain.apply_block(&blk2)?      ──► tip_height = 2
//!     └── …
//! ```
//!
//! [`chain::LightChain::apply_header`] is also available for callers
//! that only have the header chain (e.g. during a bulk header-first
//! sync, with full bodies fetched later).
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No IO. No clock. No async runtime. No background threads.
//! - All public methods are deterministic and re-entrant-safe.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chain;
pub mod checkpoint;

pub use chain::{
    AppliedBlock, AppliedHeader, LightChain, LightChainConfig, LightChainError, LightChainStats,
};
pub use checkpoint::{
    decode_checkpoint_bytes, encode_checkpoint_bytes, CheckpointParts, LightCheckpointError,
    LIGHT_CHECKPOINT_MAGIC, LIGHT_CHECKPOINT_VERSION,
};

// Re-export the small set of `mfn-consensus` types the M2.0.8 shadow
// state surface uses, so downstream callers don't have to depend on
// `mfn-consensus` directly to inspect `validator_stats`,
// `pending_unbonds`, or the bond-epoch counters.
pub use mfn_consensus::{BondEpochCounters, BondingParams, PendingUnbond, ValidatorStats};
