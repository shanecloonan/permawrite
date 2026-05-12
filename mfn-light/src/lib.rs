//! # `mfn-light`
//!
//! Light-client chain follower for the Permawrite protocol. Built on
//! top of the M2.0.5 ([`mfn_consensus::verify_header`]) and M2.0.7
//! ([`mfn_consensus::verify_block_body`]) primitives.
//!
//! A light client *follows* a chain without holding the full
//! `ChainState`: it tracks the current tip's height and `block_id`,
//! it holds a *trusted* validator set (bootstrapped from a
//! [`mfn_consensus::GenesisConfig`]), and for every new header (or
//! block) it:
//!
//! 1. **Verifies chain linkage** — `header.prev_hash` matches the
//!    current `tip_id`, `header.height == current_height + 1`.
//! 2. **Cryptographically verifies the header** via the M2.0.5 light
//!    primitive: `validator_root` matches the trusted set,
//!    producer-proof + BLS finality aggregate verify.
//! 3. **(Optional, M2.0.7) Body verification.** If the caller passes a
//!    full block via [`chain::LightChain::apply_block`], the four
//!    header-bound body roots (`tx_root`, `bond_root`, `slashing_root`,
//!    `storage_proof_root`) are re-derived from the body and matched
//!    against the (now authenticated) header.
//! 4. **Advances tip** — new `tip_id = block_id(&header)`.
//!
//! That's enough to follow the chain through a window of stable
//! validator-set membership. **Validator-set evolution** across
//! `BondOp::Register` / `BondOp::Unbond` / slashings / unbond
//! settlements / liveness slashing arrives in a later slice
//! ([M2.0.8 — Validator-set evolution]). Until then, callers should
//! re-bootstrap the trusted set across rotation boundaries (e.g.
//! from a freshly-trusted checkpoint header + body).
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

pub use chain::{
    AppliedBlock, AppliedHeader, LightChain, LightChainConfig, LightChainError, LightChainStats,
};
