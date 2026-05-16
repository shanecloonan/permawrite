//! # `mfn-store`
//!
//! Persistence for [`mfn_runtime::Chain`]: checkpoint snapshots and the
//! append-only `chain.blocks` sidecar.
//!
//! ## Layout
//!
//! | Crate | Role |
//! |-------|------|
//! | `mfn-consensus` | Pure STF + wire formats |
//! | `mfn-runtime` | In-memory chain driver (no IO) |
//! | **`mfn-store`** | Checkpoint + block log persistence |
//! | `mfn-node` | Daemon: RPC, P2P, `mfnd` |
//!
//! ## Backends
//!
//! - [`fs::ChainStore`] — directory with `chain.checkpoint` + `chain.blocks` (today).
//! - [`ChainPersistence`] — trait seam for future `redb` / column-family backends.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - Single-writer convention; no async runtime in this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;
pub mod fs;
#[path = "trait.rs"]
pub mod r#trait;

pub use error::{StoreError, StoreSave};
pub use fs::ChainStore;
pub use r#trait::ChainPersistence;
