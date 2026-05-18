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
//! | `mfn-rpc` | JSON-RPC dispatch (no sockets) |
//! | `mfn-net` | P2P framing + handshakes |
//! | `mfn-node` | Daemon: RPC TCP loop, `mfnd` |
//!
//! ## Backends
//!
//! - [`fs::ChainStore`] — directory with `chain.checkpoint` + `chain.blocks`.
//! - [`redb_store::RedbChainStore`] — embedded `chain.redb` KV database.
//! - [`ChainPersistence`] — trait seam shared by both backends.
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
pub mod mempool_persist;
pub mod redb_store;
#[path = "trait.rs"]
pub mod r#trait;
mod validate;

pub use error::{StoreError, StoreSave};
pub use mempool_persist::{
    load_mempool, mempool_path, remove_mempool_file, save_mempool, MempoolSaveMeta, MEMPOOL_FILE,
};
pub use fs::ChainStore;
pub use r#trait::ChainPersistence;
pub use redb_store::RedbChainStore;
