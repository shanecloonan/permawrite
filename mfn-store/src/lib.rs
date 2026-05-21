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

pub mod chunk_inbox;
pub mod error;
pub mod fs;
pub mod mempool_persist;
pub mod peers_persist;
pub mod proof_pool_persist;
pub mod redb_store;
#[path = "trait.rs"]
pub mod r#trait;
mod validate;

pub use chunk_inbox::{
    chunk_inbox_commit_dir, chunk_inbox_complete, chunk_inbox_path, list_chunk_inbox_indices,
    missing_chunk_inbox_indices, read_chunk_inbox, save_chunk_inbox, ChunkInboxError,
    CHUNK_INBOX_DIR,
};
pub use error::{StoreError, StoreSave};
pub use fs::ChainStore;
pub use mempool_persist::{
    load_mempool, mempool_path, remove_mempool_file, save_mempool, MempoolSaveMeta, MEMPOOL_FILE,
};
pub use peers_persist::{
    load_peers, peers_path, remove_peers_file, save_peers, PeersFileV1, DEFAULT_MAX_OUTBOUND_PEERS,
    PEERS_FILE,
};
pub use proof_pool_persist::{
    load_proof_pool, proof_pool_path, remove_proof_pool_file, save_proof_pool, ProofPoolSaveMeta,
    PROOF_POOL_FILE,
};
pub use r#trait::ChainPersistence;
pub use redb_store::RedbChainStore;
