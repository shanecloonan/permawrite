//! # `mfn-node`
//!
//! Permawrite node daemon: JSON-RPC + P2P ([`mfnd`]) and composition of
//! [`mfn_runtime`] (chain driver), [`mfn_store`] (persistence), [`mfn_rpc`], and [`mfn_net`].
//!
//! ## Crate boundaries
//!
//! - [`mfn_runtime`] — in-process chain + mempool + producer (no IO).
//! - [`mfn_store`] — checkpoint + block-log persistence.
//! - [`mfn_rpc`] — JSON-RPC dispatch (no sockets).
//! - [`mfn_net`] — P2P framing, handshakes, serve P2P threads.
//! - **`mfn-node`** (this crate) — RPC TCP accept loop, `mfnd` binary.
//! - [`mfn_consensus`] — pure state-transition function.
//!
//! Public types from [`mfn_runtime`] and [`mfn_store`] are re-exported for
//! backward compatibility (`Chain`, `ChainStore`, …).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
// Production daemon paths must never panic on peer input (B-08); tests are exempt.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

mod archive_export;
mod mfnd_cli;
mod mfnd_serve;
mod node_store;
mod p2p_block_sync;
mod p2p_boot;
mod p2p_chunk_fanout;
mod p2p_chunk_inbox;
mod p2p_fanout;
mod p2p_gossip;
mod p2p_light_follow_fetch;
mod p2p_peer_quarantine;
mod p2p_reconnect_plan;
mod runner;

pub use archive_export::{
    export_archive, verify_archive, ArchiveCommitment, ArchiveError, ArchiveExportReport,
    ArchiveManifest, ArchiveVerifyReport, ARCHIVE_FORMAT_V1, ARCHIVE_MANIFEST_FILE,
};
pub use node_store::{NodeStore, StoreBackend};

pub mod network {
    //! Re-exported from [`mfn_net`] (frame, handshake, serve helpers).
    pub use mfn_net::*;
}

// Re-export runtime orchestration (prefer `mfn_runtime` in new code).
pub use mfn_runtime::{build_proposal, produce_solo_block, seal_proposal, vote_on_proposal};
pub use mfn_runtime::{
    genesis_config_from_json_bytes, genesis_config_from_json_path, hex_seed32, AdmitError,
    AdmitOutcome, BlockInputs, BlockProposal, Chain, ChainConfig, ChainError, ChainStats,
    GenesisSpecError, Mempool, MempoolConfig, MempoolEntry, ProducerError,
    MAX_SYNTHETIC_DECOY_UTXOS,
};
pub mod chain {
    //! Re-exported from [`mfn_runtime::chain`].
    pub use mfn_runtime::chain::*;
}
pub mod demo_genesis {
    //! Re-exported from [`mfn_runtime::demo_genesis`].
    pub use mfn_runtime::demo_genesis::*;
}
pub mod genesis_spec {
    //! Re-exported from [`mfn_runtime::genesis_spec`].
    pub use mfn_runtime::genesis_spec::*;
}
pub mod mempool {
    //! Re-exported from [`mfn_runtime::mempool`].
    pub use mfn_runtime::mempool::*;
}
pub mod producer {
    //! Re-exported from [`mfn_runtime::producer`].
    pub use mfn_runtime::producer::*;
}
pub mod store {
    //! Re-exported from [`mfn_store`].
    pub use mfn_store::*;
}

pub use mfn_store::{ChainPersistence, ChainStore, RedbChainStore, StoreError, StoreSave};
pub use network::NetworkConfig;

pub use crate::p2p_fanout::P2pPeerSet;
pub use crate::runner::{
    produce_config_from_env, ProduceConfig, ProductionEngine, ProductionEngineDeps,
};

/// Entry point for the `mfnd` binary (`cargo run -p mfn-node --bin mfnd`).
#[must_use]
pub fn mfnd_main() -> std::process::ExitCode {
    mfnd_cli::mfnd_main()
}
