//! # `mfn-node`
//!
//! Permawrite node daemon: persistence ([`store`]), JSON-RPC + P2P ([`mfnd`]),
//! and composition of [`mfn_runtime`] (chain driver, mempool, producer).
//!
//! ## Crate boundaries
//!
//! - [`mfn_runtime`] — in-process chain + mempool + producer (no IO).
//! - **`mfn-node`** (this crate) — filesystem store, `network`, `mfnd` binary.
//! - [`mfn_consensus`] — pure state-transition function.
//!
//! Public types from [`mfn_runtime`] are re-exported here for backward compatibility
//! (`Chain`, `Mempool`, `produce_solo_block`, genesis helpers, …).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod network;
pub mod store;

mod mfnd_cli;
mod mfnd_serve;

// Re-export runtime orchestration (prefer `mfn_runtime` in new code).
pub use mfn_runtime::{
    genesis_config_from_json_bytes, genesis_config_from_json_path, hex_seed32,
    AdmitError, AdmitOutcome, BlockInputs, BlockProposal, Chain, ChainConfig, ChainError,
    ChainStats, GenesisSpecError, Mempool, MempoolConfig, MempoolEntry, ProducerError,
    MAX_SYNTHETIC_DECOY_UTXOS,
};
pub use mfn_runtime::{
    build_proposal, produce_solo_block, seal_proposal, vote_on_proposal,
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

pub use network::NetworkConfig;
pub use store::{ChainStore, StoreError, StoreSave};

/// Entry point for the `mfnd` binary (`cargo run -p mfn-node --bin mfnd`).
#[must_use]
pub fn mfnd_main() -> std::process::ExitCode {
    mfnd_cli::mfnd_main()
}
