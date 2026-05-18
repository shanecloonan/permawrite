//! # `mfn-runtime`
//!
//! In-process orchestration over [`mfn_consensus`]: the deterministic layer that
//! turns the state-transition function into a **live chain** without IO,
//! clocks, async, or networking.
//!
//! ## Modules
//!
//! - [`Chain`] — owns [`mfn_consensus::ChainState`], applies blocks via
//!   [`mfn_consensus::apply_block`], checkpoint encode/decode.
//! - [`Mempool`] — admission, replace-by-fee, fee-ordered drain, mined eviction.
//! - [`producer`] — build / vote / seal block proposals; [`produce_solo_block`] for devnet.
//! - [`genesis_spec`] — versioned JSON → [`mfn_consensus::GenesisConfig`].
//! - [`demo_genesis`] — default empty local dev genesis.
//!
//! ## Crate boundaries
//!
//! | Crate | Role |
//! |-------|------|
//! | `mfn-consensus` | Pure STF + wire formats (no IO) |
//! | **`mfn-runtime`** | Chain + mempool + producer (no IO) |
//! | `mfn-store` | Checkpoint + block log persistence |
//! | `mfn-rpc` | JSON-RPC dispatch (no sockets) |
//! | `mfn-net` | P2P framing + handshakes |
//! | `mfn-node` | Daemon: RPC TCP loop, `mfnd` binary |
//!
//! Light clients and wallets depend on `mfn-consensus` (and optionally
//! `mfn-runtime` for tests); they must not depend on `mfn-node`.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No background threads, no filesystem access in the public API
//!   ([`genesis_spec::genesis_config_from_json_path`] is the only IO helper).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chain;
pub mod demo_genesis;
pub mod genesis_spec;
pub mod mempool;
pub mod mempool_snapshot;
pub mod producer;
pub mod proposal_wire;

pub use chain::{Chain, ChainConfig, ChainError, ChainStats};
pub use genesis_spec::{
    genesis_config_from_json_bytes, genesis_config_from_json_path, hex_seed32, GenesisSpecError,
    MAX_SYNTHETIC_DECOY_UTXOS,
};
pub use mempool::{AdmitError, AdmitOutcome, Mempool, MempoolConfig, MempoolEntry};
pub use mempool_snapshot::{
    decode_mempool_snapshot, encode_mempool_snapshot, mempool_root, MempoolRestoreStats,
    MempoolSnapshotEntry, MempoolSnapshotError, MEMPOOL_HEIGHT_UNKNOWN, MEMPOOL_SNAPSHOT_MAGIC,
    MEMPOOL_SNAPSHOT_VERSION,
};
pub use producer::{
    build_proposal, produce_solo_block, seal_proposal, vote_on_proposal, BlockInputs,
    BlockProposal, ProducerError,
};
pub use proposal_wire::{
    decode_block_proposal, decode_committee_vote, encode_block_proposal, encode_committee_vote,
    verify_committee_vote_sig, ProposalWireError,
};
