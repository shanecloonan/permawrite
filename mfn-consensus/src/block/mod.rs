//! Block + chain-state machine.
//!
//! This module turns the
//! crate's other primitives — transactions, coinbase, emission, slashing,
//! consensus finality — into an **actual chain** with a deterministic
//! state-transition function.
//!
//! Three concepts:
//!
//! - [`BlockHeader`] / [`Block`] — header + body, deterministically hashed.
//! - [`ChainState`] — known UTXOs, spent key images, storage registry,
//!   validator set, treasury, accumulator root, and the block-id chain.
//! - [`apply_block`] — pure function that validates a candidate block
//!   against the current state and returns either a new state or a list
//!   of errors. Same inputs always produce the same outputs (modulo
//!   hashing the same bytes).
//!
//! ## v0.1 scope
//!
//! This is the consensus-critical subset. The rest of the protocol
//! (storage proof verification, endowment-based per-tx burden, treasury
//! drain → storage reward routing, storage proof reward bonuses) lives
//! gated behind the future [`mfn-storage`](https://github.com/...)
//! crate. Block application here:
//!
//! - verifies header sanity (height, prev hash);
//! - checks the tx Merkle root;
//! - verifies the producer's [`crate::consensus::FinalityProof`] when
//!   the chain has a validator set;
//! - walks the tx list: position 0 may be a coinbase, all others go
//!   through [`crate::transaction::verify_transaction`];
//! - rejects cross-tx and cross-chain double-spends;
//! - inserts new UTXOs into both the map and the cryptographic
//!   accumulator;
//! - registers new storage commitments (without enforcing endowment);
//! - applies slashing evidence (stake zeroed);
//! - verifies the coinbase against `emission(height) + producer_fee` when
//!   the producer has a payout address;
//! - checks the storage Merkle root + the UTXO accumulator root.
//!
//! When the storage layer lands, the per-block apply function will gain
//! storage-proof verification, endowment-burden enforcement, and the
//! two-sided treasury/emission settlement. The wire format is forward-
//! compatible: blocks produced today will still validate then.

#[cfg(feature = "bls")]
mod apply;
#[cfg(feature = "bls")]
mod builder;
mod error;
mod genesis;
mod header;
mod internal;
mod state;
mod wire;

#[cfg(feature = "bls")]
pub use apply::{apply_block, ApplyOutcome};
#[cfg(feature = "bls")]
pub use builder::{build_unsealed_header, seal_block};
pub use error::BlockError;
pub use genesis::{apply_genesis, build_genesis, GenesisConfig, GenesisOutput};
pub use header::{
    block_header_bytes, block_id, decode_block_header, header_signing_bytes, header_signing_hash,
    Block, BlockHeader, HeaderDecodeError, HEADER_VERSION,
};
pub use state::{
    ChainState, ConsensusParams, PendingUnbond, StorageEntry, UtxoEntry, ValidatorStats,
    DEFAULT_CONSENSUS_PARAMS,
};
pub use wire::{
    decode_block, decode_block_body, encode_block, encode_block_body, storage_merkle_root,
    tx_merkle_root, BlockBody, BlockDecodeError,
};
