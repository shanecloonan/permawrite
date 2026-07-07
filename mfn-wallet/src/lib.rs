//! Permawrite wallet primitives.
//!
//! `mfn-wallet` is the first **consumer-facing** crate in the workspace.
//! Everything below the wallet (consensus, crypto, storage, light client)
//! is concerned with making the chain *correct and verifiable*. The wallet
//! is concerned with making the chain *usable by humans*:
//!
//! 1. **Receive privately.** Scan every block as it lands and find the
//!    outputs that pay this wallet, using indexed stealth addresses + the
//!    encrypted-amount blob. Verify the Pedersen commitment opens to the
//!    advertised `(value, blinding)` before treating an output as owned —
//!    `decrypt_output_amount` is XOR-pad-shaped and will happily return
//!    garbage for outputs that are not addressed to us.
//!
//! 2. **Track ownership.** Maintain a local UTXO database keyed by
//!    one-time-address. Pre-compute the *key image* for each owned output
//!    so that when we see one of our own UTXOs spent on-chain (e.g. by
//!    another instance of this wallet on another device) we can mark it
//!    spent locally without re-running the whole scan.
//!
//! 3. **Send privately.** Build CLSAG-signed transfer transactions by
//!    drawing decoys from a gamma-age pool (see
//!    [`mfn_crypto::select_gamma_decoys`]), assembling the ring with the
//!    real input at a random slot, and delegating to
//!    [`mfn_consensus::sign_transaction`] for the RingCT ceremony.
//!
//! 4. **Store permanently.** Build CLSAG-signed *storage upload*
//!    transactions ([`build_storage_upload`]) that anchor a
//!    [`mfn_storage::StorageCommitment`] in the tx's first output and
//!    pay a fee whose treasury slice (`fee · fee_to_treasury_bps /
//!    10000`) covers the protocol-required upfront endowment. Every
//!    reason the mempool's storage gate could reject the tx is hoisted
//!    to a typed wallet error so the wallet never signs a tx the
//!    network would refuse — saving CLSAG work and avoiding the privacy
//!    cost of broadcasting a tx whose key images become public for
//!    nothing.
//!
//! Everything here is **pure, deterministic, and IO-free**. The wallet
//! does not own a `Chain`, a `LightChain`, or any database — callers feed
//! it [`Block`]s and ask for [`TransactionWire`]s. This keeps the crate
//! WASM-friendly and lets the same primitives back a desktop wallet, a
//! mobile wallet, a backend signer, and the future `mfn-cli wallet`
//! binary.
//!
//! [`Block`]: mfn_consensus::Block
//! [`TransactionWire`]: mfn_consensus::TransactionWire

#![warn(missing_docs)]

pub mod claiming;
pub mod keys;

pub use claiming::ClaimingIdentity;
pub use keys::{wallet_from_seed, WalletKeys};

#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod decoy;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod error;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod owned;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod scan;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod spend;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod stored;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod upload;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod upload_artifact;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub mod wallet;

/// Minimum CLSAG ring size enforced by reference wallets (matches consensus `min_ring_size`).
pub const WALLET_MIN_RING_SIZE: usize = 16;

/// Minimum number of outputs the reference wallet will place in a
/// value-transfer transaction (privacy floor, Monero-parity).
///
/// A transaction with a single output leaks that it is a no-change
/// sweep or an exact-amount payment — a strong fingerprint that lets an
/// observer distinguish those spends from ordinary "payment + change"
/// transfers and shrinks the plausible-recipient set. The reference
/// wallet therefore never broadcasts a one-output transfer: it pads to
/// two outputs with a zero-value output back to the sender. Output
/// amounts are Pedersen-committed, so the padding output is
/// indistinguishable on-chain from any other output.
pub const WALLET_MIN_TX_OUTPUTS: usize = 2;

/// Normative OS CSPRNG for transaction construction (**F5-P9** / B3 tail).
///
/// Every reference frontend (CLI, WASM, native wallet) must pass this
/// function (or an equivalent OS-backed CSPRNG with the same `[0, 1)`
/// contract) as the `rng` argument to [`Wallet::build_transfer`],
/// [`build_transfer`], and [`build_storage_upload`]. It drives decoy
/// sampling, signer-slot selection, and output-order shuffling — a
/// predictable or reused seed collapses all three to a fingerprint.
///
/// [`mfn_crypto::seeded_rng`] is for unit/integration tests only.
pub use mfn_crypto::crypto_random as production_tx_rng;

#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use decoy::{
    build_decoy_pool, build_decoy_pool_from_sources, DecoyPoolBuilder, RingMember, UtxoDecoySource,
};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use error::WalletError;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use owned::{key_image_for_owned, owned_balance, verify_pedersen_open, OwnedOutput, OwnedRef};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use scan::{scan_block, scan_transaction, BlockScan, ScannedOutput, TxScan};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use spend::{build_transfer, TransferPlan, TransferRecipient};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use stored::StoredOwnedOutput;
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use upload::{
    build_storage_upload, estimate_minimum_fee_for_upload, StorageUploadPlan, UploadArtifacts,
};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use upload_artifact::{
    decode_upload_artifact_meta, encode_upload_artifact_meta, rebuild_built_commitment,
    upload_artifact_meta_from_upload, UploadArtifactMeta, UploadArtifactMetaError,
    UploadArtifactRebuildError,
};
#[cfg(any(feature = "full", feature = "wasm-full"))]
pub use wallet::Wallet;
