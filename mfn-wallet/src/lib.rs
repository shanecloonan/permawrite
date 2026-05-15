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
pub mod decoy;
pub mod error;
pub mod keys;
pub mod owned;
pub mod scan;
pub mod spend;
pub mod upload;
pub mod wallet;

pub use claiming::ClaimingIdentity;
pub use decoy::{build_decoy_pool, DecoyPoolBuilder};
pub use error::WalletError;
pub use keys::{wallet_from_seed, WalletKeys};
pub use owned::{key_image_for_owned, owned_balance, verify_pedersen_open, OwnedOutput, OwnedRef};
pub use scan::{scan_block, scan_transaction, BlockScan, ScannedOutput, TxScan};
pub use spend::{build_transfer, TransferPlan, TransferRecipient};
pub use upload::{
    build_storage_upload, estimate_minimum_fee_for_upload, StorageUploadPlan, UploadArtifacts,
};
pub use wallet::Wallet;
