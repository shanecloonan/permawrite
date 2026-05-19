//! Permawrite browser bindings (**M4.0**).
//!
//! Exposes the same Rust wallet and storage primitives as `mfn-cli` / `mfn-wallet`
//! via [`wasm-bindgen`] so web extensions and demo pages do not drift from the
//! reference implementation.
//!
//! Network IO (JSON-RPC to `mfnd serve`) stays in JavaScript; cryptography and
//! commitment construction run here.

#![warn(missing_docs)]

mod core;
mod wasm;

#[cfg(feature = "wasm-full")]
mod scan_core;
#[cfg(feature = "wasm-full")]
mod transfer_core;
#[cfg(feature = "wasm-full")]
mod upload_core;

pub use core::{
    claim_pubkey_hex_from_seed, storage_upload_preview_json, wallet_address_json_from_seed,
    WasmCoreError,
};

pub use wasm::{
    wasm_claim_pubkey_from_seed_hex, wasm_storage_upload_preview, wasm_wallet_address_from_seed_hex,
};

#[cfg(feature = "wasm-full")]
pub use scan_core::{scan_block_hex_json, scan_transaction_hex_json};
#[cfg(feature = "wasm-full")]
pub use transfer_core::{build_transfer_json, decoy_pool_preview_json};
#[cfg(feature = "wasm-full")]
pub use upload_core::{build_storage_upload_json, upload_min_fee_json};

#[cfg(feature = "wasm-full")]
pub use wasm::{
    wasm_build_storage_upload, wasm_build_transfer_json, wasm_decoy_pool_preview_json,
    wasm_scan_block_hex, wasm_scan_transaction_hex, wasm_upload_min_fee,
};
