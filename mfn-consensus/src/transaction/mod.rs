//! Confidential transaction — RingCT-style with stealth addressing and
//! permanence binding.
//!
//! The shape and
//! encoding are byte-for-byte identical so Rust //! implementation produce equal `tx_id` values for the same input.
//!
//! ## Anatomy
//!
//! ```text
//! Transaction
//! ├── version              codec version (2 current; 1 legacy)
//! ├── R                    tx-level public key (R = r·G; recipients scan with it)
//! ├── fee                  public u64 (the producer claims this)
//! ├── extra                opaque payload (memo, hint), bound by the preimage
//! ├── inputs[i]
//! │   ├── ring             { P[..], C[..] } — anonymity set
//! │   ├── c_pseudo         pseudo-output commitment (matches real value)
//! │   └── sig              CLSAG signature + key image
//! └── outputs[i]
//!     ├── one_time_addr    stealth address P_i
//!     ├── amount           Pedersen commitment C_i = γ_i·G + v_i·H
//!     ├── range_proof      Bulletproof for v_i ∈ [0, 2^TX_RANGE_BITS)
//!     ├── enc_amount       40-byte RingCT-style encrypted (value, blinding)
//!     ├── view_tag         optional 1-byte scan hint (v2 only)
//!     └── storage          optional StorageCommitment (permanence binding)
//! ```
//!
//! ## Soundness chain
//!
//! 1. Each `range_proof` proves the output amount is non-negative and bounded
//!    — no overflow into the modular wrap-around.
//! 2. The balance equation `Σ c_pseudo − Σ amount − fee·H == 0·G` proves
//!    inputs and outputs sum to the same hidden value plus the public fee.
//! 3. Each CLSAG proves the spender owns one of the ring members AND knows
//!    the blinding-factor difference `r_in − r_pseudo`, linking the pseudo
//!    commitment to a real prior output.
//! 4. The key image `I` is unique per real input: the same `I` appearing in
//!    two transactions is a global double-spend.

/// Current consensus version of the transaction wire format.
pub const TX_VERSION: u32 = 2;

/// Legacy wire format without per-output view tags.
pub const TX_VERSION_LEGACY: u32 = 1;

/// Whether `version` is accepted at transaction ingress.
#[must_use]
pub fn tx_version_supported(version: u32) -> bool {
    version == TX_VERSION || version == TX_VERSION_LEGACY
}

/// Canonical bit width of output range proofs. Amounts are 64-bit unsigned.
pub const TX_RANGE_BITS: u32 = 64;

mod build;
mod codec;
mod id;
mod internal;
mod verify;
mod wire;

#[cfg(test)]
mod tests;

pub use build::{
    sign_transaction, InputSpec, OutputSpec, Recipient, SignedTransaction, TxBuildError,
};
pub(crate) use codec::read_transaction;
pub use codec::{decode_transaction, encode_transaction, TxDecodeError};
pub use id::{tx_id, tx_preimage};
pub use verify::{verify_transaction, VerifyResult};
pub use wire::{TransactionWire, TxInputWire, TxOutputWire};
