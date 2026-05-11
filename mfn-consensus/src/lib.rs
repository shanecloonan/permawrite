//! # `mfn-consensus`
//!
//! State-transition function for the Permawrite protocol.
//!
//! This crate turns the raw primitives in [`mfn_crypto`] into a **chain**:
//!
//! - [`emission`] — the protocol's monetary policy (initial subsidy, halvings,
//!   tail emission, treasury split).
//! - [`storage`] — `StorageCommitment` (the optional per-output binding that
//!   anchors a permanent data payload to a transaction). Minimal subset for
//!   v0; the full SPoRA prover + Merkle tree lives in the future
//!   `mfn-storage` crate.
//! - [`transaction`] — RingCT-style confidential transaction: ring-signed
//!   inputs, Pedersen-committed amounts, bulletproof range proofs, stealth
//!   addresses, pseudo-output blindings that prove balance without revealing
//!   amounts.
//! - [`coinbase`] — synthetic block-reward transaction, deterministic so any
//!   node can replay history byte-for-byte.
//!
//! Block + consensus-engine modules (validators, slot leader election,
//! finality, slashing) are next on the roadmap.
//!
//! ## Byte-for-byte parity
//!
//! Every encoder in this crate matches the TypeScript reference in
//! `cloonan-group/lib/network/*.ts` exactly. Test vectors flow TS → Rust
//! initially; once a primitive lands here it becomes the ground truth.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - Secret material — output blindings, ephemeral tx-private scalars,
//!   coinbase blinding factors — is held in [`curve25519_dalek::scalar::Scalar`]
//!   and zeroized on drop (via `mfn_crypto`'s `random_scalar` flow).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod coinbase;
pub mod emission;
pub mod storage;
pub mod transaction;

pub use coinbase::{
    build_coinbase, coinbase_tx_priv, describe_coinbase, is_coinbase_shaped, verify_coinbase,
    CoinbaseError, CoinbaseVerifyResult, PayoutAddress,
};
pub use emission::{
    annual_tail_emission, annualized_inflation_ppb, cumulative_emission, emission_at_height,
    pre_tail_supply_cap, validate_emission_params, EmissionError, EmissionParams,
    DEFAULT_EMISSION_PARAMS, MFN_BASE, MFN_DECIMALS,
};
pub use storage::{storage_commitment_hash, StorageCommitment};
pub use transaction::{
    sign_transaction, tx_id, tx_preimage, verify_transaction, InputSpec, OutputSpec, Recipient,
    SignedTransaction, TransactionWire, TxBuildError, TxInputWire, TxOutputWire, VerifyResult,
    TX_RANGE_BITS, TX_VERSION,
};
