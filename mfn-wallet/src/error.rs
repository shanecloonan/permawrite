//! Errors surfaced by [`mfn_wallet`](crate).
//!
//! Wallet operations distinguish three failure axes:
//!
//! - **Input shape** — caller passed something structurally wrong (e.g.
//!   empty recipient list, fee but no spendable outputs).
//! - **Insufficient state** — wallet's owned-UTXO set or the supplied
//!   decoy pool cannot cover the request.
//! - **Underlying crypto** — `mfn-crypto` / `mfn-consensus` rejected a
//!   primitive (range-proof construction failed, CLSAG balance check
//!   failed). These are flattened via `#[from]` so a caller can `?` them
//!   without rewriting matches every time the upstream error grows.

use thiserror::Error;

/// Top-level error type for wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// `Wallet::build_transfer` was called with an empty recipient list.
    #[error("no recipients supplied")]
    NoRecipients,

    /// Caller asked to send `requested` atomic units but the wallet only
    /// holds `available` in unspent owned outputs (plus fee, if any).
    #[error("insufficient funds: requested {requested}, available {available}")]
    InsufficientFunds {
        /// Total `Σ recipients.value + fee` requested.
        requested: u64,
        /// Total spendable balance currently in the wallet.
        available: u64,
    },

    /// A specific owned-output index was named for spending but is not
    /// (or no longer) in the wallet's spendable set.
    #[error("unknown owned output: {0}")]
    UnknownOwnedOutput(String),

    /// Caller asked for a ring size that the supplied decoy pool cannot
    /// satisfy even after the gamma sampler's fallback to uniform.
    ///
    /// The wallet itself will not silently drop ring size for caller
    /// safety — Monero-style anonymity-set degradation should be an
    /// explicit caller decision.
    #[error("decoy pool too small: ring_size {ring_size}, pool {pool_size}")]
    DecoyPoolTooSmall {
        /// Requested ring size (real + decoys).
        ring_size: usize,
        /// Number of distinct candidates the caller provided.
        pool_size: usize,
    },

    /// The encrypted-amount blob on a candidate output decoded under our
    /// view-key but did NOT open the Pedersen commitment. The output is
    /// not ours (XOR-pad collision artifact). Surfaced as a hard error
    /// only by the `*_strict` scan helpers; the lenient default just
    /// drops the output silently.
    #[error("pedersen commitment does not open with decrypted (value, blinding)")]
    PedersenOpenMismatch,

    /// Underlying `mfn-crypto` error (e.g. `hash_to_point` failure on
    /// derived key-image base).
    #[error(transparent)]
    Crypto(#[from] mfn_crypto::CryptoError),

    /// Underlying `mfn-consensus::sign_transaction` error.
    #[error(transparent)]
    TxBuild(#[from] mfn_consensus::TxBuildError),
}
